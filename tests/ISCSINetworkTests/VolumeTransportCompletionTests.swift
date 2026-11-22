import FSKit
import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private func volumeTerminalEventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<100_000 {
        if await condition() { return true }
        await Task.yield()
    }
    return false
}

private func volumeTerminalFixture() async throws -> (
    ReservedRemoteDisk, LUNImageVolume, ReservationTarget, ContinuousLeaseFixture, IntentFixture
) {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store,
        maximumTransferBlocks: 1, diagnostics: nil)
    return (
        reserved, LUNImageVolume(reservedDisk: reserved, identifier: UUID()), target, lease, store
    )
}

@Test func volumeTerminalCompletionJoinsOneOriginalSessionWithoutReleasingReservation() async throws
{
    let (_, volume, target, lease, store) = try await volumeTerminalFixture()
    #expect(try await volume.write(contents: Data([7]), to: volume.imageItem, at: 7) == 1)
    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
        await volume.finishCacheClose(volume.imageItem)
    #endif
    let original = store.load()
    let syncs = await target.dataCommands.filter { $0 == 0x35 }.count
    #expect(await volume.finishTransportAfterDrainingIO() == .synchronizedAndLoggedOut)
    #expect(await volume.finishTransportAfterDrainingIO() == .synchronizedAndLoggedOut)
    #expect(await target.dataCommands.filter { $0 == 0x35 }.count == syncs + 1)
    #expect(await target.logoutRequests == 1)
    #expect(await target.actions == [0, 1])
    #expect(await target.hasReservation())
    #expect(store.load() == original)
    #expect(!lease.externalWritersAdmitted)
    await #expect(throws: POSIXError.self) { try await volume.synchronize(flags: .wait) }
}

@Test func volumeTerminalSealLetsOriginalChunkedWriteFinishAndRejectsQueuedIO() async throws {
    let (_, volume, target, _, _) = try await volumeTerminalFixture()
    let before = await target.dataCommands.count
    await target.pauseNextDataOut(fence: { false })
    let write = Task {
        try await volume.write(
            contents: Data(repeating: 7, count: 1024), to: volume.imageItem, at: 0)
    }
    #expect(await volumeTerminalEventually { await target.dataPause.isWaiting })
    let stale = try volume.captureIOAdmission()
    let queued = Task { try await volume.synchronize(flags: .wait) }
    #expect(await volumeTerminalEventually { await volume.queuedIOCount == 1 })
    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
        let close = Task { await volume.finishCacheClose(volume.imageItem) }
        #expect(await volumeTerminalEventually { await volume.queuedIOCount == 2 })
    #endif
    let normal = Task { await volume.finishTransportAfterDrainingIO() }
    #expect(await volumeTerminalEventually { volume.isTransportCompletionStarted })
    await #expect(throws: POSIXError.self) { try await volume.synchronize(flags: .wait) }
    await target.dataPause.resume()
    #expect(try await write.value == 1024)
    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
        await close.value
    #endif
    await #expect(throws: POSIXError.self) { try await queued.value }
    #expect(await normal.value == .synchronizedAndLoggedOut)
    await #expect(throws: POSIXError.self) {
        try await volume.performIO(admission: stale) { try await volume.synchronize(flags: .wait) }
    }
    #expect(await target.dataCommands.dropFirst(before).filter { $0 == 0x2A }.count == 2)
    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
        #expect(await target.dataCommands.dropFirst(before).filter { $0 == 0x35 }.count == 3)
    #else
        #expect(await target.dataCommands.dropFirst(before).filter { $0 == 0x35 }.count == 2)
    #endif
    #expect(await target.logoutRequests == 1)
}

@Test func volumeTerminalAlreadyCancelledCallerCannotPublishUncancelledNormalWork() async throws {
    let (_, volume, target, _, store) = try await volumeTerminalFixture()
    let before = await target.dataCommands
    let normal = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await volume.finishTransportAfterDrainingIO()
    }
    #expect(await normal.value == .abandoned)
    #expect(await target.dataCommands == before)
    #expect(await target.logoutRequests == 0)
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test(arguments: [false, true])
func volumeTerminalCancellationOrGenericShutdownJoinsOriginalLogout(_ generic: Bool) async throws {
    let (_, volume, target, _, store) = try await volumeTerminalFixture()
    await target.pauseNextLogout()
    let results = Mutex<[ReservedTransportCloseResult]>([])
    let first = Task {
        let result = await volume.finishTransportAfterDrainingIO()
        results.withLock { $0.append(result) }
        return result
    }
    #expect(await volumeTerminalEventually { await target.logoutPause.isWaiting })
    let second = Task { await volume.finishTransportAfterDrainingIO() }
    if generic { await volume.shutdown() } else { first.cancel() }
    #expect(await volumeTerminalEventually { await target.isClosed })
    #expect(results.withLock { $0.isEmpty })
    await target.logoutPause.resume()
    #expect(await first.value == .abandoned)
    #expect(await second.value == .abandoned)
    #expect(await target.logoutRequests == 1)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func volumeTerminalUnrecoveredIncidentCannotBeConvertedIntoFinalSynchronization() async throws
{
    let (reserved, volume, target, lease, _) = try await volumeTerminalFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    let original = reserved.disk.mutationEvidence
    let commands = await target.dataCommands
    #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
    #expect(await target.dataCommands == commands)
    #expect(reserved.disk.mutationEvidence == original)
    #expect(lease.outstandingPins > 0)
    #expect(await target.logoutRequests == 0)
}

@Test func volumeTerminalLateCancellationPreservesCompletedHistoricalResult() async throws {
    let (reserved, volume, target, _, _) = try await volumeTerminalFixture()
    #expect(await volume.finishTransportAfterDrainingIO() == .synchronizedAndLoggedOut)
    let calls = await target.closeCalls
    let late = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await volume.finishTransportAfterDrainingIO()
    }
    #expect(await late.value == .synchronizedAndLoggedOut)
    // Joining the lower completion also joins any cleanup task a late cancellation started;
    // the volume's own result doesn't, so without this a late cleanup could go unseen.
    #expect(await reserved.transportCompletion().wait() == .synchronizedAndLoggedOut)
    #expect(await target.closeCalls == calls)
}

@Test func volumeTerminalPrecompletedLowerCannotEraseUpperCancellation() async throws {
    let (reserved, volume, _, _, _) = try await volumeTerminalFixture()
    #expect(await reserved.transportCompletion().wait() == .synchronizedAndLoggedOut)
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await volume.finishTransportAfterDrainingIO()
    }
    #expect(await cancelled.value == .abandoned)
}

@Test func volumeTerminalPrecompletedLowerCannotEraseGenericShutdownFailure() async throws {
    let (reserved, volume, _, _, _) = try await volumeTerminalFixture()
    #expect(await reserved.transportCompletion().wait() == .synchronizedAndLoggedOut)
    await volume.shutdown()
    #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
}

#if ISCSI_FSKIT_CACHE_DIAGNOSTIC
    @available(macOS 27.0, *)
    @Test func volumeTerminalPrecompletedLowerCannotEraseOpenCachePrerequisite() async throws {
        let (reserved, volume, _, _, _) = try await volumeTerminalFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        #expect(await reserved.transportCompletion().wait() == .synchronizedAndLoggedOut)
        #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
    }

    @available(macOS 27.0, *)
    @Test func volumeTerminalRetainsOriginalCacheCloseWaitingForRecovery() async throws {
        let (reserved, volume, target, lease, _) = try await volumeTerminalFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        await target.failNextSynchronization()
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
        }
        let original = reserved.disk.mutationEvidence
        let syncs = await target.dataCommands.filter { $0 == 0x35 }.count
        lease.pauseAssertion()
        let recovery = Task { try await volume.recoverSynchronizationFailure() }
        #expect(await volumeTerminalEventually { await lease.pause.isWaiting })
        let close = Task { await volume.finishCacheClose(volume.imageItem) }
        #expect(await volumeTerminalEventually { volume.isCacheCloseWaitingForRecovery })
        let normal = Task { await volume.finishTransportAfterDrainingIO() }
        #expect(await volumeTerminalEventually { volume.isTransportCompletionStarted })
        await lease.pause.resume()
        try await recovery.value
        await close.value
        #expect(await normal.value == .synchronizedAndLoggedOut)
        #expect(reserved.disk.recoveryHistory.map(\.original) == [original])
        // Original recovery barrier, original close barrier, and terminal barrier.
        #expect(await target.dataCommands.filter { $0 == 0x35 }.count == syncs + 3)
        #expect(await target.logoutRequests == 1)
        await #expect(throws: POSIXError.self) {
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .none)
        }
    }

    @available(macOS 27.0, *)
    @Test func volumeTerminalActiveCacheBarrierFailureRemainsUnaccepted() async throws {
        let (reserved, volume, target, lease, _) = try await volumeTerminalFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        try await reserved.disk.write(offset: 0, data: Data(repeating: 3, count: 512))
        await target.pauseNextSynchronization()
        let close = Task { await volume.finishCacheClose(volume.imageItem) }
        #expect(await volumeTerminalEventually { await target.synchronizationPause.isWaiting })
        let normal = Task { await volume.finishTransportAfterDrainingIO() }
        #expect(await volumeTerminalEventually { volume.isTransportCompletionStarted })
        await target.failNextSynchronization()
        await target.synchronizationPause.resume()
        await close.value
        #expect(await normal.value == .abandoned)
        #expect(reserved.disk.mutationEvidence.incident != nil)
        #expect(lease.outstandingPins > 0)
        #expect(await target.logoutRequests == 0)
    }

    @available(macOS 27.0, *)
    @Test func volumeTerminalOpenCacheItemCannotBeLaunderedByALateClose() async throws {
        let (_, volume, target, _, _) = try await volumeTerminalFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        let commands = await target.dataCommands
        #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
        await volume.finishCacheClose(volume.imageItem)
        #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
        #expect(await target.dataCommands == commands)
        #expect(await target.logoutRequests == 0)
    }
#else
    @Test func volumeTerminalLegacyOpenItemMustAlreadyBeClosed() async throws {
        let (_, volume, target, _, _) = try await volumeTerminalFixture()
        try await volume.openItem(volume.imageItem, modes: .read)
        let commands = await target.dataCommands
        #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
        #expect(await target.dataCommands == commands)
        #expect(await target.logoutRequests == 0)
    }
#endif
