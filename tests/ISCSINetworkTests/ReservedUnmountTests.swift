import FSKit
import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private func unmountEventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<100_000 {
        if await condition() { return true }
        await Task.yield()
    }
    return false
}

private func unmountFixture(_ behavior: ReservedUnmountBehavior = .abandon) async throws -> (
    LUNImageVolume, ReservationTarget, ContinuousLeaseFixture, IntentFixture
) {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store,
        maximumTransferBlocks: 1, diagnostics: nil)
    let volume = LUNImageVolume(
        reservedDisk: reserved, identifier: UUID(), unmountBehavior: behavior)
    return (volume, target, lease, store)
}

@Test func reservedUnmountDefaultStillAbandonsWithoutNewIO() async throws {
    let (volume, target, lease, store) = try await unmountFixture()
    let commands = await target.dataCommands
    await volume.unmount()
    #expect(await target.dataCommands == commands)
    #expect(await target.logoutRequests == 0)
    #expect(await target.isClosed)
    #expect(store.load().map(\.phase) == [.reserved])
    #expect(!lease.externalWritersAdmitted)
}

@Test func reservedUnmountOptInJoinsOneExchangeAndKeepsReservation() async throws {
    let (volume, target, lease, store) = try await unmountFixture(.attemptTransportCompletion)
    let original = store.load()
    let syncs = await target.dataCommands.filter { $0 == 0x35 }.count
    await target.pauseNextLogout()
    let completed = Mutex(0)
    let first = Task {
        await volume.unmount()
        completed.withLock { $0 += 1 }
    }
    #expect(await unmountEventually { await target.logoutPause.isWaiting })
    let second = Task {
        await volume.unmount()
        completed.withLock { $0 += 1 }
    }
    #expect(completed.withLock { $0 } == 0)
    await target.logoutPause.resume()
    await first.value
    await second.value
    #expect(completed.withLock { $0 } == 2)
    #expect(await target.dataCommands.filter { $0 == 0x35 }.count == syncs + 1)
    #expect(await target.logoutRequests == 1)
    #expect(await target.isClosed)
    #expect(await target.hasReservation())
    #expect(await target.actions == [0, 1])
    #expect(store.load() == original)
    #expect(!lease.externalWritersAdmitted)
}

private enum UnmountInterruption: Sendable {
    case shutdown, deactivate, forcedDeactivate, unload, cancellation
}
private enum UnmountPause: Sendable { case synchronization, logout }

@Test(
    arguments: [
        UnmountInterruption.shutdown, .deactivate, .forcedDeactivate, .unload, .cancellation,
    ],
    [UnmountPause.synchronization, .logout])
private func reservedUnmountInterruptionAbortsBeforeOriginalOwnerFinishes(
    _ interruption: UnmountInterruption, _ pause: UnmountPause
) async throws {
    let (volume, target, lease, store) = try await unmountFixture(.attemptTransportCompletion)
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(1), readOnly: false, isid: [128, 1, 2, 3, 4, 5])
    let controller = ResourceController { _, _ in volume }
    if interruption == .unload { _ = try await controller.load(descriptor, readOnly: false) }
    if pause == .synchronization {
        await target.pauseNextSynchronization()
    } else {
        await target.pauseNextLogout()
    }
    let completed = Mutex(false)
    let original = Task {
        await volume.unmount()
        completed.withLock { $0 = true }
    }
    #expect(
        await unmountEventually {
            if pause == .synchronization { return await target.synchronizationPause.isWaiting }
            return await target.logoutPause.isWaiting
        })
    switch interruption {
    case .shutdown: await volume.shutdown()
    case .deactivate: try await volume.deactivate()
    case .forcedDeactivate: try await volume.deactivate(options: .force)
    case .unload: try await controller.unload(descriptor)
    case .cancellation: original.cancel()
    }
    #expect(await unmountEventually { await target.isClosed })
    #expect(!completed.withLock { $0 })
    await target.synchronizationPause.resume()
    await target.logoutPause.resume()
    await original.value
    #expect(completed.withLock { $0 })
    #expect(await volume.finishTransportAfterDrainingIO() == .abandoned)
    #expect(await target.logoutRequests == (pause == .logout ? 1 : 0))
    #expect(store.load().map(\.phase) == [.reserved])
    #expect(!lease.externalWritersAdmitted)
}

@Test func reservedUnmountAlreadyCancelledCallerCannotBeginTerminalIO() async throws {
    let (volume, target, _, store) = try await unmountFixture(.attemptTransportCompletion)
    let commands = await target.dataCommands
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        await volume.unmount()
    }
    await task.value
    #expect(await target.dataCommands == commands)
    #expect(await target.logoutRequests == 0)
    #expect(await target.isClosed)
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedUnmountUnrecoveredFailureCannotIssueMoreTerminalIO() async throws {
    let (volume, target, lease, store) = try await unmountFixture(.attemptTransportCompletion)
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    let commands = await target.dataCommands
    await volume.unmount()
    #expect(await target.dataCommands == commands)
    #expect(await target.logoutRequests == 0)
    #expect(await target.isClosed)
    #expect(lease.outstandingPins > 0)
    #expect(store.load().map(\.phase) == [.reserved])
}

#if ISCSI_FSKIT_CACHE_DIAGNOSTIC
    @Test(arguments: [false, true])
    func reservedUnmountOpenItemOrMissingFinalCacheCloseRemainsRefused(_ open: Bool) async throws {
        let (volume, target, _, _) = try await unmountFixture(.attemptTransportCompletion)
        if open {
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
        } else {
            #expect(try await volume.write(contents: Data([9]), to: volume.imageItem, at: 7) == 1)
        }
        let commands = await target.dataCommands
        await volume.unmount()
        #expect(await target.dataCommands == commands)
        #expect(await target.logoutRequests == 0)
        #expect(await target.isClosed)
    }

    @Test func reservedUnmountJoinsOriginalRecoveryAndCacheClose() async throws {
        let (volume, target, lease, store) = try await unmountFixture(.attemptTransportCompletion)
        _ = try await volume.negotiateCacheOpen(
            volume.imageItem, modes: .write, cacheMode: .none)
        await target.failNextSynchronization()
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.write(contents: Data([7]), to: volume.imageItem, at: 7)
        }
        lease.pauseAssertion()
        let recovery = Task { try await volume.recoverSynchronizationFailure() }
        #expect(await unmountEventually { await lease.pause.isWaiting })
        let close = Task { await volume.finishCacheClose(volume.imageItem) }
        #expect(await unmountEventually { volume.isCacheCloseWaitingForRecovery })
        let unmount = Task { await volume.unmount() }
        #expect(await unmountEventually { volume.isTransportCompletionStarted })
        await lease.pause.resume()
        try await recovery.value
        await close.value
        await unmount.value
        #expect(await target.logoutRequests == 1)
        #expect(await target.isClosed)
        #expect(store.load().map(\.phase) == [.reserved])
        #expect(!lease.externalWritersAdmitted)
    }
#else
    @Test func reservedUnmountLegacyOpenItemCannotStartCompletion() async throws {
        let (volume, target, _, _) = try await unmountFixture(.attemptTransportCompletion)
        try await volume.openItem(volume.imageItem, modes: .read)
        let commands = await target.dataCommands
        await volume.unmount()
        #expect(await target.dataCommands == commands)
        #expect(await target.logoutRequests == 0)
    }
#endif
