import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSINetwork

private func completionEventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<100_000 {
        if await condition() { return true }
        await Task.yield()
    }
    return false
}

private func completionFixture(maximumTransferBlocks: UInt32 = 0) async throws -> (
    ReservedRemoteDisk, ISCSISession, ReservationTarget, ContinuousLeaseFixture, IntentFixture
) {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store,
        maximumTransferBlocks: maximumTransferBlocks, diagnostics: nil)
    return (reserved, session, target, lease, store)
}

@Test func reservedTransportCompletionSynchronizesAndLogsOutOnceWithoutReleasing() async throws {
    let (reserved, session, target, lease, store) = try await completionFixture()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    let original = store.load()
    let syncs = await target.dataCommands.filter { $0 == 0x35 || $0 == 0x91 }.count
    #expect(lease.outstandingPins > 0)
    let operation = reserved.transportCompletion()
    #expect(operation === reserved.transportCompletion())
    #expect(await operation.wait() == .synchronizedAndLoggedOut)
    #expect(await operation.wait() == .synchronizedAndLoggedOut)
    #expect(await session.state == .closed)
    #expect(await target.logoutRequests == 1)
    #expect(await target.dataCommands.filter { $0 == 0x35 || $0 == 0x91 }.count == syncs + 1)
    #expect(await target.actions == [0, 1])
    #expect(await target.hasReservation())
    #expect(store.load() == original)
    #expect(lease.outstandingPins == 0)
    #expect(lease.externalWritersAdmitted == false)
    await reserved.close()
}

@Test func reservedTransportCompletionRetainsFailedBarrierAndPins() async throws {
    let (reserved, _, target, lease, store) = try await completionFixture()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 9, count: 512))
    await target.failNextSynchronization()
    let original = store.load()
    let operation = reserved.transportCompletion()
    #expect(await operation.wait() == .abandoned)
    let commands = await target.dataCommands
    #expect(await operation.wait() == .abandoned)
    #expect(await target.dataCommands == commands)
    #expect(reserved.disk.mutationEvidence.incident != nil)
    #expect(lease.outstandingPins > 0)
    #expect(lease.externalWritersAdmitted == false)
    #expect(await target.logoutRequests == 0)
    #expect(await target.hasReservation())
    #expect(store.load() == original)
}

@Test func reservedTransportCompletionAlreadyCancelledDoesNotStartSynchronization() async throws {
    let (reserved, session, target, _, store) = try await completionFixture()
    let commands = await target.dataCommands
    let operation = reserved.transportCompletion()
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await operation.wait()
    }
    #expect(await task.value == .abandoned)
    #expect(await target.dataCommands == commands)
    #expect(await target.logoutRequests == 0)
    #expect(await session.state == .closed)
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedTransportCompletionWaitsForOriginalChunksBeforeFinalBarrier() async throws {
    let (reserved, _, target, _, store) = try await completionFixture(maximumTransferBlocks: 1)
    let before = await target.dataCommands.count
    await target.pauseNextDataOut(fence: { false })
    let write = Task {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 2, count: 1024))
    }
    #expect(await completionEventually { await target.dataPause.isWaiting })
    let operation = reserved.transportCompletion()
    let result = Task { await operation.wait() }
    #expect(await completionEventually { await reserved.disk.isIssuedIOSealed })
    await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
    await target.dataPause.resume()
    try await write.value
    #expect(await result.value == .synchronizedAndLoggedOut)
    let after = Array(await target.dataCommands.dropFirst(before))
    #expect(after == [0x2A, 0x2A, 0x35])
    #expect(await target.logoutRequests == 1)
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedTransportConcurrentCallersJoinOriginalLogout() async throws {
    let (reserved, _, target, _, _) = try await completionFixture()
    await target.pauseNextLogout()
    let operation = reserved.transportCompletion()
    let completed = Mutex(0)
    let a = Task {
        let result = await operation.wait()
        completed.withLock { $0 += 1 }
        return result
    }
    #expect(await completionEventually { await target.logoutPause.isWaiting })
    let b = Task {
        let result = await operation.wait()
        completed.withLock { $0 += 1 }
        return result
    }
    for _ in 0..<50 { await Task.yield() }
    #expect(completed.withLock { $0 } == 0)
    await target.logoutPause.resume()
    #expect(await a.value == .synchronizedAndLoggedOut)
    #expect(await b.value == .synchronizedAndLoggedOut)
    #expect(await target.logoutRequests == 1)
}

@Test(arguments: [false, true])
func reservedTransportCancellationOrDiskAliasCloseInterruptsLostOwnerLogout(_ generic: Bool)
    async throws
{
    let (reserved, session, target, _, store) = try await completionFixture()
    await target.pauseNextLogout()
    let operation = reserved.transportCompletion()
    let finished = Mutex(false)
    let a = Task {
        let result = await operation.wait()
        finished.withLock { $0 = true }
        return result
    }
    #expect(await completionEventually { await target.logoutPause.isWaiting })
    if generic {
        await reserved.disk.close()
    } else {
        a.cancel()
        #expect(await completionEventually { await session.state == .closed })
    }
    #expect(await session.state == .closed)
    #expect(finished.withLock { $0 } == false)
    await target.logoutPause.resume()
    #expect(await a.value == .abandoned)
    #expect(await operation.wait() == .abandoned)
    #expect(await target.logoutRequests == 1)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedTransportCancellationDuringTerminalSynchronizationNeverLogsOut() async throws {
    let (reserved, session, target, lease, _) = try await completionFixture()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 3, count: 512))
    await target.pauseNextSynchronization()
    let operation = reserved.transportCompletion()
    let task = Task { await operation.wait() }
    #expect(await completionEventually { await target.synchronizationPause.isWaiting })
    task.cancel()
    #expect(await completionEventually { await session.state == .closed })
    await target.synchronizationPause.resume()
    #expect(await task.value == .abandoned)
    #expect(await target.logoutRequests == 0)
    #expect(lease.outstandingPins > 0)
    #expect(lease.externalWritersAdmitted == false)
}

@Test func reservedTransportLateCancellationCreatesNoNewCleanupTask() async throws {
    let (reserved, _, target, _, _) = try await completionFixture()
    let operation = reserved.transportCompletion()
    #expect(await operation.wait() == .synchronizedAndLoggedOut)
    let calls = await target.closeCalls
    operation.cancel()
    #expect(await operation.wait() == .synchronizedAndLoggedOut)
    #expect(await target.closeCalls == calls)
    #expect(await target.logoutRequests == 1)
}

@Test func reservedTerminalLogoutRejectsCancelledSignalBeforeActorAdmission() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let gate = OwnedIOGate()
    let signal = try await gate.sealAndDrain()
    try await gate.consume(signal)
    signal.invalidate()
    #expect(await session.closeGracefully(terminalSignal: signal) == false)
    #expect(await target.logoutRequests == 0)
    #expect(await target.admittedFrames.isEmpty)
}

@Test func reservedTerminalLogoutRechecksSignalAtActualSubmission() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let gate = OwnedIOGate()
    let signal = try await gate.sealAndDrain()
    try await gate.consume(signal)
    await target.pauseNextLogoutAdmission()
    let task = Task { await session.closeGracefully(terminalSignal: signal) }
    #expect(await completionEventually { await target.logoutAdmissionPause.isWaiting })
    // Invalidate while the asynchronous abort has not closed the session. No frame
    // may enqueue merely because the earlier session-actor reservation succeeded.
    signal.invalidate()
    await target.logoutAdmissionPause.resume()
    #expect(await task.value == false)
    #expect(await target.logoutRequests == 0)
    #expect(await target.admittedFrames.isEmpty)
}

@Test(arguments: [ReservationTarget.SynchronizationReplyFault.body, .underflow])
func reservedTerminalSynchronizationCannotMintSuccessFromMalformedGOOD(
    _ fault: ReservationTarget.SynchronizationReplyFault
) async throws {
    let (reserved, _, target, lease, store) = try await completionFixture()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 1, count: 512))
    await target.malformNextSynchronization(fault)
    #expect(await reserved.transportCompletion().wait() == .abandoned)
    #expect(await target.logoutRequests == 0)
    #expect(lease.outstandingPins > 0)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedTransportLostLogoutReplyIsNotSuccessfulCompletion() async throws {
    let (reserved, _, target, _, store) = try await completionFixture()
    await target.dropNextLogout()
    let operation = reserved.transportCompletion()
    #expect(await operation.wait() == .abandoned)
    #expect(await target.logoutRequests == 1)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}
