import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSINetwork

private func gateEventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<100_000 {
        if await condition() { return true }
        await Task.yield()
    }
    return false
}

@Test func ownedGateRejectsForeignStaleAndDuplicateRelease() async throws {
    let gate = OwnedIOGate()
    let other = OwnedIOGate()
    let original = try await gate.acquire()
    let foreign = try await other.acquire()
    #expect(await gate.release(foreign) == false)
    let queued = Task { try await gate.acquire() }
    #expect(await gateEventually { await gate.waitingCount == 1 })
    #expect(await gate.release(original))
    let second = try await queued.value
    #expect(await gate.release(original) == false)
    #expect(await gate.release(second))
    #expect(await gate.release(second) == false)
    #expect(await other.release(foreign))
}

@Test func ownedGateSealRejectsQueueAndJoinsOneTerminalOwner() async throws {
    let gate = OwnedIOGate()
    let lease = try await gate.acquire()
    let queued = Task { try await gate.acquire() }
    #expect(await gateEventually { await gate.waitingCount == 1 })
    let first = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    let second = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 2 })
    await #expect(throws: ProtocolError.invalidState) { try await queued.value }
    await #expect(throws: ProtocolError.invalidState) { try await gate.acquire() }
    #expect(await gate.release(lease))
    let a = try await first.value
    let b = try await second.value
    #expect(a === b)
    try await gate.consume(a)
    await #expect(throws: ProtocolError.invalidState) { try await gate.consume(b) }
    await #expect(throws: ProtocolError.invalidState) { try await gate.acquire() }
    let other = OwnedIOGate()
    let foreign = try await other.sealAndDrain()
    await #expect(throws: ProtocolError.invalidState) { try await other.consume(a) }
    try await other.consume(foreign)
}

@Test func ownedGateCancelledDrainInvalidatesAuthorityWithoutReleasingOwner() async throws {
    let gate = OwnedIOGate()
    let other = OwnedIOGate()
    let lease = try await gate.acquire()
    let foreign = try await other.acquire()
    let drain = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    drain.cancel()
    await #expect(throws: CancellationError.self) { try await drain.value }
    #expect(await gate.release(foreign) == false)
    let observer = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    #expect(await gate.release(lease))
    let result = try await observer.value
    await #expect(throws: ProtocolError.invalidState) { try await gate.consume(result) }
    await #expect(throws: ProtocolError.invalidState) { try await gate.acquire() }
    #expect(await other.release(foreign))
}

@Test func ownedGateCancellationAfterGrantCannotReleaseAnotherOwner() async throws {
    let gate = OwnedIOGate()
    let first = try await gate.acquire()
    let pause = ReservationLeasePause()
    let next = Task {
        let lease = try await gate.acquire()
        await pause.wait()
        return await gate.release(lease)
    }
    #expect(await gateEventually { await gate.waitingCount == 1 })
    #expect(await gate.release(first))
    #expect(await gateEventually { await pause.isWaiting })
    next.cancel()
    let drain = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    #expect(await gate.release(first) == false)
    await pause.resume()
    #expect(try await next.value)
    try await gate.consume(try await drain.value)
}

@Test func ownedGateAbortInvalidatesEvenAnAlreadyObservedDrain() async throws {
    let gate = OwnedIOGate()
    let drain = try await gate.sealAndDrain()
    await gate.abort()
    await #expect(throws: ProtocolError.invalidState) { try await gate.consume(drain) }
    await #expect(throws: ProtocolError.invalidState) { try await gate.acquire() }
}

extension OwnedIOGate {
    /// Keep this actor occupied while onCancel runs: its queued cleanup task cannot
    /// execute before consume. Authorization must already be invalidated synchronously.
    fileprivate func cancelReleaseAndConsume(
        _ observer: Task<Drain, any Error>, lease: Lease, drain: Drain
    ) throws {
        observer.cancel()
        guard release(lease) else { throw ProtocolError.invalidState }
        try consume(drain)
    }

    fileprivate func grantSealAndCancelBeforeResumption(
        _ first: Lease, next: Task<(Bool, Bool), any Error>
    ) throws -> (Drain, Bool) {
        guard release(first) else { throw ProtocolError.invalidState }
        let drain = seal()
        next.cancel()
        do {
            try consume(drain)
            return (drain, true)
        } catch { return (drain, false) }
    }
}

@Test func ownedGateCancellationInvalidatesBeforeDeferredActorCleanup() async throws {
    let gate = OwnedIOGate()
    let lease = try await gate.acquire()
    let handle = await gate.seal()
    let observer = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    await #expect(throws: ProtocolError.invalidState) {
        try await gate.cancelReleaseAndConsume(observer, lease: lease, drain: handle)
    }
    await #expect(throws: CancellationError.self) { try await observer.value }
    await #expect(throws: ProtocolError.invalidState) { try await gate.consume(handle) }
}

@Test func ownedGateCancelledForeignConsumptionCannotInvalidateItsOwner() async throws {
    let gate = OwnedIOGate()
    let other = OwnedIOGate()
    let foreign = try await other.sealAndDrain()
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await gate.consume(foreign)
    }
    await #expect(throws: ProtocolError.invalidState) { try await task.value }
    try await other.consume(foreign)
}

@Test func ownedGateAlreadyCancelledSealNeverReopensAdmission() async throws {
    let gate = OwnedIOGate()
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await gate.sealAndDrain()
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await gate.isSealed)
    let handle = await gate.seal()
    await #expect(throws: ProtocolError.invalidState) { try await gate.consume(handle) }
    await #expect(throws: ProtocolError.invalidState) { try await gate.acquire() }
}

@Test func ownedGateGrantedButNotResumedTaskRetainsItsLeaseThroughCancellation() async throws {
    let gate = OwnedIOGate()
    let first = try await gate.acquire()
    let next = Task {
        let lease = try await gate.acquire()
        let cancelled = Task.isCancelled
        return (cancelled, await gate.release(lease))
    }
    #expect(await gateEventually { await gate.waitingCount == 1 })
    let (drain, premature) = try await gate.grantSealAndCancelBeforeResumption(first, next: next)
    #expect(premature == false)
    let result = try await next.value
    #expect(result.0 && result.1)
    try await gate.consume(drain)
}

@Test func ownedGateCancelledOrdinaryWaiterCannotReleaseActiveOwner() async throws {
    let gate = OwnedIOGate()
    let lease = try await gate.acquire()
    let queued = Task { try await gate.acquire() }
    #expect(await gateEventually { await gate.waitingCount == 1 })
    queued.cancel()
    await #expect(throws: CancellationError.self) { try await queued.value }
    let observer = Task { try await gate.sealAndDrain() }
    #expect(await gateEventually { await gate.waitingDrainCount == 1 })
    #expect(await gate.release(lease))
    try await gate.consume(try await observer.value)
}

/// Real product disk/session against the project's simulated target, not native drain.
@Test func reservedIssuedIODrainLetsOriginalMultiCommandWriteFinish() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store,
        maximumTransferBlocks: 1, diagnostics: nil)
    let intents = store.load()
    let initialSyncs = await target.dataCommands.filter { $0 == 0x35 || $0 == 0x91 }.count
    await target.pauseNextDataOut(fence: { false })
    let write = Task {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 1024))
    }
    #expect(await gateEventually { await target.dataPause.isWaiting })
    let queued = Task {
        try await reserved.disk.write(offset: 2048, data: Data(repeating: 9, count: 512))
    }
    let sync = Task { try await reserved.disk.synchronize() }
    let recovery = Task { try await reserved.recoverSynchronizationFailure() }
    #expect(await gateEventually { await reserved.disk.queuedIOCount == 3 })
    let drain = Task { try await reserved.prepareIssuedIODrain() }
    #expect(await gateEventually { await reserved.disk.waitingIssuedIODrainCount == 1 })
    await #expect(throws: ProtocolError.invalidState) { try await queued.value }
    await #expect(throws: ProtocolError.invalidState) { try await sync.value }
    await #expect(throws: ProtocolError.invalidState) { try await recovery.value }
    await #expect(throws: ProtocolError.invalidState) {
        try await reserved.disk.read(offset: 0, length: 1)
    }
    await target.dataPause.resume()
    try await write.value
    let proof = try await drain.value
    #expect(await target.dataCommands.filter { $0 == 0x2A || $0 == 0x8A }.count == 2)
    #expect(await target.dataCommands.filter { $0 == 0x35 || $0 == 0x91 }.count == initialSyncs)
    #expect(lease.outstandingPins > 0)
    let evidence = reserved.disk.mutationEvidence
    let pins = lease.outstandingPins
    try await reserved.consumeIssuedIODrain(proof)
    await #expect(throws: ProtocolError.invalidState) {
        try await reserved.consumeIssuedIODrain(proof)
    }
    await reserved.close()
    #expect(await target.logoutRequests == 0)
    #expect(await target.actions == [0, 1])
    #expect(await target.hasReservation())
    #expect(store.load() == intents)
    #expect(reserved.disk.mutationEvidence == evidence)
    #expect(lease.outstandingPins == pins)
}

@Test func reservedGenericCloseInterruptsPendingDrainAndInvalidatesItsProof() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store,
        diagnostics: nil)
    await target.pauseNextDataOut(fence: { false })
    let write = Task {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 3, count: 512))
    }
    #expect(await gateEventually { await target.dataPause.isWaiting })
    let drain = Task { try await reserved.prepareIssuedIODrain() }
    #expect(await gateEventually { await reserved.disk.waitingIssuedIODrainCount == 1 })
    await reserved.close()  // Must not wait for Data-Out or its gate lease.
    #expect(await session.state == .closed)
    #expect(await target.logoutRequests == 0)
    await target.dataPause.resume()
    await #expect(throws: (any Error).self) { try await write.value }
    await #expect(throws: (any Error).self) { try await drain.value }
    #expect(store.load().map(\.phase) == [.reserved])
    #expect(await target.hasReservation())
}

@Test func reservedIssuedIODrainProofIsInvalidAfterGenericClose() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store,
        diagnostics: nil)
    let proof = try await reserved.prepareIssuedIODrain()
    await reserved.close()
    await #expect(throws: ProtocolError.self) { try await reserved.consumeIssuedIODrain(proof) }
    #expect(await target.logoutRequests == 0)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedIssuedIODrainDoesNotEraseCurrentWriteFailure() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store,
        diagnostics: nil)
    await target.failNextWrite()
    await target.pauseNextDataOut(fence: { false })
    let write = Task {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 1, count: 512))
    }
    #expect(await gateEventually { await target.dataPause.isWaiting })
    let drain = Task { try await reserved.prepareIssuedIODrain() }
    #expect(await gateEventually { await reserved.disk.waitingIssuedIODrainCount == 1 })
    await target.dataPause.resume()
    await #expect(throws: ProtocolError.self) { try await write.value }
    await #expect(throws: ProtocolError.self) { try await drain.value }
    #expect(reserved.disk.mutationEvidence.incident != nil)
    let evidence = reserved.disk.mutationEvidence
    let pins = lease.outstandingPins
    #expect(pins > 0)
    await reserved.close()
    #expect(reserved.disk.mutationEvidence == evidence)
    #expect(lease.outstandingPins == pins)
    #expect(await target.logoutRequests == 0)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test func reservedIssuedIODrainWaitsForOriginalRecoveryCommit() async throws {
    let (reserved, _, target, lease) = try await recoverableReservedDisk()
    lease.pauseAssertion(after: 2)
    let recovery = Task { try await reserved.recoverSynchronizationFailure() }
    #expect(await gateEventually { await lease.pause.isWaiting })
    let queued = Task {
        try await reserved.disk.write(offset: 2048, data: Data(repeating: 4, count: 512))
    }
    #expect(await gateEventually { await reserved.disk.queuedIOCount == 1 })
    let drain = Task { try await reserved.prepareIssuedIODrain() }
    #expect(await gateEventually { await reserved.disk.waitingIssuedIODrainCount == 1 })
    await #expect(throws: ProtocolError.invalidState) { try await queued.value }
    await lease.pause.resume()
    try await recovery.value
    let proof = try await drain.value
    #expect(reserved.disk.mutationEvidence.serviceGeneration == 1)
    #expect(reserved.disk.mutationEvidence.incident == nil)
    #expect(reserved.disk.recoveryHistory.count == 1)
    try await reserved.consumeIssuedIODrain(proof)
    await reserved.close()
    #expect(await target.logoutRequests == 0)
    #expect(await target.hasReservation())
}

@Test func reservedIssuedIODrainRejectsAnotherLiveDiskWithoutConsumingItsProof() async throws {
    let firstStore = IntentFixture()
    let secondStore = IntentFixture()
    let (firstSession, firstTarget) = try await reservedSession(firstStore)
    let (secondSession, secondTarget) = try await reservedSession(secondStore)
    let first = try await ReservedRemoteDisk.acquire(
        session: firstSession, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(),
        store: firstStore,
        diagnostics: nil)
    let second = try await ReservedRemoteDisk.acquire(
        session: secondSession, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(),
        store: secondStore,
        diagnostics: nil)
    let proof = try await first.prepareIssuedIODrain()
    await #expect(throws: (any Error).self) { try await second.consumeIssuedIODrain(proof) }
    try await first.consumeIssuedIODrain(proof)
    await first.close()
    await second.close()
    #expect(await firstTarget.logoutRequests == 0)
    #expect(await secondTarget.logoutRequests == 0)
    #expect(firstStore.load().map(\.phase) == [.reserved])
    #expect(secondStore.load().map(\.phase) == [.reserved])
}

@Test func reservedCancelledPreparationCannotBeReplacedByAnotherUsableProof() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store,
        diagnostics: nil)
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await reserved.prepareIssuedIODrain()
    }
    await #expect(throws: CancellationError.self) { try await cancelled.value }
    await #expect(throws: ProtocolError.invalidState) { try await reserved.prepareIssuedIODrain() }
    await #expect(throws: ProtocolError.invalidState) {
        try await reserved.disk.read(offset: 0, length: 1)
    }
    await reserved.close()
    #expect(await target.logoutRequests == 0)
    #expect(await target.hasReservation())
    #expect(store.load().map(\.phase) == [.reserved])
}
