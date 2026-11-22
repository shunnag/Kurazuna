import FSKit
import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private func mountedReservedFixture(identifier: UUID = UUID()) async throws -> (
    ReservedRemoteDisk, LUNImageVolume, ISCSISession, ReservationTarget, ContinuousLeaseFixture
) {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    let volume = LUNImageVolume(reservedDisk: reserved, identifier: identifier)
    return (reserved, volume, session, target, lease)
}

private func failMountedSynchronization(_ volume: LUNImageVolume, target: ReservationTarget)
    async throws -> LUNImageVolume.SynchronizationRecoverySelection
{
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([0x41]), to: volume.imageItem, at: 7)
    }
    return try #require(volume.synchronizationFailureSelection)
}

@Test func matchedRecoveryHasNoSelectionForHealthyOrClosedVolume() async throws {
    let (_, volume, _, target, _) = try await mountedReservedFixture()
    #expect(volume.synchronizationFailureSelection == nil)
    let guessed = LUNImageVolume.SynchronizationRecoverySelection(
        liveVolumeID: UUID(), failureID: UUID(), ioEpoch: 0)
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.recoverSynchronizationFailure(matching: guessed)
    }
    #expect(await target.dataCommands.count == count)
    let selected = try await failMountedSynchronization(volume, target: target)
    await volume.shutdown()
    #expect(volume.synchronizationFailureSelection == nil)
    let closedCount = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    #expect(await target.dataCommands.count == closedCount)
}

@Test func matchedRecoveryRejectsEveryMismatchedFieldWithoutBackendIO() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    let original = reserved.disk.mutationEvidence
    let count = await target.dataCommands.count
    for wrong in [
        LUNImageVolume.SynchronizationRecoverySelection(
            liveVolumeID: UUID(), failureID: selected.failureID, ioEpoch: selected.ioEpoch),
        LUNImageVolume.SynchronizationRecoverySelection(
            liveVolumeID: selected.liveVolumeID, failureID: UUID(), ioEpoch: selected.ioEpoch),
        LUNImageVolume.SynchronizationRecoverySelection(
            liveVolumeID: selected.liveVolumeID, failureID: selected.failureID,
            ioEpoch: selected.ioEpoch + 1),
    ] {
        await #expect(throws: POSIXError(.EBUSY)) {
            try await volume.recoverSynchronizationFailure(matching: wrong)
        }
        #expect(volume.synchronizationFailureSelection == selected)
        #expect(await target.dataCommands.count == count)
        #expect(reserved.disk.mutationEvidence == original)
        #expect(reserved.disk.recoveryHistory.isEmpty)
    }
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    #expect(await target.dataCommands.count == count)
    try await volume.recoverSynchronizationFailure(matching: selected)
    #expect(volume.synchronizationFailureSelection == nil)
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(try await volume.write(contents: Data([3]), to: volume.imageItem, at: 9) == 1)
    await volume.shutdown()
}

@Test func matchedRecoveryCannotCrossLiveVolumesWithSameStableFilesystemID() async throws {
    let stable = UUID()
    let (_, first, _, firstTarget, _) = try await mountedReservedFixture(identifier: stable)
    let (reserved, second, _, secondTarget, _) = try await mountedReservedFixture(
        identifier: stable)
    let firstSelection = try await failMountedSynchronization(first, target: firstTarget)
    let secondSelection = try await failMountedSynchronization(second, target: secondTarget)
    #expect(firstSelection.liveVolumeID != secondSelection.liveVolumeID)
    let count = await secondTarget.dataCommands.count
    let original = reserved.disk.mutationEvidence
    await #expect(throws: POSIXError(.EBUSY)) {
        try await second.recoverSynchronizationFailure(matching: firstSelection)
    }
    #expect(await secondTarget.dataCommands.count == count)
    #expect(reserved.disk.mutationEvidence == original)
    try await second.recoverSynchronizationFailure(matching: secondSelection)
    await first.shutdown()
    await second.shutdown()
}

@Test func matchedRecoveryOldRequestCannotSelectNextIncident() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    let first = try await failMountedSynchronization(volume, target: target)
    try await volume.recoverSynchronizationFailure(matching: first)
    let second = try await failMountedSynchronization(volume, target: target)
    #expect(first.liveVolumeID == second.liveVolumeID)
    #expect(first.failureID != second.failureID)
    #expect(second.ioEpoch == first.ioEpoch + 1)
    let original = reserved.disk.mutationEvidence
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.recoverSynchronizationFailure(matching: first)
    }
    #expect(await target.dataCommands.count == count)
    #expect(reserved.disk.mutationEvidence == original)
    #expect(volume.synchronizationFailureSelection == second)
    try await volume.recoverSynchronizationFailure(matching: second)
    #expect(reserved.disk.recoveryHistory.count == 2)
    await volume.shutdown()
}

@Test func matchedRecoveryFailedAttemptRetainsIncidentAndCannotReopenRevokedLease() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    let original = reserved.disk.mutationEvidence
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    #expect(volume.synchronizationFailureSelection == selected)
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    let failedCount = await target.dataCommands.count
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    #expect(await target.dataCommands.count == failedCount)
    #expect(volume.synchronizationFailureSelection == selected)
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    #expect(await target.dataCommands.count == failedCount)
    await volume.shutdown()
}

@Test func matchedRecoveryConcurrentAndCompletedDuplicatesCannotExecuteAgain() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    lease.pauseAssertion()
    let recovery = Task { try await volume.recoverSynchronizationFailure(matching: selected) }
    for _ in 0..<10_000 {
        if await lease.pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await lease.pause.isWaiting)
    #expect(volume.synchronizationFailureSelection == selected)
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    #expect(await target.dataCommands.count == count)
    await lease.pause.resume()
    try await recovery.value
    let completed = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    #expect(await target.dataCommands.count == completed)
    #expect(reserved.disk.recoveryHistory.count == 1)
    await volume.shutdown()
}

@Test func matchedRecoveryCancelledBeforeAdmissionPreservesIncident() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    let original = reserved.disk.mutationEvidence
    let count = await target.dataCommands.count
    let pause = ReservationLeasePause()
    let recovery = Task {
        await pause.wait()
        try await volume.recoverSynchronizationFailure(matching: selected)
    }
    for _ in 0..<10_000 {
        if await pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await pause.isWaiting)
    recovery.cancel()
    await pause.resume()
    await #expect(throws: CancellationError.self) { try await recovery.value }
    #expect(await target.dataCommands.count == count)
    #expect(reserved.disk.mutationEvidence == original)
    #expect(volume.synchronizationFailureSelection == selected)
    try await volume.recoverSynchronizationFailure(matching: selected)
    await volume.shutdown()
}

@Test func matchedRecoveryShutdownBeforeCommitCannotReopenVolume() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    lease.pauseAssertion()
    let recovery = Task { try await volume.recoverSynchronizationFailure(matching: selected) }
    for _ in 0..<10_000 {
        if await lease.pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await lease.pause.isWaiting)
    await volume.shutdown()
    await lease.pause.resume()
    await #expect(throws: (any Error).self) { try await recovery.value }
    #expect(reserved.disk.recoveryHistory.isEmpty)
    #expect(volume.synchronizationFailureSelection == nil)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
}

@Test func matchedRecoveryCancellationAfterCommitKeepsSuccess() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    lease.setAfterCriticalBody {
        if reserved.disk.recoveryHistory.count == 1 { withUnsafeCurrentTask { $0?.cancel() } }
    }
    defer { lease.setAfterCriticalBody(nil) }
    let recovery = Task {
        try await volume.recoverSynchronizationFailure(matching: selected)
        return Task.isCancelled
    }
    #expect(try await recovery.value)
    lease.setAfterCriticalBody(nil)
    #expect(volume.synchronizationFailureSelection == nil)
    #expect(reserved.disk.recoveryHistory.count == 1)
    #expect(try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9) == 1)
    await volume.shutdown()
}

@Test func matchedRecoveryShutdownAfterCommitKeepsSuccessAndTerminalState() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    let selected = try await failMountedSynchronization(volume, target: target)
    let shutdown = Synchronization.Mutex<Task<Void, Never>?>(nil)
    lease.setAfterCriticalBody {
        if reserved.disk.recoveryHistory.count == 1 {
            shutdown.withLock { if $0 == nil { $0 = volume.beginShutdown() } }
        }
    }
    defer { lease.setAfterCriticalBody(nil) }
    try await volume.recoverSynchronizationFailure(matching: selected)
    lease.setAfterCriticalBody(nil)
    let closing = try #require(shutdown.withLock { $0 })
    await closing.value
    #expect(reserved.disk.recoveryHistory.count == 1)
    #expect(volume.synchronizationFailureSelection == nil)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    #expect(await target.actions == [0, 1])
}

private func producerSynchronizationFailure(
    _ reserved: ReservedRemoteDisk, target: ReservationTarget
) async throws -> ReservedSynchronizationFailure {
    try await reserved.disk.write(offset: 7, data: Data([0xAB, 0xCD]))
    await target.failNextSynchronization()
    do {
        try await reserved.synchronizeForProducer()
        throw ProtocolError.invalidState
    } catch let ticket as ReservedSynchronizationFailure { return ticket }
}

@Test func producerSynchronizationCapturesExactOriginalAndOrdinaryAPIKeepsOriginalError()
    async throws
{
    let (reserved, _, _, target, _) = try await mountedReservedFixture()
    let ticket = try await producerSynchronizationFailure(reserved, target: target)
    #expect(
        ticket.underlyingError as? ProtocolError
            == .scsiFailure(
                status: 2, sense: Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])))
    let original = reserved.disk.mutationEvidence
    let count = await target.dataCommands.count
    await #expect(throws: ProtocolError.invalidState) {
        try await reserved.synchronizeForProducer()
    }
    #expect(await target.dataCommands.count == count)
    try await reserved.recoverSynchronizationFailure(matching: ticket)
    #expect(reserved.disk.recoveryHistory[0].original == original)
    let after = await target.dataCommands.count
    await #expect(throws: MutationRecoveryIssue.self) {
        try await reserved.recoverSynchronizationFailure(matching: ticket)
    }
    #expect(await target.dataCommands.count == after)
    await reserved.close()

    let (ordinary, _, ordinaryTarget, _) = try await recoverableReservedDisk()
    #expect(ordinary.disk.mutationEvidence.incident != nil)
    #expect(await ordinaryTarget.dataCommands.last == 0x35)
    await ordinary.close()
}

@Test func producerTicketFromAnotherDiskCannotIssueRecoveryCommands() async throws {
    let (first, _, _, firstTarget, _) = try await mountedReservedFixture()
    let (second, _, _, secondTarget, _) = try await mountedReservedFixture()
    let ticket = try await producerSynchronizationFailure(first, target: firstTarget)
    let secondTicket = try await producerSynchronizationFailure(second, target: secondTarget)
    let count = await secondTarget.dataCommands.count
    await #expect(throws: MutationRecoveryIssue.self) {
        try await second.recoverSynchronizationFailure(matching: ticket)
    }
    #expect(await secondTarget.dataCommands.count == count)
    try await second.recoverSynchronizationFailure(matching: secondTicket)
    await first.close()
    await second.close()
}

@Test func producerOldTicketCannotRecoverASecondIncident() async throws {
    let (reserved, _, _, target, _) = try await mountedReservedFixture()
    let first = try await producerSynchronizationFailure(reserved, target: target)
    try await reserved.recoverSynchronizationFailure(matching: first)
    let second = try await producerSynchronizationFailure(reserved, target: target)
    let original = reserved.disk.mutationEvidence
    let count = await target.dataCommands.count
    await #expect(throws: MutationRecoveryIssue.self) {
        try await reserved.recoverSynchronizationFailure(matching: first)
    }
    #expect(await target.dataCommands.count == count)
    #expect(reserved.disk.mutationEvidence == original)
    try await reserved.recoverSynchronizationFailure(matching: second)
    #expect(reserved.disk.recoveryHistory.count == 2)
    await reserved.close()
}

@Test func volumeWriteBarrierFailureRecoversThroughConcreteReservedAdapter() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([0xAB, 0xCD]), to: volume.imageItem, at: 7)
    }
    let original = reserved.disk.mutationEvidence
    #expect(original.incident?.operation == .synchronize)
    await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
    try await volume.recoverSynchronizationFailure()
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(try await volume.write(contents: Data([9]), to: volume.imageItem, at: 1024) == 1)
    try await volume.synchronize(flags: .wait)
    await #expect(throws: POSIXError(.EBUSY)) { try await volume.recoverSynchronizationFailure() }
    await volume.shutdown()
    #expect(await target.actions == [0, 1])
}

@Test func volumeExplicitSyncAndLegacyCloseCaptureTheirExactBackendIncident() async throws {
    for close in [false, true] {
        let (reserved, volume, _, target, _) = try await mountedReservedFixture()
        try await volume.openItem(volume.imageItem, modes: .write)
        // Prime an acknowledged but unsynchronized physical write to exercise these
        // two distinct callback sites without relying on write()'s automatic barrier.
        try await reserved.disk.write(offset: 7, data: Data([0xAB, 0xCD]))
        await target.failNextSynchronization()
        await #expect(throws: POSIXError(.EIO)) {
            if close {
                try await volume.closeItem(volume.imageItem, modes: [])
            } else {
                try await volume.synchronize(flags: .wait)
            }
        }
        try await volume.recoverSynchronizationFailure()
        try await volume.closeItem(volume.imageItem, modes: [])
        await volume.shutdown()
    }
}

@Test func volumeStaleTicketAfterExternalRecoveryDoesNotClearItsLocalFailure() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    try await reserved.recoverSynchronizationFailure()
    #expect(
        try await volume.xattr(
            named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
            of: volume.imageItem) == DiskConnectionState.interrupted.encoded)
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EIO)) { try await volume.recoverSynchronizationFailure() }
    #expect(await target.dataCommands.count == count)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    await volume.shutdown()
}

@Test func volumeFailedRecoveryPreservesOriginalAndCannotIssueNewWrites() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    let original = reserved.disk.mutationEvidence
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) { try await volume.recoverSynchronizationFailure() }
    #expect(reserved.disk.mutationEvidence == original)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    await volume.shutdown()
}

@Test func volumeRecoveryCannotClearAClosedOrUnreservedVolume() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    await volume.shutdown()
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) { try await volume.recoverSynchronizationFailure() }
    #expect(await target.dataCommands.count == count)
    let ordinary = LUNImageVolume(disk: reserved.disk, identifier: UUID())
    await #expect(throws: POSIXError(.EBUSY)) { try await ordinary.recoverSynchronizationFailure() }
}

@Test func volumeRecoveryKeepsTwoSeparateIncidentHistories() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    var originals: [MutationEvidence] = []
    for byte: UInt8 in [1, 2] {
        await target.failNextSynchronization()
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.write(contents: Data([byte]), to: volume.imageItem, at: 7)
        }
        originals.append(reserved.disk.mutationEvidence)
        try await volume.recoverSynchronizationFailure()
    }
    #expect(reserved.disk.recoveryHistory.map(\.original) == originals)
    await volume.shutdown()
}

private actor RecoveryExecutionCount {
    var count = 0
    func executed() { count += 1 }
}

@Test func volumeAdmissionCapturedBeforeRecoveryCannotRunInNewEpochOrOtherVolume() async throws {
    let (_, volume, _, target, _) = try await mountedReservedFixture()
    let old = try volume.captureIOAdmission()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    try await volume.recoverSynchronizationFailure()
    let counter = RecoveryExecutionCount()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.performIO(admission: old) { await counter.executed() }
    }
    #expect(await counter.count == 0)
    let fresh = try volume.captureIOAdmission()
    try await volume.performIO(admission: fresh) { await counter.executed() }
    #expect(await counter.count == 1)
    let (_, other, _, _, _) = try await mountedReservedFixture()
    await #expect(throws: POSIXError(.EIO)) {
        try await other.performIO(admission: fresh) { await counter.executed() }
    }
    #expect(await counter.count == 1)
    await other.shutdown()
    await volume.shutdown()
}

@Test func volumeIOWhileRecoveryOwnsGateIsRefusedAndNewCallsResume() async throws {
    let (_, volume, _, target, lease) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    lease.pauseAssertion()
    let recovery = Task { try await volume.recoverSynchronizationFailure() }
    for _ in 0..<10_000 {
        if await lease.pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await lease.pause.isWaiting)
    let count = await target.dataCommands.count
    await #expect(throws: POSIXError(.EBUSY)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    #expect(await target.dataCommands.count == count)
    await lease.pause.resume()
    try await recovery.value
    #expect(try await volume.write(contents: Data([3]), to: volume.imageItem, at: 9) == 1)
    await volume.shutdown()
}

@Test func volumeShutdownBeforeRecoveryCommitRemainsTerminal() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    lease.pauseAssertion()
    let recovery = Task { try await volume.recoverSynchronizationFailure() }
    for _ in 0..<10_000 {
        if await lease.pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await lease.pause.isWaiting)
    await volume.shutdown()
    await lease.pause.resume()
    await #expect(throws: (any Error).self) { try await recovery.value }
    #expect(reserved.disk.recoveryHistory.isEmpty)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
}

#if ISCSI_FSKIT_CACHE_DIAGNOSTIC
    @available(macOS 27.0, *)
    @Test func matchedRecoveryCacheCloseRetainsFailureUntilExactSelectionCommits() async throws {
        let (reserved, volume, _, target, _) = try await mountedReservedFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        try await reserved.disk.write(offset: 7, data: Data([1]))
        await target.failNextSynchronization()
        await volume.finishCacheClose(volume.imageItem)
        let selected = try #require(volume.synchronizationFailureSelection)
        let original = reserved.disk.mutationEvidence
        let count = await target.dataCommands.count
        let wrong = LUNImageVolume.SynchronizationRecoverySelection(
            liveVolumeID: selected.liveVolumeID, failureID: UUID(), ioEpoch: selected.ioEpoch)
        await #expect(throws: POSIXError(.EBUSY)) {
            try await volume.recoverSynchronizationFailure(matching: wrong)
        }
        await #expect(throws: POSIXError(.EIO)) {
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
        }
        #expect(await target.dataCommands.count == count)
        #expect(volume.synchronizationFailureSelection == selected)
        #expect(reserved.disk.mutationEvidence == original)
        try await volume.recoverSynchronizationFailure(matching: selected)
        #expect(reserved.disk.recoveryHistory[0].original == original)
        #expect(volume.synchronizationFailureSelection == nil)
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        #expect(try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9) == 1)
        await volume.finishCacheClose(volume.imageItem)
        await volume.shutdown()
    }

    @available(macOS 27.0, *)
    @Test func volumeFinalCacheCloseFailureRetiresOnlyAfterMatchingRecovery() async throws {
        let (reserved, volume, _, target, _) = try await mountedReservedFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        try await reserved.disk.write(offset: 7, data: Data([1]))
        await target.failNextSynchronization()
        await volume.finishCacheClose(volume.imageItem)
        let original = reserved.disk.mutationEvidence
        await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
        try await volume.recoverSynchronizationFailure()
        #expect(reserved.disk.recoveryHistory[0].original == original)
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        #expect(try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9) == 1)
        await volume.finishCacheClose(volume.imageItem)
        await volume.shutdown()
    }

    @available(macOS 27.0, *)
    @Test func cacheCloseArrivingDuringRecoveryWaitsThenPerformsItsOwnBarrier() async throws {
        let (_, volume, _, target, lease) = try await mountedReservedFixture()
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .write, cacheMode: .none)
        await target.failNextSynchronization()
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
        }
        let syncs = await target.dataCommands.filter { $0 == 0x35 }.count
        lease.pauseAssertion()
        let recovery = Task { try await volume.recoverSynchronizationFailure() }
        for _ in 0..<10_000 {
            if await lease.pause.isWaiting { break }
            await Task.yield()
        }
        #expect(await lease.pause.isWaiting)
        let close = Task { await volume.finishCacheClose(volume.imageItem) }
        for _ in 0..<10_000 {
            if volume.isCacheCloseWaitingForRecovery { break }
            await Task.yield()
        }
        #expect(volume.isCacheCloseWaitingForRecovery)
        await lease.pause.resume()
        try await recovery.value
        await close.value
        #expect(await target.dataCommands.filter { $0 == 0x35 }.count == syncs + 2)
        _ = try await volume.negotiateCacheOpen(volume.imageItem, modes: .read, cacheMode: .none)
        await volume.finishCacheClose(volume.imageItem)
        await volume.shutdown()
    }
#endif

@Test func volumeCancellationAfterNetworkCommitDoesNotReportFailedRecovery() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    let original = reserved.disk.mutationEvidence
    lease.setAfterCriticalBody {
        if reserved.disk.recoveryHistory.count == 1 {
            withUnsafeCurrentTask { $0?.cancel() }
        }
    }
    defer { lease.setAfterCriticalBody(nil) }
    let recovery = Task {
        try await volume.recoverSynchronizationFailure()
        return Task.isCancelled
    }
    #expect(try await recovery.value)
    lease.setAfterCriticalBody(nil)
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(
        try await volume.xattr(
            named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
            of: volume.imageItem) == DiskConnectionState.connected.encoded)
    #expect(try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9) == 1)
    await volume.shutdown()
}

@Test func volumeShutdownAfterNetworkCommitDoesNotRelabelRecoveryAsFailure() async throws {
    let (reserved, volume, _, target, lease) = try await mountedReservedFixture()
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 7)
    }
    let original = reserved.disk.mutationEvidence
    let shutdown = Synchronization.Mutex<Task<Void, Never>?>(nil)
    lease.setAfterCriticalBody {
        if reserved.disk.recoveryHistory.count == 1 {
            shutdown.withLock {
                if $0 == nil { $0 = volume.beginShutdown() }
            }
        }
    }
    defer { lease.setAfterCriticalBody(nil) }
    try await volume.recoverSynchronizationFailure()
    lease.setAfterCriticalBody(nil)
    let closing = try #require(shutdown.withLock { $0 })
    await closing.value
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(
        try await volume.xattr(
            named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
            of: volume.imageItem) == DiskConnectionState.closed.encoded)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([2]), to: volume.imageItem, at: 9)
    }
    #expect(await target.actions == [0, 1])
}

@Test func producerTicketKeepsEvidenceGenerationSeparateFromServiceGeneration() async throws {
    let (reserved, volume, _, target, _) = try await mountedReservedFixture()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    try await reserved.disk.synchronize()
    #expect(reserved.disk.mutationEvidence.generation == 1)
    #expect(reserved.disk.mutationEvidence.serviceGeneration == 0)
    let ticket = try await producerSynchronizationFailure(reserved, target: target)
    let original = reserved.disk.mutationEvidence
    #expect(original.generation == 1 && original.serviceGeneration == 0)
    try await reserved.recoverSynchronizationFailure(matching: ticket)
    #expect(reserved.disk.mutationEvidence.generation == 2)
    #expect(reserved.disk.mutationEvidence.serviceGeneration == 1)
    #expect(reserved.disk.recoveryHistory[0].original == original)
    await volume.shutdown()
}
