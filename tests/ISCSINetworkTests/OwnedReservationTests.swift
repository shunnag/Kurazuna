import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

@Test func reservedDiskQueuedTransportCannotWriteAfterAdministrativeFenceEnds() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    await target.pauseNextDataOut { lease.externalWritersAdmitted }
    let write = Task {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 9, count: 512))
    }
    for _ in 0..<10_000 {
        if await target.dataPause.isWaiting { break }
        await Task.yield()
    }
    #expect(await target.dataPause.isWaiting)
    lease.revoke()
    await target.dataPause.resume()
    await #expect(throws: (any Error).self) { try await write.value }
    #expect(await target.writesAfterFenceRelease == 0)
    await reserved.close()
}

@Test func reservedDiskRequiresStableInitialBarrierBeforePublishingDataCapability() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    await target.failNextSynchronization()
    await #expect(throws: ProtocolError.self) {
        try await ReservedRemoteDisk.acquire(
            session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(),
            store: store, diagnostics: nil)
    }
    #expect(await target.dataCommands == [0x35])
    #expect(store.load().first?.phase == .reserved)
    #expect(await target.actions == [0, 1])
    await session.close()
}

@Test func reservedDiskGoodCachedWriteKeepsAdministrativeFenceUntilSuccessfulBarrier() async throws
{
    let store = IntentFixture()
    let (session, _) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    lease.revoke()
    #expect(!lease.externalWritersAdmitted)
    await reserved.close()
    #expect(!lease.externalWritersAdmitted)
}

@Test func reservedDiskSuccessfulBarrierRetiresOnlyAcknowledgedDirtyWriteFence() async throws {
    let store = IntentFixture()
    let (session, _) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    for _ in 0..<3 {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    }
    #expect(lease.outstandingPins == 1)
    try await reserved.disk.synchronize()
    #expect(lease.outstandingPins == 0)
    lease.revoke()
    #expect(lease.externalWritersAdmitted)
    await reserved.close()
}

@Test func reservedDiskAppliedWriteFailureCannotUseSynchronizationRecovery() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    await target.failNextWrite()
    await #expect(throws: ProtocolError.self) {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    }
    let original = reserved.disk.mutationEvidence
    let before = await target.dataCommands
    #expect(original.incident?.operation == .write)
    #expect(original.intents.first?.outcome == .failedResponse(2))
    await #expect(throws: MutationRecoveryIssue.unsupportedIncident) {
        try await reserved.recoverSynchronizationFailure()
    }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(await target.dataCommands == before)
    lease.revoke()
    await reserved.close()
    #expect(!lease.externalWritersAdmitted)
}

@Test func reservedDiskFailedRecoveryBarrierDoesNotRetireUncertainPinsOrOriginalEvidence()
    async throws
{
    let (reserved, _, target, lease) = try await recoverableReservedDisk()
    let original = reserved.disk.mutationEvidence
    await target.failNextSynchronization()
    await #expect(throws: ProtocolError.self) { try await reserved.recoverSynchronizationFailure() }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    let before = await target.dataCommands
    await #expect(throws: ProtocolError.self) { try await reserved.recoverSynchronizationFailure() }
    #expect(await target.dataCommands == before)
    lease.revoke()
    await reserved.close()
    #expect(!lease.externalWritersAdmitted)
}

@Test func reservedDiskCancellationAfterRecoveryBarrierCannotCommitOrDropEvidence() async throws {
    let (reserved, _, _, lease) = try await recoverableReservedDisk()
    let original = reserved.disk.mutationEvidence
    lease.pauseAssertion(after: 2)
    let recovery = Task { try await reserved.recoverSynchronizationFailure() }
    for _ in 0..<10_000 {
        if await lease.pause.isWaiting { break }
        await Task.yield()
    }
    #expect(await lease.pause.isWaiting)
    recovery.cancel()
    await lease.pause.resume()
    await #expect(throws: (any Error).self) { try await recovery.value }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    await reserved.close()
}

@Test func reservedDiskPromotionConsumesUnexposedAuthorityAndKeepsOrdinaryCommandsClosed()
    async throws
{
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let owned = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store)
    let reserved = try await owned.transferToDisk(diagnostics: nil)
    #expect(await owned.state == .transferred)
    await #expect(throws: ProtocolError.self) { try await owned.release() }
    await #expect(throws: ProtocolError.self) { try await owned.transferToDisk(diagnostics: nil) }
    await #expect(throws: ProtocolError.busy) {
        try await session.execute(.read16(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(1))
    }
    let bytes = Data(repeating: 0xA5, count: 512)
    try await reserved.disk.write(offset: 0, data: bytes)
    #expect(try await reserved.disk.read(offset: 0, length: 512) == bytes)
    #expect(reserved.disk.mutationEvidence.reservedOrigin?.intentID == store.load()[0].id)
    await reserved.close()
    #expect(await target.actions == [0, 1])
    #expect(store.load()[0].phase == .reserved)
    #expect(await session.state == .closed)
}

@Test func reservedDiskTargetReportedCommunicationFailureUsesVerifiedOriginalBacking() async throws
{
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store,
        diagnostics: nil)
    try await reserved.disk.write(offset: 0, data: Data(repeating: 0x5A, count: 512))
    await target.failNextSynchronization(communication: true)
    await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
    let original = reserved.disk.mutationEvidence
    try await reserved.recoverSynchronizationFailure()
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(reserved.disk.recoveryHistory[0].refusal == .targetReportedCommunicationFailure)
    #expect(reserved.disk.mutationEvidence.serviceGeneration == 1)
    #expect(
        try await reserved.disk.read(offset: 0, length: 512) == Data(repeating: 0x5A, count: 512))
    await reserved.close()
}

@Test(arguments: [false, true])
private func reservedDiskCommunicationRecoveryRefusesFailedBarrierOrReplacedBacking(_ replace: Bool)
    async throws
{
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    try await reserved.disk.write(offset: 0, data: Data(repeating: 0x5A, count: 512))
    await target.failNextSynchronization(communication: true)
    await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
    let original = reserved.disk.mutationEvidence
    let before = await target.dataCommands
    if replace {
        lease.replaceBackingWithoutChangingSCSIIdentity()
    } else {
        await target.failNextSynchronization(communication: true)
    }
    await #expect(throws: (any Error).self) { try await reserved.recoverSynchronizationFailure() }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    if replace { #expect(await target.dataCommands == before) }
    let after = await target.dataCommands
    await #expect(throws: (any Error).self) { try await reserved.recoverSynchronizationFailure() }
    #expect(await target.dataCommands == after)
    await reserved.close()
}

@Test func reservedDiskRecoveryChecksRealBlockBytesAndBarrierBeforeNewServiceGeneration()
    async throws
{
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let (reserved, session, target, _) = try await recoverableReservedDisk(diagnostics: recorder)
    let original = reserved.disk.mutationEvidence
    try await reserved.recoverSynchronizationFailure()
    let after = reserved.disk.mutationEvidence
    #expect(after.incident == nil && after.serviceGeneration == 1)
    #expect(after.generation == original.generation + 1)
    #expect(reserved.disk.recoveryHistory.count == 1)
    #expect(reserved.disk.recoveryHistory[0].original == original)
    #expect(reserved.disk.recoveryHistory[0].checkedBytes == 512)
    #expect(recorder.retainedMutationCauseID == original.incident?.id)
    let beforeReplay = await target.dataCommands
    await #expect(throws: MutationRecoveryIssue.self) {
        try await reserved.recoverSynchronizationFailure()
    }
    #expect(await target.dataCommands == beforeReplay)
    try await reserved.disk.write(offset: 512, data: Data(repeating: 9, count: 512))
    try await reserved.disk.synchronize()
    #expect(await reserved.disk.connectionState() == .connected)
    #expect(await session.storageContinuity?.hasAdmittedDataAccess == true)
    await reserved.close()
}

@Test func reservedDiskSecondIncidentPreservesBothOriginalsAndFirstDiagnosticCause() async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let (reserved, _, target, _) = try await recoverableReservedDisk(diagnostics: recorder)
    let first = reserved.disk.mutationEvidence
    try await reserved.recoverSynchronizationFailure()
    try await reserved.disk.write(offset: 0, data: Data(repeating: 8, count: 512))
    await target.failNextSynchronization()
    await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
    let second = reserved.disk.mutationEvidence
    #expect(second.incident?.id != first.incident?.id)
    try await reserved.recoverSynchronizationFailure()
    #expect(reserved.disk.recoveryHistory.map(\.original) == [first, second])
    #expect(recorder.retainedMutationCauseID == first.incident?.id)
    let snapshot = recorder.snapshot()
    #expect(snapshot.events.filter { $0.stage == .mutationFailureRetained }.count == 2)
    #expect(snapshot.summary.integrityValid)
    await reserved.close()
}

@Test(arguments: [false, true])
private func reservedDiskFailedReadbackOrLostFenceNeverReopens(_ revoke: Bool) async throws {
    let (reserved, _, target, lease) = try await recoverableReservedDisk()
    let original = reserved.disk.mutationEvidence
    if revoke { lease.revoke() } else { await target.corruptMedia() }
    await #expect(throws: (any Error).self) { try await reserved.recoverSynchronizationFailure() }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(reserved.disk.recoveryHistory.isEmpty)
    let data = await target.dataCommands
    await #expect(throws: (any Error).self) {
        try await reserved.disk.write(offset: 0, data: Data(repeating: 4, count: 512))
    }
    #expect(await target.dataCommands == data)
    #expect(await target.actions == [0, 1])
    await reserved.close()
}

@Test func reservedDiskReservationConflictDuringRecoveryPreventsCommitWithoutRetry() async throws {
    let (reserved, session, target, _) = try await recoverableReservedDisk()
    let original = reserved.disk.mutationEvidence
    let before = await target.dataCommands
    await target.injectStatus(0x18)
    await #expect(throws: ProtocolError.self) { try await reserved.recoverSynchronizationFailure() }
    #expect(reserved.disk.mutationEvidence == original)
    #expect(await session.storageContinuity?.disruptionEpoch == 1)
    #expect(await target.dataCommands == before)
    await reserved.close()
}

@Test func reservedDiskRecoveryRejectsQueuedOldGenerationAndConcurrentClose() async throws {
    for close in [false, true] {
        let (reserved, _, target, lease) = try await recoverableReservedDisk()
        let original = reserved.disk.mutationEvidence
        // The second ownership assertion occurs after real readback and the GOOD barrier.
        lease.pauseAssertion(after: 2)
        let recovery = Task { try await reserved.recoverSynchronizationFailure() }
        for _ in 0..<10_000 {
            if await lease.pause.isWaiting { break }
            await Task.yield()
        }
        #expect(await lease.pause.isWaiting)
        let queued = Task {
            try await reserved.disk.write(offset: 512, data: Data(repeating: 4, count: 512))
        }
        for _ in 0..<10_000 {
            if await reserved.disk.queuedIOCount == 1 { break }
            await Task.yield()
        }
        #expect(await reserved.disk.queuedIOCount == 1)
        if close { await reserved.close() }
        await lease.pause.resume()
        if close {
            await #expect(throws: ProtocolError.self) { try await recovery.value }
            #expect(reserved.disk.mutationEvidence == original)
        } else {
            try await recovery.value
            #expect(reserved.disk.mutationEvidence.serviceGeneration == 1)
        }
        await #expect(throws: ProtocolError.self) { try await queued.value }
        #expect(await target.actions == [0, 1])
        await reserved.close()
    }
}

@Test func reservedDiskCancelledRecoveryAndEvidenceOverflowKeepOriginalIncident() async throws {
    for overflow in [false, true] {
        let store = IntentFixture()
        let (session, target) = try await reservedSession(store)
        let reserved = try await ReservedRemoteDisk.acquire(
            session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store,
            diagnostics: nil)
        for _ in 0..<(overflow ? 129 : 1) {
            try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
        }
        await target.failNextSynchronization()
        await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
        let original = reserved.disk.mutationEvidence
        let before = await target.dataCommands
        let task = Task {
            if !overflow { withUnsafeCurrentTask { $0?.cancel() } }
            try await reserved.recoverSynchronizationFailure()
        }
        await #expect(throws: (any Error).self) { try await task.value }
        #expect(reserved.disk.mutationEvidence == original)
        #expect(await target.dataCommands == before)
        #expect(reserved.disk.recoveryHistory.isEmpty)
        await reserved.close()
    }
}

@Test func ownedReservationAcquiresAndReleasesWithDurablePhasesAndNoDataAdmission() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let owned = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    #expect(store.load().first?.phase == .reserved)
    #expect(await session.storageContinuity?.hasAdmittedDataAccess == false)
    await #expect(throws: ProtocolError.busy) {
        try await session.execute(.read16(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(1))
    }
    try await owned.release()
    #expect(await owned.state == .released && store.load().first?.phase == .released)
    #expect(await target.actions == [0, 1, 2, 0])
    #expect(await target.isClosed)
    #expect(await session.state == .closed)
    await #expect(throws: ProtocolError.self) { try await owned.release() }
}

@Test(arguments: [OwnedReservationIntent.Phase.prepared, .registered, .reserving, .reserved])
func ownedReservationPublicationFailureNeverCleansUpOrReopens(
    _ phase: OwnedReservationIntent.Phase
) async throws {
    for committed in [false, true] {
        let store = IntentFixture(failPhase: phase, commitThenFail: committed)
        let (session, target) = try await reservedSession(store)
        await #expect(throws: POSIXError.self) {
            try await UnexposedLUNReservation.acquire(
                session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
        }
        #expect(await session.state == .closed)
        #expect(await target.isClosed)
        #expect(
            await target.actions == (phase == .prepared ? [] : phase == .reserved ? [0, 1] : [0]))
    }
}

@Test(arguments: [
    ReservationTarget.Fault.ownISID, .targetPort, .allPorts, .foreignKey, .identity, .unitAttention,
])
private func ownedReservationRejectsUnprovedNexusAndLossWithoutStealingOrRetrying(
    _ fault: ReservationTarget.Fault
) async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store, fault: fault)
    await #expect(throws: ProtocolError.self) {
        try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    }
    #expect(await target.actions == (fault == .unitAttention ? [0, 1] : [0]))
    #expect(await target.isClosed)
    #expect(await session.state == .closed)
    #expect(store.load().first?.phase != .released)
}

@Test func ownedReservationRejectsChangedLIOT10AfterRegisterDespiteStableNAA() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store, fault: .t10Identity)
    await #expect(throws: ProtocolError.self) {
        try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    }
    #expect(await target.actions == [0])
    #expect(await target.isClosed)
    #expect(await session.state == .closed)
    #expect(store.load().first?.phase == .prepared)
    #expect(store.load().count == 1)
}

@Test(arguments: [1, 2, 3])
func ownedReservationRequiresQuiescenceThroughPublication(_ call: Int) async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    await #expect(throws: POSIXError.self) {
        try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(failCall: call),
            store: store)
    }
    #expect(await target.actions == (call == 1 ? [] : call == 2 ? [0] : [0, 1]))
    #expect(await session.state == .closed)
}

@Test(arguments: [1, 2, 3])
func ownedReservationCancellationDoesNotPublishOrSendCleanup(_ call: Int) async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let operation = Task {
        try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(cancelCall: call),
            store: store)
    }
    await #expect(throws: ProtocolError.self) { try await operation.value }
    #expect(await target.actions == (call == 1 ? [] : call == 2 ? [0] : [0, 1]))
    #expect(await session.state == .closed)
}

@Test(arguments: [OwnedReservationIntent.Phase.releasing, .unregistering, .released])
func ownedReservationReleasePublicationUncertaintyRetainsOrphan(
    _ phase: OwnedReservationIntent.Phase
)
    async throws
{
    for committed in [false, true] {
        let store = IntentFixture(failPhase: phase, commitThenFail: committed)
        let (session, target) = try await reservedSession(store)
        let owned = try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
        await #expect(throws: POSIXError.self) { try await owned.release() }
        #expect(await owned.state == .lost)
        #expect(await session.state == .closed)
        #expect(
            await target.actions
                == (phase == .releasing
                    ? [0, 1] : phase == .unregistering ? [0, 1, 2] : [0, 1, 2, 0]))
        await #expect(throws: ProtocolError.self) { try await owned.release() }
    }
}

@Test func ownedReservationAbandonNeverMutatesTheOrphanOrReopensSession() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let owned = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    await owned.abandon()
    #expect(await owned.state == .lost)
    #expect(await session.state == .closed)
    #expect(await target.actions == [0, 1] && store.load().first?.phase == .reserved)
}

@Test func ownedReservationTicketCannotBeFinishedToReopenPublicExecution() async throws {
    let transport = ScriptedTransport(try loginFixtures(normal: true))
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
    try await session.ownUnexposedReservation(ticket)
    #expect(await session.finishStorageInspection(ticket) == false)
    await #expect(throws: ProtocolError.busy) {
        try await session.execute(.synchronizeCache10(), lun: LogicalUnit(1))
    }
    #expect(await transport.writes.count == 2)
    await session.close()
}

@Test func ownedReservationCommandsCannotBypassTheIntentAndQuiescenceFactory() async throws {
    let transport = ScriptedTransport(try loginFixtures(normal: true))
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .milliseconds(100))
    try await session.login()
    let control = try SCSIReservationControl(action: .register, key: 0, newKey: 77)
    await #expect(throws: ProtocolError.invalidState) {
        try await session.execute(control.command, lun: LogicalUnit(1), output: control.parameters)
    }
    #expect(await transport.writes.count == 2)
    await session.close()
}

@Test func ownedReservationRefusesPriorDataOrSynchronizationAdmission() async throws {
    for dataAccess in [false, true] {
        var frames = try loginFixtures(normal: true)
        frames.append(
            try fixture(
                opcode: dataAccess ? 0x25 : 0x21, flags: dataAccess ? 0x81 : 0x80,
                tag: 2, stat: 2, exp: 2, data: dataAccess ? Data(repeating: 0, count: 512) : Data())
        )
        let transport = ScriptedTransport(frames)
        let session = try ISCSISession(
            transport: transport, configuration: configuration(normal: true))
        try await session.login()
        _ = try await session.execute(
            dataAccess ? .read16(lba: 0, blocks: 1, blockSize: 512) : .synchronizeCache10(),
            lun: LogicalUnit(1))
        let store = IntentFixture()
        await #expect(throws: ProtocolError.self) {
            try await UnexposedLUNReservation.acquire(
                session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
        }
        #expect(store.load().isEmpty)
        #expect(await session.state == .closed)
        #expect(await transport.writes.count == 3)
    }
}

@Test(arguments: [UInt8(2), 0x18])
func ownedReservationLosesOwnershipBeforeReleaseWithoutMutating(_ status: UInt8) async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let owned = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    await target.injectStatus(status)
    await #expect(throws: ProtocolError.self) { try await owned.release() }
    #expect(await owned.state == .lost)
    #expect(await session.state == .closed)
    #expect(await target.actions == [0, 1])
    #expect(store.load().first?.phase == .reserved)
}

@Test func ownedReservationUnknownReserveCompletionCannotBeReleasedOrReacquired() async throws {
    let store = IntentFixture()
    let target = ReservationTarget(store: store, dropAction: 1)
    let session = try ISCSISession(transport: target, configuration: configuration(normal: true))
    try await session.login()
    await #expect(throws: ProtocolError.self) {
        try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: QuiescenceFixture(), store: store)
    }
    #expect(await target.hasReservation())
    #expect(await target.actions == [0, 1])
    #expect(store.load().first?.phase == .reserving)
    #expect(await session.state == .closed)
}

private actor ReleasePauseFixture: StorageQuiescenceLease {
    nonisolated let id = UUID()
    nonisolated let relativeTargetPort: UInt16 = 12
    private var calls = 0
    private var paused: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func assertHeld(for binding: OwnedReservationBinding) async throws {
        calls += 1
        if calls == 4 {
            await withCheckedContinuation {
                paused = $0
                observer?.resume()
                observer = nil
            }
        }
    }
    func waitForPause() async {
        if paused != nil { return }
        await withCheckedContinuation { observer = $0 }
    }
    func resume() {
        paused?.resume()
        paused = nil
    }
}

@Test func ownedReservationAbandonDuringReleaseClosesBeforeFurtherMutation() async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ReleasePauseFixture()
    let owned = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store)
    let release = Task {
        do {
            try await owned.release()
            return true
        } catch { return false }
    }
    await lease.waitForPause()
    await #expect(throws: ProtocolError.self) { try await owned.release() }
    await owned.abandon()
    #expect(await owned.state == .lost)
    #expect(await session.state == .closed)
    await lease.resume()
    #expect(await release.value == false)
    #expect(await owned.state == .lost)
    #expect(await target.actions == [0, 1])
    #expect(store.load().first?.phase == .reserved)
}

/// The reserved path has its own recovery, so a status that the shipping path retries still
/// latches a reserved disk after its first and only attempt.
private struct UnexecutedRejection: Sendable, CustomStringConvertible {
    let status: UInt8
    let sense: Data
    var description: String { "\(status)/\(Array(sense.prefix(3)))" }
    static let all = [
        Self(status: 8, sense: Data()), Self(status: 0x28, sense: Data()),
        Self(status: 2, sense: Data([0x72, 6, 0x2F, 0, 0, 0, 0, 0])),
        Self(status: 2, sense: Data([0x72, 6, 0x29, 0, 0, 0, 0, 0])),
    ]
}

@Test(arguments: UnexecutedRejection.all)
private func reservedDiskNeverRetriesAnUnexecutedSynchronization(
    _ rejection: UnexecutedRejection
) async throws {
    let (status, sense) = (rejection.status, rejection.sense)
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: nil)
    try await reserved.disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    let before = await target.dataCommands
    await target.rejectNextSynchronization(status: status, sense: sense)
    await #expect(throws: ProtocolError.scsiFailure(status: status, sense: sense)) {
        try await reserved.disk.synchronize()
    }
    #expect(await target.dataCommands == before + [0x35])
    #expect(reserved.disk.mutationEvidence.incident?.operation == .synchronize)
    #expect(reserved.disk.mutationEvidence.intents.count == 1)
    lease.revoke()
    await reserved.close()
}
