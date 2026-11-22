import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func mutationReply(
    tag: UInt32, opcode: UInt8 = 0x21,
    status: UInt8 = 0, length: UInt32 = 0,
    sense: Data = Data()
) throws -> Data {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = opcode
    header[1] = 0x80
    header[3] = status
    header.put(tag, at: 16)
    header.put(tag, at: 24)
    header.put(tag, at: 28)
    header.put(UInt32(32), at: 32)
    if opcode == 0x31 {
        header.put(UInt32(73), at: 20)
        header.put(length, at: 44)
    }
    return try PDU(
        header: header, data: sense.isEmpty ? Data() : Data([0, UInt8(sense.count)]) + sense
    ).encoded()
}

private func mutationTestDisk(
    _ transport: ScriptedTransport, blocks: UInt32 = 1,
    diagnostics: IODiagnostics.Recorder? = nil
) throws
    -> (ISCSISession, RemoteDisk)
{
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(31), at: 0)
    capacity.put(UInt32(512), at: 4)
    // The shipping path retains no payloads; these tests examine the retained evidence.
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        maximumTransferBlocks: blocks, diagnostics: diagnostics, reservedAccess: nil,
        retainedMutationBytes: 4_194_304)
    return (session, disk)
}

@Test func remoteDiskMutationEvidenceRecordsRealRMWBytesAndFailedSync() async throws {
    let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var replies = try loginFixtures(normal: true)
    replies.append(
        try fixture(
            opcode: 0x25, flags: 0x81, tag: 2, stat: 2, exp: 2,
            data: Data(repeating: 0x11, count: 512)))
    replies.append(try mutationReply(tag: 3, opcode: 0x31, length: 512))
    replies.append(try mutationReply(tag: 3))
    replies.append(try mutationReply(tag: 4, status: 2, sense: sense))
    let transport = ScriptedTransport(replies)
    let diagnostics = IODiagnostics.Recorder(layer: .remoteDisk)
    let (session, disk) = try mutationTestDisk(transport, diagnostics: diagnostics)
    try await session.login()
    try await disk.write(offset: 7, data: Data([0xA5, 0xCC]))
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.synchronize()
    }
    let evidence = disk.mutationEvidence
    var expected = Data(repeating: 0x11, count: 512)
    expected[7] = 0xA5
    expected[8] = 0xCC
    #expect(evidence.intents.count == 1)
    #expect(evidence.intents[0].offset == 0)
    #expect(evidence.intents[0].payload == expected)
    #expect(evidence.intents[0].outcome == .fullyAcknowledged)
    #expect(evidence.incident?.operation == .synchronize)
    #expect(evidence.incident?.id == diagnostics.retainedMutationCauseID)
    let sent = await transport.writes.count
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 512, data: Data(repeating: 9, count: 512))
    }
    #expect(await disk.connectionState() == .interrupted)
    #expect(await transport.writes.count == sent)
    #expect(disk.mutationEvidence == evidence)
    #expect(try mutationEvidencePlan(evidence).ranges[0].expected == expected)
    #expect(evidence.simulatedOrigin == nil)
    let simulated = RecoveryMemory(bytes: Data(repeating: 0x11, count: 16_384))
    let simulationBinding = await simulated.observation()
    await #expect(throws: MutationRecoveryIssue.wrongContext) {
        try await SimulatedRecoveryVerifier.verify(
            mutationEvidencePlan(evidence), binding: simulationBinding, media: simulated)
    }
    #expect(await disk.connectionState() == .interrupted)
    await session.close()
    #expect(disk.mutationEvidence == evidence)
}

@Test func remoteDiskMutationSplitFailureRetainsOnlyAttemptedPhysicalPrefix() async throws {
    let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var replies = try loginFixtures(normal: true)
    replies.append(try mutationReply(tag: 2, opcode: 0x31, length: 512))
    replies.append(try mutationReply(tag: 2))
    replies.append(try mutationReply(tag: 3, status: 2, sense: sense))
    let transport = ScriptedTransport(replies)
    let (session, disk) = try mutationTestDisk(transport)
    try await session.login()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.write(offset: 0, data: Data(repeating: 0xA5, count: 1536))
    }
    let evidence = disk.mutationEvidence
    #expect(evidence.intents.map(\.offset) == [0, 512])
    #expect(evidence.intents.map(\.outcome) == [.fullyAcknowledged, .failedResponse(2)])
    #expect(evidence.incident?.operation == .write)
    #expect(evidence.incident?.writeSequence == 2)
    #expect(evidence.higherLayerDirtyCoverageEstablished == false)
    #expect(throws: MutationRecoveryIssue.unsupportedIncident) {
        try mutationEvidencePlan(evidence)
    }
    #expect(await disk.connectionState() == .interrupted)
    await session.close()
}

@Test func remoteDiskMutationCancelledBeforeGateCreatesNoIntent() async throws {
    let transport = ScriptedTransport([])
    let (_, disk) = try mutationTestDisk(transport)
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(disk.mutationEvidence.intents.isEmpty)
    #expect(disk.mutationEvidence.nextWriteSequence == 1)
    #expect(await transport.writes.isEmpty)
}

@Test func remoteDiskMutationCancellationAfterDataRemainsIndeterminate() async throws {
    var replies = try loginFixtures(normal: true)
    replies.append(try mutationReply(tag: 2, opcode: 0x31, length: 512))
    replies.append(try mutationReply(tag: 2))
    let ends = replies.reduce(into: [Int]()) { result, bytes in
        result.append((result.last ?? 0) + bytes.count)
    }
    let transport = ScriptedTransport(
        replies,
        gates: [
            (0, 1), (ends[0], 2), (ends[1], 3), (ends[2], Int.max),
        ])
    let (session, disk) = try mutationTestDisk(transport)
    try await session.login()
    let task = Task { try await disk.write(offset: 0, data: Data(repeating: 7, count: 512)) }
    for _ in 0..<10_000 {
        if await transport.writes.count >= 4 { break }
        await Task.yield()
    }
    #expect(await transport.writes.count == 4)
    #expect(disk.mutationEvidence.intents.first?.outcome == .awaitingResponse)
    task.cancel()
    await #expect(throws: (any Error).self) { try await task.value }
    #expect(disk.mutationEvidence.intents.first?.outcome == .indeterminate)
    #expect(!disk.mutationEvidence.outcomesCertain)
    #expect(disk.mutationEvidence.incident == nil)
    #expect(disk.mutationEvidence.higherLayerDirtyCoverageEstablished == false)
    await session.close()
}

private actor RecoveryMemory: SimulatedRecoveryMedia {
    enum Change: Sendable, Equatable {
        case none, shortRead, corruptRead, afterRead, afterBarrier, failedBarrier, sameOwnerMutation
    }
    var binding: SimulatedRecoveryBinding
    private var bytes: Data
    private(set) var durable: Data
    private(set) var reads = 0
    private(set) var barriers = 0
    private let change: Change
    private var rejectNextSync = false

    init(bytes: Data, change: Change = .none) {
        self.bytes = bytes
        durable = Data(repeating: 0, count: bytes.count)
        binding = SimulatedRecoveryBinding(
            mediaID: UUID(), ownerID: UUID(), ownershipEpoch: 1,
            byteCount: UInt64(bytes.count), blockSize: 512)
        self.change = change
    }
    func observation() -> SimulatedRecoveryBinding { binding }
    func applyWrite(offset: Int, payload: Data, under expected: SimulatedRecoveryBinding) throws {
        guard binding == expected, binding.contentRevision < UInt64.max else {
            throw MutationRecoveryIssue.bindingChanged
        }
        bytes.replaceSubrange(offset..<(offset + payload.count), with: payload)
        binding = SimulatedRecoveryBinding(
            mediaID: binding.mediaID, ownerID: binding.ownerID,
            ownershipEpoch: binding.ownershipEpoch, contentRevision: binding.contentRevision + 1,
            byteCount: binding.byteCount, blockSize: binding.blockSize)
    }
    func failNextSynchronization() { rejectNextSync = true }
    private func invalidate() {
        binding = SimulatedRecoveryBinding(
            mediaID: binding.mediaID, ownerID: binding.ownerID, ownershipEpoch: 3,
            contentRevision: binding.contentRevision,
            byteCount: binding.byteCount, blockSize: binding.blockSize)
    }
    func read(offset: UInt64, length: Int, under expected: SimulatedRecoveryBinding) throws -> Data
    {
        guard expected == binding else { throw MutationRecoveryIssue.bindingChanged }
        reads += 1
        var result = Data(bytes[Int(offset)..<(Int(offset) + length)])
        if change == .shortRead { result.removeLast() }
        if change == .corruptRead { result[0] ^= 1 }
        if change == .afterRead { invalidate() }
        if change == .sameOwnerMutation {
            bytes[0] ^= 1
            binding = SimulatedRecoveryBinding(
                mediaID: binding.mediaID, ownerID: binding.ownerID,
                ownershipEpoch: binding.ownershipEpoch,
                contentRevision: binding.contentRevision + 1,
                byteCount: binding.byteCount, blockSize: binding.blockSize)
        }
        return result
    }
    func synchronize(under expected: SimulatedRecoveryBinding) throws -> UUID {
        guard expected == binding else { throw MutationRecoveryIssue.bindingChanged }
        barriers += 1
        if rejectNextSync {
            rejectNextSync = false
            throw ProtocolError.scsiFailure(
                status: 2, sense: Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0]))
        }
        if change == .failedBarrier { throw ProtocolError.timedOut }
        durable = bytes
        if change == .afterBarrier { invalidate() }
        return UUID()
    }
}

@Test func mutationRecoverySimulationChecksBytesAndRealSimulatedBarrier() async throws {
    let bytes = Data(repeating: 7, count: 4096)
    let media = RecoveryMemory(bytes: bytes)
    let binding = await media.observation()
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512, simulatedOrigin: binding)
    let sequence = journal.beginWrite(offset: 0, payload: bytes)
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let evidence = try mutationEvidenceFreeze(journal)
    let plan = try mutationEvidencePlan(evidence)
    let receipt = try await SimulatedRecoveryVerifier.verify(
        plan, binding: binding, media: media, maximumReadBytes: 512)
    #expect(receipt.simulatedOnly && !receipt.normalIOReopened)
    #expect(!receipt.higherLayerDirtyCoverageEstablished)
    #expect(receipt.planFingerprint == plan.fingerprint)
    #expect(receipt.incidentID == evidence.incident?.id)
    #expect(receipt.checkedBytes == 4096)
    let reads = await media.reads
    let barriers = await media.barriers
    #expect(reads == 8 && barriers == 1)
    #expect(await media.durable == bytes)
    #expect(journal.snapshot == evidence)
    #expect(journal.hasIncident)
}

@Test(arguments: [
    RecoveryMemory.Change.shortRead, .corruptRead, .afterRead, .afterBarrier, .failedBarrier,
])
private func mutationRecoverySimulationRejectsUnprovenMedia(_ change: RecoveryMemory.Change)
    async throws
{
    let media = RecoveryMemory(bytes: Data(repeating: 7, count: 4096), change: change)
    let binding = await media.observation()
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512, simulatedOrigin: binding)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let evidence = try mutationEvidenceFreeze(journal)
    let plan = try mutationEvidencePlan(evidence)
    await #expect(throws: (any Error).self) {
        try await SimulatedRecoveryVerifier.verify(plan, binding: binding, media: media)
    }
    #expect(journal.snapshot == evidence)
    #expect(journal.hasIncident)
    #expect(await media.reads > 0)
}

@Test func mutationRecoveryRequiresAnOriginBeforeCallingItRecovery() async throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let plan = try mutationEvidencePlan(mutationEvidenceFreeze(journal))
    let unrelated = RecoveryMemory(bytes: Data(repeating: 7, count: 4096))
    let unrelatedBinding = await unrelated.observation()
    await #expect(throws: MutationRecoveryIssue.self) {
        try await SimulatedRecoveryVerifier.verify(
            plan, binding: unrelatedBinding, media: unrelated)
    }
}

@Test func mutationRecoveryCheckedContentMustRemainStableUntilBarrier() async throws {
    let bytes = Data(repeating: 7, count: 4096)
    let media = RecoveryMemory(bytes: bytes, change: .sameOwnerMutation)
    let binding = await media.observation()
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512, simulatedOrigin: binding)
    let sequence = journal.beginWrite(offset: 0, payload: bytes)
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let plan = try mutationEvidencePlan(mutationEvidenceFreeze(journal))
    await #expect(throws: MutationRecoveryIssue.self) {
        try await SimulatedRecoveryVerifier.verify(
            plan, binding: binding, media: media, maximumReadBytes: 512)
    }
    #expect(await media.reads == 1)
    #expect(await media.barriers == 0)
}

@Test func mutationRecoveryDifferentMediaWithMatchingBytesCannotBorrowOrigin() async throws {
    let bytes = Data(repeating: 7, count: 4096)
    let original = RecoveryMemory(bytes: bytes)
    let origin = await original.observation()
    let other = RecoveryMemory(bytes: bytes)
    let otherBinding = await other.observation()
    #expect(origin.mediaID != otherBinding.mediaID)
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512, simulatedOrigin: origin)
    let sequence = journal.beginWrite(offset: 0, payload: bytes)
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let plan = try mutationEvidencePlan(mutationEvidenceFreeze(journal))
    await #expect(throws: MutationRecoveryIssue.wrongContext) {
        try await SimulatedRecoveryVerifier.verify(plan, binding: otherBinding, media: other)
    }
    #expect(await other.reads == 0)
    #expect(await other.barriers == 0)
}

@Test func mutationRecoveryJournaledWritesAdvanceRevisionBeforeVerificationStarts() async throws {
    let media = RecoveryMemory(bytes: Data(repeating: 0x11, count: 4096))
    let origin = await media.observation()
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512, simulatedOrigin: origin)
    let payload = Data(repeating: 0xA7, count: 512)
    let sequence = journal.beginWrite(offset: 0, payload: payload)
    try await media.applyWrite(offset: 0, payload: payload, under: origin)
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let current = await media.observation()
    #expect(current.contentRevision > origin.contentRevision)
    await media.failNextSynchronization()
    await #expect(throws: ProtocolError.self) { try await media.synchronize(under: current) }
    let evidence = try mutationEvidenceFreeze(journal)
    let plan = try mutationEvidencePlan(evidence)
    let receipt = try await SimulatedRecoveryVerifier.verify(plan, binding: current, media: media)
    #expect(receipt.checkedBytes == 512)
    var expected = Data(repeating: 0x11, count: 4096)
    expected.replaceSubrange(0..<512, with: payload)
    #expect(await media.durable == expected)
    #expect(await media.barriers == 2)
    #expect(journal.snapshot == evidence)
    #expect(!receipt.normalIOReopened)
}
