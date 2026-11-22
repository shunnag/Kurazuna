import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

func mutationEvidenceFailureSense() throws -> SCSISense {
    try SCSISense(data: Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0]))
}

func mutationEvidenceFreeze(_ journal: MutationEvidenceJournal) throws -> MutationEvidence {
    journal.beginSynchronization()
    let sense = try mutationEvidenceFailureSense()
    journal.noteSynchronization(opcode: 0x35, outcome: .failedResponse(2), sense: sense)
    _ = journal.retainFailure(operation: .synchronize, sequence: nil, status: 2, sense: sense)
    return journal.snapshot
}

func mutationEvidencePlan(_ evidence: MutationEvidence, fragments: Int = 256) throws
    -> MutationRecoveryPlan
{
    try MutationRecoveryPlan(
        evidence: evidence, diskID: evidence.diskID, generation: evidence.generation,
        byteCount: evidence.byteCount, blockSize: evidence.blockSize, maximumFragments: fragments)
}

@Test func mutationRecoveryClassifiesOnlyCurrentSynchronizationRefusalsWithoutRewritingSense()
    throws
{
    for tuple in [(UInt8(3), UInt8(0x0C)), (UInt8(2), UInt8(8))] {
        let sense = try SCSISense(data: Data([0x72, tuple.0, tuple.1, 0, 0, 0, 0, 0]))
        let incident = MutationIncident(
            id: UUID(), generation: 0, operation: .synchronize, writeSequence: nil,
            status: 2, sense: sense)
        #expect(
            incident.synchronizationRefusal
                == (tuple.0 == 3 ? .mediumWriteError : .targetReportedCommunicationFailure))
        for status: UInt8 in [0, 8, 0x18] {
            #expect(
                MutationIncident(
                    id: UUID(), generation: 0, operation: .synchronize,
                    writeSequence: nil, status: status, sense: sense
                ).synchronizationRefusal == nil)
        }
        #expect(
            MutationIncident(
                id: UUID(), generation: 0, operation: .write,
                writeSequence: 1, status: 2, sense: sense
            ).synchronizationRefusal == nil)
        for bytes in [
            Data([0x73, tuple.0, tuple.1, 0, 0, 0, 0, 0]),
            Data([0x72, tuple.0, tuple.1, 1, 0, 0, 0, 0]),
        ] {
            #expect(
                MutationIncident(
                    id: UUID(), generation: 0, operation: .synchronize,
                    writeSequence: nil, status: 2, sense: try SCSISense(data: bytes)
                ).synchronizationRefusal == nil)
        }
    }
}

@Test func targetCommunicationFailureWithoutOriginalReservedAuthorityRemainsUnsupported() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 0x5A, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let sense = try SCSISense(data: Data([0x72, 2, 8, 0, 0, 0, 0, 0]))
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .failedResponse(2), sense: sense)
    _ = journal.retainFailure(operation: .synchronize, sequence: nil, status: 2, sense: sense)
    #expect(throws: MutationRecoveryIssue.unsupportedIncident) {
        try mutationEvidencePlan(journal.snapshot)
    }
}

@Test func mutationEvidenceCopiesIntentBeforeAcknowledgment() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    var payload = Data(repeating: 0xA5, count: 512)
    let sequence = journal.beginWrite(offset: 512, payload: payload)
    let before = journal.snapshot
    payload[0] = 0
    #expect(before.intents[0].payload == Data(repeating: 0xA5, count: 512))
    #expect(before.intents[0].outcome == .awaitingResponse)
    #expect(before.pendingWrite == sequence)
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let after = journal.snapshot
    #expect(after.intents[0].outcome == .fullyAcknowledged)
    #expect(before.intents[0].outcome == .awaitingResponse)
    #expect(after.seal == after.fingerprint())
    #expect(after.higherLayerDirtyCoverageEstablished == false)
}

@Test func mutationEvidenceFailedSyncRetainsIncidentAcrossCloseLikeCalls() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let failed = try mutationEvidenceFreeze(journal)
    #expect(journal.hasIncident)
    #expect(journal.beginWrite(offset: 512, payload: Data(repeating: 8, count: 512)) == nil)
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .fullyAcknowledged, sense: nil)
    journal.completeSynchronization()
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    #expect(
        journal.retainFailure(operation: .write, sequence: sequence, status: 8, sense: nil) == nil)
    #expect(journal.snapshot == failed)
    #expect(try mutationEvidencePlan(failed).incidentID == failed.incident?.id)
}

@Test func mutationEvidenceUnsupported10RetiresOnlyAfterRealGood16() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let unsupported = try SCSISense(data: Data([0x72, 5, 0x20, 0, 0, 0, 0, 0]))
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .failedResponse(2), sense: unsupported)
    journal.completeSynchronization()
    #expect(journal.snapshot.generation == 0)
    #expect(journal.snapshot.intents.count == 1)
    journal.noteSynchronization(opcode: 0x91, outcome: .fullyAcknowledged, sense: nil)
    journal.completeSynchronization()
    let retired = journal.snapshot
    #expect(retired.generation == 1)
    #expect(retired.intents.isEmpty)
    #expect(retired.precedingBarrier?.attempts.map(\.opcode) == [0x35, 0x91])
    #expect(retired.precedingBarrier?.nextWriteSequence == 2)
    journal.completeSynchronization()
    #expect(journal.snapshot == retired)
}

@Test func mutationEvidenceIndeterminateWriteIsNotErasedByGoodBarrier() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .indeterminate)
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .fullyAcknowledged, sense: nil)
    journal.completeSynchronization()
    #expect(journal.snapshot.generation == 0)
    #expect(journal.snapshot.intents.count == 1)
    #expect(!journal.snapshot.outcomesCertain)
    #expect(journal.snapshot.precedingBarrier == nil)
    #expect(throws: MutationRecoveryIssue.self) {
        try mutationEvidencePlan(mutationEvidenceFreeze(journal))
    }
}

@Test(arguments: [0, 511, 512, 1024])
func mutationEvidenceByteLimitIsExplicitAndNewBarrierStartsFresh(_ limit: Int) throws {
    let journal = MutationEvidenceJournal(
        byteCount: 4096, blockSize: 512, maximumBytes: limit)
    for index in 0..<2 {
        let sequence = journal.beginWrite(
            offset: UInt64(index * 512), payload: Data(repeating: UInt8(index), count: 512))
        journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    }
    let before = journal.snapshot
    #expect(before.intents.reduce(0) { $0 + $1.payload.count } <= limit)
    #expect(before.coverageComplete == (limit == 1024))
    #expect(before.outcomesCertain)
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .fullyAcknowledged, sense: nil)
    journal.completeSynchronization()
    #expect(journal.snapshot.generation == 1)
    #expect(journal.snapshot.coverageComplete)
    #expect(journal.snapshot.intents.isEmpty)
    #expect(before.coverageComplete == (limit == 1024))
}

@Test func mutationEvidenceEntryLimitCannotAdmitAnIncompletePlan() throws {
    let journal = MutationEvidenceJournal(
        byteCount: 4096, blockSize: 512, maximumIntents: 1)
    for offset in [UInt64(0), 512] {
        let sequence = journal.beginWrite(offset: offset, payload: Data(repeating: 7, count: 512))
        journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    }
    let evidence = try mutationEvidenceFreeze(journal)
    #expect(evidence.intents.count == 1)
    #expect(evidence.nextWriteSequence == 3)
    #expect(!evidence.coverageComplete)
    #expect(throws: MutationRecoveryIssue.incompleteEvidence) { try mutationEvidencePlan(evidence) }
}

@Test(arguments: [UInt32(512), 4096])
func mutationRecoveryOverlapViewMatchesIndependentByteOracle(_ blockSize: UInt32) throws {
    let size = Int(blockSize)
    let journal = MutationEvidenceJournal(byteCount: UInt64(size * 16), blockSize: blockSize)
    var oracle = [UInt8](repeating: 0, count: size * 16)
    var covered = [Bool](repeating: false, count: size * 16)
    var random: UInt32 = 387
    for ordinal in 0..<50 {
        random = 1_664_525 &* random &+ 1_013_904_223
        let start = Int(random % 12)
        random = 1_664_525 &* random &+ 1_013_904_223
        let blocks = 1 + Int(random % 4)
        let payload = [UInt8](repeating: UInt8(ordinal), count: blocks * size)
        oracle.replaceSubrange(start * size..<(start + blocks) * size, with: payload)
        for i in start * size..<(start + blocks) * size { covered[i] = true }
        let sequence = journal.beginWrite(offset: UInt64(start * size), payload: Data(payload))
        journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    }
    let evidence = try mutationEvidenceFreeze(journal)
    let plan = try mutationEvidencePlan(evidence)
    var seen = [Bool](repeating: false, count: oracle.count)
    var lastEnd: UInt64 = 0
    for range in plan.ranges {
        #expect(range.offset >= lastEnd)
        let start = Int(range.offset)
        #expect(range.expected == Data(oracle[start..<(start + range.expected.count)]))
        for i in start..<(start + range.expected.count) { seen[i] = true }
        lastEnd = range.end
    }
    #expect(seen == covered)
    #expect(evidence.intents.count == 50)
}

@Test func mutationRecoveryNestedReplacementHonorsFragmentLimit() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    for (offset, payload) in [
        (UInt64(0), Data(repeating: 1, count: 2048)),
        (512, Data(repeating: 2, count: 512)),
    ] {
        let sequence = journal.beginWrite(offset: offset, payload: payload)
        journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    }
    let evidence = try mutationEvidenceFreeze(journal)
    #expect(throws: MutationRecoveryIssue.fragmentLimit) {
        try mutationEvidencePlan(evidence, fragments: 2)
    }
    #expect(
        try mutationEvidencePlan(evidence, fragments: 3).ranges.map(\.offset) == [0, 512, 1024])
}

@Test func mutationRecoveryRejectsAlteredBytesAndSequenceGaps() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    let evidence = try mutationEvidenceFreeze(journal)
    var altered = evidence
    altered.intents[0] = MutationWriteIntent(
        sequence: sequence!, offset: 0, payload: Data(repeating: 8, count: 512),
        outcome: .fullyAcknowledged)
    #expect(throws: MutationRecoveryIssue.inconsistentEvidence) {
        try mutationEvidencePlan(altered)
    }
    var gap = evidence
    gap.nextWriteSequence += 1
    gap.seal = gap.fingerprint()
    #expect(throws: MutationRecoveryIssue.incompleteEvidence) { try mutationEvidencePlan(gap) }
    #expect(throws: MutationRecoveryIssue.wrongContext) {
        try MutationRecoveryPlan(
            evidence: evidence, diskID: UUID(), generation: 0, byteCount: 4096, blockSize: 512)
    }
    #expect(throws: MutationRecoveryIssue.wrongContext) {
        try MutationRecoveryPlan(
            evidence: evidence, diskID: evidence.diskID, generation: 1,
            byteCount: 4096, blockSize: 512)
    }
}

@Test func mutationEvidenceInvalidSynchronizationChainCannotRetireOrAnchorEvidence() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    journal.beginSynchronization()
    journal.noteSynchronization(opcode: 0x35, outcome: .indeterminate, sense: nil)
    journal.noteSynchronization(opcode: 0x91, outcome: .fullyAcknowledged, sense: nil)
    journal.completeSynchronization()
    #expect(journal.snapshot.generation == 0)
    #expect(journal.snapshot.intents.count == 1)

    let other = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let first = other.beginWrite(offset: 0, payload: Data(repeating: 8, count: 512))
    other.finishWrite(first, outcome: .fullyAcknowledged)
    other.beginSynchronization()
    other.noteSynchronization(opcode: 0x35, outcome: .fullyAcknowledged, sense: nil)
    other.completeSynchronization()
    let second = other.beginWrite(offset: 512, payload: Data(repeating: 9, count: 512))
    other.finishWrite(second, outcome: .fullyAcknowledged)
    var evidence = try mutationEvidenceFreeze(other)
    let old = try #require(evidence.precedingBarrier)
    evidence.precedingBarrier = MutationBarrier(
        id: old.id, retiredGeneration: old.retiredGeneration,
        nextWriteSequence: old.nextWriteSequence,
        attempts: [
            MutationSynchronization(opcode: 0x35, outcome: .indeterminate, sense: nil),
            MutationSynchronization(opcode: 0x91, outcome: .fullyAcknowledged, sense: nil),
        ])
    evidence.seal = evidence.fingerprint()
    #expect(throws: MutationRecoveryIssue.inconsistentEvidence) {
        try mutationEvidencePlan(evidence)
    }
}

@Test func mutationRecoveryNormalizesSlicedPayloadForBoundedRead() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    var evidence = try mutationEvidenceFreeze(journal)
    let sliced = Data(repeating: 7, count: 1024).dropFirst(512)
    #expect(sliced.startIndex == 512)
    evidence.intents[0] = MutationWriteIntent(
        sequence: sequence!, offset: 0, payload: sliced, outcome: .fullyAcknowledged)
    evidence.seal = evidence.fingerprint()
    let plan = try mutationEvidencePlan(evidence)
    // Demonstrate the original invalid indexing assumption without crashing the test process.
    #expect(plan.ranges[0].expected.startIndex == 0)
    #expect(plan.ranges[0].expected.count == 512)
}

@Test func mutationEvidenceDroppedSynchronizationTailCannotRetireValidPrefix() throws {
    let journal = MutationEvidenceJournal(byteCount: 4096, blockSize: 512)
    let sequence = journal.beginWrite(offset: 0, payload: Data(repeating: 7, count: 512))
    journal.finishWrite(sequence, outcome: .fullyAcknowledged)
    journal.beginSynchronization()
    journal.noteSynchronization(
        opcode: 0x35, outcome: .failedResponse(2),
        sense: try SCSISense(data: Data([0x72, 5, 0x20, 0, 0, 0, 0, 0])))
    journal.noteSynchronization(opcode: 0x91, outcome: .fullyAcknowledged, sense: nil)
    journal.noteSynchronization(
        opcode: 0x91, outcome: .failedResponse(2), sense: try mutationEvidenceFailureSense())
    journal.completeSynchronization()
    #expect(journal.snapshot.generation == 0)
    #expect(journal.snapshot.intents.count == 1)
}
