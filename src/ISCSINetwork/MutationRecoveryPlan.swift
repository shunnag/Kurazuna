import CryptoKit
import Foundation

enum MutationRecoveryIssue: Error, Sendable, Equatable {
    case wrongContext, inconsistentEvidence, unsupportedIncident, incompleteEvidence
    case invalidRange, fragmentLimit, invalidReadLimit, bindingChanged, readMismatch
}

struct MutationRecoveryRange: Sendable, Equatable {
    let offset: UInt64
    let expected: Data
    var end: UInt64 { offset + UInt64(expected.count) }
}

/// A byte comparison plan only; it confers no authority to resume a failed disk.
struct MutationRecoveryPlan: Sendable {
    let diskID: UUID
    let generation: UInt64
    let incidentID: UUID
    let byteCount: UInt64
    let blockSize: UInt32
    let evidenceSeal: Data
    let ranges: [MutationRecoveryRange]
    let simulatedOrigin: SimulatedRecoveryBinding?
    let refusal: MutationIncident.SynchronizationRefusal

    init(
        evidence: MutationEvidence, diskID: UUID, generation: UInt64,
        byteCount: UInt64, blockSize: UInt32, maximumFragments: Int = 256
    ) throws {
        guard evidence.diskID == diskID, evidence.generation == generation,
            evidence.byteCount == byteCount, evidence.blockSize == blockSize
        else {
            throw MutationRecoveryIssue.wrongContext
        }
        guard evidence.seal == evidence.fingerprint() else {
            throw MutationRecoveryIssue.inconsistentEvidence
        }
        guard let incident = evidence.incident, incident.generation == generation,
            let refusal = incident.synchronizationRefusal, let sense = incident.sense,
            refusal != .targetReportedCommunicationFailure
                || (evidence.reservedOrigin != nil && evidence.simulatedOrigin == nil)
        else {
            throw MutationRecoveryIssue.unsupportedIncident
        }
        guard evidence.coverageComplete, evidence.outcomesCertain,
            evidence.synchronizationHistoryComplete,
            evidence.pendingWrite == nil, !evidence.intents.isEmpty,
            evidence.intents.count <= 128,
            evidence.nextWriteSequence >= evidence.firstWriteSequence,
            evidence.nextWriteSequence - evidence.firstWriteSequence
                == UInt64(evidence.intents.count)
        else {
            throw MutationRecoveryIssue.incompleteEvidence
        }
        guard [UInt32(512), 4096].contains(blockSize), byteCount > 0,
            byteCount % UInt64(blockSize) == 0
        else {
            throw MutationRecoveryIssue.invalidRange
        }
        if generation == 0 {
            guard evidence.precedingBarrier == nil else {
                throw MutationRecoveryIssue.inconsistentEvidence
            }
        } else {
            guard let barrier = evidence.precedingBarrier,
                barrier.retiredGeneration == generation - 1,
                barrier.nextWriteSequence == evidence.firstWriteSequence,
                MutationSynchronization.isSuccessfulBarrier(barrier.attempts)
            else {
                throw MutationRecoveryIssue.inconsistentEvidence
            }
        }
        let attempts = evidence.synchronizationAttempts
        guard (1...2).contains(attempts.count), let last = attempts.last,
            [UInt8(0x35), 0x91].contains(last.opcode),
            last.outcome == .failedResponse(2), last.sense == sense
        else {
            throw MutationRecoveryIssue.inconsistentEvidence
        }
        if attempts.count == 2 {
            let first = attempts[0]
            guard first.opcode == 0x35, last.opcode == 0x91,
                first.outcome == .failedResponse(2), let unsupported = first.sense,
                !unsupported.isDeferred, unsupported.key == 5,
                unsupported.additionalSenseCode == 0x20, unsupported.qualifier == 0
            else {
                throw MutationRecoveryIssue.inconsistentEvidence
            }
        }
        guard maximumFragments > 0, maximumFragments <= 256 else {
            throw MutationRecoveryIssue.fragmentLimit
        }
        var derived: [MutationRecoveryRange] = []
        var bytes = 0
        for (index, intent) in evidence.intents.enumerated() {
            guard intent.sequence == evidence.firstWriteSequence + UInt64(index),
                intent.outcome == .fullyAcknowledged
            else {
                throw MutationRecoveryIssue.incompleteEvidence
            }
            guard !intent.payload.isEmpty, intent.payload.count <= 4_194_304 - bytes,
                intent.offset % UInt64(blockSize) == 0,
                intent.payload.count % Int(blockSize) == 0,
                intent.offset <= byteCount,
                UInt64(intent.payload.count) <= byteCount - intent.offset
            else {
                throw MutationRecoveryIssue.invalidRange
            }
            bytes += intent.payload.count
            let normalized = intent.payload.withUnsafeBytes {
                Data(bytes: $0.baseAddress!, count: $0.count)
            }
            let replacement = MutationRecoveryRange(offset: intent.offset, expected: normalized)
            var next: [MutationRecoveryRange] = []
            for old in derived {
                if old.end <= replacement.offset || old.offset >= replacement.end {
                    next.append(old)
                } else {
                    if old.offset < replacement.offset {
                        next.append(
                            MutationRecoveryRange(
                                offset: old.offset,
                                expected: Data(
                                    old.expected.prefix(Int(replacement.offset - old.offset)))))
                    }
                    if old.end > replacement.end {
                        next.append(
                            MutationRecoveryRange(
                                offset: replacement.end,
                                expected: Data(old.expected.suffix(Int(old.end - replacement.end))))
                        )
                    }
                }
                guard next.count <= maximumFragments else {
                    throw MutationRecoveryIssue.fragmentLimit
                }
            }
            next.append(replacement)
            guard next.count <= maximumFragments else { throw MutationRecoveryIssue.fragmentLimit }
            derived = next.sorted { $0.offset < $1.offset }
        }
        self.diskID = diskID
        self.generation = generation
        incidentID = incident.id
        self.byteCount = byteCount
        self.blockSize = blockSize
        evidenceSeal = evidence.seal
        ranges = derived
        simulatedOrigin = evidence.simulatedOrigin
        self.refusal = refusal
    }

    var fingerprint: Data {
        var hash = SHA256()
        hash.update(data: evidenceSeal)
        for range in ranges {
            var offset = range.offset.bigEndian
            var count = UInt64(range.expected.count).bigEndian
            withUnsafeBytes(of: &offset) { hash.update(bufferPointer: $0) }
            withUnsafeBytes(of: &count) { hash.update(bufferPointer: $0) }
            hash.update(data: range.expected)
        }
        return Data(hash.finalize())
    }
}

/// Simulation-only ownership. No real target identity or reservation provider exists yet.
struct SimulatedRecoveryBinding: Sendable, Equatable {
    let mediaID: UUID
    let ownerID: UUID
    let ownershipEpoch: UInt64
    /// Must increase for every content mutation, including writes by the same owner.
    let contentRevision: UInt64
    let byteCount: UInt64
    let blockSize: UInt32

    init(
        mediaID: UUID, ownerID: UUID, ownershipEpoch: UInt64,
        contentRevision: UInt64 = 0, byteCount: UInt64, blockSize: UInt32
    ) {
        self.mediaID = mediaID
        self.ownerID = ownerID
        self.ownershipEpoch = ownershipEpoch
        self.contentRevision = contentRevision
        self.byteCount = byteCount
        self.blockSize = blockSize
    }

    /// Identity/ownership is bound before writes; revision is sampled when verification starts.
    func hasSameOrigin(as other: Self) -> Bool {
        mediaID == other.mediaID && ownerID == other.ownerID
            && ownershipEpoch == other.ownershipEpoch && byteCount == other.byteCount
            && blockSize == other.blockSize && other.contentRevision >= contentRevision
    }
}

protocol SimulatedRecoveryMedia: Sendable {
    func observation() async throws -> SimulatedRecoveryBinding
    /// Fence ownership and revision throughout each operation; never reuse either after ABA.
    func read(offset: UInt64, length: Int, under binding: SimulatedRecoveryBinding) async throws
        -> Data
    func synchronize(under binding: SimulatedRecoveryBinding) async throws -> UUID
}

struct SimulatedRecoveryReceipt: Sendable {
    let incidentID: UUID
    let generation: UInt64
    let planFingerprint: Data
    let binding: SimulatedRecoveryBinding
    let checkedBytes: UInt64
    let barrierID: UUID
    var simulatedOnly: Bool { true }
    var normalIOReopened: Bool { false }
    var higherLayerDirtyCoverageEstablished: Bool { false }
}

enum SimulatedRecoveryVerifier {
    static func verify(
        _ plan: MutationRecoveryPlan, binding: SimulatedRecoveryBinding,
        media: any SimulatedRecoveryMedia,
        maximumReadBytes: Int = 65_536
    ) async throws -> SimulatedRecoveryReceipt {
        guard maximumReadBytes >= Int(plan.blockSize), maximumReadBytes <= 65_536,
            maximumReadBytes % Int(plan.blockSize) == 0
        else {
            throw MutationRecoveryIssue.invalidReadLimit
        }
        guard binding.byteCount == plan.byteCount, binding.blockSize == plan.blockSize else {
            throw MutationRecoveryIssue.wrongContext
        }
        guard let origin = plan.simulatedOrigin, origin.hasSameOrigin(as: binding) else {
            throw MutationRecoveryIssue.wrongContext
        }
        func checkBinding() async throws {
            guard try await media.observation() == binding else {
                throw MutationRecoveryIssue.bindingChanged
            }
        }
        try Task.checkCancellation()
        try await checkBinding()
        var checked: UInt64 = 0
        for range in plan.ranges {
            var cursor = 0
            while cursor < range.expected.count {
                try Task.checkCancellation()
                try await checkBinding()
                let count = min(maximumReadBytes, range.expected.count - cursor)
                let bytes = try await media.read(
                    offset: range.offset + UInt64(cursor), length: count, under: binding)
                try await checkBinding()
                let start = range.expected.startIndex + cursor
                guard bytes.count == count,
                    bytes == Data(range.expected[start..<(start + count)])
                else {
                    throw MutationRecoveryIssue.readMismatch
                }
                checked += UInt64(count)
                cursor += count
            }
        }
        try Task.checkCancellation()
        try await checkBinding()
        let barrier = try await media.synchronize(under: binding)
        try await checkBinding()
        try Task.checkCancellation()
        return SimulatedRecoveryReceipt(
            incidentID: plan.incidentID, generation: plan.generation,
            planFingerprint: plan.fingerprint, binding: binding, checkedBytes: checked,
            barrierID: barrier)
    }
}
