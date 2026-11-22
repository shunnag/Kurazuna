import CryptoKit
import Foundation
import ISCSICore
import Synchronization

enum MutationWriteOutcome: Sendable, Equatable {
    case awaitingResponse, fullyAcknowledged, indeterminate
    case failedResponse(UInt8)
}

struct MutationWriteIntent: Sendable, Equatable {
    let sequence: UInt64
    let offset: UInt64
    let payload: Data
    var outcome: MutationWriteOutcome
}

struct MutationSynchronization: Sendable, Equatable {
    let opcode: UInt8
    let outcome: MutationWriteOutcome
    let sense: SCSISense?

    var isCurrentUnsupported10: Bool {
        opcode == 0x35 && outcome == .failedResponse(2)
            && sense?.isDeferred == false && sense?.key == 5
            && sense?.additionalSenseCode == 0x20 && sense?.qualifier == 0
    }

    static func isSuccessfulBarrier(_ attempts: [Self]) -> Bool {
        guard let last = attempts.last, [UInt8(0x35), 0x91].contains(last.opcode),
            last.outcome == .fullyAcknowledged, last.sense == nil
        else { return false }
        return attempts.count == 1
            || (attempts.count == 2 && attempts[0].isCurrentUnsupported10 && last.opcode == 0x91)
    }
}

struct MutationIncident: Sendable, Equatable {
    /// A read latches only when its retry found that the device no longer matched.
    enum Operation: Sendable, Equatable { case write, synchronize, read }
    let id: UUID
    let generation: UInt64
    let operation: Operation
    let writeSequence: UInt64?
    let status: UInt8
    let sense: SCSISense?

    enum SynchronizationRefusal: String, Sendable {
        case mediumWriteError, targetReportedCommunicationFailure
    }

    var synchronizationRefusal: SynchronizationRefusal? {
        guard operation == .synchronize, writeSequence == nil, status == 2,
            let sense, !sense.isDeferred, sense.qualifier == 0
        else { return nil }
        if sense.key == 3, sense.additionalSenseCode == 0x0C { return .mediumWriteError }
        if sense.key == 2, sense.additionalSenseCode == 8 {
            return .targetReportedCommunicationFailure
        }
        return nil
    }
}

struct MutationBarrier: Sendable, Equatable {
    let id: UUID
    let retiredGeneration: UInt64
    let nextWriteSequence: UInt64
    let attempts: [MutationSynchronization]
}

/// In-memory evidence of submitted physical writes, never a durable journal or all dirty data.
struct MutationEvidence: Sendable, Equatable {
    let diskID: UUID
    let byteCount: UInt64
    let blockSize: UInt32
    var generation: UInt64
    var firstWriteSequence: UInt64
    var nextWriteSequence: UInt64
    var intents: [MutationWriteIntent]
    var coverageComplete: Bool
    var outcomesCertain: Bool
    var pendingWrite: UInt64?
    var incident: MutationIncident?
    var precedingBarrier: MutationBarrier?
    var synchronizationAttempts: [MutationSynchronization]
    var synchronizationHistoryComplete: Bool
    let simulatedOrigin: SimulatedRecoveryBinding?
    let reservedOrigin: ReservedMutationOrigin?
    var serviceGeneration: UInt64
    var seal: Data

    var higherLayerDirtyCoverageEstablished: Bool { false }

    /// A consistency digest, not proof of media identity, exclusivity, or persistence.
    func fingerprint() -> Data {
        var hash = SHA256()
        func number(_ value: UInt64) {
            var encoded = value.bigEndian
            withUnsafeBytes(of: &encoded) { hash.update(bufferPointer: $0) }
        }
        func uuid(_ value: UUID) { hash.update(data: Data(value.uuidString.utf8)) }
        func outcome(_ value: MutationWriteOutcome) {
            switch value {
            case .awaitingResponse: number(0)
            case .fullyAcknowledged: number(1)
            case .indeterminate: number(2)
            case .failedResponse(let status):
                number(3)
                number(UInt64(status))
            }
        }
        func sense(_ value: SCSISense?) {
            guard let value else {
                number(0)
                return
            }
            number(1)
            number(value.isDeferred ? 1 : 0)
            number(UInt64(value.key))
            number(UInt64(value.additionalSenseCode))
            number(UInt64(value.qualifier))
        }
        func attempts(_ values: [MutationSynchronization]) {
            number(UInt64(values.count))
            for value in values {
                number(UInt64(value.opcode))
                outcome(value.outcome)
                sense(value.sense)
            }
        }
        number(1)
        number(serviceGeneration)
        if let reservedOrigin {
            number(1)
            uuid(reservedOrigin.authorityID)
            uuid(reservedOrigin.diskID)
            uuid(reservedOrigin.intentID)
            // These values are validated by acquisition; sorted Codable bytes include every
            // binding field, including LU names, port, session identity and quiescence ID.
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            hash.update(data: (try? encoder.encode(reservedOrigin.binding)) ?? Data())
        } else {
            number(0)
        }
        uuid(diskID)
        number(byteCount)
        number(UInt64(blockSize))
        number(generation)
        number(firstWriteSequence)
        number(nextWriteSequence)
        number(coverageComplete ? 1 : 0)
        number(outcomesCertain ? 1 : 0)
        number(pendingWrite == nil ? 0 : 1)
        number(pendingWrite ?? 0)
        number(UInt64(intents.count))
        for entry in intents {
            number(entry.sequence)
            number(entry.offset)
            number(UInt64(entry.payload.count))
            hash.update(data: entry.payload)
            outcome(entry.outcome)
        }
        if let incident {
            number(1)
            uuid(incident.id)
            number(incident.generation)
            switch incident.operation {
            case .write: number(0)
            case .synchronize: number(1)
            case .read: number(2)
            }
            number(incident.writeSequence == nil ? 0 : 1)
            number(incident.writeSequence ?? 0)
            number(UInt64(incident.status))
            sense(incident.sense)
        } else {
            number(0)
        }
        if let precedingBarrier {
            number(1)
            uuid(precedingBarrier.id)
            number(precedingBarrier.retiredGeneration)
            number(precedingBarrier.nextWriteSequence)
            attempts(precedingBarrier.attempts)
        } else {
            number(0)
        }
        attempts(synchronizationAttempts)
        number(synchronizationHistoryComplete ? 1 : 0)
        if let simulatedOrigin {
            number(1)
            uuid(simulatedOrigin.mediaID)
            uuid(simulatedOrigin.ownerID)
            number(simulatedOrigin.ownershipEpoch)
            number(simulatedOrigin.contentRevision)
            number(simulatedOrigin.byteCount)
            number(UInt64(simulatedOrigin.blockSize))
        } else {
            number(0)
        }
        return Data(hash.finalize())
    }
}

/// Transitions are called under RemoteDisk's I/O gate; snapshots use only this bounded mutex.
final class MutationEvidenceJournal: Sendable {
    struct Recovery: Sendable {
        let original: MutationEvidence
        let planFingerprint: Data
        let checkedBytes: UInt64
        let nextServiceGeneration: UInt64
        let refusal: MutationIncident.SynchronizationRefusal
    }
    private struct State: Sendable {
        var evidence: MutationEvidence
        var retainedBytes = 0
        var recovered: [Recovery] = []
    }
    private let state: Mutex<State>
    private let maximumBytes: Int
    private let maximumIntents: Int

    init(
        byteCount: UInt64, blockSize: UInt32, maximumBytes: Int = 4_194_304,
        maximumIntents: Int = 128, simulatedOrigin: SimulatedRecoveryBinding? = nil,
        reservedOrigin: ReservedMutationOrigin? = nil
    ) {
        self.maximumBytes = max(0, min(maximumBytes, 4_194_304))
        self.maximumIntents = max(0, min(maximumIntents, 128))
        state = Mutex(
            State(
                evidence: MutationEvidence(
                    diskID: reservedOrigin?.diskID ?? UUID(), byteCount: byteCount,
                    blockSize: blockSize, generation: 0,
                    firstWriteSequence: 1, nextWriteSequence: 1, intents: [],
                    coverageComplete: true,
                    outcomesCertain: true, pendingWrite: nil, incident: nil, precedingBarrier: nil,
                    synchronizationAttempts: [], synchronizationHistoryComplete: true,
                    simulatedOrigin: simulatedOrigin, reservedOrigin: reservedOrigin,
                    serviceGeneration: 0, seal: Data())))
    }

    var hasIncident: Bool { state.withLock { $0.evidence.incident != nil } }
    var incidentID: UUID? { state.withLock { $0.evidence.incident?.id } }
    var recoveryHistory: [Recovery] { state.withLock { $0.recovered } }
    var snapshot: MutationEvidence {
        var value = state.withLock { $0.evidence }
        value.seal = value.fingerprint()  // Hashing and diagnostics never hold the journal mutex.
        return value
    }

    func beginWrite(offset: UInt64, payload: Data) -> UInt64? {
        state.withLock { value in
            guard value.evidence.incident == nil else { return nil }
            guard value.evidence.pendingWrite == nil,
                value.evidence.nextWriteSequence < UInt64.max
            else {
                value.evidence.coverageComplete = false
                value.evidence.outcomesCertain = false
                return nil
            }
            let sequence = value.evidence.nextWriteSequence
            value.evidence.nextWriteSequence += 1
            value.evidence.pendingWrite = sequence
            guard !payload.isEmpty, offset <= value.evidence.byteCount,
                UInt64(payload.count) <= value.evidence.byteCount - offset,
                value.evidence.coverageComplete,
                value.evidence.intents.count < maximumIntents,
                payload.count <= maximumBytes - value.retainedBytes
            else {
                value.evidence.coverageComplete = false
                return sequence
            }
            // Detach from a possibly larger Data slice; the retained-byte limit is real.
            let bytes = payload.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
            value.evidence.intents.append(
                MutationWriteIntent(
                    sequence: sequence, offset: offset, payload: bytes, outcome: .awaitingResponse))
            value.retainedBytes += bytes.count
            return sequence
        }
    }

    func finishWrite(_ sequence: UInt64?, outcome: MutationWriteOutcome) {
        state.withLock { value in
            guard value.evidence.incident == nil else { return }
            guard let sequence, value.evidence.pendingWrite == sequence,
                outcome != .awaitingResponse
            else {
                value.evidence.coverageComplete = false
                value.evidence.outcomesCertain = false
                return
            }
            value.evidence.pendingWrite = nil
            if outcome != .fullyAcknowledged { value.evidence.outcomesCertain = false }
            if let index = value.evidence.intents.firstIndex(where: { $0.sequence == sequence }) {
                guard value.evidence.intents[index].outcome == .awaitingResponse else {
                    value.evidence.outcomesCertain = false
                    return
                }
                value.evidence.intents[index].outcome = outcome
            } else {
                value.evidence.coverageComplete = false
            }
        }
    }

    func beginSynchronization() {
        state.withLock { value in
            if value.evidence.incident == nil {
                value.evidence.synchronizationAttempts = []
                value.evidence.synchronizationHistoryComplete = true
            }
        }
    }

    func noteSynchronization(opcode: UInt8, outcome: MutationWriteOutcome, sense: SCSISense?) {
        state.withLock { value in
            guard value.evidence.incident == nil else { return }
            guard [UInt8(0x35), 0x91].contains(opcode),
                value.evidence.synchronizationAttempts.count < 2
            else {
                value.evidence.synchronizationHistoryComplete = false
                return
            }
            value.evidence.synchronizationAttempts.append(
                MutationSynchronization(opcode: opcode, outcome: outcome, sense: sense))
        }
    }

    func completeSynchronization() {
        state.withLock { value in
            guard value.evidence.incident == nil, value.evidence.pendingWrite == nil,
                value.evidence.outcomesCertain,
                value.evidence.synchronizationHistoryComplete,
                MutationSynchronization.isSuccessfulBarrier(value.evidence.synchronizationAttempts),
                value.evidence.generation < UInt64.max
            else { return }
            value.evidence.precedingBarrier = MutationBarrier(
                id: UUID(), retiredGeneration: value.evidence.generation,
                nextWriteSequence: value.evidence.nextWriteSequence,
                attempts: value.evidence.synchronizationAttempts)
            value.evidence.generation += 1
            value.evidence.firstWriteSequence = value.evidence.nextWriteSequence
            value.evidence.intents = []
            value.evidence.coverageComplete = true
            value.evidence.synchronizationAttempts = []
            value.retainedBytes = 0
        }
    }

    func retainFailure(
        operation: MutationIncident.Operation, sequence: UInt64?, status: UInt8,
        sense: SCSISense?
    ) -> MutationIncident? {
        state.withLock { value in
            guard value.evidence.incident == nil else { return nil }
            let incident = MutationIncident(
                id: UUID(), generation: value.evidence.generation, operation: operation,
                writeSequence: sequence, status: status, sense: sense)
            value.evidence.incident = incident
            return incident
        }
    }

    /// Session-authority commit, under RemoteDisk's gate and a continuous control-plane fence.
    /// Original evidence remains immutable and bounded; no public reset operation exists.
    func commitRecovery(
        evidence: MutationEvidence, plan: MutationRecoveryPlan,
        checkedBytes: UInt64, serviceGeneration: UInt64, barrierOpcode: UInt8
    ) throws {
        var current = snapshot
        guard current == evidence, current.reservedOrigin != nil,
            current.simulatedOrigin == nil, current.serviceGeneration == serviceGeneration,
            serviceGeneration < .max, current.generation < .max,
            current.incident?.id == plan.incidentID, current.seal == plan.evidenceSeal,
            [UInt8(0x35), 0x91].contains(barrierOpcode),
            checkedBytes == plan.ranges.reduce(UInt64(0), { $0 + UInt64($1.expected.count) })
        else { throw MutationRecoveryIssue.inconsistentEvidence }
        let record = Recovery(
            original: evidence, planFingerprint: plan.fingerprint,
            checkedBytes: checkedBytes, nextServiceGeneration: serviceGeneration + 1,
            refusal: plan.refusal)
        try state.withLock { value in
            // Hashing stays outside the mutex; the bounded record retains existing Data.
            current.seal = value.evidence.seal
            guard value.evidence == current, value.recovered.count < 8 else {
                throw MutationRecoveryIssue.incompleteEvidence
            }
            value.recovered.append(record)
            value.evidence.precedingBarrier = MutationBarrier(
                id: UUID(), retiredGeneration: value.evidence.generation,
                nextWriteSequence: value.evidence.nextWriteSequence,
                attempts: [
                    MutationSynchronization(
                        opcode: barrierOpcode, outcome: .fullyAcknowledged, sense: nil)
                ])
            value.evidence.generation += 1
            value.evidence.serviceGeneration += 1
            value.evidence.firstWriteSequence = value.evidence.nextWriteSequence
            value.evidence.intents = []
            value.evidence.incident = nil
            value.evidence.synchronizationAttempts = []
            value.retainedBytes = 0
        }
    }
}
