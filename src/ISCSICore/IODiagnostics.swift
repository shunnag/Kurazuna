import Darwin
import Foundation
import OSLog

/// Optional diagnostic capture. Records contain generated identities and closed enums only.
/// A snapshot describes instrumented boundaries; it does not prove kernel dispatch or log delivery.
public enum IODiagnostics {
    public static let bindingAttributeName = "dev.soba.iscsi.ioDiagnostics"
    public enum Layer: String, Codable, Sendable { case volume, remoteDisk }
    public enum Operation: String, Codable, Sendable {
        case readCallback, read, write, synchronize, close
    }
    public enum Stage: String, Codable, Sendable {
        case entered, validated, gateWaiting, gateAcquired, backendBegin, backendEnd
        case rejected, retainedMutationRejected, mutationFailureRetained, finished
    }
    /// Lifecycle, backend and retention transitions belong to their structured wrappers.
    public enum Checkpoint: String, Codable, Sendable {
        case validated, gateWaiting, gateAcquired, rejected, retainedMutationRejected
        fileprivate var stage: Stage {
            switch self {
            case .validated: .validated
            case .gateWaiting: .gateWaiting
            case .gateAcquired: .gateAcquired
            case .rejected: .rejected
            case .retainedMutationRejected: .retainedMutationRejected
            }
        }
    }
    public enum Detail: String, Codable, Sendable {
        case none, read, write, synchronize, synchronize10, synchronize16
        case cancelled, closing, cacheBarrier
    }
    public enum Outcome: String, Codable, Sendable {
        case pending, success, cancelled, posix, protocolFailure, other
    }
    public enum ProtocolCategory: String, Codable, Sendable {
        case malformed, unsupported, limitExceeded, digestMismatch, invalidState, busy
        case connectionClosed, timedOut, localNetworkAccessRequired, loginRejected
        case loginRedirect, authenticationFailed, targetEvent, scsiFailure
    }

    public struct Result: Codable, Equatable, Sendable {
        public let outcome: Outcome
        public let code: Int32?
        public let protocolCategory: ProtocolCategory?

        public static let pending = Self(outcome: .pending, code: nil, protocolCategory: nil)
        public static let success = Self(outcome: .success, code: nil, protocolCategory: nil)

        public static func failure(_ error: any Error) -> Self {
            if error is CancellationError {
                return Self(outcome: .cancelled, code: nil, protocolCategory: nil)
            }
            if let error = error as? POSIXError {
                return Self(
                    outcome: error.code == .ECANCELED ? .cancelled : .posix,
                    code: error.code.rawValue, protocolCategory: nil)
            }
            if let error = error as? ProtocolError {
                let category: ProtocolCategory =
                    switch error {
                    case .malformed: .malformed
                    case .unsupported: .unsupported
                    case .limitExceeded: .limitExceeded
                    case .digestMismatch: .digestMismatch
                    case .invalidState: .invalidState
                    case .busy: .busy
                    case .connectionClosed: .connectionClosed
                    case .timedOut: .timedOut
                    case .localNetworkAccessRequired: .localNetworkAccessRequired
                    case .loginRejected: .loginRejected
                    case .loginRedirect: .loginRedirect
                    case .authenticationFailed: .authenticationFailed
                    case .targetEvent: .targetEvent
                    case .scsiFailure: .scsiFailure
                    }
                return Self(outcome: .protocolFailure, code: nil, protocolCategory: category)
            }
            return Self(outcome: .other, code: nil, protocolCategory: nil)
        }
    }

    public struct Event: Codable, Equatable, Sendable {
        public let schemaVersion: Int
        public let processInstanceID: UUID
        public let processID: Int32
        public let recorderID: UUID
        public let scopeID: UUID
        public let layer: Layer
        public let sequence: UInt64
        public let observedTicks: UInt64
        public let publicationTicks: UInt64
        public let operationID: UUID
        public let parentScopeID: UUID?
        public let parentOperationID: UUID?
        public let parentBackendAttemptID: UUID?
        public let operation: Operation
        public let stage: Stage
        public let detail: Detail
        public let backendAttemptID: UUID?
        public let retainedCauseID: UUID?
        public let result: Result
    }

    public struct RetainedCause: Codable, Equatable, Sendable {
        public let id: UUID
        public let operationID: UUID
        public let backendAttemptID: UUID?
        public let backendKind: Detail?
        public let observedTicks: UInt64
        public let publicationTicks: UInt64
        public let result: Result
    }

    public struct Summary: Codable, Equatable, Sendable {
        public let schemaVersion: Int
        public let processInstanceID: UUID
        public let processID: Int32
        public let recorderID: UUID
        public let scopeID: UUID
        public let layer: Layer
        public let clockDomain: String
        public let timebaseNumerator: UInt32
        public let timebaseDenominator: UInt32
        public let publicationTicks: UInt64
        public let attemptedEvents: UInt64
        public let admittedEvents: Int
        public let suppressedEvents: UInt64
        public let invalidRecords: UInt64
        public let integrityValid: Bool
        public let activeOperations: UInt64
        public let countersSaturated: Bool
        public let retainedMutationCause: RetainedCause?
    }

    public struct Snapshot: Sendable {
        public let summary: Summary
        public let events: [Event]
    }

    public struct BackendAttempt: Sendable {
        public let id: UUID
        public let kind: Detail
        fileprivate let operationID: UUID
        fileprivate let recorderID: UUID
    }

    struct ExportSummary: Codable, Sendable {
        enum Purpose: String, Codable, Sendable { case periodic, checkpoint, retainedCause }
        let purpose: Purpose
        let summary: Summary
        let eventSequenceThrough: UInt64
        let pendingCapturedEvents: Int
        let eventExportBudgetExhausted: Bool
        let collectorDeliveryVerified: Bool
    }

    fileprivate struct Context: Sendable {
        let scopeID: UUID
        let operationID: UUID
        let backendAttemptID: UUID?
    }
    @TaskLocal private static var context: Context?
    private static let processInstanceID = UUID()
    private static let processID = getpid()
    private static let timebase: mach_timebase_info_data_t = {
        var value = mach_timebase_info_data_t()
        mach_timebase_info(&value)
        return value
    }()

    public final class Recorder: @unchecked Sendable {
        public let id = UUID()
        public let scopeID: UUID
        public let layer: Layer
        public let capacity: Int
        private let lock = NSLock()
        // Optional slots never escape. A public snapshot owns a distinct Event array,
        // so a slow exporter cannot force a copy-on-write allocation on capture.
        private var slots: [Event?]
        private var admitted = 0
        private var attempted: UInt64 = 0
        private var suppressed: UInt64 = 0
        private var active: UInt64 = 0
        private var saturated = false
        private var invalid: UInt64 = 0
        private var integrityValid = true
        private var retainedCause: RetainedCause?
        private var activeRetainedCauseID: UUID?

        public init(layer: Layer, scopeID: UUID = UUID(), capacity: Int = 1024) {
            self.layer = layer
            self.scopeID = scopeID
            self.capacity = max(1, min(capacity, 4096))
            slots = Array(repeating: nil, count: self.capacity)
        }

        public var retainedMutationCauseID: UUID? { lock.withLock { retainedCause?.id } }

        /// A verified service transition retires active rejection, preserving the original
        /// cause and all events. Diagnostics never grants or reconstructs recovery authority.
        @_spi(StorageRecovery)
        public func finishVerifiedMutationRecovery(incidentID: UUID) {
            lock.withLock {
                guard activeRetainedCauseID == incidentID else { return }
                activeRetainedCauseID = nil
            }
        }

        /// Immutable producer identity, without copying captured events or accepting input.
        public var binding: Binding {
            Binding(
                version: 1, processInstanceID: IODiagnostics.processInstanceID,
                processID: IODiagnostics.processID, recorderID: id, scopeID: scopeID,
                layer: layer, capacity: capacity)
        }

        public func snapshot() -> Snapshot {
            snapshot(after: 0, limit: capacity)
        }

        fileprivate func snapshot(after sequence: UInt64, limit: Int) -> Snapshot {
            lock.withLock {
                var low = 0
                var high = admitted
                while low < high {
                    let middle = low + (high - low) / 2
                    if let event = slots[middle], event.sequence <= sequence {
                        low = middle + 1
                    } else {
                        high = middle
                    }
                }
                let end = min(admitted, low + max(1, min(limit, 4096)))
                let copied = slots[low..<end].compactMap { $0 }
                return Snapshot(
                    summary: Summary(
                        schemaVersion: 1, processInstanceID: processInstanceID,
                        processID: processID,
                        recorderID: id,
                        scopeID: scopeID, layer: layer,
                        clockDomain: "mach_absolute_time",
                        timebaseNumerator: timebase.numer, timebaseDenominator: timebase.denom,
                        publicationTicks: mach_absolute_time(), attemptedEvents: attempted,
                        admittedEvents: admitted, suppressedEvents: suppressed,
                        invalidRecords: invalid, integrityValid: integrityValid,
                        activeOperations: active, countersSaturated: saturated,
                        retainedMutationCause: retainedCause),
                    events: copied)
            }
        }

        private func increment(_ value: inout UInt64) {
            if value < .max { value += 1 } else { saturated = true }
        }

        fileprivate func capture(
            trace: Trace, stage: Stage, detail: Detail = .none,
            attemptID: UUID? = nil, causeID: UUID? = nil, result: Result = .pending,
            retainMutation: Bool = false, originatingAttempt: BackendAttempt? = nil
        ) {
            // Observation precedes lock acquisition; sequence orders publication, not observation.
            let observed = mach_absolute_time()
            lock.withLock {
                let published = mach_absolute_time()
                if stage == .entered { increment(&active) }
                if stage == .finished {
                    if active > 0 { active -= 1 } else { saturated = true }
                }
                if retainMutation, let originatingAttempt,
                    originatingAttempt.operationID != trace.operationID
                        || originatingAttempt.recorderID != id
                {
                    increment(&attempted)
                    increment(&invalid)
                    integrityValid = false
                    return
                }
                if retainMutation, activeRetainedCauseID != nil {
                    increment(&attempted)
                    increment(&invalid)
                    integrityValid = false
                    // Preserve the first cause and refuse a second causal publication.
                    return
                }
                if retainMutation, let causeID {
                    activeRetainedCauseID = causeID
                    let cause = RetainedCause(
                        id: causeID, operationID: trace.operationID,
                        backendAttemptID: originatingAttempt?.id,
                        backendKind: originatingAttempt?.kind, observedTicks: observed,
                        publicationTicks: published, result: result)
                    if retainedCause == nil { retainedCause = cause }
                }
                guard attempted < .max else {
                    saturated = true
                    increment(&suppressed)
                    return
                }
                attempted += 1
                guard admitted < capacity else {
                    increment(&suppressed)
                    return
                }
                slots[admitted] = Event(
                    schemaVersion: 1, processInstanceID: processInstanceID, processID: processID,
                    recorderID: id,
                    scopeID: scopeID, layer: layer, sequence: attempted,
                    observedTicks: observed, publicationTicks: published,
                    operationID: trace.operationID,
                    parentScopeID: trace.parent?.scopeID,
                    parentOperationID: trace.parent?.operationID,
                    parentBackendAttemptID: trace.parent?.backendAttemptID,
                    operation: trace.operation, stage: stage, detail: detail,
                    backendAttemptID: attemptID, retainedCauseID: causeID, result: result)
                admitted += 1
            }
        }
    }

    public struct Trace: Sendable {
        public let operationID = UUID()
        public let operation: Operation
        fileprivate let recorder: Recorder
        fileprivate let parent: Context?

        public func record(
            _ stage: Checkpoint, detail: Detail = .none, causeID: UUID? = nil,
            error: (any Error)? = nil
        ) {
            recorder.capture(
                trace: self, stage: stage.stage, detail: detail, causeID: causeID,
                result: error.map(Result.failure) ?? .pending)
        }

        /// Call only after the existing product latch's first false-to-true transition,
        /// outside its mutex and before releasing the existing product I/O gate.
        public func retainMutationFailure(
            id: UUID, error: any Error, originatingAttempt: BackendAttempt? = nil
        ) {
            recorder.capture(
                trace: self, stage: .mutationFailureRetained,
                detail: originatingAttempt?.kind ?? .none,
                attemptID: originatingAttempt?.id, causeID: id,
                result: .failure(error), retainMutation: true,
                originatingAttempt: originatingAttempt)
        }

        public func backend<Value: Sendable>(
            _ kind: Detail, _ body: @Sendable (BackendAttempt) async throws -> Value
        ) async rethrows -> Value {
            let attempt = BackendAttempt(
                id: UUID(), kind: kind, operationID: operationID, recorderID: recorder.id)
            recorder.capture(trace: self, stage: .backendBegin, detail: kind, attemptID: attempt.id)
            return try await $context.withValue(
                Context(
                    scopeID: recorder.scopeID, operationID: operationID,
                    backendAttemptID: attempt.id)
            ) {
                do {
                    let value = try await body(attempt)
                    recorder.capture(
                        trace: self, stage: .backendEnd, detail: kind, attemptID: attempt.id,
                        result: .success)
                    return value
                } catch {
                    recorder.capture(
                        trace: self, stage: .backendEnd, detail: kind, attemptID: attempt.id,
                        result: .failure(error))
                    throw error
                }
            }
        }
    }

    public static func withOperation<Value: Sendable>(
        _ operation: Operation, recorder: Recorder?,
        _ body: @Sendable (Trace?) async throws -> Value
    ) async rethrows -> Value {
        guard let recorder else { return try await body(nil) }
        let trace = Trace(operation: operation, recorder: recorder, parent: context)
        recorder.capture(trace: trace, stage: .entered)
        return try await $context.withValue(
            Context(
                scopeID: recorder.scopeID, operationID: trace.operationID, backendAttemptID: nil)
        ) {
            do {
                let value = try await body(trace)
                recorder.capture(trace: trace, stage: .finished, result: .success)
                return value
            } catch {
                recorder.capture(trace: trace, stage: .finished, result: .failure(error))
                throw error
            }
        }
    }

    public static func backend<Value: Sendable>(
        _ kind: Detail, trace: Trace?, _ body: @Sendable (BackendAttempt?) async throws -> Value
    ) async rethrows -> Value {
        if let trace { return try await trace.backend(kind) { try await body($0) } }
        return try await body(nil)
    }

    public static func live(layer: Layer, scopeID: UUID = UUID()) -> Recorder? {
        #if ISCSI_IO_DIAGNOSTICS
            let recorder = Recorder(layer: layer, scopeID: scopeID, capacity: 4096)
            return exporter.register(recorder) ? recorder : nil
        #else
            return nil
        #endif
    }

    public struct Binding: Encodable, Sendable, Equatable {
        public let version: Int
        public let processInstanceID: UUID
        public let processID: Int32
        public let recorderID: UUID
        public let scopeID: UUID
        public let layer: Layer
        public let capacity: Int
    }

    #if ISCSI_IO_DIAGNOSTICS
        private static let exporter = Exporter()
    #endif

    /// A stalled sink cannot hold product gates: one serial consumer polls bounded buffers.
    /// Export attempts never establish collector receipt or complete process coverage.
    final class Exporter: @unchecked Sendable {
        private struct Cursor {
            let recorder: Recorder
            var through: UInt64 = 0
            var eventAttempts = 0
            var cause: UUID?
            var summaryBand: UInt64 = .max
        }
        private let lock = NSLock()
        private var registered: [Recorder] = []
        private var registrationRefused = false
        private var cursors: [Cursor] = []  // Serial consumer only, maximum 32.
        private var remaining: Int
        private let maximumRegistered: Int
        private var truncatedPublished = false
        private var registrationWarningPublished = false
        private let timer: DispatchSourceTimer
        private let queue: DispatchQueue
        private let sink: @Sendable (String) -> Void

        init(
            eventLimit: Int = 16_384, registrationLimit: Int = 32,
            automaticDrain: Bool = true, sink: (@Sendable (String) -> Void)? = nil
        ) {
            remaining = max(1, min(eventLimit, 16_384))
            maximumRegistered = max(1, min(registrationLimit, 32))
            let logger = Logger(subsystem: "dev.soba.iscsi", category: "IOBoundaries")
            self.sink =
                sink ?? { line in
                    logger.notice("IOBoundaries \(line, privacy: .public)")
                }
            queue = DispatchQueue(label: "dev.soba.iscsi.io-export")
            timer = DispatchSource.makeTimerSource(queue: queue)
            if automaticDrain {
                timer.schedule(deadline: .now(), repeating: .milliseconds(500))
            }
            timer.setEventHandler { [weak self] in _ = self?.drain(forceSummary: false) }
            timer.resume()
        }

        deinit { timer.cancel() }

        struct FlushResult: Sendable {
            let allCurrentSummariesAttempted: Bool
            let registrationComplete: Bool
            let collectorDeliveryVerified = false
        }

        @discardableResult
        func flush() async -> FlushResult {
            await withCheckedContinuation { reply in
                queue.async { reply.resume(returning: self.drain(forceSummary: true)) }
            }
        }

        func register(_ recorder: Recorder) -> Bool {
            lock.withLock {
                guard registered.count < maximumRegistered else {
                    registrationRefused = true
                    return false
                }
                registered.append(recorder)
                return true
            }
        }

        @discardableResult
        private func emit<Value: Encodable>(_ value: Value) -> Bool {
            guard remaining > 0 else {
                if !truncatedPublished {
                    truncatedPublished = true
                    sink(
                        "process=\(processInstanceID) pid=\(processID) processExportTruncated=1 deliveryVerified=0"
                    )
                }
                return false
            }
            remaining -= 1
            guard let data = try? JSONEncoder().encode(value) else { return false }
            sink(String(decoding: data, as: UTF8.self))
            return true
        }

        private func drain(forceSummary: Bool) -> FlushResult {
            let (records, refused) = lock.withLock { (registered, registrationRefused) }
            if refused && !registrationWarningPublished {
                registrationWarningPublished = true
                sink(
                    "process=\(processInstanceID) pid=\(processID) registrationIncomplete=1 deliveryVerified=0"
                )
            }
            while cursors.count < records.count {
                cursors.append(Cursor(recorder: records[cursors.count]))
            }
            var allSummaries = true
            for index in cursors.indices {
                let snapshot = cursors[index].recorder.snapshot(
                    after: cursors[index].through, limit: 64)
                let before = cursors[index].through
                for event in snapshot.events where event.sequence > cursors[index].through {
                    guard emit(event) else { break }
                    cursors[index].through = event.sequence
                    cursors[index].eventAttempts += 1
                }
                let summary = snapshot.summary
                let band =
                    summary.suppressedEvents == 0
                    ? 0 : UInt64(UInt64.bitWidth - summary.suppressedEvents.leadingZeroBitCount)
                let frame = ExportSummary(
                    purpose: .retainedCause,
                    summary: summary, eventSequenceThrough: cursors[index].through,
                    pendingCapturedEvents: summary.admittedEvents - cursors[index].eventAttempts,
                    eventExportBudgetExhausted: remaining == 0,
                    collectorDeliveryVerified: false)
                if cursors[index].cause != summary.retainedMutationCause?.id,
                    summary.retainedMutationCause != nil
                {
                    // One reserved cause summary per registered recorder (at most 32).
                    // It survives exhaustion of ordinary event outputs. Loss still denies
                    // completeness, even when this cause's export is attempted.
                    if let data = try? JSONEncoder().encode(frame) {
                        sink(String(decoding: data, as: UTF8.self))
                    }
                    cursors[index].cause = summary.retainedMutationCause?.id
                }
                if forceSummary || cursors[index].through != before
                    || cursors[index].summaryBand != band
                    || cursors[index].cause != summary.retainedMutationCause?.id
                {
                    let ordinaryFrame = ExportSummary(
                        purpose: forceSummary ? .checkpoint : .periodic,
                        summary: summary, eventSequenceThrough: cursors[index].through,
                        pendingCapturedEvents: summary.admittedEvents
                            - cursors[index].eventAttempts,
                        eventExportBudgetExhausted: remaining <= 1,
                        collectorDeliveryVerified: false)
                    if !emit(ordinaryFrame) { allSummaries = false }
                    cursors[index].summaryBand = band
                    cursors[index].cause = summary.retainedMutationCause?.id
                }
            }
            return FlushResult(
                allCurrentSummariesAttempted: allSummaries,
                registrationComplete: !refused)
        }
    }
}
