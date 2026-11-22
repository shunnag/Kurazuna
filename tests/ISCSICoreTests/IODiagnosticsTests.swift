import Foundation
import Testing

@testable import ISCSICore

private final class IOLocked<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.withLock { body(&value) }
    }
}

@Test func ioDiagnosticAncestrySurvivesAsyncBackendBoundaries() async throws {
    let bridge = IODiagnostics.Recorder(layer: .volume)
    let remote = IODiagnostics.Recorder(layer: .remoteDisk)
    let value = await IODiagnostics.withOperation(.write, recorder: bridge) { trace in
        trace?.record(.validated)
        return await IODiagnostics.backend(.write, trace: trace) { _ in
            await Task.yield()
            return await IODiagnostics.withOperation(.write, recorder: remote) { child in
                child?.record(.gateWaiting)
                await Task.yield()
                child?.record(.gateAcquired)
                return 42
            }
        }
    }
    #expect(value == 42)
    let parent = bridge.snapshot()
    let child = remote.snapshot()
    let begin = try #require(parent.events.first { $0.stage == .backendBegin })
    let end = try #require(parent.events.first { $0.stage == .backendEnd })
    #expect(begin.backendAttemptID != nil && begin.backendAttemptID == end.backendAttemptID)
    #expect(
        child.events.allSatisfy {
            $0.parentScopeID == bridge.scopeID && $0.parentOperationID == begin.operationID
                && $0.parentBackendAttemptID == begin.backendAttemptID
        })
    #expect(parent.summary.activeOperations == 0 && child.summary.activeOperations == 0)
    #expect(parent.events.allSatisfy { $0.observedTicks <= $0.publicationTicks })
    #expect(parent.summary.clockDomain == "mach_absolute_time")
    #expect(parent.summary.processID == ProcessInfo.processInfo.processIdentifier)
    #expect(parent.events.allSatisfy { $0.processID == parent.summary.processID })
    #expect(parent.summary.timebaseNumerator > 0 && parent.summary.timebaseDenominator > 0)
}

@Test func ioDiagnosticBudgetNeverDiscardsTheRetainedMutationCause() async {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk, capacity: 3)
    let cause = UUID()
    await IODiagnostics.withOperation(.write, recorder: recorder) { trace in
        for _ in 0..<10 { trace?.record(.validated) }
        trace?.retainMutationFailure(
            id: cause, error: ProtocolError.scsiFailure(status: 2, sense: Data()))
    }
    let value = recorder.snapshot()
    #expect(value.events.count == 3)
    #expect(value.summary.attemptedEvents == 13)
    #expect(value.summary.suppressedEvents == 10)
    #expect(value.summary.activeOperations == 0)
    #expect(value.summary.retainedMutationCause?.id == cause)
    #expect(value.summary.retainedMutationCause?.result.protocolCategory == .scsiFailure)
    #expect(!value.events.contains { $0.stage == .mutationFailureRetained })
    #expect(recorder.retainedMutationCauseID == cause)
}

@Test func ioDiagnosticOrdinaryErrorsNeverBecomeRetainedMutationCauses() async {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    for error: any Error in [
        POSIXError(.EINVAL), CancellationError(),
        ProtocolError.scsiFailure(status: 2, sense: Data()),
    ] {
        do {
            try await IODiagnostics.withOperation(.read, recorder: recorder) { _ in throw error }
        } catch {}
    }
    #expect(recorder.retainedMutationCauseID == nil)
    #expect(recorder.snapshot().summary.activeOperations == 0)
    #expect(recorder.snapshot().events.filter { $0.stage == .finished }.count == 3)
}

private struct PrivateDiagnosticError: LocalizedError {
    let touched: IOLocked<Int>
    var errorDescription: String? {
        touched.withLock { $0 += 1 }
        return "private-password-private-host"
    }
}

@Test func ioDiagnosticsNeverSerializeErrorTextOrAssociatedData() async throws {
    let touched = IOLocked(0)
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let secret = "private-password-private-host"
    let errors: [any Error] = [
        PrivateDiagnosticError(touched: touched),
        ProtocolError.malformed(secret), ProtocolError.unsupported(secret),
        ProtocolError.scsiFailure(status: 2, sense: Data(secret.utf8)),
        NSError(domain: secret, code: 900, userInfo: [NSLocalizedDescriptionKey: secret]),
    ]
    for error in errors {
        do {
            try await IODiagnostics.withOperation(.write, recorder: recorder) { _ in throw error }
        } catch {}
    }
    for event in recorder.snapshot().events {
        let encoded = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
        #expect(!encoded.contains(secret))
    }
    #expect(touched.withLock { $0 } == 0)
}

@Test func ioDiagnosticsTrackConcurrentWorkWithoutAnUnboundedOperationMap() async {
    let recorder = IODiagnostics.Recorder(layer: .volume, capacity: 4096)
    await withTaskGroup(of: Void.self) { group in
        for _ in 0..<100 {
            group.addTask {
                await IODiagnostics.withOperation(.read, recorder: recorder) { trace in
                    trace?.record(.gateWaiting)
                    await Task.yield()
                    trace?.record(.gateAcquired)
                }
            }
        }
    }
    let snapshot = recorder.snapshot()
    #expect(snapshot.summary.activeOperations == 0)
    #expect(snapshot.summary.attemptedEvents == 400)
    #expect(snapshot.events.map(\.sequence) == Array(1...400))
    #expect(Set(snapshot.events.map(\.operationID)).count == 100)
    #expect(!snapshot.summary.countersSaturated)
    #expect(snapshot.events.allSatisfy { $0.observedTicks <= $0.publicationTicks })
}

@Test func ioDiagnosticsReportAlreadyActiveOperationsAtACheckpoint() async {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    await IODiagnostics.withOperation(.read, recorder: recorder) { _ in
        #expect(recorder.snapshot().summary.activeOperations == 1)
    }
    #expect(recorder.snapshot().summary.activeOperations == 0)
}

@Test func ioDiagnosticsDisabledPreservesErrorsAndDoesNotInventATrace() async {
    let expected = ProtocolError.malformed("untouched-error")
    do {
        try await IODiagnostics.withOperation(.read, recorder: nil) { trace in
            #expect(trace == nil)
            throw expected
        }
        Issue.record("Expected original error")
    } catch { #expect(error as? ProtocolError == expected) }
}

@Test func ioDiagnosticExporterHasFiniteRegistrationAndOutputBudgets() async {
    let lines = IOLocked<[String]>([])
    let exporter = IODiagnostics.Exporter(
        eventLimit: 2, registrationLimit: 1, automaticDrain: false,
        sink: { line in lines.withLock { $0.append(line) } })
    let recorder = IODiagnostics.Recorder(layer: .volume)
    #expect(exporter.register(recorder))
    #expect(!exporter.register(IODiagnostics.Recorder(layer: .remoteDisk)))
    await IODiagnostics.withOperation(.read, recorder: recorder) { trace in
        trace?.record(.validated)
    }
    await exporter.flush()
    await exporter.flush()
    let values = lines.withLock { $0 }
    #expect(values.count == 4)  // Two attempts plus two fixed loss warnings.
    #expect(values.filter { $0.contains("processExportTruncated=1") }.count == 1)
    #expect(values.filter { $0.contains("registrationIncomplete=1") }.count == 1)
}

@Test func ioDiagnosticBlockedOrReentrantExporterCannotBlockCapture() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let entered = DispatchSemaphore(value: 0)
    let released = DispatchSemaphore(value: 0)
    let once = IOLocked(false)
    let exporter = IODiagnostics.Exporter(automaticDrain: false) { _ in
        // Reentrant snapshot must not contend with a lock held by capture/export.
        _ = recorder.snapshot()
        if once.withLock({ value in
            if value { return false }
            value = true
            return true
        }) {
            entered.signal()
            _ = released.wait(timeout: .now() + 3)
        }
    }
    #expect(exporter.register(recorder))
    await IODiagnostics.withOperation(.read, recorder: recorder) { _ in }
    let flushing = Task { await exporter.flush() }
    defer { released.signal() }
    let ready: Bool = await withCheckedContinuation { reply in
        DispatchQueue.global().async {
            reply.resume(returning: entered.wait(timeout: .now() + 2) == .success)
        }
    }
    #expect(ready)
    await IODiagnostics.withOperation(.write, recorder: recorder) { trace in
        trace?.retainMutationFailure(id: UUID(), error: POSIXError(.EIO))
    }
    #expect(recorder.snapshot().summary.activeOperations == 0)
    #expect(recorder.retainedMutationCauseID != nil)
    released.signal()
    _ = await flushing.value
}

@Test func ioDiagnosticManualFinishMustNotClaimTheRunningBodyIsQuiescent() async {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    await IODiagnostics.withOperation(.read, recorder: recorder) { trace in
        #expect(IODiagnostics.Checkpoint(rawValue: "finished") == nil)
        #expect(IODiagnostics.Checkpoint(rawValue: "entered") == nil)
        #expect(IODiagnostics.Checkpoint(rawValue: "backendBegin") == nil)
        #expect(IODiagnostics.Checkpoint(rawValue: "mutationFailureRetained") == nil)
        let snapshot = recorder.snapshot()
        #expect(snapshot.summary.activeOperations == 1)
        #expect(!snapshot.summary.countersSaturated)
    }
}

@Test func ioDiagnosticFlushMustExportCurrentCountsAfterPrefixExhaustion() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume, capacity: 1)
    let lines = IOLocked<[String]>([])
    let exporter = IODiagnostics.Exporter(automaticDrain: false) { line in
        lines.withLock { $0.append(line) }
    }
    #expect(exporter.register(recorder))
    await IODiagnostics.withOperation(.read, recorder: recorder) { trace in
        for _ in 0..<4 { trace?.record(.validated) }
        await exporter.flush()
    }
    await exporter.flush()
    let summaries = lines.withLock { $0 }.compactMap { line in
        try? JSONDecoder().decode(IODiagnostics.ExportSummary.self, from: Data(line.utf8))
    }
    #expect(summaries.last?.summary.activeOperations == 0)
    #expect(summaries.last?.summary.suppressedEvents == 5)
}

@Test func ioDiagnosticConflictingRetentionMustNotPublishASecondCausalClaim() async {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let first = UUID()
    await IODiagnostics.withOperation(.write, recorder: recorder) { trace in
        trace?.retainMutationFailure(id: first, error: POSIXError(.EIO))
        trace?.retainMutationFailure(id: UUID(), error: POSIXError(.EIO))
    }
    let value = recorder.snapshot()
    #expect(value.summary.retainedMutationCause?.id == first)
    #expect(!value.summary.integrityValid && value.summary.invalidRecords == 1)
    #expect(
        value.events.filter { $0.stage == .mutationFailureRetained }.map(\.retainedCauseID) == [
            first
        ])
}

@Test func ioDiagnosticLiveFactoryRequiresExplicitBuildOptIn() {
    let requested = ProcessInfo.processInfo.environment["ISCSI_IO_DIAGNOSTICS"] == "1"
    let recorder = IODiagnostics.live(layer: .volume)
    #expect((recorder != nil) == requested)
    if requested { #expect(recorder?.capacity == 4096) }
}
