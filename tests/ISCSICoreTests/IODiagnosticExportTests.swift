import Foundation
import Testing

@testable import ISCSICore

private final class ExportLines: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.withLock { lines.append(line) } }
    var values: [String] { lock.withLock { lines } }
    var summaries: [IODiagnostics.ExportSummary] {
        values.compactMap {
            try? JSONDecoder().decode(IODiagnostics.ExportSummary.self, from: Data($0.utf8))
        }
    }
}

@Test func ioDiagnosticFinalOrdinarySummaryReportsTheBudgetItConsumes() async throws {
    let lines = ExportLines()
    let exporter = IODiagnostics.Exporter(eventLimit: 3, automaticDrain: false, sink: lines.append)
    let recorder = IODiagnostics.Recorder(layer: .volume)
    #expect(exporter.register(recorder))
    await IODiagnostics.withOperation(.read, recorder: recorder) { _ in }
    let result = await exporter.flush()
    #expect(result.allCurrentSummariesAttempted)
    #expect(lines.values.count == 3)
    let summary = try #require(lines.summaries.last)
    #expect(summary.eventExportBudgetExhausted)
    #expect(!summary.collectorDeliveryVerified)
}

@Test func ioDiagnosticRetainedCauseKeepsItsBackendAttemptAfterPrefixExhaustion() async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk, capacity: 1)
    let cause = UUID()
    let failure = ProtocolError.scsiFailure(status: 2, sense: Data())
    do {
        try await IODiagnostics.withOperation(.synchronize, recorder: recorder) { trace in
            _ = await IODiagnostics.backend(.synchronize10, trace: trace) { _ in 0 }
            try await IODiagnostics.backend(.synchronize16, trace: trace) { attempt in
                trace?.retainMutationFailure(id: cause, error: failure, originatingAttempt: attempt)
                throw failure
            }
        }
        Issue.record("Expected backend failure")
    } catch { #expect(error as? ProtocolError == failure) }
    let snapshot = recorder.snapshot()
    #expect(snapshot.summary.retainedMutationCause?.id == cause)
    #expect(snapshot.summary.retainedMutationCause?.backendKind == .synchronize16)
    #expect(snapshot.summary.retainedMutationCause?.backendAttemptID != nil)
    #expect(snapshot.summary.activeOperations == 0)
    #expect(snapshot.summary.integrityValid)
    #expect(snapshot.events.count == 1 && snapshot.summary.suppressedEvents > 0)
}

@Test func ioDiagnosticForeignBackendAttemptInvalidatesTheDiagnosticClaim() async {
    let first = IODiagnostics.Recorder(layer: .remoteDisk)
    let other = IODiagnostics.Recorder(layer: .remoteDisk)
    let foreign = await IODiagnostics.withOperation(.read, recorder: first) { trace in
        await IODiagnostics.backend(.read, trace: trace) { $0 }
    }
    await IODiagnostics.withOperation(.write, recorder: other) { trace in
        trace?.retainMutationFailure(
            id: UUID(), error: POSIXError(.EIO), originatingAttempt: foreign)
    }
    let snapshot = other.snapshot()
    #expect(!snapshot.summary.integrityValid)
    #expect(snapshot.summary.invalidRecords == 1)
    #expect(snapshot.summary.retainedMutationCause == nil)
    #expect(
        snapshot.summary.attemptedEvents == UInt64(snapshot.summary.admittedEvents)
            + snapshot.summary.invalidRecords)
}

@Test func ioDiagnosticLateCauseHasReservedOutputButNeverRestoresCompleteness() async {
    let lines = ExportLines()
    let exporter = IODiagnostics.Exporter(eventLimit: 1, automaticDrain: false, sink: lines.append)
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    #expect(exporter.register(recorder))
    await IODiagnostics.withOperation(.read, recorder: recorder) { _ in }
    let first = await exporter.flush()
    #expect(!first.allCurrentSummariesAttempted)
    let cause = UUID()
    await IODiagnostics.withOperation(.write, recorder: recorder) { trace in
        trace?.retainMutationFailure(id: cause, error: POSIXError(.EIO))
    }
    let final = await exporter.flush()
    await exporter.flush()
    #expect(!final.allCurrentSummariesAttempted && !final.collectorDeliveryVerified)
    #expect(lines.summaries.count == 1)
    #expect(lines.summaries.last?.summary.retainedMutationCause?.id == cause)
    #expect(lines.summaries.last?.eventExportBudgetExhausted == true)
    #expect(lines.summaries.last?.collectorDeliveryVerified == false)
    #expect((lines.summaries.last?.pendingCapturedEvents ?? 0) > 0)
    #expect(lines.values.count == 3)  // One ordinary record, one warning, one reserved cause.
}

@Test func ioDiagnosticExportUsesBoundedBatchesAndDeclaresPendingRecords() async throws {
    let lines = ExportLines()
    let exporter = IODiagnostics.Exporter(automaticDrain: false, sink: lines.append)
    let recorder = IODiagnostics.Recorder(layer: .volume)
    #expect(exporter.register(recorder))
    for _ in 0..<100 { await IODiagnostics.withOperation(.read, recorder: recorder) { _ in } }
    let heldSnapshot = recorder.snapshot()
    await exporter.flush()
    let first = try #require(lines.summaries.last)
    #expect(first.eventSequenceThrough == 64)
    #expect(first.pendingCapturedEvents == 136)
    for _ in 0..<3 { await exporter.flush() }
    let final = try #require(lines.summaries.last)
    #expect(final.eventSequenceThrough == 200 && final.pendingCapturedEvents == 0)
    #expect(final.summary.activeOperations == 0 && final.summary.suppressedEvents == 0)
    await IODiagnostics.withOperation(.write, recorder: recorder) { _ in }
    #expect(heldSnapshot.events.count == 200)
    #expect(recorder.snapshot().events.count == 202)
}
