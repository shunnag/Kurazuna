import Foundation
import ISCSICore
import OSLog

/// A trace accepts only generated identifiers, enums and numbers, never disk paths,
/// server descriptors, device descriptions or text supplied by an OS error.
enum DiskEjectionDiagnostics {
    enum Phase: String, Codable, Sendable {
        case begin, submitted, callback, rejected, deadline, finished
    }

    enum Operation: String, Codable, Sendable { case unmount, eject }

    enum Outcome: String, Codable, Sendable {
        case pending, success, alreadyUnmounted, busy, failed, cancelled, timedOut, posix, other
    }

    struct Event: Codable, Equatable, Sendable {
        let requestID: UUID
        let phase: Phase
        let force: Bool
        let targetCount: Int
        let operation: Operation?
        let targetIndex: Int?
        let status: UInt32?
        let outcome: Outcome
        let errorCode: Int
        let awaitingReply: Bool?

        var fields: String {
            "request=\(requestID.uuidString) event=\(phase.rawValue) force=\(force ? 1 : 0) "
                + "targets=\(targetCount) operation=\(operation?.rawValue ?? "none") "
                + "index=\(targetIndex ?? -1) status=\(status.map { String(format: "0x%08x", $0) } ?? "none") "
                + "outcome=\(outcome.rawValue) code=\(errorCode) "
                + "awaiting=\(awaitingReply.map { $0 ? "1" : "0" } ?? "none")"
        }
    }

    typealias Observer = @Sendable (Event) -> Void

    struct Trace: Sendable {
        let id: UUID
        let force: Bool
        let targetCount: Int
        let observer: Observer

        init(
            id: UUID = UUID(), force: Bool, targetCount: Int,
            observer: @escaping Observer = DiskEjectionDiagnostics.log
        ) {
            self.id = id
            self.force = force
            self.targetCount = targetCount
            self.observer = observer
        }

        func record(
            _ phase: Phase, operation: Operation? = nil, targetIndex: Int? = nil,
            status: UInt32? = nil, outcome: Outcome = .pending, errorCode: Int = 0,
            awaitingReply: Bool? = nil
        ) {
            observer(
                Event(
                    requestID: id, phase: phase, force: force, targetCount: targetCount,
                    operation: operation, targetIndex: targetIndex, status: status,
                    outcome: outcome, errorCode: errorCode, awaitingReply: awaitingReply))
        }
    }

    static func failure(_ error: any Error) -> (Outcome, Int) {
        if error is CancellationError { return (.cancelled, 0) }
        if case ProtocolError.timedOut = error { return (.timedOut, 0) }
        if let error = error as? POSIXError {
            return (error.code == .EBUSY ? .busy : .posix, Int(error.code.rawValue))
        }
        return (.other, 0)
    }

    private static let logger = Logger(subsystem: "dev.soba.iscsi", category: "DiskEjection")

    static func log(_ event: Event) {
        logger.notice("DiskEjection \(event.fields, privacy: .public)")
    }
}
