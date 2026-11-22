import Foundation
import OSLog

/// Only generated identifiers, operation names and numeric flags/errors enter a trace.
/// Resource URLs, item names, descriptors and error descriptions are never accepted.
enum VolumeLifecycleDiagnostics {
    enum Operation: String, Codable, Sendable {
        case open, close, synchronize, unmount, deactivate, shutdown
        case cacheOpen, cacheUpgrade, cacheGrant, cacheClose
        case recoverSynchronization
    }

    enum Phase: String, Codable, Sendable { case begin, finished }
    enum Outcome: String, Codable, Sendable { case pending, success, cancelled, posix, other }

    struct Event: Codable, Equatable, Sendable {
        let volumeID: UUID
        let requestID: UUID
        let operation: Operation
        let phase: Phase
        let flags: UInt64
        let outcome: Outcome
        let errorCode: Int

        var fields: String {
            "volume=\(volumeID.uuidString) request=\(requestID.uuidString) "
                + "operation=\(operation.rawValue) event=\(phase.rawValue) flags=\(flags) "
                + "outcome=\(outcome.rawValue) code=\(errorCode)"
        }
    }

    typealias Observer = @Sendable (Event) -> Void

    struct Trace: Sendable {
        let volumeID: UUID
        let requestID = UUID()
        let operation: Operation
        let flags: UInt64
        let observer: Observer

        func record(_ phase: Phase, error: (any Error)? = nil) {
            let result: (Outcome, Int)
            if let error {
                if error is CancellationError {
                    result = (.cancelled, 0)
                } else if let error = error as? POSIXError {
                    result = (
                        error.code == .ECANCELED ? .cancelled : .posix,
                        Int(error.code.rawValue)
                    )
                } else {
                    result = (.other, 0)
                }
            } else {
                result = (phase == .begin ? .pending : .success, 0)
            }
            observer(
                Event(
                    volumeID: volumeID, requestID: requestID, operation: operation,
                    phase: phase, flags: flags, outcome: result.0, errorCode: result.1))
        }
    }

    private static let logger = Logger(subsystem: "dev.soba.iscsi", category: "FSKitLifecycle")

    static func log(_ event: Event) {
        logger.notice("FSKitLifecycle \(event.fields, privacy: .public)")
    }
}
