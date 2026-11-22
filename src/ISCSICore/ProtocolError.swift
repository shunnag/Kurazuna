import Foundation

public enum ProtocolError: Error, Equatable, Sendable {
    case malformed(String)
    case unsupported(String)
    case limitExceeded(String)
    case digestMismatch
    case invalidState
    case busy
    case connectionClosed
    case timedOut
    case localNetworkAccessRequired
    case loginRejected(statusClass: UInt8, detail: UInt8)
    case loginRedirect(LoginRedirect)
    case authenticationFailed
    case targetEvent(UInt8)
    case scsiFailure(status: UInt8, sense: Data)
}

extension ProtocolError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformed(let detail): "Invalid iSCSI response: \(detail)"
        case .unsupported(let detail): "Unsupported iSCSI setting: \(detail)"
        case .limitExceeded(let detail): "iSCSI limit exceeded: \(detail)"
        case .digestMismatch: "The data integrity check failed."
        case .invalidState: "The connection is not ready."
        case .busy: "Another operation is in progress."
        case .connectionClosed: "The server closed the connection."
        case .timedOut: "The server did not respond in time."
        case .localNetworkAccessRequired: "Local network access is required."
        case .loginRejected(let statusClass, let detail):
            "The server rejected the connection (\(statusClass):\(detail))."
        case .loginRedirect: "The server redirected the connection."
        case .authenticationFailed: "Server authentication failed."
        case .targetEvent(let event):
            "The server reported an iSCSI event (\(event)) and the connection ended."
        case .scsiFailure(let status, _): "The disk returned an error (\(status))."
        }
    }
}
