import Foundation

/// Volatile I/O health, independent of whether DiskImages is still attached.
public enum DiskConnectionState: UInt8, Sendable, CaseIterable {
    case unknown = 0
    case connected = 1
    case interrupted = 2
    case closed = 3
    /// The connection was lost and is being reestablished. I/O waits instead of failing.
    case reconnecting = 4

    public var encoded: Data { Data([1, rawValue]) }

    public init(encoded: Data) throws {
        guard encoded.count == 2, encoded.first == 1,
            let state = Self(rawValue: encoded[encoded.startIndex + 1])
        else { throw ProtocolError.malformed("connection state attribute") }
        self = state
    }
}
