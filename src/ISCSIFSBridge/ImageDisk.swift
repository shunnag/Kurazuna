import Foundation
import ISCSICore
import ISCSINetwork

/// A fixed-capacity disk. Successful writes and synchronization mean target completion.
public protocol ImageDisk: Sendable {
    var capacity: DiskCapacity { get }
    var isReadOnly: Bool { get }
    func read(offset: Int64, length: Int) async throws -> Data
    func write(offset: Int64, data: Data) async throws
    func synchronize() async throws
    func close() async
    func connectionState() async -> DiskConnectionState
    /// Increases each time the connection is reestablished, or the target reports a reset.
    func connectionEpoch() async -> UInt64
    /// Runs `pass`, which writes and then synchronizes, again until one whole pass completed
    /// within a single connection epoch.
    func repeatingWithinOneEpoch<Value: Sendable>(_ pass: @Sendable () async throws -> Value)
        async throws -> Value
    /// Stops reconnecting: waiting I/O fails at once and no further login is attempted.
    func abandonConnectionRecovery() async
}

extension ImageDisk {
    /// A disk without reconnection has a single epoch.
    public func connectionEpoch() async -> UInt64 { 0 }

    public func repeatingWithinOneEpoch<Value: Sendable>(
        _ pass: @Sendable () async throws -> Value
    ) async throws -> Value {
        try await pass()
    }

    public func abandonConnectionRecovery() async {}
}

extension RemoteDisk: ImageDisk {}
