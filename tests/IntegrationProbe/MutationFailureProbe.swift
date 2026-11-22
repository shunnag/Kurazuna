import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork

/// Exercises production volume callbacks against the independent target's rejection.
/// This does not mount a filesystem or establish kernel error propagation.
enum MutationFailureProbe {
    static func run(disk: RemoteDisk, session: ISCSISession, operation: String) async throws {
        guard operation == "write" || operation == "synchronize" else {
            throw ProtocolError.invalidState
        }
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        let (item, _) = try await (volume as any FSVolume.Operations).lookupItem(
            named: FSFileName(string: LUNImageVolume.imageName), inDirectory: volume.rootItem)
        let stateName = FSFileName(string: ConnectionDescriptor.connectionStateAttributeName)
        guard
            try await volume.xattr(named: stateName, of: volume.rootItem)
                == DiskConnectionState.connected.encoded
        else { throw ProtocolError.malformed("initial disk health") }
        try await volume.openItem(item, modes: .write)
        if operation == "synchronize" {
            // Acknowledged but not flushed: a flush with nothing to make durable isn't sent.
            try await disk.write(offset: 0, data: Data(repeating: 0x6C, count: 512))
        }
        try await expectIOFailure {
            if operation == "write" {
                _ = try await volume.write(
                    contents: Data(repeating: 0x6D, count: 512), to: item, at: 0)
            } else {
                try await volume.synchronize(flags: .wait)
            }
        }
        guard await session.state == .ready else {
            throw ProtocolError.malformed("rejection unexpectedly closed the session")
        }
        for subject in [volume.rootItem, item] {
            guard
                try await volume.xattr(named: stateName, of: subject)
                    == DiskConnectionState.interrupted.encoded
            else { throw ProtocolError.malformed("failed disk reported a healthy connection") }
        }
        try await expectIOFailure {
            _ = try await volume.write(
                contents: Data(repeating: 0x7E, count: 512), to: item, at: 512)
        }
        try await expectIOFailure { try await volume.synchronize(flags: .wait) }
        try await expectIOFailure { try await volume.closeItem(item, modes: []) }
        try await expectIOFailure { try await volume.openItem(item, modes: .write) }
        do {
            _ = try await disk.read(offset: 0, length: 512)
            throw ProtocolError.malformed("read admitted after failed mutation")
        } catch ProtocolError.invalidState {}
        // The rejecting fixture waits for EOF and rejects every extra wire request.
        // Close explicitly after checking all callbacks, then finish volume teardown.
        await session.close()
        await volume.shutdown()
        guard
            try await volume.xattr(named: stateName, of: volume.rootItem)
                == DiskConnectionState.closed.encoded
        else { throw ProtocolError.malformed("retired disk did not close") }
        print("PASS: rejected \(operation), interrupted state, later I/O blocked before transport")
    }

    private static func expectIOFailure(_ body: () async throws -> Void) async throws {
        do {
            try await body()
            throw ProtocolError.malformed("failed mutation reported success")
        } catch let error as POSIXError where error.code == .EIO {}
    }
}
