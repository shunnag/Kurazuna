import Foundation

/// A bounded transport name for immutable connection metadata shared by the app and extension.
/// The full descriptor remains the journal format and the source of the resource identity.
public struct ConnectionResourceReference: Sendable, Equatable {
    public let mountID: UUID
    public let identity: Data

    public init(descriptor: ConnectionDescriptor) throws {
        guard let mountID = descriptor.mountID else {
            throw ProtocolError.malformed("mount resource reference")
        }
        self.mountID = mountID
        identity = try descriptor.resourceIdentity
    }

    public init(url: URL) throws {
        let parts = url.path.split(separator: "/", omittingEmptySubsequences: false)
        guard url.absoluteString.utf8.count == 121, parts.count == 3, parts[0].isEmpty,
            let mountID = UUID(uuidString: String(parts[1])), parts[2].utf8.count == 64,
            parts[2].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw ProtocolError.malformed("mount resource reference") }
        self.mountID = mountID
        var bytes = Data()
        let hex = Array(parts[2])
        for index in stride(from: 0, to: hex.count, by: 2) {
            guard let byte = UInt8(String(hex[index...index + 1]), radix: 16) else {
                throw ProtocolError.malformed("mount resource reference")
            }
            bytes.append(byte)
        }
        identity = bytes
        // Reject alternate hosts, user info, escaping, case, queries, ports and fragments.
        guard url.absoluteString == self.url.absoluteString else {
            throw ProtocolError.malformed("mount resource reference")
        }
    }

    public var url: URL {
        // All components are fixed ASCII or validated UUID/digest bytes.
        URL(string: "\(ConnectionDescriptor.scheme)://mount/\(account)")!
    }

    public var account: String {
        mountID.uuidString.lowercased() + "/"
            + identity.map { String(format: "%02x", $0) }.joined()
    }

    public func validate(_ descriptor: ConnectionDescriptor) throws {
        guard try Self(descriptor: descriptor) == self else {
            throw ProtocolError.malformed("mount resource binding")
        }
    }
}

extension ConnectionDescriptor {
    /// Legacy full URLs and bounded references bind to exactly the same logical resource.
    public func acceptsResourceURL(_ url: URL) -> Bool {
        if let reference = try? ConnectionResourceReference(url: url) {
            return (try? reference.validate(self)) != nil
        }
        return (try? Self(resourceURL: url)) == self
    }
}
