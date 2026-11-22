import Foundation

public struct Portal: Sendable, Equatable, Hashable, Codable, CustomStringConvertible {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16 = 3260) throws {
        guard !host.isEmpty, port != 0, host.utf8.count <= 253,
            !host.contains(where: { $0.isWhitespace || $0.isNewline }),
            !host.contains("/"), !host.contains("@"), !host.contains("["), !host.contains("]"),
            host.utf8.allSatisfy({ $0 >= 33 && $0 != 127 }),
            !host.contains("?"), !host.contains("#"), !host.contains("=")
        else { throw ProtocolError.malformed("server address") }
        self.host = host
        self.port = port
    }

    public init(_ address: String) throws {
        if address.hasPrefix("[") {
            guard let closing = address.firstIndex(of: "]") else {
                throw ProtocolError.malformed("IPv6 address")
            }
            let host = String(address[address.index(after: address.startIndex)..<closing])
            let suffix = String(address[address.index(after: closing)...])
            if suffix.isEmpty {
                try self.init(host: host)
            } else {
                guard suffix.hasPrefix(":"), let port = UInt16(suffix.dropFirst()) else {
                    throw ProtocolError.malformed("server port")
                }
                try self.init(host: host, port: port)
            }
        } else {
            let parts = address.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count <= 2 else {
                throw ProtocolError.malformed("enclose IPv6 addresses in brackets")
            }
            if parts.count == 2 {
                guard let port = UInt16(parts[1]) else {
                    throw ProtocolError.malformed("server port")
                }
                try self.init(host: String(parts[0]), port: port)
            } else {
                try self.init(host: address)
            }
        }
    }

    public var description: String { "\(host.contains(":") ? "[\(host)]" : host):\(port)" }

    /// DNS names and hexadecimal address text ignore case; IPv6 zone identifiers do not.
    public func isSameEndpoint(as other: Portal) -> Bool {
        func normalized(_ host: String) -> String {
            let parts = host.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
            return parts[0].lowercased() + (parts.count == 2 ? "%" + String(parts[1]) : "")
        }
        return port == other.port && normalized(host) == normalized(other.host)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            host: container.decode(String.self, forKey: .host),
            port: container.decode(UInt16.self, forKey: .port))
    }
}
