import Foundation

/// RFC 7143 TargetAddress, including its binary-value port and optional portal group.
public struct TargetAddress: Sendable, Equatable {
    public let portal: Portal
    public let portalGroupTag: UInt16?

    public init(portal: Portal, portalGroupTag: UInt16? = nil) {
        self.portal = portal
        self.portalGroupTag = portalGroupTag
    }

    public init(_ value: String) throws {
        let parts = value.split(separator: ",", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { throw ProtocolError.malformed("TargetAddress") }
        let address = String(parts[0])
        let host: String
        let suffix: String?
        if address.hasPrefix("[") {
            guard let end = address.firstIndex(of: "]") else {
                throw ProtocolError.malformed("TargetAddress")
            }
            host = String(address[address.index(after: address.startIndex)..<end])
            let tail = String(address[address.index(after: end)...])
            guard tail.isEmpty || tail.hasPrefix(":") else {
                throw ProtocolError.malformed("TargetAddress")
            }
            suffix = tail.isEmpty ? nil : String(tail.dropFirst())
        } else {
            let endpoint = address.split(separator: ":", omittingEmptySubsequences: false)
            guard (1...2).contains(endpoint.count) else {
                throw ProtocolError.malformed("TargetAddress")
            }
            host = String(endpoint[0])
            suffix = endpoint.count == 2 ? String(endpoint[1]) : nil
        }
        portal = try Portal(host: host, port: suffix.map(Self.binary16) ?? 3260)
        portalGroupTag = try parts.count == 2 ? Self.binary16(String(parts[1])) : nil
    }

    private static func binary16(_ value: String) throws -> UInt16 {
        if value.hasPrefix("0b") || value.hasPrefix("0B") {
            guard let data = Data(base64Encoded: String(value.dropFirst(2))),
                !data.isEmpty, data.count <= 2
            else { throw ProtocolError.malformed("TargetAddress") }
            return data.reduce(0) { ($0 << 8) | UInt16($1) }
        }
        return UInt16(
            try LoginNegotiation.numeric(.init("TargetAddress", value), range: 0...65_535))
    }
}

public struct LoginRedirect: Sendable, Equatable {
    public enum Kind: UInt8, Sendable {
        case temporary = 1
        case permanent = 2
    }
    public let kind: Kind
    public let addresses: [Portal]

    public init(kind: Kind, addresses: [Portal]) throws {
        guard !addresses.isEmpty else { throw ProtocolError.malformed("redirect TargetAddress") }
        guard addresses.count <= 16 else {
            throw ProtocolError.limitExceeded("login redirect addresses")
        }
        self.kind = kind
        self.addresses = addresses
    }

    init(kind: Kind, text: Data) throws {
        guard let parameters = try? TextParameters(data: text) else {
            throw ProtocolError.malformed("redirect TargetAddress")
        }
        let entries = parameters.entries.filter { $0.key == "TargetAddress" }
        guard entries.count <= 16 else {
            throw ProtocolError.limitExceeded("login redirect addresses")
        }
        let addresses = try entries.map { entry in
            guard let address = try? TargetAddress(entry.value) else {
                throw ProtocolError.malformed("redirect TargetAddress")
            }
            guard address.portalGroupTag == nil else {
                throw ProtocolError.malformed("redirect TargetAddress portal group")
            }
            return address.portal
        }
        try self.init(kind: kind, addresses: addresses)
    }
}
