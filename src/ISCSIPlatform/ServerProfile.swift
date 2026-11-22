import CryptoKit
import Foundation
import ISCSICore

public struct ServerProfile: Codable, Identifiable, Sendable, Equatable {
    private enum CodingKeys: String, CodingKey {
        case id, name, portal, chapUsername, targetCHAPUsername, credentialID,
            discoveryAuthentication
    }
    public let id: UUID
    public let name: String
    public let portal: Portal
    public let chapUsername: String?
    public let targetCHAPUsername: String?
    public let credentialID: UUID?
    public let discoveryAuthentication: DiscoveryAuthentication

    /// Keep saved and editable names intact while exposing controls in object labels.
    /// Joining controls, variation selectors and ordinary RTL text retain their meaning.
    public var displayName: String {
        var scalars = String.UnicodeScalarView()
        for scalar in name.unicodeScalars {
            if scalar.properties.generalCategory == .control || scalar.properties.isBidiControl {
                let hex = String(scalar.value, radix: 16, uppercase: true)
                let padding = String(repeating: "0", count: max(0, 4 - hex.count))
                scalars.append(contentsOf: "[U+\(padding)\(hex)]".unicodeScalars)
            } else {
                scalars.append(scalar)
            }
        }
        return String(scalars)
    }

    public init(
        id: UUID = UUID(), name: String, portal: Portal, chapUsername: String? = nil,
        credentialID: UUID? = nil, targetCHAPUsername: String? = nil,
        discoveryAuthentication: DiscoveryAuthentication = .sameAsConnection
    ) throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 80, !name.contains(where: { $0.isNewline }),
            !name.utf8.contains(0)
        else {
            throw ProtocolError.malformed("server name")
        }
        guard credentialID == nil || chapUsername != nil else {
            throw ProtocolError.malformed("credential reference without CHAP")
        }
        if let chapUsername {
            guard !chapUsername.isEmpty, chapUsername.utf8.count <= 223,
                chapUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else {
                throw ProtocolError.malformed("CHAP username")
            }
        }
        if let targetCHAPUsername {
            guard chapUsername != nil, !targetCHAPUsername.isEmpty,
                targetCHAPUsername.utf8.count <= 223,
                targetCHAPUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else { throw ProtocolError.malformed("mutual CHAP username") }
        }
        self.id = id
        self.name = name
        self.portal = portal
        self.chapUsername = chapUsername
        self.targetCHAPUsername = targetCHAPUsername
        self.credentialID = credentialID
        self.discoveryAuthentication = discoveryAuthentication
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: c.decode(UUID.self, forKey: .id), name: c.decode(String.self, forKey: .name),
            portal: c.decode(Portal.self, forKey: .portal),
            chapUsername: c.decodeIfPresent(String.self, forKey: .chapUsername),
            credentialID: c.decodeIfPresent(UUID.self, forKey: .credentialID),
            targetCHAPUsername: c.decodeIfPresent(String.self, forKey: .targetCHAPUsername),
            discoveryAuthentication: c.decodeIfPresent(
                DiscoveryAuthentication.self, forKey: .discoveryAuthentication) ?? .sameAsConnection
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(portal, forKey: .portal)
        try c.encodeIfPresent(chapUsername, forKey: .chapUsername)
        try c.encodeIfPresent(targetCHAPUsername, forKey: .targetCHAPUsername)
        try c.encodeIfPresent(credentialID, forKey: .credentialID)
        if discoveryAuthentication != .sameAsConnection {
            try c.encode(discoveryAuthentication, forKey: .discoveryAuthentication)
        }
    }

    public var credentialContext: CredentialContext? {
        chapUsername.map {
            CredentialContext(
                profileID: id, portal: portal, username: $0,
                credentialID: credentialID, targetUsername: targetCHAPUsername)
        }
    }

    public var discoveryCredentialContext: CredentialContext? {
        switch discoveryAuthentication {
        case .sameAsConnection: credentialContext
        case .none: nil
        case .chap(let identity): identity.context(profileID: id, portal: portal, use: .discovery)
        }
    }

    public var credentialContexts: [CredentialContext] {
        var result = credentialContext.map { [$0] } ?? []
        if case .chap(let identity) = discoveryAuthentication {
            result.append(identity.context(profileID: id, portal: portal, use: .discovery))
        }
        return result
    }
}

public struct InitiatorIdentity: Codable, Sendable, Equatable {
    public let name: String
    public let seed: [UInt8]

    public init(name: String, seed: [UInt8]) throws {
        _ = try LoginConfiguration(initiatorName: name, isid: seed)
        self.name = name
        self.seed = seed
    }

    public static func makeNew() throws -> Self {
        try Self(
            name: "iqn.2026-10.dev.soba:\(UUID().uuidString.lowercased())",
            seed: [0x80] + (0..<5).map { _ in UInt8.random(in: .min ... .max) })
    }

    /// Separate LUN connections must not reinstate each other's sessions at the target.
    public func isid(targetName: String, lun: LogicalUnit) -> [UInt8] {
        var input = Data(seed)
        input.append(contentsOf: targetName.utf8)
        input.append(contentsOf: lun.wireBytes)
        return [0x80] + Array(SHA256.hash(data: input).prefix(5))
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            name: c.decode(String.self, forKey: .name), seed: c.decode([UInt8].self, forKey: .seed))
    }
}

public struct ProfileDocument: Codable, Sendable, Equatable {
    public let version: Int
    public let identity: InitiatorIdentity
    public var servers: [ServerProfile]
    public var pendingCredentialRemovals: [CredentialContext]
    public var permanentRedirects: [SavedPermanentRedirect]
    public var handledMountRedirects: [UUID]

    public init(
        identity: InitiatorIdentity, servers: [ServerProfile] = [],
        pendingCredentialRemovals: [CredentialContext] = [],
        permanentRedirects: [SavedPermanentRedirect] = [], handledMountRedirects: [UUID] = []
    ) throws {
        guard servers.count <= 128, Set(servers.map(\.id)).count == servers.count else {
            throw ProtocolError.malformed("duplicate or excessive server profiles")
        }
        let pending = pendingCredentialRemovals.map(\.account)
        let current = Set(servers.flatMap(\.credentialContexts).map(\.account))
        guard pending.count <= 256, Set(pending).count == pending.count,
            current.isDisjoint(with: pending)
        else {
            throw ProtocolError.malformed("pending credential removals")
        }
        for context in pendingCredentialRemovals {
            _ = try ServerProfile(
                id: context.profileID, name: "Credential", portal: context.portal,
                chapUsername: context.username, credentialID: context.credentialID,
                targetCHAPUsername: context.targetUsername)
        }
        guard permanentRedirects.count <= 64 else {
            throw ProtocolError.limitExceeded("saved permanent redirects")
        }
        var checked: [SavedPermanentRedirect] = []
        for saved in permanentRedirects {
            guard servers.contains(where: { $0.id == saved.profileID }),
                !checked.contains(where: { $0.isSameKey(as: saved) })
            else { throw ProtocolError.malformed("saved permanent redirect scope") }
            checked.append(saved)
        }
        guard handledMountRedirects.count <= 128,
            Set(handledMountRedirects).count == handledMountRedirects.count
        else {
            throw ProtocolError.malformed("mounted redirect receipts")
        }
        if !handledMountRedirects.isEmpty {
            self.version = 6
        } else if !permanentRedirects.isEmpty {
            self.version = 5
        } else if servers.contains(where: { $0.discoveryAuthentication != .sameAsConnection })
            || pendingCredentialRemovals.contains(where: { $0.use == .discovery })
        {
            self.version = 4
        } else {
            self.version =
                servers.contains { $0.targetCHAPUsername != nil }
                    || pendingCredentialRemovals.contains { $0.targetUsername != nil } ? 3 : 2
        }
        self.identity = identity
        self.servers = servers
        self.pendingCredentialRemovals = pendingCredentialRemovals
        self.permanentRedirects = permanentRedirects
        self.handledMountRedirects = handledMountRedirects
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let version = try c.decode(Int.self, forKey: .version)
        guard [1, 2, 3, 4, 5, 6].contains(version) else {
            throw ProtocolError.unsupported("profile document version")
        }
        let saved =
            try c.decodeIfPresent([SavedPermanentRedirect].self, forKey: .permanentRedirects) ?? []
        guard saved.isEmpty || version >= 5 else {
            throw ProtocolError.malformed("saved permanent redirect version")
        }
        let handled = try c.decodeIfPresent([UUID].self, forKey: .handledMountRedirects) ?? []
        guard handled.isEmpty || version == 6 else {
            throw ProtocolError.malformed("mounted redirect receipt version")
        }
        try self.init(
            identity: c.decode(InitiatorIdentity.self, forKey: .identity),
            servers: c.decode([ServerProfile].self, forKey: .servers),
            pendingCredentialRemovals: c.decodeIfPresent(
                [CredentialContext].self,
                forKey: .pendingCredentialRemovals) ?? [], permanentRedirects: saved,
            handledMountRedirects: handled)
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(identity, forKey: .identity)
        try values.encode(servers, forKey: .servers)
        try values.encode(pendingCredentialRemovals, forKey: .pendingCredentialRemovals)
        if !permanentRedirects.isEmpty {
            try values.encode(permanentRedirects, forKey: .permanentRedirects)
        }
        if !handledMountRedirects.isEmpty {
            try values.encode(handledMountRedirects, forKey: .handledMountRedirects)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case version, identity, servers, pendingCredentialRemovals, permanentRedirects,
            handledMountRedirects
    }
}
