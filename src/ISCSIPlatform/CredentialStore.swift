import CryptoKit
import Foundation
import ISCSICore
import Security

public struct CredentialContext: Sendable, Codable, Equatable {
    public enum Use: String, Sendable, Codable { case connection, discovery }
    public let profileID: UUID
    public let portal: Portal
    public let username: String
    public let credentialID: UUID?
    public let targetUsername: String?
    public let use: Use

    public init(
        profileID: UUID, portal: Portal, username: String, credentialID: UUID? = nil,
        targetUsername: String? = nil, use: Use = .connection
    ) {
        self.profileID = profileID
        self.portal = portal
        self.username = username
        self.credentialID = credentialID
        self.targetUsername = targetUsername
        self.use = use
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let username = try c.decode(String.self, forKey: .username)
        guard !username.isEmpty, username.utf8.count <= 223,
            username.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
        else {
            throw ProtocolError.malformed("CHAP username")
        }
        let targetUsername = try c.decodeIfPresent(String.self, forKey: .targetUsername)
        if let targetUsername {
            guard !targetUsername.isEmpty, targetUsername.utf8.count <= 223,
                targetUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else { throw ProtocolError.malformed("mutual CHAP username") }
        }
        self.init(
            profileID: try c.decode(UUID.self, forKey: .profileID),
            portal: try c.decode(Portal.self, forKey: .portal), username: username,
            credentialID: try c.decodeIfPresent(UUID.self, forKey: .credentialID),
            targetUsername: targetUsername,
            use: try c.decodeIfPresent(Use.self, forKey: .use) ?? .connection)
    }

    /// Binding the account to the server prevents a modified resource URL from reusing a
    /// saved password against another endpoint. Usernames remain case-sensitive.
    public var account: String {
        var parts = [
            profileID.uuidString.lowercased(), portal.host.lowercased(), String(portal.port),
            username,
        ]
        // Preserve the original account hash for existing profiles and mounted resource URLs.
        if let credentialID { parts.append(credentialID.uuidString.lowercased()) }
        if use == .discovery { parts.append("discovery") }
        if let targetUsername { parts += ["mutual", targetUsername] }
        let value = parts.joined(separator: "\0")
        return SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public protocol CredentialStore: Sendable {
    func save(password: String, context: CredentialContext) async throws
    func save(password: String, targetPassword: String, context: CredentialContext) async throws
    func credentials(context: CredentialContext) async throws -> CHAPCredentials
    func remove(context: CredentialContext) async throws
    func copyCredentials(from source: CredentialContext, to destination: CredentialContext)
        async throws
}

extension CredentialStore {
    public func copyCredentials(from source: CredentialContext, to destination: CredentialContext)
        async throws
    {
        throw ProtocolError.unsupported("credential copy")
    }

    public func save(password: String, targetPassword: String, context: CredentialContext)
        async throws
    {
        throw ProtocolError.unsupported("mutual CHAP credential storage")
    }
}

public actor KeychainCredentialStore: CredentialStore {
    private let accessGroup: String?
    private let identity: ApplicationIdentity

    public init(accessGroup: String?, identity: ApplicationIdentity = .current) {
        self.accessGroup = accessGroup
        self.identity = identity
    }

    public static func sharedForCurrentBundle() -> KeychainCredentialStore {
        let group =
            Bundle.main.object(forInfoDictionaryKey: "ISCSISharedKeychainAccessGroup") as? String
        return KeychainCredentialStore(accessGroup: group)
    }

    public func save(password: String, context: CredentialContext) throws {
        guard context.targetUsername == nil else {
            throw ProtocolError.malformed("mutual CHAP credentials")
        }
        _ = try CHAPCredentials(username: context.username, password: password)
        try save(data: Data(password.utf8), context: context)
    }

    public func save(password: String, targetPassword: String, context: CredentialContext)
        async throws
    {
        guard context.targetUsername != nil else {
            throw ProtocolError.malformed("mutual CHAP credentials")
        }
        _ = try CHAPCredentials(
            username: context.username, password: password,
            targetUsername: context.targetUsername, targetPassword: targetPassword)
        try save(
            data: JSONEncoder().encode(
                StoredPair(password: password, targetPassword: targetPassword)),
            context: context)
    }

    private struct StoredPair: Codable {
        let password: String
        let targetPassword: String
    }

    private func save(data: Data, context: CredentialContext) throws {
        let query = try query(for: context)
        let attributes: [String: Any] = [kSecValueData as String: data]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item.merge(attributes) { _, new in new }
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw error(status) }
    }

    public func credentials(context: CredentialContext) throws -> CHAPCredentials {
        try decode(data: credentialData(context: context), context: context)
    }

    /// Copy inside the store so callers never need access to either secret.
    public func copyCredentials(from source: CredentialContext, to destination: CredentialContext)
        async throws
    {
        guard source.profileID == destination.profileID,
            source.username == destination.username,
            source.targetUsername == destination.targetUsername,
            source.use == .connection, destination.use == .connection,
            destination.credentialID != nil, source.account != destination.account
        else { throw ProtocolError.malformed("credential copy context") }
        let data = try credentialData(context: source)
        _ = try decode(data: data, context: source)
        try save(data: data, context: destination)
    }

    private func credentialData(context: CredentialContext) throws -> Data {
        var query = try query(for: context)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw error(status) }
        guard let data = result as? Data, data.count <= 16384 else {
            throw ProtocolError.malformed("saved CHAP credential")
        }
        return data
    }

    private func decode(data: Data, context: CredentialContext) throws -> CHAPCredentials {
        if context.targetUsername != nil {
            let pair = try JSONDecoder().decode(StoredPair.self, from: data)
            return try CHAPCredentials(
                username: context.username, password: pair.password,
                targetUsername: context.targetUsername, targetPassword: pair.targetPassword)
        }
        guard let password = String(data: data, encoding: .utf8) else {
            throw ProtocolError.malformed("saved CHAP credential")
        }
        return try CHAPCredentials(username: context.username, password: password)
    }

    public func remove(context: CredentialContext) throws {
        let status = SecItemDelete(try query(for: context) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw error(status) }
    }

    private func query(for context: CredentialContext) throws -> [String: Any] {
        try Self.query(for: context, accessGroup: accessGroup, identity: identity)
    }

    static func query(
        for context: CredentialContext, accessGroup: String?, identity: ApplicationIdentity
    ) throws -> [String: Any] {
        guard let accessGroup, identity.permitsKeychainGroup(accessGroup)
        else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecMissingEntitlement))
        }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identity.credentialService,
            kSecAttrAccount as String: context.account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}
