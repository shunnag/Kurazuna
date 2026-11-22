import Foundation
import ISCSICore

/// Public authentication metadata; secrets remain in the credential store.
public struct CHAPIdentity: Codable, Sendable, Equatable {
    public let username: String
    public let targetUsername: String?
    public let credentialID: UUID?

    public init(username: String, targetUsername: String? = nil, credentialID: UUID? = nil) throws {
        guard !username.isEmpty, username.utf8.count <= 223,
            username.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
        else { throw ProtocolError.malformed("CHAP username") }
        if let targetUsername {
            guard !targetUsername.isEmpty, targetUsername.utf8.count <= 223,
                targetUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else { throw ProtocolError.malformed("mutual CHAP username") }
        }
        self.username = username
        self.targetUsername = targetUsername
        self.credentialID = credentialID
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            username: c.decode(String.self, forKey: .username),
            targetUsername: c.decodeIfPresent(String.self, forKey: .targetUsername),
            credentialID: c.decodeIfPresent(UUID.self, forKey: .credentialID))
    }

    public func context(profileID: UUID, portal: Portal, use: CredentialContext.Use)
        -> CredentialContext
    {
        CredentialContext(
            profileID: profileID, portal: portal, username: username,
            credentialID: credentialID, targetUsername: targetUsername, use: use)
    }
}

public enum DiscoveryAuthentication: Sendable, Equatable, Codable {
    case sameAsConnection
    case none
    case chap(CHAPIdentity)

    private enum Method: String, Codable { case sameAsConnection, none, chap }
    private enum CodingKeys: String, CodingKey { case method, identity }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(Method.self, forKey: .method) {
        case .sameAsConnection: self = .sameAsConnection
        case .none: self = .none
        case .chap: self = .chap(try c.decode(CHAPIdentity.self, forKey: .identity))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .sameAsConnection: try c.encode(Method.sameAsConnection, forKey: .method)
        case .none: try c.encode(Method.none, forKey: .method)
        case .chap(let identity):
            try c.encode(Method.chap, forKey: .method)
            try c.encode(identity, forKey: .identity)
        }
    }
}
