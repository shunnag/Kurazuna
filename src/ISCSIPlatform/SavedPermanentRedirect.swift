import Foundation
import ISCSICore

/// nil targetName is Discovery; a Normal-session hint belongs to one exact target name.
public struct SavedPermanentRedirect: Codable, Sendable, Equatable {
    public let profileID: UUID
    public let targetName: String?
    public let redirect: PermanentPortalRedirect

    public init(profileID: UUID, targetName: String?, redirect: PermanentPortalRedirect) throws {
        _ = try LoginConfiguration(
            initiatorName: "iqn.2026-10.dev.soba:route-validation", targetName: targetName,
            isid: [0x80, 0, 0, 0, 0, 0])
        self.profileID = profileID
        self.targetName = targetName
        self.redirect = redirect
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            profileID: values.decode(UUID.self, forKey: .profileID),
            targetName: values.decodeIfPresent(String.self, forKey: .targetName),
            redirect: values.decode(PermanentPortalRedirect.self, forKey: .redirect))
    }

    func isSameKey(as other: Self) -> Bool {
        profileID == other.profileID && targetName == other.targetName
            && redirect.source.isSameEndpoint(as: other.redirect.source)
    }
}

extension ProfileDocument {
    public func permanentRedirects(for server: ServerProfile, targetName: String?)
        -> [PermanentPortalRedirect]
    {
        guard servers.contains(server) else { return [] }
        return permanentRedirects.filter {
            $0.profileID == server.id && $0.targetName == targetName
        }.map(\.redirect)
    }
}
