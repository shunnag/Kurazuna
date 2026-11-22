import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

@Test(arguments: [false, true], [false, true])
func discoveryCredentialAccountsAreSeparatedWhileConnectionAccountsRemainStable(
    _ discovery: Bool, _ mutual: Bool
) throws {
    let context = CredentialContext(
        profileID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        portal: try Portal("NAS.LOCAL"), username: "User",
        credentialID: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
        targetUsername: mutual ? "Server" : nil, use: discovery ? .discovery : .connection)
    // Independent SHA-256 vectors retain the version56 connection account bytes.
    let expected =
        discovery
        ? (mutual
            ? "1a71acbebc566dfa0390fc3f4bbbd88e961f2559f1fe8856f1452988b3d625b5"
            : "afd795785991dd78077d6dfb2c999c44bb967639be710bc21ce46e7c62e2591a")
        : (mutual
            ? "8a91cf35ca991ce039e889723d85086760ee0bc410941be553985a225086300d"
            : "d5386552ab00afe0bafc7f96926c0841a2ea5f3e53f0bce7b67ebac1be25131b")
    #expect(context.account == expected)
    #expect(
        try JSONDecoder().decode(CredentialContext.self, from: JSONEncoder().encode(context))
            == context)
}

@Test func legacyCredentialsAndProfilesKeepInheritedDiscoveryAuthentication() throws {
    let context = CredentialContext(
        profileID: UUID(), portal: try Portal("nas.local"), username: "User")
    var reference = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(context)) as? [String: Any])
    reference.removeValue(forKey: "use")
    let old = try JSONDecoder().decode(
        CredentialContext.self, from: JSONSerialization.data(withJSONObject: reference))
    #expect(old.use == .connection && old.account == context.account)
    let server = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), chapUsername: "User")
    let encoded = try JSONEncoder().encode(server)
    let fields = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(fields["discoveryAuthentication"] == nil)
    let restored = try JSONDecoder().decode(ServerProfile.self, from: encoded)
    #expect(restored.discoveryAuthentication == .sameAsConnection)
    #expect(restored.discoveryCredentialContext == restored.credentialContext)
}

@Test(arguments: ["method", "username", "targetUsername", "role"])
func malformedDiscoveryAuthenticationMetadataIsRejected(_ fault: String) throws {
    let identity = try CHAPIdentity(
        username: "Search", targetUsername: "Server", credentialID: UUID())
    let discovery = DiscoveryAuthentication.chap(identity)
    if fault == "role" {
        let context = identity.context(
            profileID: UUID(), portal: try Portal("nas.local"), use: .discovery)
        var fields = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(context)) as? [String: Any])
        fields["use"] = "unknown"
        let data = try JSONSerialization.data(withJSONObject: fields)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(CredentialContext.self, from: data)
        }
    } else {
        var fields = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(discovery)) as? [String: Any])
        if fault == "method" {
            fields["method"] = "unknown"
        } else {
            var value = try #require(fields["identity"] as? [String: Any])
            value[fault] = "\n"
            fields["identity"] = value
        }
        let data = try JSONSerialization.data(withJSONObject: fields)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(DiscoveryAuthentication.self, from: data)
        }
    }
}

@Test func currentDiscoveryCredentialsCannotAlsoBePendingRemoval() throws {
    let identity = try CHAPIdentity(username: "Search", credentialID: UUID())
    let server = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), discoveryAuthentication: .chap(identity))
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(
            identity: .makeNew(), servers: [server],
            pendingCredentialRemovals: server.credentialContexts)
    }
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    #expect(document.version == 4)
    #expect(
        try JSONDecoder().decode(ProfileDocument.self, from: JSONEncoder().encode(document))
            == document)
}
