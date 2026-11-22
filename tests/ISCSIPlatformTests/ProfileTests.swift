import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

@Test func firstLaunchPersistsIdentityBeforeAServerIsAdded() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
    let first = try store.loadOrCreate()
    let second = try store.loadOrCreate()
    #expect(first.identity == second.identity)
    #expect(second.servers.isEmpty)
    try Data("invalid settings".utf8).write(to: store.url)
    #expect(throws: DecodingError.self) { try store.loadOrCreate() }
    #expect(try Data(contentsOf: store.url) == Data("invalid settings".utf8))
}

@Test func keychainAccountsAreBoundToProfileServerPortAndUser() throws {
    let id = UUID()
    let context = CredentialContext(
        profileID: id, portal: try Portal("nas.local"), username: "User")
    #expect(
        context.account
            == CredentialContext(profileID: id, portal: try Portal("NAS.LOCAL"), username: "User")
            .account)
    #expect(
        context.account
            != CredentialContext(profileID: id, portal: try Portal("other.local"), username: "User")
            .account)
    #expect(
        context.account
            != CredentialContext(
                profileID: id, portal: try Portal("nas.local:3261"), username: "User"
            ).account)
    #expect(
        context.account
            != CredentialContext(
                profileID: UUID(), portal: try Portal("nas.local"), username: "User"
            ).account)
    #expect(
        context.account
            != CredentialContext(profileID: id, portal: try Portal("nas.local"), username: "user")
            .account)
}

@Test func persistedIdentityIsStableAndSeparatesLUNSessions() throws {
    let identity = try InitiatorIdentity.makeNew()
    let copy = try JSONDecoder().decode(
        InitiatorIdentity.self, from: JSONEncoder().encode(identity))
    #expect(identity == copy)
    let first = identity.isid(targetName: "iqn.2026-10.test:disk", lun: try LogicalUnit(0))
    #expect(first == copy.isid(targetName: "iqn.2026-10.test:disk", lun: try LogicalUnit(0)))
    #expect(first != identity.isid(targetName: "iqn.2026-10.test:disk", lun: try LogicalUnit(1)))
    #expect(first != identity.isid(targetName: "iqn.2026-10.test:other", lun: try LogicalUnit(0)))
    #expect(first.count == 6 && first[0] == 0x80)
}

@Test func profileDocumentHasNoPasswordFieldAndRejectsDuplicateIDs() throws {
    let identity = try InitiatorIdentity.makeNew()
    let profile = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), chapUsername: "User")
    let data = try JSONEncoder().encode(ProfileDocument(identity: identity, servers: [profile]))
    let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let servers = try #require(json["servers"] as? [[String: Any]])
    #expect(Set(servers[0].keys) == ["id", "name", "portal", "chapUsername"])
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(identity: identity, servers: [profile, profile])
    }
}

@Test func legacyProfilesMigrateWithoutChangingKeychainAccount() throws {
    let profile = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), chapUsername: "User")
    let original = try ProfileDocument(identity: .makeNew(), servers: [profile])
    var json = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
    json["version"] = 1
    json["pendingCredentialRemovals"] = nil
    let migrated = try JSONDecoder().decode(
        ProfileDocument.self, from: JSONSerialization.data(withJSONObject: json))
    #expect(migrated.version == 2 && migrated.identity == original.identity)
    #expect(
        migrated.servers.first?.credentialContext?.account == profile.credentialContext?.account)
    #expect(migrated.pendingCredentialRemovals.isEmpty)
    let generation = CredentialContext(
        profileID: profile.id, portal: profile.portal, username: "User", credentialID: UUID())
    #expect(generation.account != profile.credentialContext?.account)
    #expect(
        try JSONDecoder().decode(CredentialContext.self, from: JSONEncoder().encode(generation))
            == generation)
}

@Test func removalRecordsCannotReferToActiveCredentialsOrDuplicateAccounts() throws {
    let profile = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), chapUsername: "User", credentialID: UUID())
    let context = try #require(profile.credentialContext)
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(
            identity: .makeNew(), servers: [profile], pendingCredentialRemovals: [context])
    }
    let otherCase = CredentialContext(
        profileID: profile.id, portal: try Portal("NAS.LOCAL"), username: "User",
        credentialID: profile.credentialID)
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(identity: .makeNew(), pendingCredentialRemovals: [context, otherCase])
    }
    #expect(throws: ProtocolError.self) {
        try ServerProfile(name: "Invalid", portal: Portal("nas.local"), credentialID: UUID())
    }
}
