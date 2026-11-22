import Foundation
import ISCSICore
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

private final class RemovalSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var document: ProfileDocument
    init(_ document: ProfileDocument) { self.document = document }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { document } }
    func save(_ document: ProfileDocument) { lock.withLock { self.document = document } }
}

private actor RemovalCredentials: CredentialStore {
    private(set) var removed: [CredentialContext] = []
    func save(password: String, context: CredentialContext) throws {}
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw POSIXError(.ENOENT)
    }
    func remove(context: CredentialContext) throws { removed.append(context) }
}

@MainActor private func removalFixture() throws
    -> (AppModel, RemovalSettings, RemovalCredentials, ServerProfile)
{
    let server = try ServerProfile(
        name: "Archive", portal: Portal("storage.invalid"), chapUsername: "archive-user")
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let storage = RemovalSettings(document)
    let credentials = RemovalCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let model = AppModel(configuration: configuration, credentials: credentials)
    model.document = document
    model.selectedServerID = server.id
    model.recoveryComplete = true
    return (model, storage, credentials, server)
}

@MainActor private func waitForRemoval(_ model: AppModel) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test @MainActor private func choosingRemoveServerDoesNotDeleteSettingsOrPasswords() async throws {
    let (model, storage, credentials, server) = try removalFixture()
    let before = storage.load()
    model.removeServer(server)
    try await waitForRemoval(model)
    #expect(storage.load() == before)
    #expect(await credentials.removed.isEmpty)
    #expect(model.selectedServerID == server.id)
    #expect(model.serverRemovalRequest?.server == server)
    #expect(!model.canAddServer && !model.canEditServer(server) && !model.busy)
}

@Test @MainActor private func matchingDisplayedNamesDoNotChangeTheRemovalIdentity() async throws {
    let controlled = try ServerProfile(name: "A\u{202E}B", portal: Portal("first.invalid"))
    let literal = try ServerProfile(name: "A[U+202E]B", portal: Portal("second.invalid"))
    #expect(controlled.displayName == literal.displayName)
    let document = try ProfileDocument(identity: .makeNew(), servers: [controlled, literal])
    let storage = RemovalSettings(document)
    let credentials = RemovalCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let model = AppModel(configuration: configuration, credentials: credentials)
    model.document = document
    model.selectedServerID = controlled.id
    model.recoveryComplete = true
    model.removeServer(controlled)
    let request = try #require(model.serverRemovalRequest)
    #expect(request.server.id == controlled.id)
    model.confirmServerRemoval(request)
    try await waitForRemoval(model)
    #expect(storage.load().servers == [literal])
    #expect(await credentials.removed.isEmpty)
}

@Test @MainActor private func cancellingServerRemovalPreservesSettingsAndPasswords() async throws {
    let (model, storage, credentials, server) = try removalFixture()
    let before = storage.load()
    model.removeServer(server)
    let request = try #require(model.serverRemovalRequest)
    model.cancelServerRemoval(request)
    model.confirmServerRemoval(request)
    try await waitForRemoval(model)
    #expect(storage.load() == before && model.serverRemovalRequest == nil)
    #expect(await credentials.removed.isEmpty)
    #expect(model.canAddServer && model.selectedServerID == server.id)
}

@Test @MainActor private func explicitlyConfirmedServerRemovalRunsOnlyOnce() async throws {
    let (model, storage, credentials, server) = try removalFixture()
    model.removeServer(server)
    let request = try #require(model.serverRemovalRequest)
    model.confirmServerRemoval(request)
    model.confirmServerRemoval(request)
    try await waitForRemoval(model)
    #expect(storage.load().servers.isEmpty && model.servers.isEmpty)
    #expect(await credentials.removed == server.credentialContexts)
    #expect(model.serverRemovalRequest == nil && model.selectedServerID == nil)
    #expect(!model.busy && model.issue == nil)
}

@Test @MainActor private func anOldRemovalRequestCannotApproveOrCancelANewRequest() async throws {
    let (model, storage, credentials, server) = try removalFixture()
    let before = storage.load()
    model.removeServer(server)
    let old = try #require(model.serverRemovalRequest)
    model.cancelServerRemoval(old)
    model.removeServer(server)
    let current = try #require(model.serverRemovalRequest)
    #expect(current.id != old.id)
    model.cancelServerRemoval(old)
    model.confirmServerRemoval(old)
    #expect(model.serverRemovalRequest == current)
    #expect(storage.load() == before)
    #expect(await credentials.removed.isEmpty)
    model.cancelServerRemoval(current)
}

@Test @MainActor private func changedServerSettingsInvalidateRemovalConfirmation() async throws {
    let (model, storage, credentials, server) = try removalFixture()
    model.removeServer(server)
    let request = try #require(model.serverRemovalRequest)
    var changed = storage.load()
    changed.servers[0] = try ServerProfile(
        id: server.id, name: "Updated Archive", portal: Portal("updated.invalid"))
    storage.save(changed)
    model.document = changed
    model.confirmServerRemoval(request)
    try await waitForRemoval(model)
    #expect(storage.load() == changed && model.serverRemovalRequest == nil)
    #expect(await credentials.removed.isEmpty)
}

@Test @MainActor private func aNewConnectionPreventsPreviouslyRequestedServerRemoval() async throws
{
    let (model, storage, credentials, server) = try removalFixture()
    let before = storage.load()
    model.removeServer(server)
    let request = try #require(model.serverRemovalRequest)
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: server.id, portal: server.portal, initiatorName: before.identity.name,
        targetName: "iqn.2026-10.dev.soba:removal-test", lun: LogicalUnit(0),
        readOnly: false, isid: before.identity.seed, mountID: id)
    let entry = try AttachmentJournalEntry(
        id: id, descriptor: descriptor,
        bridgeURL: URL(fileURLWithPath: "/unused-removal-test/\(id.uuidString)"), phase: .connected)
    var disk = AttachedDisk(entry: entry)
    disk.verificationFailed = false
    model.attached = [disk]
    model.confirmServerRemoval(request)
    try await waitForRemoval(model)
    #expect(storage.load() == before && model.serverRemovalRequest == nil)
    #expect(await credentials.removed.isEmpty)
    #expect(model.attached.map(\.id) == [id])
}

@Test @MainActor private func removalConfirmationNamesTheCurrentSavedProfile() throws {
    let (model, _, _, server) = try removalFixture()
    let stale = try ServerProfile(
        id: server.id, name: "Old Archive", portal: Portal("old.invalid"))
    model.removeServer(stale)
    #expect(model.serverRemovalRequest?.server == server)
}
