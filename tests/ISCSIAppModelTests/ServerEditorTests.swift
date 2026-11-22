import Foundation
import ISCSICore
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

private final class EditorSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    init(_ value: ProfileDocument) { self.value = value }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ document: ProfileDocument) { lock.withLock { value = document } }
}

private actor EditorCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw ProtocolError.invalidState
    }
}

@MainActor private func editorFixture() throws -> (AppModel, EditorSettings, ServerProfile) {
    let server = try ServerProfile(name: "Archive", portal: Portal("example.invalid"))
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let storage = EditorSettings(document)
    let credentials = EditorCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let model = AppModel(configuration: configuration, credentials: credentials)
    model.document = document
    model.recoveryComplete = true
    return (model, storage, server)
}

@Test(arguments: [false, true])
@MainActor private func anOpenServerEditorCannotBeReplacedOrItsProfileRemoved(_ editing: Bool)
    throws
{
    let (model, storage, server) = try editorFixture()
    if editing { model.editServer(server) } else { model.addServer() }
    #expect(model.showingServerEditor)
    #expect(model.editingServer?.id == (editing ? server.id : nil))
    #expect(!model.canAddServer && !model.canEditServer(server))
    model.addServer()
    model.editServer(server)
    model.removeServer(server)
    #expect(model.showingServerEditor)
    #expect(model.editingServer?.id == (editing ? server.id : nil))
    #expect(storage.load().servers == [server] && !model.busy)
    // Dismissing a sheet must allow the next command to choose a fresh editing context.
    model.showingServerEditor = false
    if editing { model.addServer() } else { model.editServer(server) }
    #expect(model.showingServerEditor)
    #expect(model.editingServer?.id == (editing ? nil : server.id))
}

@Test(arguments: [0, 1, 2])
@MainActor private func serverEditorCommandsWaitForAvailableSettings(_ unavailable: Int) throws {
    let (model, _, server) = try editorFixture()
    switch unavailable {
    case 0: model.document = nil
    case 1: model.recoveryComplete = false
    default: model.busy = true
    }
    #expect(!model.canAddServer && !model.canEditServer(server))
    model.addServer()
    model.editServer(server)
    #expect(!model.showingServerEditor && model.editingServer == nil)
}

@Test @MainActor private func serverEditorUsesTheSavedProfileAndRefusesConnectedOrRemovedProfiles()
    throws
{
    let (model, _, server) = try editorFixture()
    let stale = try ServerProfile(id: server.id, name: "Old Name", portal: Portal("old.invalid"))
    model.editServer(stale)
    #expect(model.editingServer == server)
    model.showingServerEditor = false
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: server.id, portal: server.portal, initiatorName: model.identityName,
        targetName: "iqn.2026-10.dev.soba:editor-test", lun: LogicalUnit(0),
        readOnly: false, isid: #require(model.document).identity.seed, mountID: id)
    let entry = try AttachmentJournalEntry(
        id: id, descriptor: descriptor,
        bridgeURL: URL(fileURLWithPath: "/unused-editor-test/\(id.uuidString)"), phase: .connected)
    var disk = AttachedDisk(entry: entry)
    disk.verificationFailed = false
    model.attached = [disk]
    #expect(model.canAddServer && !model.canEditServer(server))
    model.editServer(server)
    #expect(!model.showingServerEditor)
    disk.verificationFailed = true
    model.attached = [disk]
    #expect(!model.canAddServer)
    model.attached = []
    model.document?.servers = []
    model.editServer(server)
    #expect(!model.canEditServer(server) && !model.showingServerEditor)
}

@Test @MainActor private func savingFromAnOpenEditorKeepsTheProfileIdentityAndClosesTheSheet()
    async throws
{
    let (model, storage, server) = try editorFixture()
    model.editServer(server)
    try await model.saveServer(
        id: server.id, name: "Work", address: "work.invalid", username: nil, password: "")
    let saved = try #require(storage.load().servers.first)
    #expect(saved.id == server.id && saved.name == "Work")
    #expect(saved.portal == (try Portal("work.invalid")))
    #expect(storage.load().servers.count == 1 && model.selectedServerID == server.id)
    #expect(!model.showingServerEditor && model.editingServer == nil && !model.busy)
    #expect(model.canAddServer && model.canEditServer(saved))
}
