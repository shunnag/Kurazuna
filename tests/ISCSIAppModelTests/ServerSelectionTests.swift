import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private final class SelectionSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    init(_ value: ProfileDocument) { self.value = value }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ value: ProfileDocument) { lock.withLock { self.value = value } }
}

private actor SelectionCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws { throw POSIXError(.EACCES) }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw POSIXError(.ENOENT)
    }
    func remove(context: CredentialContext) throws { throw POSIXError(.EACCES) }
}

private actor SelectionBackend: AttachmentBackend {
    private(set) var sideEffects: [String] = []
    func unexpected(_ operation: String) { sideEffects.append(operation) }
    func bridgeURL(for id: UUID) throws -> URL {
        unexpected("prepare")
        throw ProtocolError.invalidState
    }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        -> AttachmentInspection
    {
        AttachmentInspection(
            ownership: .verified,
            attachment: DiskAttachment(device: "/dev/disk900020", volumeURLs: []),
            connectionState: .connected)
    }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        unexpected("mount")
        throw ProtocolError.invalidState
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        unexpected("attach")
        throw ProtocolError.invalidState
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        unexpected("detach")
        throw ProtocolError.invalidState
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        unexpected("unmount")
        throw ProtocolError.invalidState
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        unexpected("discard")
        throw ProtocolError.invalidState
    }
}

@MainActor private func selectionModel(
    servers: [ServerProfile], recovered: ServerProfile? = nil
) throws -> (AppModel, SelectionBackend, SelectionSettings) {
    let identity = try InitiatorIdentity.makeNew()
    let settings = SelectionSettings(try ProfileDocument(identity: identity, servers: servers))
    let credentials = SelectionCredentials()
    let configuration = try ServerConfiguration(storage: settings, credentials: credentials)
    var entries: [AttachmentJournalEntry] = []
    if let recovered {
        let id = UUID()
        let descriptor = try ConnectionDescriptor(
            profileID: recovered.id, portal: recovered.portal, initiatorName: identity.name,
            targetName: "iqn.2026-10.example:selection", lun: LogicalUnit(0), readOnly: true,
            isid: identity.seed, mountID: id)
        entries.append(
            try AttachmentJournalEntry(
                id: id, descriptor: descriptor,
                bridgeURL: URL(fileURLWithPath: "/unused/Selection/\(id)"), phase: .connected))
    }
    let backend = SelectionBackend()
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: MemoryAttachmentJournal(entries: entries))
    let model = AppModel(
        coordinator: coordinator, configuration: configuration, credentials: credentials,
        sessionFactory: { _, _, _ in
            await backend.unexpected("network")
            throw ProtocolError.invalidState
        }, extensionCheck: { .ready })
    return (model, backend, settings)
}

@Test(arguments: [1, 2]) @MainActor
private func loadingSavedServersShowsTheFirstServerWithoutConnecting(_ count: Int) async throws {
    let servers = try (0..<count).map {
        try ServerProfile(name: "Storage \($0)", portal: Portal("storage\($0).invalid"))
    }
    let (model, backend, settings) = try selectionModel(servers: servers)
    await model.load()
    #expect(model.selectedServerID == servers[0].id)
    #expect(model.selectedServer == servers[0])
    #expect(model.issue == nil && !model.busy && model.recoveryComplete)
    #expect(model.targets.isEmpty && model.choices.isEmpty && model.attached.isEmpty)
    #expect(await backend.sideEffects.isEmpty)
    #expect(settings.load().servers == servers)
}

@Test @MainActor
private func loadingPreservesAnExistingSelectionAndDoesNotUndoLaterDeselection() async throws {
    let first = try ServerProfile(name: "First", portal: Portal("first.invalid"))
    let second = try ServerProfile(name: "Second", portal: Portal("second.invalid"))
    let (model, backend, _) = try selectionModel(servers: [first, second])
    model.selectedServerID = second.id
    await model.load()
    #expect(model.selectedServer == second)
    model.selectedServerID = nil
    await model.load()
    #expect(model.selectedServer == nil && model.servers.count == 2)
    #expect(await backend.sideEffects.isEmpty)
}

@Test(arguments: [false, true]) @MainActor
private func loadingPrefersARecoveredConnectionToTheFirstSavedServer(_ saved: Bool) async throws {
    let first = try ServerProfile(name: "First", portal: Portal("first.invalid"))
    let recovered = try ServerProfile(name: "Recovered", portal: Portal("recovered.invalid"))
    let (model, backend, settings) = try selectionModel(
        servers: saved ? [first, recovered] : [first], recovered: recovered)
    await model.load()
    #expect(model.selectedServerID == recovered.id)
    #expect(model.selectedServer?.portal == recovered.portal)
    #expect(model.attached.count == 1 && model.recoveryComplete && model.issue == nil)
    #expect(settings.load().servers.count == (saved ? 2 : 1))
    #expect(await backend.sideEffects.isEmpty)
}

@Test @MainActor
private func loadingWithoutServersKeepsTheFirstRunReadyToAddAServer() async throws {
    let (model, backend, _) = try selectionModel(servers: [])
    await model.load()
    #expect(model.selectedServer == nil && model.selectedServerID == nil && model.servers.isEmpty)
    #expect(model.canAddServer && model.issue == nil)
    #expect(await backend.sideEffects.isEmpty)
}
