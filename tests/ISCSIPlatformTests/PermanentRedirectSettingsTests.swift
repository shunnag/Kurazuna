import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private final class RedirectSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    private let commitBeforeFailure: Bool?
    private(set) var saves = 0
    init(_ value: ProfileDocument, commitBeforeFailure: Bool? = nil) {
        self.value = value
        self.commitBeforeFailure = commitBeforeFailure
    }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ document: ProfileDocument) throws {
        try lock.withLock {
            saves += 1
            if commitBeforeFailure != false { value = document }
            if commitBeforeFailure != nil { throw POSIXError(.ENOSPC) }
        }
    }
}

private actor UntouchedRedirectCredentials: CredentialStore {
    private(set) var calls = 0
    func save(password: String, context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        calls += 1
        throw ProtocolError.invalidState
    }
}

private func hint(_ source: String = "source.local", destination: String = "storage.local") throws
    -> PermanentPortalRedirect
{
    try PermanentPortalRedirect(source: Portal(source), destinations: [Portal(destination)])
}

@Test func savedRedirectsSurviveARealSettingsFileReopenWithoutRebindingCredentials() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("Servers.json")
    let server = try ServerProfile(
        name: "Archive", portal: Portal("source.local"), chapUsername: "User", credentialID: UUID(),
        targetCHAPUsername: "Server")
    let identity = try InitiatorIdentity.makeNew()
    do {
        let store = try ProfileStore(url: url)
        var document = try ProfileDocument(identity: identity, servers: [server])
        #expect(document.version == 3)
        document.permanentRedirects.append(
            try SavedPermanentRedirect(profileID: server.id, targetName: nil, redirect: hint()))
        // Saving a mutated document must canonicalize the format version before encoding.
        try store.save(document)
    }
    let reopened = try ProfileStore(url: url)
    let document = try reopened.load()
    #expect(document.version == 5 && document.identity == identity && document.servers == [server])
    #expect(document.servers[0].credentialContexts == server.credentialContexts)
    #expect(document.permanentRedirects(for: server, targetName: nil) == [try hint()])
    #expect(document.permanentRedirects(for: server, targetName: "iqn.2026-10.test:disk").isEmpty)
}

@Test func permanentRedirectScopesKeepDiscoveryTargetsAndProfilesSeparate() throws {
    let first = try ServerProfile(name: "First", portal: Portal("source.local"))
    let second = try ServerProfile(name: "Second", portal: first.portal)
    let records = try [
        SavedPermanentRedirect(
            profileID: first.id, targetName: nil, redirect: hint(destination: "search.local")),
        SavedPermanentRedirect(
            profileID: first.id, targetName: "iqn.2026-10.test:a",
            redirect: hint(destination: "a.local")),
        SavedPermanentRedirect(
            profileID: second.id, targetName: nil, redirect: hint(destination: "other.local")),
    ]
    let document = try ProfileDocument(
        identity: .makeNew(), servers: [first, second], permanentRedirects: records)
    #expect(document.permanentRedirects(for: first, targetName: nil) == [records[0].redirect])
    #expect(
        document.permanentRedirects(for: first, targetName: "iqn.2026-10.test:a") == [
            records[1].redirect
        ])
    #expect(document.permanentRedirects(for: first, targetName: "iqn.2026-10.test:b").isEmpty)
    let edited = try ServerProfile(id: first.id, name: first.name, portal: Portal("edited.local"))
    #expect(document.permanentRedirects(for: edited, targetName: nil).isEmpty)
}

@Test func rememberingRedirectsDoesNotTouchSecretsAndIdenticalHintsDoNotWriteAgain() async throws {
    let server = try ServerProfile(
        name: "Archive", portal: Portal("source.local"), chapUsername: "User", credentialID: UUID())
    let pending = CredentialContext(
        profileID: server.id, portal: server.portal, username: "Unused", credentialID: UUID())
    let document = try ProfileDocument(
        identity: .makeNew(), servers: [server], pendingCredentialRemovals: [pending])
    let storage = RedirectSettings(document)
    let credentials = UntouchedRedirectCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    try await configuration.rememberPermanentRedirects([hint()], for: server, targetName: nil)
    try await configuration.rememberPermanentRedirects([hint()], for: server, targetName: nil)
    #expect(storage.saves == 1 && storage.load().servers == [server])
    #expect(storage.load().pendingCredentialRemovals == [pending])
    #expect(await credentials.calls == 0)
}

@Test(arguments: [false, true])
func aFailedRedirectSaveReloadsTheActualCommittedDocument(_ committed: Bool) async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let storage = RedirectSettings(
        try ProfileDocument(identity: .makeNew(), servers: [server]), commitBeforeFailure: committed
    )
    let credentials = UntouchedRedirectCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.rememberPermanentRedirects([hint()], for: server, targetName: nil)
    }
    #expect(await configuration.document == storage.load())
    #expect(storage.load().permanentRedirects.isEmpty == !committed)
    #expect(await credentials.calls == 0)
}

@Test func staleServerResultsCannotSaveHintsAfterItsSettingsChange() async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let storage = RedirectSettings(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let credentials = UntouchedRedirectCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    try await configuration.rememberPermanentRedirects([hint()], for: server, targetName: nil)
    let edited = try ServerProfile(id: server.id, name: "Renamed", portal: server.portal)
    try await configuration.save(edited, password: "")
    #expect(storage.load().permanentRedirects.isEmpty)
    await #expect(throws: ProtocolError.invalidState) {
        try await configuration.rememberPermanentRedirects([hint()], for: server, targetName: nil)
    }
    #expect(await credentials.calls == 0)
}

@Test func redirectCacheEvictionAndInvalidationNeverRemoveServerSettings() async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let storage = RedirectSettings(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let credentials = UntouchedRedirectCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    for i in 0..<65 {
        try await configuration.rememberPermanentRedirects(
            [hint("source\(i).local")], for: server, targetName: nil)
    }
    #expect(storage.load().permanentRedirects.count == 64)
    #expect(
        storage.load().permanentRedirects.first?.redirect.source == (try Portal("source1.local")))
    try await configuration.rememberPermanentRedirects(
        [], invalidating: [Portal("source1.local")], for: server, targetName: nil)
    #expect(storage.load().permanentRedirects.count == 63 && storage.load().servers == [server])
    try await configuration.remove(server.id)
    #expect(storage.load().permanentRedirects.isEmpty && storage.load().servers.isEmpty)
    #expect(await credentials.calls == 0)
}

@Test func malformedSavedRedirectScopesAndLegacyDocumentsCannotActivateHints() throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let record = try SavedPermanentRedirect(profileID: server.id, targetName: nil, redirect: hint())
    #expect(throws: (any Error).self) {
        try ProfileDocument(identity: .makeNew(), servers: [], permanentRedirects: [record])
    }
    #expect(throws: (any Error).self) {
        try ProfileDocument(
            identity: .makeNew(), servers: [server], permanentRedirects: [record, record])
    }
    let document = try ProfileDocument(
        identity: .makeNew(), servers: [server], permanentRedirects: [record])
    var object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(document)) as? [String: Any])
    object["version"] = 4
    let data = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: ProtocolError.malformed("saved permanent redirect version")) {
        try JSONDecoder().decode(ProfileDocument.self, from: data)
    }
}

private func mountedDescriptor(
    _ server: ServerProfile, binding: Bool = true, target: String = "iqn.2026-10.test:disk"
) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: server.id, portal: server.portal, initiatorName: "iqn.2026-10.test:initiator",
        targetName: target, lun: LogicalUnit(0), readOnly: false, chapUsername: server.chapUsername,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID(), credentialID: server.credentialID,
        targetCHAPUsername: server.targetCHAPUsername,
        settingsBinding: binding ? try server.connectionSettingsBinding : nil)
}

private func mountedReport(
    _ descriptor: ConnectionDescriptor, destination: String = "storage.local"
) throws -> ConnectionRouteReport {
    let route = try PermanentPortalRedirect(
        source: descriptor.portal, destinations: [Portal(destination)])
    return try ConnectionRouteReport(
        resourceIdentity: descriptor.resourceIdentity, connectedPortal: route.destinations[0],
        contactedPortals: [descriptor.portal, route.destinations[0]], permanentRedirects: [route],
        creationOrder: 1)
}

@Test func nativeRedirectReceiptAndCacheSurviveReopenAndCannotReplayAfterAHostRefresh() async throws
{
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("Servers.json")
    let server = try ServerProfile(
        name: "Archive", portal: Portal("source.local"), chapUsername: "User", credentialID: UUID(),
        targetCHAPUsername: "Server")
    let descriptor = try mountedDescriptor(server)
    let report = try mountedReport(descriptor)
    let credentials = UntouchedRedirectCredentials()
    do {
        let store = try ProfileStore(url: url)
        try store.save(ProfileDocument(identity: .makeNew(), servers: [server]))
        let configuration = try ServerConfiguration(storage: store, credentials: credentials)
        await configuration.setMountedRedirectContext(
            epoch: 1, descriptors: [descriptor], inventoryVerified: true)
        try await configuration.rememberMountedRedirects(
            report, descriptor: descriptor, contextEpoch: 1)
        let saved = try store.load()
        #expect(saved.version == 6 && saved.handledMountRedirects == [descriptor.mountID!])
        #expect(
            saved.permanentRedirects(for: server, targetName: descriptor.targetName)
                == report.permanentRedirects)
        try await configuration.rememberPermanentRedirects(
            [hint(destination: "newer.local")], for: server, targetName: descriptor.targetName,
            contextEpoch: 1)
    }
    let reopened = try ProfileStore(url: url)
    let configuration = try ServerConfiguration(storage: reopened, credentials: credentials)
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: true)
    let before = try Data(contentsOf: url)
    try await configuration.rememberMountedRedirects(
        report, descriptor: descriptor, contextEpoch: 1)
    #expect(try Data(contentsOf: url) == before)
    #expect(
        try reopened.load().permanentRedirects(for: server, targetName: descriptor.targetName) == [
            hint(destination: "newer.local")
        ])
    #expect(await credentials.calls == 0)
    await configuration.setMountedRedirectContext(
        epoch: 2, descriptors: [], inventoryVerified: false)
    try await configuration.pruneMountedRedirectReceipts(contextEpoch: 2)
    #expect(try reopened.load().handledMountRedirects == [descriptor.mountID!])
    await configuration.setMountedRedirectContext(
        epoch: 3, descriptors: [], inventoryVerified: true)
    try await configuration.pruneMountedRedirectReceipts(contextEpoch: 3)
    #expect(try reopened.load().handledMountRedirects.isEmpty)
    #expect(try reopened.load().version == 5 && reopened.load().servers == [server])
}

@Test(arguments: [false, true])
func aFreshHostInspectionConsumesEvenADelayedNativeReport(_ inventoryVerified: Bool) async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let descriptor = try mountedDescriptor(server)
    let storage = RedirectSettings(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let configuration = try ServerConfiguration(
        storage: storage, credentials: UntouchedRedirectCredentials())
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: inventoryVerified)
    try await configuration.rememberPermanentRedirects(
        [], invalidating: [server.portal], for: server, targetName: descriptor.targetName,
        contextEpoch: 1)
    #expect(
        storage.load().permanentRedirects.isEmpty
            && storage.load().handledMountRedirects == [descriptor.mountID!])
    await configuration.setMountedRedirectContext(
        epoch: 2, descriptors: [descriptor], inventoryVerified: true)
    try await configuration.rememberMountedRedirects(
        mountedReport(descriptor), descriptor: descriptor, contextEpoch: 2)
    #expect(storage.saves == 1 && storage.load().permanentRedirects.isEmpty)
}

@Test func discoveryAndOtherTargetInspectionsDoNotConsumeAMountedTargetReport() async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let descriptor = try mountedDescriptor(server)
    let storage = RedirectSettings(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let configuration = try ServerConfiguration(
        storage: storage, credentials: UntouchedRedirectCredentials())
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: true)
    for target in [nil, "iqn.2026-10.test:other"] {
        try await configuration.rememberPermanentRedirects(
            [hint(destination: "different.local")], for: server, targetName: target, contextEpoch: 1
        )
        #expect(storage.load().handledMountRedirects.isEmpty)
    }
    try await configuration.rememberMountedRedirects(
        mountedReport(descriptor), descriptor: descriptor, contextEpoch: 1)
    #expect(storage.load().permanentRedirects.count == 3)
}

@Test(arguments: [false, true])
func legacyOrEditedMountReportsAreConsumedWithoutChangingRoutes(_ legacy: Bool) async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let descriptor = try mountedDescriptor(server, binding: !legacy)
    let edited = try ServerProfile(id: server.id, name: "Renamed", portal: server.portal)
    let storage = RedirectSettings(
        try ProfileDocument(identity: .makeNew(), servers: [legacy ? server : edited]))
    let configuration = try ServerConfiguration(
        storage: storage, credentials: UntouchedRedirectCredentials())
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: true)
    try await configuration.rememberMountedRedirects(
        mountedReport(descriptor), descriptor: descriptor, contextEpoch: 1)
    #expect(
        storage.load().permanentRedirects.isEmpty
            && storage.load().handledMountRedirects == [descriptor.mountID!])
    if !legacy { try await configuration.save(server, password: "") }
    try await configuration.rememberMountedRedirects(
        mountedReport(descriptor), descriptor: descriptor, contextEpoch: 1)
    #expect(storage.load().permanentRedirects.isEmpty)
}

@Test func lateEpochUnknownInventoryAndUnregisteredReportsNeverWriteSettings() async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let descriptor = try mountedDescriptor(server)
    let storage = RedirectSettings(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let configuration = try ServerConfiguration(
        storage: storage, credentials: UntouchedRedirectCredentials())
    let report = try mountedReport(descriptor)
    await configuration.setMountedRedirectContext(
        epoch: 2, descriptors: [], inventoryVerified: true)
    // A delayed observer cannot put an ejected descriptor back in the registry.
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: true)
    for epoch: UInt64 in [1, 2] {
        try await configuration.rememberMountedRedirects(
            report, descriptor: descriptor, contextEpoch: epoch)
    }
    await configuration.setMountedRedirectContext(
        epoch: 3, descriptors: [descriptor], inventoryVerified: false)
    try await configuration.rememberMountedRedirects(
        report, descriptor: descriptor, contextEpoch: 3)
    await configuration.setMountedRedirectContext(
        epoch: 4, descriptors: [descriptor, descriptor], inventoryVerified: true)
    try await configuration.rememberMountedRedirects(
        report, descriptor: descriptor, contextEpoch: 4)
    await #expect(throws: CancellationError.self) {
        try await configuration.rememberPermanentRedirects(
            [hint()], for: server, targetName: descriptor.targetName, contextEpoch: 3)
    }
    #expect(storage.saves == 0)
}

@Test(arguments: [false, true])
func mountedRouteAndReceiptCommitTogetherEvenWhenSavingReportsFailure(_ committed: Bool)
    async throws
{
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let descriptor = try mountedDescriptor(server)
    let storage = RedirectSettings(
        try ProfileDocument(identity: .makeNew(), servers: [server]), commitBeforeFailure: committed
    )
    let configuration = try ServerConfiguration(
        storage: storage, credentials: UntouchedRedirectCredentials())
    await configuration.setMountedRedirectContext(
        epoch: 1, descriptors: [descriptor], inventoryVerified: true)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.rememberMountedRedirects(
            mountedReport(descriptor), descriptor: descriptor, contextEpoch: 1)
    }
    #expect(await configuration.document == storage.load())
    #expect(storage.load().permanentRedirects.isEmpty == !committed)
    #expect(storage.load().handledMountRedirects.isEmpty == !committed)
}

@Test func settingsBindingCoversCredentialReferencesAndIndependentDiscoveryPolicy() throws {
    let server = try ServerProfile(
        name: "Archive", portal: Portal("source.local"), chapUsername: "User", credentialID: UUID())
    let baseline = try server.connectionSettingsBinding
    let variations = try [
        ServerProfile(
            id: server.id, name: "New name", portal: server.portal,
            chapUsername: server.chapUsername, credentialID: server.credentialID),
        ServerProfile(
            id: server.id, name: server.name, portal: Portal("other.local"),
            chapUsername: server.chapUsername, credentialID: server.credentialID),
        ServerProfile(
            id: server.id, name: server.name, portal: server.portal,
            chapUsername: server.chapUsername, credentialID: UUID()),
        ServerProfile(
            id: server.id, name: server.name, portal: server.portal,
            chapUsername: server.chapUsername, credentialID: server.credentialID,
            discoveryAuthentication: .none),
    ]
    #expect(baseline.count == 32)
    #expect(try baseline == server.connectionSettingsBinding)
    for value in variations { #expect(try value.connectionSettingsBinding != baseline) }
}

@Test func receiptFormatIsBoundedVersionedAndCanonicalizedByTheStore() throws {
    let identity = try InitiatorIdentity.makeNew()
    let id = UUID()
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(identity: identity, handledMountRedirects: [id, id])
    }
    #expect(throws: ProtocolError.self) {
        try ProfileDocument(
            identity: identity, handledMountRedirects: (0..<129).map { _ in UUID() })
    }
    let document = try ProfileDocument(identity: identity, handledMountRedirects: [id])
    #expect(document.version == 6)
    #expect(
        try JSONDecoder().decode(ProfileDocument.self, from: JSONEncoder().encode(document))
            == document)
    var object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(document)) as? [String: Any])
    for version in [1, 2, 3, 4, 5] {
        object["version"] = version
        #expect(throws: ProtocolError.self) {
            try JSONDecoder().decode(
                ProfileDocument.self, from: JSONSerialization.data(withJSONObject: object))
        }
    }
}
