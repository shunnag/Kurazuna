import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private let oldSecret = "old disposable test credential"
private let newSecret = "new disposable test credential"

private final class FaultProfileStorage: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    private var calls = 0
    private var failureCall: Int?
    private var failReads = false
    private let commitBeforeFailure: Bool
    init(_ document: ProfileDocument, failureCall: Int? = nil, commitBeforeFailure: Bool = false) {
        value = document
        self.failureCall = failureCall
        self.commitBeforeFailure = commitBeforeFailure
    }
    func loadOrCreate() throws -> ProfileDocument { try load() }
    func load() throws -> ProfileDocument {
        try lock.withLock {
            if failReads { throw POSIXError(.EIO) }
            return value
        }
    }
    func save(_ document: ProfileDocument) throws {
        try lock.withLock {
            calls += 1
            if calls == failureCall {
                if commitBeforeFailure { value = document }
                throw POSIXError(.ENOSPC)
            }
            value = document
        }
    }
    func setReadFailure() { lock.withLock { failReads = true } }
    func allowWritesAndReads() {
        lock.withLock {
            failureCall = nil
            failReads = false
        }
    }
    var saveCount: Int { lock.withLock { calls } }
}

private actor TestCredentialStore: CredentialStore {
    private(set) var values: [String: String] = [:]
    private(set) var targetValues: [String: String] = [:]
    private(set) var saved: [CredentialContext] = []
    private(set) var removed: [CredentialContext] = []
    private(set) var reads = 0
    private var saveFailure: Bool?
    private var saveFailureCall: Int?
    private var removalFailure = false
    private var pauseSave = false
    private var saveStarted = false
    private var arrival: CheckedContinuation<Void, Never>?
    private var release: CheckedContinuation<Void, Never>?
    func seed(_ context: CredentialContext, targetPassword: String? = nil) {
        values[context.account] = oldSecret
        targetValues[context.account] = targetPassword
    }
    func failSave(afterWrite: Bool) { saveFailure = afterWrite }
    func failSave(call: Int, afterWrite: Bool) {
        saveFailureCall = call
        saveFailure = afterWrite
    }
    func failRemoval() { removalFailure = true }
    func allowRemoval() { removalFailure = false }
    func pauseNextSave() { pauseSave = true }
    func waitForSave() async {
        if !saveStarted { await withCheckedContinuation { arrival = $0 } }
    }
    func resumeSave() {
        release?.resume()
        release = nil
    }
    func save(password: String, context: CredentialContext) async throws {
        try await savePair(password: password, targetPassword: nil, context: context)
    }
    func save(password: String, targetPassword: String, context: CredentialContext) async throws {
        try await savePair(password: password, targetPassword: targetPassword, context: context)
    }
    private func savePair(password: String, targetPassword: String?, context: CredentialContext)
        async throws
    {
        saved.append(context)
        saveStarted = true
        arrival?.resume()
        arrival = nil
        if pauseSave { await withCheckedContinuation { release = $0 } }
        let failing = saveFailureCall == nil || saveFailureCall == saved.count
        if failing && saveFailure == false { throw POSIXError(.EACCES) }
        values[context.account] = password
        targetValues[context.account] = targetPassword
        if failing && saveFailure == true { throw POSIXError(.EACCES) }
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        reads += 1
        guard let secret = values[context.account] else { throw POSIXError(.ENOENT) }
        return try CHAPCredentials(
            username: context.username, password: secret,
            targetUsername: context.targetUsername, targetPassword: targetValues[context.account])
    }
    func copyCredentials(from source: CredentialContext, to destination: CredentialContext)
        async throws
    {
        guard let password = values[source.account] else { throw POSIXError(.ENOENT) }
        try await savePair(
            password: password, targetPassword: targetValues[source.account], context: destination)
    }
    func remove(context: CredentialContext) throws {
        removed.append(context)
        if removalFailure { throw POSIXError(.EACCES) }
        values[context.account] = nil
        targetValues[context.account] = nil
    }
}

private func profile(credentialID: UUID? = nil) throws -> ServerProfile {
    try ServerProfile(
        name: "Archive", portal: Portal("nas.local"), chapUsername: "User",
        credentialID: credentialID)
}

private let serverSecret = "server disposable test credential"
private let discoverySecret = "new discovery disposable secret"

@Test(arguments: [0, 1, 2, 3, 4, 5], [false, true])
func endpointCredentialCopiesRejectChangedIdentityBeforeCallingTheKeychain(
    _ variation: Int, _ throughProtocol: Bool
)
    async throws
{
    let source = CredentialContext(
        profileID: UUID(), portal: try Portal("original.local"),
        username: "User", credentialID: UUID(), targetUsername: "Server")
    let destination = CredentialContext(
        profileID: variation == 0 ? UUID() : source.profileID,
        portal: variation == 4 ? source.portal : try Portal("selected.local"),
        username: variation == 1 ? "user" : source.username,
        credentialID: variation == 5 ? nil : source.credentialID,
        targetUsername: variation == 2 ? nil : source.targetUsername,
        use: variation == 3 ? .discovery : .connection)
    let store = KeychainCredentialStore(accessGroup: nil)
    await #expect(throws: ProtocolError.malformed("credential copy context")) {
        if throughProtocol {
            let existential: any CredentialStore = store
            try await existential.copyCredentials(from: source, to: destination)
        } else {
            try await store.copyCredentials(from: source, to: destination)
        }
    }
}

@Test(arguments: [false, true])
func unchangedEndpointsUseExistingCredentialReferencesWithoutCreatingItems(_ authenticated: Bool)
    async throws
{
    let server = try ServerProfile(
        name: "Archive", portal: Portal("discovery.local"),
        chapUsername: authenticated ? "User" : nil, credentialID: authenticated ? UUID() : nil)
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let identity = try await configuration.prepareConnectionIdentity(
        for: server, portal: server.portal)
    #expect(identity?.credentialID == server.credentialID)
    #expect(storage.saveCount == 0)
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
    #expect(await secrets.saved.isEmpty)
}

@Test(arguments: [false, true])
func selectedEndpointCredentialsAreRecordedBeforeCopyAndRetainedOnlyWhileMounted(_ mutual: Bool)
    async throws
{
    let server = try ServerProfile(
        name: "Archive", portal: Portal("discovery.local"),
        chapUsername: "User", credentialID: UUID(), targetCHAPUsername: mutual ? "Server" : nil)
    let source = try #require(server.credentialContext)
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let secrets = TestCredentialStore()
    await secrets.seed(source, targetPassword: mutual ? serverSecret : nil)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let selected = try Portal("storage.local:3271")
    let identity = try #require(
        try await configuration.prepareConnectionIdentity(for: server, portal: selected))
    let destination = identity.context(profileID: server.id, portal: selected, use: .connection)
    #expect(identity.credentialID != source.credentialID)
    #expect(storage.saveCount == 1)
    #expect(try storage.load().servers == [server])
    #expect(try storage.load().pendingCredentialRemovals == [destination])
    #expect(await secrets.values[destination.account] == oldSecret)
    #expect(await secrets.targetValues[destination.account] == (mutual ? serverSecret : nil))
    #expect(await secrets.values[source.account] == oldSecret)
    #expect(await configuration.cleanupNeeded(protecting: [destination]) == false)
    let restored = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restored.retryCleanup(protecting: [destination])
    #expect(await secrets.values[destination.account] == oldSecret)
    try await restored.retryCleanup()
    #expect(await secrets.values[destination.account] == nil)
    #expect(await secrets.values[source.account] == oldSecret)
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test(arguments: [false, true])
func selectedEndpointCopyFailuresLeaveDurableCleanupIntent(_ afterWrite: Bool) async throws {
    let server = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(server.credentialContext))
    await secrets.failSave(afterWrite: afterWrite)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.prepareConnectionIdentity(
            for: server, portal: Portal("storage.local"))
    }
    #expect(try storage.load().pendingCredentialRemovals.count == 1)
    let destination = try #require(try storage.load().pendingCredentialRemovals.first)
    #expect((await secrets.values[destination.account] != nil) == afterWrite)
    try await configuration.retryCleanup()
    #expect(await secrets.values[destination.account] == nil)
}

@Test(arguments: [false, true])
func selectedEndpointCannotCopyBeforeTheIntentSaveCompletes(_ committed: Bool) async throws {
    let server = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), servers: [server]),
        failureCall: 1, commitBeforeFailure: committed)
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(server.credentialContext))
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.prepareConnectionIdentity(
            for: server, portal: Portal("storage.local"))
    }
    #expect(await secrets.saved.isEmpty)
    #expect(try storage.load().pendingCredentialRemovals.count == (committed ? 1 : 0))
}

@Test func cancellingTheEndpointCopyRetainsItsIntentForCleanupAfterRestart() async throws {
    let server = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [server]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(server.credentialContext))
    await secrets.pauseNextSave()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let task = Task {
        try await configuration.prepareConnectionIdentity(
            for: server, portal: Portal("storage.local"))
    }
    await secrets.waitForSave()
    #expect(try storage.load().pendingCredentialRemovals.count == 1)
    task.cancel()
    await secrets.resumeSave()
    await #expect(throws: CancellationError.self) { try await task.value }
    let restored = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restored.retryCleanup()
    #expect(await secrets.values.count == 1)
}

@Test(arguments: [false, true])
func discoveryPasswordRequirementsAreCheckedBeforeAnyCredentialOrFileWrite(_ mutual: Bool)
    async throws
{
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try ServerProfile(
        id: old.id, name: old.name, portal: old.portal, chapUsername: old.chapUsername,
        discoveryAuthentication: .chap(
            CHAPIdentity(username: "Search", targetUsername: mutual ? "Search Server" : nil)))
    let error = await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(proposed, password: "")
    }
    switch error {
    case .discoveryPasswordRequired?: #expect(!mutual)
    case .discoveryBothPasswordsRequired?: #expect(mutual)
    default: Issue.record("Expected a discovery password requirement")
    }
    #expect(storage.saveCount == 0)
    #expect(await secrets.saved.isEmpty)
    #expect(try storage.load().servers == [old])
}

@Test func twoCredentialStagingChecksThePendingLimitBeforeCreatingEitherItem() async throws {
    let pending = try (0..<256).map { _ in
        CredentialContext(
            profileID: UUID(), portal: try Portal("nas.local"), username: "Pending",
            credentialID: UUID())
    }
    let original = try ProfileDocument(identity: .makeNew(), pendingCredentialRemovals: pending)
    let storage = FaultProfileStorage(original)
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ProtocolError.self) {
        try await configuration.save(
            separateProfile(), password: newSecret, discoveryPassword: discoverySecret)
    }
    #expect(storage.saveCount == 0)
    #expect(await secrets.saved.isEmpty)
    #expect(try storage.load() == original)
}

private func separateProfile(id: UUID = UUID()) throws -> ServerProfile {
    try ServerProfile(
        id: id, name: "Archive", portal: Portal("nas.local"), chapUsername: "User",
        credentialID: UUID(),
        discoveryAuthentication: .chap(CHAPIdentity(username: "Search", credentialID: UUID())))
}

@Test func bothAuthenticationReferencesPublishTogetherWithoutSerializingSecrets() async throws {
    let proposed = try separateProfile()
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew()))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.save(proposed, password: newSecret, discoveryPassword: discoverySecret)
    let document = try storage.load()
    let saved = try #require(document.servers.first)
    let connection = try #require(saved.credentialContext)
    let discovery = try #require(saved.discoveryCredentialContext)
    #expect(document.version == 4 && document.pendingCredentialRemovals.isEmpty)
    #expect(connection.use == .connection && discovery.use == .discovery)
    #expect(
        await secrets.values == [connection.account: newSecret, discovery.account: discoverySecret])
    let data = try JSONEncoder().encode(document)
    let text = String(decoding: data, as: UTF8.self)
    #expect(!text.contains(newSecret) && !text.contains(discoverySecret))
    #expect(try JSONDecoder().decode(ProfileDocument.self, from: data) == document)
}

@Test(arguments: [false, true])
func failureSavingTheSecondCredentialLeavesBothCleanupIntentsAndOldReferences(_ afterWrite: Bool)
    async throws
{
    let old = try separateProfile()
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    for context in old.credentialContexts { await secrets.seed(context) }
    await secrets.failSave(call: 2, afterWrite: afterWrite)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(
            separateProfile(id: old.id), password: newSecret, discoveryPassword: discoverySecret)
    }
    let document = try storage.load()
    #expect(document.servers == [old] && document.pendingCredentialRemovals.count == 2)
    #expect(Set(document.pendingCredentialRemovals.map(\.use)) == [.connection, .discovery])
    try await configuration.retryCleanup()
    let values = await secrets.values
    #expect(Set(values.keys) == Set(old.credentialContexts.map(\.account)))
    #expect(values.values.allSatisfy { $0 == oldSecret })
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test(arguments: [false, true])
func publicationFailureRetainsOnlyTheCredentialsReferencedByTheActualFile(_ committed: Bool)
    async throws
{
    let old = try separateProfile()
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), servers: [old]),
        failureCall: 2, commitBeforeFailure: committed)
    let secrets = TestCredentialStore()
    for context in old.credentialContexts { await secrets.seed(context) }
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(
            separateProfile(id: old.id), password: newSecret, discoveryPassword: discoverySecret)
    }
    storage.allowWritesAndReads()
    try await configuration.retryCleanup()
    let saved = try #require(storage.load().servers.first)
    let values = await secrets.values
    #expect(Set(values.keys) == Set(saved.credentialContexts.map(\.account)))
    #expect(values[saved.credentialContext!.account] == (committed ? newSecret : oldSecret))
    #expect(
        values[saved.discoveryCredentialContext!.account]
            == (committed ? discoverySecret : oldSecret))
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test func cancellationBetweenCredentialWritesDoesNotPublishAPartialConfiguration() async throws {
    let old = try separateProfile()
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    for context in old.credentialContexts { await secrets.seed(context) }
    await secrets.pauseNextSave()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try separateProfile(id: old.id)
    let task = Task {
        try await configuration.save(
            proposed, password: newSecret, discoveryPassword: discoverySecret)
    }
    await secrets.waitForSave()
    task.cancel()
    await secrets.resumeSave()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(try storage.load().servers == [old])
    #expect(try storage.load().pendingCredentialRemovals.count == 2)
    #expect(await secrets.saved.count == 1)
    try await configuration.retryCleanup()
    let values = await secrets.values
    #expect(Set(values.keys) == Set(old.credentialContexts.map(\.account)))
}

@Test func blankPasswordsKeepBothReferencesAndInheritedDiscoveryRemovesOnlyItsOwnItem() async throws
{
    let old = try separateProfile()
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    for context in old.credentialContexts { await secrets.seed(context) }
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.save(separateProfile(id: old.id), password: "")
    #expect(try storage.load().servers == [old])
    #expect(await secrets.saved.isEmpty)
    #expect(await secrets.reads == 0)
    let inherited = try ServerProfile(
        id: old.id, name: old.name, portal: old.portal, chapUsername: old.chapUsername)
    try await configuration.save(inherited, password: "")
    let saved = try #require(storage.load().servers.first)
    #expect(saved.credentialContext == old.credentialContext)
    #expect(saved.discoveryCredentialContext == saved.credentialContext)
    #expect(try storage.load().version == 2)
    #expect(await secrets.values == [old.credentialContext!.account: oldSecret])
    #expect(await secrets.removed.map(\.account) == [old.discoveryCredentialContext!.account])
}

@Test func removingAProfileRetainsBothRemovalIntentsUntilCleanupSucceeds() async throws {
    let old = try separateProfile()
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    for context in old.credentialContexts { await secrets.seed(context) }
    await secrets.failRemoval()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.remove(old.id)
    let document = try storage.load()
    #expect(
        document.servers.isEmpty && document.pendingCredentialRemovals.count == 2
            && document.version == 4)
    await secrets.allowRemoval()
    try await configuration.retryCleanup()
    #expect(await secrets.values.isEmpty)
    #expect(try storage.load().version == 2)
}

@Test func discoveryWithoutAuthenticationPersistsIndependentlyOfCHAPConnection() async throws {
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(old.credentialContext))
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try ServerProfile(
        id: old.id, name: old.name, portal: old.portal,
        chapUsername: old.chapUsername, discoveryAuthentication: .none)
    try await configuration.save(proposed, password: "")
    let saved = try #require(storage.load().servers.first)
    #expect(saved.discoveryAuthentication == .none)
    #expect(saved.discoveryCredentialContext == nil)
    #expect(saved.credentialContext == old.credentialContext)
    #expect(try storage.load().version == 4)
    #expect(await secrets.saved.isEmpty)
}

@Test(arguments: [false, true])
func failedMutualPublicationUsesTheActualCommittedDocumentForCleanup(_ committed: Bool) async throws
{
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), servers: [old]),
        failureCall: 2, commitBeforeFailure: committed)
    let secrets = TestCredentialStore()
    let oldContext = try #require(old.credentialContext)
    await secrets.seed(oldContext)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(
            mutualProfile(id: old.id), password: newSecret, targetPassword: serverSecret)
    }
    storage.allowWritesAndReads()
    try await configuration.retryCleanup()
    let current = try #require(storage.load().servers.first)
    let context = try #require(current.credentialContext)
    #expect(await secrets.values == [context.account: committed ? newSecret : oldSecret])
    #expect(await secrets.targetValues == (committed ? [context.account: serverSecret] : [:]))
    #expect(current.targetCHAPUsername == (committed ? "Server" : nil))
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test func changingMutualCHAPToOneWayReplacesTheBoundCredentialPair() async throws {
    let old = try mutualProfile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(old.credentialContext), targetPassword: serverSecret)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try ServerProfile(
        id: old.id, name: old.name, portal: old.portal, chapUsername: "User")
    try await configuration.save(proposed, password: newSecret)
    let saved = try #require(storage.load().servers.first)
    let context = try #require(saved.credentialContext)
    #expect(saved.targetCHAPUsername == nil)
    #expect(try storage.load().version == 2)
    #expect(await secrets.values == [context.account: newSecret])
    #expect(await secrets.targetValues.isEmpty)
}

private func mutualProfile(
    id: UUID = UUID(), credentialID: UUID? = nil, targetName: String = "Server"
) throws -> ServerProfile {
    try ServerProfile(
        id: id, name: "Archive", portal: Portal("nas.local"), chapUsername: "User",
        credentialID: credentialID, targetCHAPUsername: targetName)
}

@Test func mutualCredentialPairCommitsTogetherAndUpgradesTheDocument() async throws {
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(old.credentialContext))
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.save(
        mutualProfile(id: old.id), password: newSecret, targetPassword: serverSecret)
    let document = try storage.load()
    let server = try #require(document.servers.first)
    let context = try #require(server.credentialContext)
    #expect(document.version == 3 && document.pendingCredentialRemovals.isEmpty)
    #expect(context.targetUsername == "Server")
    #expect(await secrets.values == [context.account: newSecret])
    #expect(await secrets.targetValues == [context.account: serverSecret])
    let credentials = try await secrets.credentials(context: context)
    #expect(credentials.targetUsername == "Server")
    let data = try JSONEncoder().encode(document)
    let text = String(decoding: data, as: UTF8.self)
    #expect(!text.contains(newSecret) && !text.contains(serverSecret))
    #expect(try JSONDecoder().decode(ProfileDocument.self, from: data) == document)
}

@Test(arguments: [false, true])
func failedMutualCredentialSaveRetainsTheOldReferenceAndCleanupIntent(_ afterWrite: Bool)
    async throws
{
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    let oldContext = try #require(old.credentialContext)
    await secrets.seed(oldContext)
    await secrets.failSave(afterWrite: afterWrite)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(
            mutualProfile(id: old.id), password: newSecret, targetPassword: serverSecret)
    }
    let document = try storage.load()
    #expect(document.servers == [old])
    #expect(document.version == 3 && document.pendingCredentialRemovals.count == 1)
    #expect(document.pendingCredentialRemovals.first?.targetUsername == "Server")
    try await configuration.retryCleanup()
    #expect(await secrets.values == [oldContext.account: oldSecret])
    #expect(await secrets.targetValues.isEmpty == true)
    #expect(try storage.load().version == 2)
}

@Test func blankMutualPasswordsKeepBothCredentialsWithoutReadingTheirValues() async throws {
    let old = try mutualProfile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(try #require(old.credentialContext), targetPassword: serverSecret)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.save(mutualProfile(id: old.id), password: "")
    #expect(try storage.load().servers == [old])
    #expect(await secrets.reads == 0)
    #expect(await secrets.saved.isEmpty)
    #expect(await secrets.removed.isEmpty)
}

@Test(arguments: ["initiator-only", "target-only", "identity-changed"])
func mutualCredentialChangesRequireTheCompletePair(_ mode: String) async throws {
    let old = try mutualProfile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let error = await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(
            mutualProfile(id: old.id, targetName: mode == "identity-changed" ? "Other" : "Server"),
            password: mode == "initiator-only" ? newSecret : "",
            targetPassword: mode == "target-only" ? serverSecret : "")
    }
    guard case .bothPasswordsRequired? = error else {
        Issue.record("Expected bothPasswordsRequired")
        return
    }
    #expect(storage.saveCount == 0)
    #expect(await secrets.saved.isEmpty)
    #expect(await secrets.reads == 0)
}

@Test func mutualCredentialBindingIncludesTheServerIdentityAndMode() throws {
    let server = try mutualProfile(credentialID: UUID())
    let context = try #require(server.credentialContext)
    let ordinary = CredentialContext(
        profileID: server.id, portal: server.portal, username: "User",
        credentialID: server.credentialID)
    let other = CredentialContext(
        profileID: server.id, portal: server.portal, username: "User",
        credentialID: server.credentialID, targetUsername: "Other")
    #expect(Set([context.account, ordinary.account, other.account]).count == 3)
    #expect(
        try JSONDecoder().decode(CredentialContext.self, from: JSONEncoder().encode(context))
            == context)
}

@Test(arguments: [false, true])
func replacingPasswordPublishesNewReferenceWithoutOverwritingOldItem(versioned: Bool) async throws {
    let old = try profile(credentialID: versioned ? UUID() : nil)
    let context = try #require(old.credentialContext)
    let original = try ProfileDocument(identity: .makeNew(), servers: [old])
    let storage = FaultProfileStorage(original)
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    try await configuration.save(old, password: newSecret)
    let saved = try storage.load()
    let updated = try #require(saved.servers.first)
    let newContext = try #require(updated.credentialContext)
    #expect(updated.id == old.id && saved.identity == original.identity)
    #expect(updated.credentialID != nil && newContext.account != context.account)
    #expect(await secrets.values == [newContext.account: newSecret])
    #expect(await secrets.removed.map(\.account) == [context.account])
    #expect(saved.pendingCredentialRemovals.isEmpty)
    #expect(await configuration.cleanupNeeded == false)
    let encoded = try JSONEncoder().encode(saved)
    #expect(!String(decoding: encoded, as: UTF8.self).contains(newSecret))
}

@Test func renamingAndHostCaseChangeKeepPasswordWithoutOpeningKeychain() async throws {
    let old = try profile(credentialID: UUID())
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let renamed = try ServerProfile(
        id: old.id, name: "Backups", portal: Portal("NAS.LOCAL"), chapUsername: "User")
    try await configuration.save(renamed, password: "")
    #expect(try storage.load().servers.first?.name == "Backups")
    #expect(try storage.load().servers.first?.credentialID == old.credentialID)
    #expect(await secrets.saved.isEmpty)
    #expect(await secrets.removed.isEmpty)
    #expect(await secrets.reads == 0)
}

@Test(arguments: ["server", "user", "new"])
func changedAuthenticationContextNeedsPasswordBeforeAnySideEffect(change: String) async throws {
    let old = try profile()
    let original = try ProfileDocument(identity: .makeNew(), servers: [old])
    let storage = FaultProfileStorage(original)
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try ServerProfile(
        id: change == "new" ? UUID() : old.id, name: old.name,
        portal: Portal(change == "server" ? "other.local" : "nas.local"),
        chapUsername: change == "user" ? "user" : "User")
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(proposed, password: "")
    }
    #expect(try storage.load() == original)
    #expect(storage.saveCount == 0)
    #expect(await secrets.saved.isEmpty)
    #expect(await secrets.removed.isEmpty)
}

@Test(arguments: [false, true])
func credentialWriteFailurePreservesOldSettingsAndTracksPossibleItem(afterWrite: Bool) async throws
{
    let old = try profile()
    let context = try #require(old.credentialContext)
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    await secrets.failSave(afterWrite: afterWrite)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(old, password: newSecret)
    }
    #expect(try storage.load().servers == [old])
    #expect(try storage.load().pendingCredentialRemovals.count == 1)
    #expect(await secrets.values[context.account] == oldSecret)
    let restarted = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restarted.retryCleanup()
    #expect(await secrets.values == [context.account: oldSecret])
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test(arguments: [1, 2, 3], [false, true])
func profileSaveFailureReloadsActualCommitAndNeverDeletesCurrentCredential(
    stage: Int, committed: Bool
) async throws {
    let old = try profile()
    let context = try #require(old.credentialContext)
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), servers: [old]),
        failureCall: stage, commitBeforeFailure: committed)
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    if stage < 3 {
        await #expect(throws: ServerConfigurationError.self) {
            try await configuration.save(old, password: newSecret)
        }
    } else {
        try await configuration.save(old, password: newSecret)
        #expect(await configuration.cleanupIssue != nil)
    }
    let actual = try storage.load()
    #expect(await configuration.document == actual)
    let active = try #require(actual.servers.first?.credentialContext)
    #expect(await secrets.values[active.account] != nil)
    if stage == 1 { #expect(await secrets.saved.isEmpty) }
    if stage < 3 { #expect(await secrets.removed.isEmpty) }
    storage.allowWritesAndReads()
    let restarted = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restarted.retryCleanup()
    #expect(await secrets.values.count == 1)
    #expect(await secrets.values[active.account] != nil)
    #expect(try storage.load().pendingCredentialRemovals.isEmpty)
}

@Test(arguments: [false, true])
func removingServerOrCHAPRetainsFailedDeletionForNextLaunch(removeServer: Bool) async throws {
    let old = try profile()
    let context = try #require(old.credentialContext)
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    await secrets.failRemoval()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    if removeServer {
        try await configuration.remove(old.id)
    } else {
        try await configuration.save(
            ServerProfile(id: old.id, name: old.name, portal: old.portal), password: "")
    }
    #expect(try storage.load().servers.compactMap(\.credentialContext).isEmpty)
    #expect(try storage.load().pendingCredentialRemovals == [context])
    #expect(await configuration.cleanupNeeded)
    #expect(await secrets.values[context.account] == oldSecret)
    await secrets.allowRemoval()
    let restarted = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restarted.retryCleanup()
    #expect(await secrets.values.isEmpty)
    #expect(await restarted.cleanupNeeded == false)
}

@Test func pendingCredentialsReferencedByMountsSurviveOtherSettingsChanges() async throws {
    let context = try #require(profile().credentialContext)
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), pendingCredentialRemovals: [context]))
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let other = try ServerProfile(name: "Other", portal: Portal("other.local"))
    try await configuration.save(other, password: "", protecting: [context])
    try await configuration.retryCleanup(protecting: [context])
    #expect(await secrets.removed.isEmpty)
    #expect(await configuration.cleanupNeeded)
    await #expect(throws: ProtocolError.busy) {
        try await configuration.remove(context.profileID, protecting: [context])
    }
    try await configuration.retryCleanup()
    #expect(await secrets.values.isEmpty)
}

@Test func concurrentMutationIsRejectedAndCancellationLeavesRecoverableIntent() async throws {
    let old = try profile()
    let context = try #require(old.credentialContext)
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: [old]))
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    await secrets.pauseNextSave()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let pending = Task { try await configuration.save(old, password: newSecret) }
    await secrets.waitForSave()
    await #expect(throws: ProtocolError.busy) { try await configuration.remove(old.id) }
    await #expect(throws: ProtocolError.busy) { try await configuration.retryCleanup() }
    await #expect(throws: ProtocolError.busy) { try await configuration.save(old, password: "") }
    pending.cancel()
    await secrets.resumeSave()
    await #expect(throws: CancellationError.self) { try await pending.value }
    #expect(try storage.load().servers == [old])
    #expect(try storage.load().pendingCredentialRemovals.count == 1)
    let restarted = try ServerConfiguration(storage: storage, credentials: secrets)
    try await restarted.retryCleanup()
    #expect(await secrets.values == [context.account: oldSecret])
}

@Test func unreadableSettingsAfterFailedCommitStopMutationAndCleanupUntilReload() async throws {
    let old = try profile()
    let context = try #require(old.credentialContext)
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew(), servers: [old]),
        failureCall: 2, commitBeforeFailure: true)
    let secrets = TestCredentialStore()
    await secrets.seed(context)
    await secrets.pauseNextSave()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let pending = Task { try await configuration.save(old, password: newSecret) }
    await secrets.waitForSave()
    storage.setReadFailure()
    await secrets.resumeSave()
    await #expect(throws: ServerConfigurationError.self) { try await pending.value }
    #expect(await configuration.document == nil)
    await #expect(throws: ServerConfigurationError.self) { try await configuration.retryCleanup() }
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(old, password: newSecret)
    }
    #expect(await secrets.removed.isEmpty)
    #expect(await secrets.values.count == 2)
    storage.allowWritesAndReads()
    try await configuration.reload()
    try await configuration.retryCleanup()
    let active = try #require(storage.load().servers.first?.credentialContext)
    #expect(await secrets.values == [active.account: newSecret])
}

@Test func profileLimitIsCheckedBeforeCreatingCredential() async throws {
    let servers = try (0..<128).map {
        try ServerProfile(name: "Server \($0)", portal: Portal("nas.local"))
    }
    let storage = FaultProfileStorage(try ProfileDocument(identity: .makeNew(), servers: servers))
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    await #expect(throws: ProtocolError.self) {
        try await configuration.save(profile(), password: newSecret)
    }
    #expect(storage.saveCount == 0)
    #expect(await secrets.saved.isEmpty)
}

private func leavePendingDeletionOnDisk(url: URL, secrets: TestCredentialStore) async throws -> UUID
{
    let store = try ProfileStore(url: url)
    let configuration = try ServerConfiguration(storage: store, credentials: secrets)
    let server = try profile()
    // The credential is created through the real settings transaction; only the Keychain is fake.
    try await configuration.save(server, password: newSecret)
    await secrets.failRemoval()
    try await configuration.remove(server.id)
    #expect(await configuration.cleanupNeeded)
    return try #require(store.load().pendingCredentialRemovals.first?.credentialID)
}

@Test func pendingDeletionSurvivesRealFileCloseAndReopenWithoutSerializingSecret() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("Servers.json")
    let secrets = TestCredentialStore()
    let generation = try await leavePendingDeletionOnDisk(url: url, secrets: secrets)
    let bytes = try Data(contentsOf: url)
    #expect(!String(decoding: bytes, as: UTF8.self).contains(newSecret))
    let store = try ProfileStore(url: url)
    let configuration = try ServerConfiguration(storage: store, credentials: secrets)
    #expect(
        await configuration.document?.pendingCredentialRemovals.first?.credentialID == generation)
    await secrets.allowRemoval()
    try await configuration.retryCleanup()
    #expect(try store.load().servers.isEmpty)
    #expect(try store.load().pendingCredentialRemovals.isEmpty)
    #expect(await secrets.values.isEmpty)
}

@Test func retryingNewServerAfterCommittedSaveErrorDoesNotDuplicateOrReplaceItsPassword()
    async throws
{
    let storage = FaultProfileStorage(
        try ProfileDocument(identity: .makeNew()), failureCall: 2, commitBeforeFailure: true)
    let secrets = TestCredentialStore()
    let configuration = try ServerConfiguration(storage: storage, credentials: secrets)
    let proposed = try profile()
    await #expect(throws: ServerConfigurationError.self) {
        try await configuration.save(proposed, password: newSecret)
    }
    let committed = try #require(storage.load().servers.first)
    #expect(committed.id == proposed.id && committed.credentialID != nil)
    storage.allowWritesAndReads()
    try await configuration.save(proposed, password: "")
    #expect(try storage.load().servers == [committed])
    #expect(await secrets.saved.count == 1)
    #expect(await secrets.values.count == 1)
}
