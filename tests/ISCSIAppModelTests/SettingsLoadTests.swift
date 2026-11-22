import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private actor SettingsCredentials: CredentialStore {
    private(set) var calls = 0
    func save(password: String, context: CredentialContext) throws {
        calls += 1
        throw POSIXError(.EACCES)
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        calls += 1
        throw POSIXError(.ENOENT)
    }
    func remove(context: CredentialContext) throws {
        calls += 1
        throw POSIXError(.EACCES)
    }
}

private actor SettingsBackend: AttachmentBackend {
    private(set) var sideEffects: [String] = []
    var restoreFails = false
    var unknownBridges: [URL] = []
    func configureRecovery(fails: Bool, unknown: [URL]) {
        restoreFails = fails
        unknownBridges = unknown
    }
    func unexpected(_ operation: String) { sideEffects.append(operation) }
    func bridgeURL(for id: UUID) throws -> URL {
        unexpected("prepare")
        throw ProtocolError.invalidState
    }
    func untrackedBridges(excluding trackedURLs: [URL]) throws -> [URL] {
        if restoreFails { throw POSIXError(.EIO) }
        return unknownBridges
    }
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

private final class FailingSettings: ProfileStorage, @unchecked Sendable {
    private let document: ProfileDocument
    private let lock = NSLock()
    private var failure: (any Error)?
    init(_ document: ProfileDocument) { self.document = document }
    func fail(with error: any Error) { lock.withLock { failure = error } }
    func loadOrCreate() -> ProfileDocument { document }
    func load() throws -> ProfileDocument {
        try lock.withLock {
            if let failure { throw failure }
            return document
        }
    }
    func save(_ document: ProfileDocument) throws { throw ProtocolError.invalidState }
}

@MainActor private func settingsModel(
    _ storage: any ProfileStorage,
    entries: [AttachmentJournalEntry] = [],
    preparation:
        (@MainActor @Sendable (URL) async throws -> FileSystemExtensionPreparation.Outcome)? = nil,
    checkTimeout: Duration = .seconds(10),
    supportDirectory: (@MainActor @Sendable () throws -> URL)? = nil,
    check: @escaping @MainActor @Sendable () async throws -> AppModel.ExtensionState = { .ready }
) throws
    -> (AppModel, SettingsBackend, SettingsCredentials)
{
    let credentials = SettingsCredentials()
    let backend = SettingsBackend()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: MemoryAttachmentJournal(entries: entries))
    let model = AppModel(
        coordinator: coordinator, configuration: configuration, credentials: credentials,
        sessionFactory: { _, _, _ in
            await backend.unexpected("network")
            throw ProtocolError.invalidState
        }, extensionCheck: check, extensionPreparation: preparation,
        extensionCheckTimeout: checkTimeout,
        applicationSupportDirectory: supportDirectory ?? {
            try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil,
                create: false)
        })
    return (model, backend, credentials)
}

@MainActor private func finishSettingsOperation(_ model: AppModel) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while model.busy && ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(!model.busy)
}

@MainActor private final class SupportDirectoryRetry {
    var calls = 0
    var preparations = 0
    var shouldFail = true
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    func resolve() throws -> URL {
        calls += 1
        if shouldFail { throw POSIXError(.EACCES) }
        return url
    }
}

@Test @MainActor
private func checkConnectionsCanRecoverAnEarlySupportDirectoryFailureWithoutRepeatingStartup()
    async throws
{
    let source = SupportDirectoryRetry()
    let document = try ProfileDocument(identity: .makeNew())
    let (model, backend, credentials) = try settingsModel(
        FailingSettings(document),
        preparation: { _ in
            source.preparations += 1
            return .deferred
        },
        supportDirectory: { try source.resolve() })
    await model.load()
    #expect(source.calls == 1 && model.issue != nil && !model.recoveryComplete)
    await model.load()
    #expect(source.calls == 1 && source.preparations == 0)
    model.issue = nil
    model.checkConnections()
    try await finishSettingsOperation(model)
    #expect(source.calls == 2 && model.issue != nil && !model.recoveryComplete)
    source.shouldFail = false
    model.issue = nil
    model.checkConnections()
    try await finishSettingsOperation(model)
    #expect(source.calls == 3 && model.issue == nil && model.recoveryComplete)
    #expect(model.document == document)
    model.checkConnections()
    try await finishSettingsOperation(model)
    await model.load()
    #expect(source.calls == 3 && source.preparations == 0)
    #expect(await backend.sideEffects.isEmpty)
    #expect(await credentials.calls == 0)
}

@Test(arguments: [false, true], ["permissions", "invalidJSON"]) @MainActor
private func settingsReadFailureExplainsLocalSettingsAndCanBeRetried(
    afterLoading: Bool, damage: String
) async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
    let server = try ServerProfile(name: "Saved Storage", portal: Portal("settings.invalid"))
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    try store.save(document)
    let original = try Data(contentsOf: store.url)
    let (model, backend, credentials) = try settingsModel(store)
    if afterLoading {
        await model.load()
        #expect(model.document == document && model.issue == nil)
    }
    if damage == "permissions" {
        #expect(chmod(store.url.path, 0o644) == 0)
    } else {
        try Data("{invalid settings".utf8).write(to: store.url)
    }
    let damaged = try Data(contentsOf: store.url)
    let attributes = try FileManager.default.attributesOfItem(atPath: store.url.path)
    if afterLoading {
        model.checkConnections()
        try await finishSettingsOperation(model)
    } else {
        await model.load()
    }
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "Server Settings Are Unavailable"))
    #expect(
        issue.message
            == String(
                localized:
                    "Kurazuna couldn’t read its saved server settings. Click Check Connections to try again."
            ))
    #expect(issue.recoveryAction == nil && issue.readOnlyConnectionRequest == nil)
    #expect(model.document == nil && !model.canAddServer && !model.canEditServer(server))
    #expect(!model.credentialCleanupNeeded)
    #expect(model.attached.isEmpty && model.targets.isEmpty && model.choices.isEmpty)
    #expect(try Data(contentsOf: store.url) == damaged)
    let after = try FileManager.default.attributesOfItem(atPath: store.url.path)
    #expect(after[.posixPermissions] as? NSNumber == attributes[.posixPermissions] as? NSNumber)
    #expect(after[.systemFileNumber] as? NSNumber == attributes[.systemFileNumber] as? NSNumber)
    #expect(await backend.sideEffects.isEmpty)
    #expect(await credentials.calls == 0)

    // Only the test repairs its own file. The app must neither rewrite nor relax it.
    try original.write(to: store.url)
    #expect(chmod(store.url.path, 0o600) == 0)
    model.issue = nil
    model.checkConnections()
    try await finishSettingsOperation(model)
    #expect(model.document == document && model.issue == nil && model.canAddServer)
    #expect(try Data(contentsOf: store.url) == original)
    #expect(await backend.sideEffects.isEmpty)
    #expect(await credentials.calls == 0)
}

@Test @MainActor
private func settingsLeaseFailureKeepsTheAlreadyRunningGuidance() async throws {
    let storage = FailingSettings(try ProfileDocument(identity: .makeNew()))
    let (model, backend, credentials) = try settingsModel(storage)
    storage.fail(with: POSIXError(.EWOULDBLOCK))
    await model.load()
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "Kurazuna Is Already Running"))
    #expect(
        issue.message
            == String(localized: "Close the other copy of Kurazuna, then click Check Again."))
    #expect(await backend.sideEffects.isEmpty)
    #expect(await credentials.calls == 0)
}

@Test @MainActor
private func cancelledSettingsReloadDoesNotPresentAFailure() async throws {
    let storage = FailingSettings(try ProfileDocument(identity: .makeNew()))
    let (model, backend, credentials) = try settingsModel(storage)
    await model.load()
    storage.fail(with: CancellationError())
    model.checkConnections()
    try await finishSettingsOperation(model)
    #expect(model.issue == nil && model.document == nil)
    #expect(await backend.sideEffects.isEmpty)
    #expect(await credentials.calls == 0)
}

@Test func settingsReadDetailsStayOutOfTheRecoveryMessage() {
    let detail = "/private/example/Servers.json: synthetic diagnostic"
    let error = NSError(
        domain: NSCocoaErrorDomain, code: NSFileReadNoPermissionError,
        userInfo: [NSLocalizedDescriptionKey: detail])
    let issue = AppIssue(ServerConfigurationError.settingsLoadFailed(error))
    #expect(issue.detail == detail)
    #expect(!issue.title.contains(detail) && !issue.message.contains(detail))
    #expect(!issue.message.contains("network") && issue.recoveryAction == nil)
    #expect(AppIssue(POSIXError(.EACCES)).title != issue.title)
}

private actor StartupPreparationGate {
    private var started = false
    private var entered: CheckedContinuation<Void, Never>?
    private var completion: CheckedContinuation<Void, Never>?
    func prepare() async {
        started = true
        entered?.resume()
        entered = nil
        await withCheckedContinuation { completion = $0 }
    }
    func waitForStart() async {
        if !started { await withCheckedContinuation { entered = $0 } }
    }
    func finish() {
        completion?.resume()
        completion = nil
    }
}

@Test(arguments: [AppModel.ExtensionState.disabled, .differentCopy, .unavailable]) @MainActor
private func startupRefreshesWaitForOnePreparationAndPreserveTheAssessment(
    state: AppModel.ExtensionState
) async throws {
    let gate = StartupPreparationGate()
    var preparations = 0
    var queries = 0
    let storage = FailingSettings(try ProfileDocument(identity: .makeNew()))
    let (model, _, _) = try settingsModel(
        storage,
        preparation: { _ in
            preparations += 1
            await gate.prepare()
            return .deferred
        },
        check: {
            queries += 1
            return state
        })
    let load = Task { await model.load() }
    await gate.waitForStart()
    let refreshes = (0..<4).map { _ in Task { await model.refreshExtension() } }
    let duplicateLoad = Task { await model.load() }
    await Task.yield()
    #expect(preparations == 1 && queries == 0)
    #expect(model.busy && model.isCheckingExtension && !model.canConnect)
    await gate.finish()
    await load.value
    for refresh in refreshes { await refresh.value }
    await duplicateLoad.value
    #expect(preparations == 1 && queries == 1)
    #expect(model.extensionState == state && !model.canConnect && !model.busy)
    await model.refreshExtension()
    #expect(preparations == 1 && queries == 2)
}

@Test(arguments: ["restore-error", "unknown-bridge", "attached-disk"]) @MainActor
private func startupRegistrationRequiresSuccessfulEmptyRecovery(condition: String) async throws {
    var preparations = 0
    let storage = FailingSettings(try ProfileDocument(identity: .makeNew()))
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("registration.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let entry = try AttachmentJournalEntry(
        id: id, descriptor: descriptor,
        bridgeURL: URL(fileURLWithPath: "/unused/\(id.uuidString)"), phase: .connected)
    let (model, backend, _) = try settingsModel(
        storage, entries: condition == "attached-disk" ? [entry] : [],
        preparation: { _ in
            preparations += 1
            return .deferred
        })
    await backend.configureRecovery(
        fails: condition == "restore-error",
        unknown: condition == "unknown-bridge" ? [URL(fileURLWithPath: "/unused/unknown")] : [])
    await model.load()
    #expect(preparations == 0)
    #expect(model.extensionState == .ready)
    if condition == "attached-disk" {
        #expect(model.attached.count == 1)
    } else {
        #expect(model.connectionStatusNeedsAttention)
    }
}

@Test @MainActor
private func registrationFailureDoesNotReplaceTheReadOnlyAvailabilityAssessment() async throws {
    var preparations = 0
    let storage = FailingSettings(try ProfileDocument(identity: .makeNew()))
    let (model, _, _) = try settingsModel(
        storage,
        preparation: { _ in
            preparations += 1
            throw POSIXError(.EIO)
        },
        check: { .differentCopy })
    await model.load()
    await model.refreshExtension()
    #expect(preparations == 1)
    #expect(model.extensionState == .differentCopy && !model.canConnect)
    #expect(model.issue == nil)
}

@Test(arguments: [2, 3]) @MainActor
private func submittedRegistrationConfirmsVisibilityWithoutRegisteringAgain(readyAt: Int)
    async throws
{
    var preparations = 0
    var queries = 0
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in
            preparations += 1
            return .submitted
        },
        check: {
            queries += 1
            return queries == readyAt ? .ready : .differentCopy
        })
    await model.load()
    #expect(preparations == 1 && queries == readyAt)
    #expect(model.extensionState == .ready && model.canConnect && !model.busy)
}

@Test @MainActor
private func submittedRegistrationKeepsAPersistentDifferentCopyBlocked() async throws {
    var preparations = 0
    var queries = 0
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in
            preparations += 1
            return .submitted
        },
        check: {
            queries += 1
            return .differentCopy
        })
    await model.load()
    #expect(preparations == 1 && queries == 3)
    #expect(model.extensionState == .differentCopy && !model.canConnect)
    await model.refreshExtension()
    #expect(preparations == 1 && queries == 4)
}

@Test(arguments: [FileSystemExtensionPreparation.Outcome.deferred, .alreadyAttempted]) @MainActor
private func unsubmittedRegistrationDoesNotConfirmVisibility(
    outcome: FileSystemExtensionPreparation.Outcome
) async throws {
    var queries = 0
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in outcome },
        check: {
            queries += 1
            return .differentCopy
        })
    await model.load()
    #expect(queries == 1 && model.extensionState == .differentCopy && !model.canConnect)
}

@Test(arguments: [false, true]) @MainActor
private func registrationConfirmationPreservesDisabledChoice(afterMismatch: Bool) async throws {
    var queries = 0
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in .submitted },
        check: {
            queries += 1
            return afterMismatch && queries == 1 ? .differentCopy : .disabled
        })
    await model.load()
    #expect(queries == (afterMismatch ? 2 : 1))
    #expect(model.extensionState == .disabled && !model.canConnect)
}

@Test @MainActor
private func activationFollowersShareTheStartupConfirmationAndCannotConnectEarly() async throws {
    var queries = 0
    var preparations = 0
    var pending: CheckedContinuation<AppModel.ExtensionState, any Error>?
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in
            preparations += 1
            return .submitted
        },
        check: {
            queries += 1
            if queries == 1 { return .differentCopy }
            return try await withCheckedThrowingContinuation { pending = $0 }
        })
    let load = Task { await model.load() }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while pending == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(1))
    }
    let reply = try #require(pending)
    let followers = (0..<4).map { _ in Task { await model.refreshExtension() } }
    await Task.yield()
    #expect(preparations == 1 && queries == 2)
    #expect(model.extensionState == .checking && model.isCheckingExtension && !model.canConnect)
    reply.resume(returning: .ready)
    await load.value
    for task in followers { await task.value }
    #expect(queries == 2 && model.extensionState == .ready && model.canConnect)
}

@Test @MainActor
private func aLateConfirmationCannotOutliveTheOriginalStartupDeadline() async throws {
    var queries = 0
    var returned = false
    var pending: CheckedContinuation<AppModel.ExtensionState, any Error>?
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in .submitted }, checkTimeout: .milliseconds(200),
        check: {
            queries += 1
            if queries == 1 { return .differentCopy }
            let state = try await withCheckedThrowingContinuation { pending = $0 }
            returned = true
            return state
        })
    let load = Task { await model.load() }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while pending == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(1))
    }
    let reply = try #require(pending)
    await load.value
    #expect(queries == 2 && model.extensionState == .unavailable && !model.canConnect)
    reply.resume(returning: .ready)
    while !returned { await Task.yield() }
    await Task.yield()
    #expect(model.extensionState == .unavailable && !model.isCheckingExtension)
}

@Test @MainActor
private func cancellingStartupConfirmationDuringDelayDoesNotQueryAgain() async throws {
    var queries = 0
    let (model, _, _) = try settingsModel(
        FailingSettings(try ProfileDocument(identity: .makeNew())),
        preparation: { _ in .submitted },
        check: {
            queries += 1
            return .differentCopy
        })
    let load = Task { await model.load() }
    while queries == 0 { await Task.yield() }
    load.cancel()
    await load.value
    try await Task.sleep(for: .milliseconds(160))
    #expect(queries == 1 && model.extensionState == .unavailable && !model.canConnect)
    #expect(!model.busy && !model.isCheckingExtension)
}
