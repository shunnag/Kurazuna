import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private final class RecoverySettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    init(_ value: ProfileDocument) { self.value = value }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ value: ProfileDocument) { lock.withLock { self.value = value } }
}

private actor RecoveryCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws { throw POSIXError(.EACCES) }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw POSIXError(.ENOENT)
    }
    func remove(context: CredentialContext) throws { throw POSIXError(.EACCES) }
}

private enum RecoveryFailure: CaseIterable, Sendable {
    case completion, geometry, io, ownership
    var error: any Error {
        switch self {
        case .completion: AttachmentError.writeCompletionUnavailable
        case .geometry: AttachmentError.readOnlyGeometryRequired
        case .io: POSIXError(.EIO)
        case .ownership: AttachmentError.ownershipUnverified
        }
    }
}

private actor RecoveryBackend: AttachmentBackend {
    let failure: RecoveryFailure
    let failReadOnly: Bool
    private(set) var attempts: [ConnectionDescriptor] = []
    private var observations: [UUID: AttachmentInspection] = [:]
    init(_ failure: RecoveryFailure, failReadOnly: Bool) {
        self.failure = failure
        self.failReadOnly = failReadOnly
    }
    func bridgeURL(for id: UUID) -> URL {
        URL(fileURLWithPath: "/unused/ReadOnlyRecovery/\(id)")
    }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        attempts.append(descriptor)
        if !descriptor.readOnly || failReadOnly { throw failure.error }
        let id = try #require(descriptor.mountID)
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: nil, connectionState: .connected)
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        let id = try #require(descriptor.mountID)
        let attachment = DiskAttachment(
            device: "/dev/disk900021", volumeURLs: [URL(fileURLWithPath: "/Volumes/Archive")])
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: attachment, connectionState: .connected)
        return attachment
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        return observations[id] ?? AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        let id = try #require(descriptor.mountID)
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: nil, connectionState: .connected)
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        observations.removeValue(forKey: try #require(descriptor.mountID))
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

@MainActor private final class RecoveryExtensionCheck {
    var pause = false
    private(set) var waiting = false
    private var continuation: CheckedContinuation<Void, Never>?
    func check() async -> AppModel.ExtensionState {
        if pause {
            await withCheckedContinuation { continuation in
                self.continuation = continuation
                waiting = true
            }
        }
        return .ready
    }
    func resume() {
        continuation?.resume()
        continuation = nil
        waiting = false
        pause = false
    }
}

@MainActor private func recoveryFixture(
    _ failure: RecoveryFailure = .completion, failReadOnly: Bool = false
) async throws -> (
    AppModel, RecoveryBackend, RecoverySettings, RecoveryExtensionCheck, ServerProfile, FoundDisk
) {
    let identity = try InitiatorIdentity.makeNew()
    let server = try ServerProfile(name: "Storage", portal: Portal("storage.invalid"))
    let document = try ProfileDocument(identity: identity, servers: [server])
    let settings = RecoverySettings(document)
    let credentials = RecoveryCredentials()
    let configuration = try ServerConfiguration(storage: settings, credentials: credentials)
    let backend = RecoveryBackend(failure, failReadOnly: failReadOnly)
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: MemoryAttachmentJournal())
    try await coordinator.restore()
    let check = RecoveryExtensionCheck()
    let model = AppModel(
        coordinator: coordinator, configuration: configuration, credentials: credentials,
        extensionCheck: { await check.check() })
    model.document = document
    model.selectedServerID = server.id
    model.extensionState = .ready
    model.recoveryComplete = true
    let disk = FoundDisk(
        targetName: "iqn.2026-10.example:recovery",
        inspection: LogicalUnitInspection(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: Data([0, 0, 6, 2, 0])),
                    capacity: try DiskCapacity(readCapacity10: Data([0, 0, 7, 255, 0, 0, 2, 0])),
                    isWriteProtected: false))))
    model.choices[model.choiceKey(server, disk.targetName)] = [disk]
    return (model, backend, settings, check, server, disk)
}

@MainActor private func recoveryWait(_ condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !condition(), ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(2))
    }
    try #require(condition())
}

@MainActor private func failedWritableAttempt(
    _ model: AppModel, server: ServerProfile, disk: FoundDisk
)
    async throws -> ReadOnlyConnectionRequest
{
    model.connect(disk, server: server)
    try await recoveryWait { !model.busy }
    return try #require(model.issue?.readOnlyConnectionRequest)
}

@Test(arguments: [RecoveryFailure.completion, .geometry]) @MainActor
private func explicitReadOnlyRecoveryConnectsOnlyTheRequestedDisk(_ failure: RecoveryFailure)
    async throws
{
    let (model, backend, settings, _, server, disk) = try await recoveryFixture(failure)
    let before = settings.load()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    #expect(await backend.attempts.count == 1)
    #expect(model.attached.isEmpty)
    #expect(request.server == server && request.disk == disk && request.identity == before.identity)
    model.confirmReadOnlyConnection(request)
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { !model.busy }
    let attempts = await backend.attempts
    #expect(attempts.count == 2 && attempts.map(\.readOnly) == [false, true])
    #expect(attempts[0].targetName == attempts[1].targetName && attempts[0].lun == attempts[1].lun)
    #expect(attempts[0].mountID != attempts[1].mountID)
    #expect(model.issue == nil && model.attached.count == 1)
    #expect(model.attached.first?.descriptor.readOnly == true)
    #expect(
        settings.load().identity == before.identity && settings.load().servers == before.servers)
    model.confirmReadOnlyConnection(request)
    #expect(await backend.attempts.count == 2)
}

@Test @MainActor private func cancellingReadOnlyRecoveryDoesNotChangeSettingsOrConnect()
    async throws
{
    let (model, backend, settings, _, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    let before = settings.load()
    model.cancelReadOnlyConnection(request)
    model.confirmReadOnlyConnection(request)
    #expect(model.issue == nil && !model.busy && model.attached.isEmpty)
    #expect(await backend.attempts.count == 1)
    #expect(
        settings.load().identity == before.identity && settings.load().servers == before.servers)
}

private enum ChangedRecoveryContext: CaseIterable {
    case server, identity, selection, information, route, recovery, untracked, editor,
        extensionState, busy
}

@Test(arguments: ChangedRecoveryContext.allCases) @MainActor
private func changedReadOnlyRecoveryContextCannotStartAConnection(_ change: ChangedRecoveryContext)
    async throws
{
    let (model, backend, _, _, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    switch change {
    case .server:
        model.document = try ProfileDocument(
            identity: request.identity,
            servers: [ServerProfile(id: server.id, name: "Changed", portal: server.portal)])
    case .identity:
        model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    case .selection: model.selectedServerID = nil
    case .information:
        model.choices[model.choiceKey(server, disk.targetName)] = [
            FoundDisk(
                targetName: disk.targetName,
                inspection: LogicalUnitInspection(
                    lun: disk.lun, result: .failure(.invalidInformation)))
        ]
    case .route:
        var changed = disk
        changed.connectionAddress = TargetAddress(portal: try Portal("other.invalid"))
        model.choices[model.choiceKey(server, disk.targetName)] = [changed]
    case .recovery: model.recoveryComplete = false
    case .untracked: model.untrackedBridgeURLs = [URL(fileURLWithPath: "/unused/Untracked")]
    case .editor: model.showingServerEditor = true
    case .extensionState: model.extensionState = .disabled
    case .busy: model.busy = true
    }
    model.confirmReadOnlyConnection(request)
    #expect(await backend.attempts.count == 1)
    #expect(model.issue?.readOnlyConnectionRequest == nil)
    #expect(model.issue?.title == String(localized: "The Connection Has Changed"))
    #expect(model.attached.isEmpty)
}

@Test @MainActor private func storedServerChangesAreCheckedAgainBeforeReadOnlyRecovery()
    async throws
{
    let (model, backend, settings, _, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    settings.save(try ProfileDocument(identity: .makeNew(), servers: [server]))
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { !model.busy }
    #expect(await backend.attempts.count == 1)
    #expect(model.issue?.readOnlyConnectionRequest == nil && model.attached.isEmpty)
    #expect(model.issue?.title == String(localized: "The Connection Has Changed"))
}

@Test @MainActor private func readOnlyRecoveryRevalidatesAfterAnExtensionCheck() async throws {
    let (model, backend, _, check, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    check.pause = true
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { check.waiting }
    model.choices.removeAll()
    check.resume()
    try await recoveryWait { !model.busy }
    #expect(await backend.attempts.count == 1)
    #expect(model.issue?.title == String(localized: "The Connection Has Changed"))
    #expect(model.issue?.readOnlyConnectionRequest == nil)
}

@Test(arguments: [RecoveryFailure.io, .ownership]) @MainActor
private func otherConnectionErrorsNeverOfferReadOnlyRecovery(_ failure: RecoveryFailure)
    async throws
{
    let (model, backend, _, _, server, disk) = try await recoveryFixture(failure)
    model.connect(disk, server: server)
    try await recoveryWait { !model.busy }
    #expect(model.issue != nil && model.issue?.readOnlyConnectionRequest == nil)
    #expect(await backend.attempts.count == 1)
}

@Test @MainActor private func failedReadOnlyRecoveryDoesNotOfferAnotherRetry() async throws {
    let (model, backend, _, _, server, disk) = try await recoveryFixture(failReadOnly: true)
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { !model.busy }
    #expect(await backend.attempts.map(\.readOnly) == [false, true])
    #expect(model.issue != nil && model.issue?.readOnlyConnectionRequest == nil)
}

@Test @MainActor private func anotherOperationInvalidatesAPendingReadOnlyRecovery() async throws {
    let (model, backend, _, _, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    model.checkConnections()
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { !model.busy }
    #expect(model.issue?.readOnlyConnectionRequest == nil)
    #expect(await backend.attempts.count == 1)
}

@Test @MainActor private func anotherDiskKeepsTheWritableConnectionChoice() async throws {
    let (model, backend, _, _, server, disk) = try await recoveryFixture()
    let request = try await failedWritableAttempt(model, server: server, disk: disk)
    model.confirmReadOnlyConnection(request)
    try await recoveryWait { !model.busy }
    let other = FoundDisk(
        targetName: "iqn.2026-10.example:other", inspection: disk.inspection)
    model.choices[model.choiceKey(server, other.targetName)] = [other]
    model.connect(other, server: server)
    try await recoveryWait { !model.busy }
    let attempts = await backend.attempts
    #expect(attempts.map(\.readOnly) == [false, true, false])
    #expect(attempts.last?.targetName == other.targetName)
    #expect(model.issue?.readOnlyConnectionRequest?.disk == other)
    #expect(model.attached.count == 1 && model.attached.first?.descriptor.readOnly == true)
}

@Test @MainActor private func connectReadOnlyAppliesOnlyToTheRequestedConnection() async throws {
    let (model, backend, settings, _, server, disk) = try await recoveryFixture()
    let before = settings.load()
    model.connect(disk, server: server, readOnly: true)
    try await recoveryWait { !model.busy }
    // An explicit read-only request never offers a read-only retry of itself.
    #expect(model.issue == nil && model.attached.count == 1)
    #expect(model.attached.first?.descriptor.readOnly == true)
    let other = FoundDisk(
        targetName: "iqn.2026-10.example:writable", inspection: disk.inspection)
    model.choices[model.choiceKey(server, other.targetName)] = [other]
    model.connect(other, server: server)
    try await recoveryWait { !model.busy }
    let attempts = await backend.attempts
    #expect(attempts.map(\.readOnly) == [true, false])
    #expect(attempts.map(\.targetName) == [disk.targetName, other.targetName])
    #expect(model.issue?.readOnlyConnectionRequest?.disk == other)
    #expect(
        settings.load().identity == before.identity && settings.load().servers == before.servers)
}

@Test @MainActor private func aWriteProtectedDiskConnectsReadOnlyWithoutARequest() async throws {
    let (model, backend, _, _, server, disk) = try await recoveryFixture()
    let protected = FoundDisk(
        targetName: "iqn.2026-10.example:protected",
        inspection: LogicalUnitInspection(
            lun: disk.lun,
            result: .success(
                DiskInformation(
                    device: try #require(disk.information).device,
                    capacity: try #require(disk.information).capacity,
                    isWriteProtected: true))))
    model.choices[model.choiceKey(server, protected.targetName)] = [protected]
    model.connect(protected, server: server)
    try await recoveryWait { !model.busy }
    #expect(await backend.attempts.map(\.readOnly) == [true])
    #expect(model.issue == nil && model.attached.first?.descriptor.readOnly == true)
}
