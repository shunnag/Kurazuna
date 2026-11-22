import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private final class RouteSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    init(_ value: ProfileDocument) { self.value = value }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ value: ProfileDocument) { lock.withLock { self.value = value } }
}

private actor RouteCredentials: CredentialStore {
    private(set) var values: [String: CHAPCredentials] = [:]
    private(set) var copied: [CredentialContext] = []
    func seed(_ source: CredentialContext) throws {
        values[source.account] = try CHAPCredentials(
            username: source.username,
            password: "initiator disposable secret", targetUsername: source.targetUsername,
            targetPassword: source.targetUsername == nil ? nil : "target disposable secret")
    }
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        try #require(values[context.account])
    }
    func copyCredentials(from source: CredentialContext, to destination: CredentialContext) throws {
        values[destination.account] = try #require(values[source.account])
        copied.append(destination)
    }
    func remove(context: CredentialContext) { values[context.account] = nil }
}

private actor RouteMounts: AttachmentBackend {
    private var descriptors: [UUID: ConnectionDescriptor] = [:]
    private var images: [UUID: DiskAttachment] = [:]
    private var fault: Int
    private(set) var mounted: [ConnectionDescriptor] = []
    init(fault: Int) { self.fault = fault }
    func allow() { fault = 0 }
    func bridgeURL(for id: UUID) -> URL { URL(fileURLWithPath: "/unused/\(id)") }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        descriptors[try #require(descriptor.mountID)] = descriptor
        mounted.append(descriptor)
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        return AttachmentInspection(
            ownership: descriptors[id] == nil ? .absent : fault == 3 ? .conflicting : .verified,
            attachment: images[id], connectionState: .connected)
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        if fault == 1 { throw POSIXError(.EIO) }
        let attachment = DiskAttachment(device: "/dev/disk900001", volumeURLs: [])
        images[try #require(descriptor.mountID)] = attachment
        return attachment
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        if fault == 2 { throw POSIXError(.EBUSY) }
        images[try #require(descriptor.mountID)] = nil
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        descriptors[try #require(descriptor.mountID)] = nil
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

@Test(
    arguments: [
        (0, false), (0, true), (1, false), (1, true), (2, false), (2, true), (3, false), (3, true),
    ],
    [false, true])
@MainActor
private func mountingUsesTheInspectedEndpointAndRetainsCredentialsUntilItsRecordIsRemoved(
    _ connectionCase: (fault: Int, mutual: Bool), _ protected: Bool
) async throws {
    let (fault, mutual) = connectionCase
    let server = try ServerProfile(
        name: "Archive", portal: Portal("discovery.local"),
        chapUsername: "User", credentialID: UUID(), targetCHAPUsername: mutual ? "Server" : nil)
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let settings = RouteSettings(document)
    let credentials = RouteCredentials()
    let source = try #require(server.credentialContext)
    try await credentials.seed(source)
    let configuration = try ServerConfiguration(storage: settings, credentials: credentials)
    let mounts = RouteMounts(fault: fault)
    let coordinator = try AttachmentCoordinator(backend: mounts)
    try await coordinator.restore()
    let model = AppModel(
        coordinator: coordinator, configuration: configuration,
        credentials: credentials, extensionCheck: { .ready })
    model.document = document
    model.recoveryComplete = true
    model.extensionState = .ready
    var inquiry = [UInt8](repeating: 0x20, count: 36)
    inquiry.replaceSubrange(0..<8, with: [0, 0, 6, 2, 31, 0, 0, 0])
    var capacity = [UInt8](repeating: 0, count: 32)
    capacity.put(UInt64(7), at: 0)
    capacity.put(UInt32(512), at: 8)
    let address = TargetAddress(portal: try Portal("storage.local:3271"), portalGroupTag: 17)
    let disk = FoundDisk(
        targetName: "iqn.2026-10.test:disk",
        inspection: LogicalUnitInspection(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: Data(inquiry)),
                    capacity: try DiskCapacity(readCapacity16: Data(capacity)),
                    isWriteProtected: protected))),
        connectionAddress: address)
    func finish() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while model.busy {
            guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    model.connect(disk, server: server)
    try await finish()
    let mounted = try #require(await mounts.mounted.first)
    let copy = try #require(await credentials.copied.first)
    #expect(mounted.portal == address.portal && mounted.portalGroupTag == 17)
    #expect(mounted.readOnly == protected)
    // A read-only connection is a per-disk choice; see ReadOnlyConnectionTests for the next disk.
    #expect(try mounted.settingsBinding == server.connectionSettingsBinding)
    #expect(mounted.credentialID == copy.credentialID && copy.portal == address.portal)
    #expect(mounted.credentialID != source.credentialID)
    #expect(settings.load().servers == [server])
    #expect(await credentials.values[source.account] != nil)
    if fault == 1 {
        #expect(model.attached.isEmpty)
        #expect(await credentials.values[copy.account] == nil)
        #expect(settings.load().pendingCredentialRemovals.isEmpty)
        return
    }
    #expect(model.attached.count == 1)
    #expect(await credentials.values[copy.account] != nil)
    #expect(!model.credentialCleanupNeeded)
    if fault == 0 {
        let unused = CredentialContext(
            profileID: server.id, portal: try Portal("unused.local"),
            username: source.username, credentialID: UUID(), targetUsername: source.targetUsername)
        var withUnused = settings.load()
        withUnused.pendingCredentialRemovals.append(unused)
        settings.save(withUnused)
        try await configuration.reload()
        model.document = settings.load()
        model.credentialCleanupNeeded = true
        #expect(!model.credentialCleanupNeedsEject)
        model.retryCredentialCleanup()
        try await finish()
        #expect(!model.credentialCleanupNeeded)
        #expect(await credentials.values[copy.account] != nil)
        #expect(settings.load().pendingCredentialRemovals == [copy])
    }
    model.eject(try #require(model.attached.first))
    try await finish()
    if fault == 2 || fault == 3 {
        #expect(model.attached.count == 1)
        #expect(await credentials.values[copy.account] != nil)
        await mounts.allow()
        model.eject(try #require(model.attached.first))
        try await finish()
    }
    #expect(model.attached.isEmpty)
    #expect(await credentials.values[copy.account] == nil)
    #expect(await credentials.values[source.account] != nil)
    #expect(settings.load().pendingCredentialRemovals.isEmpty)
}
