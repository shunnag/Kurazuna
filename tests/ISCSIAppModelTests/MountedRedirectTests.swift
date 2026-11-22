import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

final class MountedRouteSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    private let committedFailure: Bool?
    private var saves = 0
    var saveCount: Int { lock.withLock { saves } }
    init(_ value: ProfileDocument, committedFailure: Bool? = nil) {
        self.value = value
        self.committedFailure = committedFailure
    }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ document: ProfileDocument) throws {
        try lock.withLock {
            saves += 1
            if !document.handledMountRedirects.isEmpty, let committedFailure {
                if committedFailure { value = document }
                throw POSIXError(.ENOSPC)
            }
            value = document
        }
    }
}

private actor MountedRouteCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
}

actor MountedRouteSignal {
    private var complete = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if complete { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func signal() {
        complete = true
        for waiter in waiters { waiter.resume() }
        waiters = []
    }
}

enum MountedRouteObservation: CaseIterable {
    case good, absent, mismatched, interrupted, conflicting
}

actor MountedRouteBackend: AttachmentBackend {
    private var descriptors: [UUID: ConnectionDescriptor] = [:]
    private var images: [UUID: DiskAttachment] = [:]
    private var observation: MountedRouteObservation = .good
    private let permanent: Bool
    private var pause: (MountedRouteSignal, MountedRouteSignal)?
    private(set) var events: [String] = []
    init(permanent: Bool) { self.permanent = permanent }
    func setObservation(_ value: MountedRouteObservation) { observation = value }
    func pauseNextInspection(started: MountedRouteSignal, release: MountedRouteSignal) {
        pause = (started, release)
    }
    func bridgeURL(for id: UUID) -> URL { URL(fileURLWithPath: "/unused/MountedRoute/\(id)") }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        descriptors[try #require(descriptor.mountID)] = descriptor
        events.append("mount")
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        let image = DiskAttachment(device: "/dev/disk900069", volumeURLs: [])
        images[try #require(descriptor.mountID)] = image
        events.append("attach")
        return image
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        let destination = try Portal("storage.local:3269")
        let report = try ConnectionRouteReport(
            resourceIdentity: observation == .mismatched
                ? Data(repeating: 0, count: 32) : descriptor.resourceIdentity,
            connectedPortal: destination, contactedPortals: [descriptor.portal, destination],
            permanentRedirects: permanent
                ? [PermanentPortalRedirect(source: descriptor.portal, destinations: [destination])]
                : [], creationOrder: 1)
        let snapshot = AttachmentInspection(
            ownership: descriptors[id] == nil
                ? .absent : observation == .conflicting ? .conflicting : .verified,
            attachment: images[id],
            connectionState: observation == .interrupted ? .interrupted : .connected,
            connectionRoute: observation == .absent ? nil : report)
        if let (started, release) = pause {
            pause = nil
            await started.signal()
            await release.wait()
        }
        return snapshot
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        images[try #require(descriptor.mountID)] = nil
        events.append("detach")
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        descriptors[try #require(descriptor.mountID)] = nil
        events.append("unmount")
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

@MainActor func mountedRouteFixture(
    permanent: Bool = true, initial: MountedRouteObservation = .good, committedFailure: Bool? = nil,
    sessionFactory: (
        @Sendable ([TargetAddress], LoginConfiguration, [PermanentPortalRedirect]) async throws ->
            SessionConnection
    )? = nil
) async throws
    -> (AppModel, MountedRouteBackend, MountedRouteSettings, ServerProfile)
{
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let storage = MountedRouteSettings(document, committedFailure: committedFailure)
    let credentials = MountedRouteCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let backend = MountedRouteBackend(permanent: permanent)
    await backend.setObservation(initial)
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    let model = AppModel(
        coordinator: coordinator, configuration: configuration, credentials: credentials,
        sessionFactory: sessionFactory, extensionCheck: { .ready })
    model.document = document
    model.recoveryComplete = true
    model.extensionState = .ready
    var inquiry = [UInt8](repeating: 0x20, count: 36)
    inquiry.replaceSubrange(0..<8, with: [0, 0, 6, 2, 31, 0, 0, 0])
    var capacity = [UInt8](repeating: 0, count: 32)
    capacity.put(UInt64(127), at: 0)
    capacity.put(UInt32(512), at: 8)
    let disk = FoundDisk(
        targetName: "iqn.2026-10.test:disk",
        inspection: LogicalUnitInspection(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: Data(inquiry)),
                    capacity: try DiskCapacity(readCapacity16: Data(capacity))))))
    model.connect(disk, server: server)
    try await finishMountedRouteOperation(model)
    return (model, backend, storage, server)
}

@MainActor func finishMountedRouteOperation(_ model: AppModel) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(3))
    while model.busy {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(1))
    }
}

@Test(arguments: [false, true])
@MainActor private func aSuccessfulNativeConnectionReportsItsEndpointAndConsumesItsMetadataOnce(
    _ permanent: Bool
) async throws {
    let (model, backend, storage, server) = try await mountedRouteFixture(permanent: permanent)
    let disk = try #require(model.attached.first)
    #expect(model.issue == nil)
    #expect(disk.connectedPortal == (try Portal("storage.local:3269")))
    #expect(try disk.descriptor.settingsBinding == server.connectionSettingsBinding)
    #expect(storage.load().servers == [server] && storage.load().handledMountRedirects == [disk.id])
    #expect(storage.load().permanentRedirects.count == (permanent ? 1 : 0))
    let saves = storage.saveCount
    await model.refreshConnectionHealth()
    #expect(storage.saveCount == saves)
    #expect(await backend.events == ["mount", "attach"])
    model.eject(disk)
    try await finishMountedRouteOperation(model)
    #expect(model.attached.isEmpty && storage.load().handledMountRedirects.isEmpty)
    #expect(storage.load().permanentRedirects.count == (permanent ? 1 : 0))
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
}

@Test(arguments: MountedRouteObservation.allCases)
@MainActor private func healthRefreshLearnsOnlyValidHealthyOwnedRouteReports(
    _ observation: MountedRouteObservation
) async throws {
    let (model, backend, storage, _) = try await mountedRouteFixture(initial: .absent)
    #expect(storage.load().handledMountRedirects.isEmpty)
    await backend.setObservation(observation)
    await model.refreshConnectionHealth()
    #expect(storage.load().permanentRedirects.count == (observation == .good ? 1 : 0))
    #expect(storage.load().handledMountRedirects.count == (observation == .good ? 1 : 0))
    #expect(await backend.events == ["mount", "attach"])
}

@Test(arguments: [false, true])
@MainActor private func aRouteSaveFailureKeepsTheConnectedDiskAndReflectsActualSettings(
    _ committed: Bool
) async throws {
    let (model, backend, storage, _) = try await mountedRouteFixture(committedFailure: committed)
    #expect(model.issue != nil)
    #expect(model.attached.count == 1 && model.attached[0].connectionState == .connected)
    #expect(!model.attached[0].verificationFailed)
    #expect(model.document == storage.load())
    #expect(storage.load().permanentRedirects.isEmpty == !committed)
    #expect(storage.load().handledMountRedirects.isEmpty == !committed)
    #expect(await backend.events == ["mount", "attach"])
}

@Test @MainActor private func aPausedNativeRouteObservationCannotSaveAfterEjection() async throws {
    let (model, backend, storage, _) = try await mountedRouteFixture(initial: .absent)
    await backend.setObservation(.good)
    let started = MountedRouteSignal()
    let release = MountedRouteSignal()
    await backend.pauseNextInspection(started: started, release: release)
    let refresh = Task { await model.refreshConnectionHealth() }
    await started.wait()
    model.eject(try #require(model.attached.first))
    try await finishMountedRouteOperation(model)
    await release.signal()
    await refresh.value
    #expect(
        model.attached.isEmpty && storage.load().permanentRedirects.isEmpty
            && storage.load().handledMountRedirects.isEmpty)
}
