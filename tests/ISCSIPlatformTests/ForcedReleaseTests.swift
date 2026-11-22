import Darwin
import DiskArbitration
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

/// A simulated bridge: the private marker, its FSKit mount, and the inner Disk.img.
private final class ForcedBridgeState: @unchecked Sendable {
    private let lock = NSLock()
    let bridge: URL
    let marker: URL
    private var markerAttached = false
    private var markerMounted = false
    private var innerAttached = false
    private var mountType = ApplicationIdentity.current.fileSystemType
    private var mountSource = "/dev/disk900000"
    private var forcedUnmounts = 0
    private var markerEjections = 0
    private var innerForcedEjections = 0
    private var otherCommands: [[String]] = []

    init(bridge: URL, marker: URL) {
        self.bridge = bridge
        self.marker = marker
    }

    var forcedUnmountCount: Int { lock.withLock { forcedUnmounts } }
    var markerEjectionCount: Int { lock.withLock { markerEjections } }
    var innerForcedEjectionCount: Int { lock.withLock { innerForcedEjections } }
    var isMarkerAttached: Bool { lock.withLock { markerAttached } }
    var isInnerAttached: Bool { lock.withLock { innerAttached } }
    var unexpectedCommands: [[String]] { lock.withLock { otherCommands } }

    func mountBridge() {
        lock.withLock {
            markerMounted = true
            innerAttached = true
        }
    }
    func unmountBridgeOutsideTheApp() { lock.withLock { markerMounted = false } }
    func detachInnerOutsideTheApp() { lock.withLock { innerAttached = false } }
    func replaceMount(type: String? = nil, source: String? = nil) {
        lock.withLock {
            if let type { mountType = type }
            if let source { mountSource = source }
        }
    }

    func mounts() -> [CachedMountTable.Entry] {
        lock.withLock {
            guard markerMounted else { return [] }
            return [
                .init(
                    type: mountType, source: mountSource, path: bridge.path, owner: getuid(),
                    flags: 0, fileSystemID: .init(first: 17, second: 24))
            ]
        }
    }

    func media(_ device: String) throws -> BlockResourceMedia {
        try BlockResourceMedia(
            device: device, identifier: 41,
            description: [
                kDADiskDescriptionMediaWholeKey as String: true,
                kDADiskDescriptionMediaWritableKey as String: true,
                kDADiskDescriptionMediaSizeKey as String: UInt64(1_048_576),
                kDADiskDescriptionMediaBlockSizeKey as String: UInt64(512),
            ])
    }

    func run(_ program: String, _ arguments: [String], _ timeout: TimeInterval) throws -> Data {
        if program == "/usr/bin/hdiutil", arguments == ["info", "-plist"] {
            return try lock.withLock {
                var images: [[String: Any]] = []
                if markerAttached {
                    var entity: [String: Any] = ["dev-entry": "/dev/disk900000"]
                    if markerMounted { entity["mount-point"] = bridge.path }
                    images.append(["image-path": marker.path, "system-entities": [entity]])
                }
                if innerAttached {
                    images.append([
                        "image-path": bridge.appendingPathComponent("Disk.img").path,
                        "system-entities": [
                            ["dev-entry": "/dev/disk900002"],
                            ["dev-entry": "/dev/disk900002s1", "mount-point": "/Volumes/Work"],
                        ],
                    ])
                }
                return try PropertyListSerialization.data(
                    fromPropertyList: ["images": images], format: .binary, options: 0)
            }
        }
        if program == "/usr/bin/hdiutil", arguments.first == "attach" {
            lock.withLock { markerAttached = true }
            return try PropertyListSerialization.data(
                fromPropertyList: ["system-entities": [["dev-entry": "/dev/disk900000"]]],
                format: .binary, options: 0)
        }
        if program == "/sbin/umount", arguments == ["-f", bridge.path] {
            lock.withLock {
                forcedUnmounts += 1
                markerMounted = false
            }
            return Data()
        }
        if program == "/usr/sbin/lsof" {
            throw SystemCommandError.failed(program: "lsof", status: 1, detail: "")
        }
        lock.withLock { otherCommands.append([program] + arguments) }
        throw ProtocolError.invalidState
    }

    func ejectedMarker() {
        lock.withLock {
            markerAttached = false
            markerEjections += 1
        }
    }
    func forcedInnerEjection() {
        lock.withLock {
            innerAttached = false
            innerForcedEjections += 1
        }
    }
}

private actor ForcedEjection: DiskEjectionService {
    let state: ForcedBridgeState
    /// An earlier, timed-out ejection of these images that the OS hasn't answered yet.
    private var pending: Set<String> = []
    private(set) var waits = 0
    /// What `probe` reported at each confirmed (normal) marker ejection.
    private(set) var observedAtConfirmedEjection: [Int] = []
    private var probe: (@Sendable () async -> Int)?
    /// Confirmed ejections that still find the marker open, as an exiting extension leaves it.
    private var busyConfirmedEjections = 0
    init(_ state: ForcedBridgeState) { self.state = state }
    func failConfirmedEjections(_ count: Int) { busyConfirmedEjections = count }
    func observeConfirmedEjections(_ probe: @escaping @Sendable () async -> Int) {
        self.probe = probe
    }
    func pendingImagePaths() -> Set<String> { pending }
    func setPending(_ paths: Set<String>) { pending = paths }
    /// The earlier request ends once the extension stopped reconnecting.
    func waitForPendingEjection(of image: URL, timeout: Duration) -> Bool {
        waits += 1
        pending.remove(image.standardizedFileURL.path)
        return true
    }
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) throws {
        Issue.record("A forced release never asks for an unconfirmed ejection")
        throw ProtocolError.invalidState
    }
    func ejectConfirmed(
        device: String, image: URL, unmountDevices: [String], mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        #expect(device == "/dev/disk900000" && mediaIdentifiers == [device: 41])
        if let probe { observedAtConfirmedEjection.append(await probe()) }
        try await validate()
        if busyConfirmedEjections > 0 {
            busyConfirmedEjections -= 1
            throw POSIXError(.EBUSY)
        }
        state.ejectedMarker()
    }
    func forceEject(
        device: String, image: URL, unmountDevices: [String], mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        #expect(device == "/dev/disk900002" && unmountDevices == [device])
        #expect(mediaIdentifiers == [device: 77])
        try await validate()
        state.forcedInnerEjection()
    }
}

private actor ForcedMetadata: MountResourceStore {
    private var values: [String: ConnectionDescriptor] = [:]
    var count: Int { values.count }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        let reference = try ConnectionResourceReference(descriptor: descriptor)
        values[reference.account] = descriptor
        return reference
    }
    func resolve(_ reference: ConnectionResourceReference) throws -> ConnectionDescriptor {
        guard let value = values[reference.account] else { throw POSIXError(.ENOENT) }
        return value
    }
    func remove(_ reference: ConnectionResourceReference) {
        values.removeValue(forKey: reference.account)
    }
}

/// What the mounted bridge returns for its identity attribute.
private enum IdentityReply: String, CaseIterable {
    case matching, other, short, oversized, missing, unsupported, ioError, noDevice, noAnswer

    func read(expected: Data) -> BridgeAttributeRead {
        switch self {
        case .matching: .value(Array(expected))
        case .other: .value(Array(repeating: 0xEE, count: 32))
        case .short: .value(Array(expected.prefix(16)))
        case .oversized: .failed(ERANGE)
        case .missing: .failed(ENOATTR)
        case .unsupported: .failed(ENOTSUP)
        case .ioError: .failed(EIO)
        case .noDevice: .failed(ENXIO)
        case .noAnswer: .timedOut
        }
    }

    /// Only an answer that names another resource is a conflict.
    var isConflict: Bool { [.other, .short, .oversized].contains(self) }
}

private final class AttributeReplies: @unchecked Sendable {
    private let lock = NSLock()
    private var identity: IdentityReply
    private var state: DiskConnectionState?
    private var reads: [String] = []
    private var written: [String] = []
    init(_ identity: IdentityReply, state: DiskConnectionState? = nil) {
        self.identity = identity
        self.state = state
    }
    var names: [String] { lock.withLock { reads } }
    var writes: [String] { lock.withLock { written } }
    /// Paths whose attribute write fails, as the kernel may refuse one on a read-only item.
    private var refused: Set<String> = []
    /// Every write fails with this, as on a read-only mount (EROFS).
    private var everyWrite: Int32?
    /// The extension answers a read of the read-only volume's control.
    private var readOnlyControl = false
    func refuseWrites(to path: String) { lock.withLock { _ = refused.insert(path) } }
    func refuseEveryWrite(_ code: Int32) { lock.withLock { everyWrite = code } }
    func answerReadOnlyControl() { lock.withLock { readOnlyControl = true } }
    func write(path: String, name: String, value: Data) -> BridgeAttributeWrite {
        lock.withLock {
            written.append("\(path):\(name)=\(String(decoding: value, as: UTF8.self))")
            if let everyWrite { return .failed(everyWrite) }
            return refused.contains(path) ? .failed(EACCES) : .written
        }
    }
    func read(name: String, expected: Data) -> BridgeAttributeRead {
        lock.withLock {
            reads.append(name)
            if name == ConnectionDescriptor.readOnlyConnectionControlAttributeName {
                return readOnlyControl
                    ? .value(Array(ConnectionDescriptor.abandonRecoveryControlValue))
                    : .failed(ENOATTR)
            }
            if name == ConnectionDescriptor.identityAttributeName {
                return identity.read(expected: expected)
            }
            guard name == ConnectionDescriptor.connectionStateAttributeName, let state else {
                return .failed(ENOATTR)
            }
            return .value(Array(state.encoded))
        }
    }
}

/// A mounted bridge whose extension never answers: each call into it blocks until the test
/// ends, and only the backend's deadline returns control. It also counts the path queries a
/// forced release must never make (lstat and statfs on the bridge).
private final class StuckBridge: @unchecked Sendable {
    let deadline = Duration.milliseconds(50)
    private let condition = NSCondition()
    private var released = false
    private var blocked = 0
    private var queried = 0
    var blockedCalls: Int { condition.withLock { blocked } }
    var pathQueries: Int { condition.withLock { queried } }

    /// Never returns before `release()`.
    func block<Value>(_ value: Value) -> Value {
        condition.withLock {
            blocked += 1
            while !released { condition.wait() }
        }
        return value
    }

    func bounded<Value: Sendable>(_ timedOut: Value, _ value: Value) async -> Value {
        await BoundedCall.run(deadline: deadline, timedOut: timedOut) { self.block(value) }
    }

    func release() {
        condition.withLock {
            released = true
            condition.broadcast()
        }
    }

    var paths: SystemAttachmentBackend.PathQueries {
        .init(
            resolve: { url in
                self.condition.withLock { self.queried += 1 }
                return url.path
            },
            status: { _ in
                self.condition.withLock { self.queried += 1 }
                return .failure(POSIXError(.ENOENT))
            })
    }
}

private struct ForcedFixture {
    let root: URL
    let id = UUID()
    let descriptor: ConnectionDescriptor
    let bridge: URL
    let state: ForcedBridgeState
    let replies: AttributeReplies
    let metadata = ForcedMetadata()
    let backend: SystemAttachmentBackend
    let blockResources: BlockMountResources
    let ejection: ForcedEjection

    init(
        _ identity: IdentityReply, connectionState: DiskConnectionState? = nil,
        stuck: StuckBridge? = nil
    ) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            .resolvingSymlinksInPath()
        descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: Portal("example.invalid"),
            initiatorName: "iqn.2026-10.test:forced", targetName: "iqn.2026-10.test:disk",
            lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
        bridge = root.appendingPathComponent(id.uuidString, isDirectory: true)
        let state = ForcedBridgeState(
            bridge: bridge,
            marker: root.appendingPathComponent(".Resources/\(id.uuidString).img"))
        self.state = state
        let replies = AttributeReplies(identity, state: connectionState)
        self.replies = replies
        let ejection = ForcedEjection(state)
        self.ejection = ejection
        let files = OwnedBlockResourceFiles(bridgeRoot: root, mounts: state.mounts)
        // A busy marker fails at once here, as it did before the bounded wait (REC022).
        blockResources = BlockMountResources(
            files: files, run: { try state.run($0, $1, $2) }, media: state.media,
            ejection: ejection, mounts: state.mounts,
            busyWait: .init(
                limit: .zero, interval: .milliseconds(500), now: { ContinuousClock.now },
                sleep: { _ in Issue.record("No busy wait is expected") }))
        let expected = try descriptor.resourceIdentity
        let diskImages = DiskImages(
            run: { try state.run($0, $1, $2) }, fileSize: { _ in 0 }, ejection: ejection,
            mediaIdentifiers: { devices in
                Dictionary(uniqueKeysWithValues: devices.map { ($0, UInt64(77)) })
            })
        if let stuck {
            backend = SystemAttachmentBackend(
                root: root, resources: metadata, blockResources: blockResources,
                diskImages: diskImages,
                mountCommand: { _, _, _ in throw ProtocolError.invalidState },
                readAttribute: { _, name, _ in
                    await stuck.bounded(.timedOut, replies.read(name: name, expected: expected))
                },
                writeAttribute: { path, name, value in
                    await stuck.bounded(
                        .timedOut, replies.write(path: path, name: name, value: value))
                },
                removeDirectory: { path in await stuck.bounded(.timedOut, .removed) },
                mounts: state.mounts, paths: stuck.paths)
        } else {
            backend = SystemAttachmentBackend(
                root: root, resources: metadata, blockResources: blockResources,
                diskImages: diskImages,
                mountCommand: { _, _, _ in throw ProtocolError.invalidState },
                readAttribute: { _, name, _ in replies.read(name: name, expected: expected) },
                writeAttribute: { replies.write(path: $0, name: $1, value: $2) },
                mounts: state.mounts)
        }
    }

    /// Creates the marker, its mount and the inner image, as a connection would.
    func connect() async throws {
        _ = try await metadata.save(descriptor)
        _ = try await blockResources.prepare(descriptor)
        try FileManager.default.createDirectory(
            at: bridge, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        state.mountBridge()
    }

    func cleanup() {
        _ = unlink(state.marker.path)
        _ = rmdir(root.appendingPathComponent(".Resources").path)
        _ = rmdir(bridge.path)
        _ = rmdir(root.path)
    }
}

@Test(arguments: IdentityReply.allCases)
private func aForcedReleaseProvesOwnershipLocallyAndRefusesOnlyAnotherIdentity(
    _ reply: IdentityReply
) async throws {
    let f = try ForcedFixture(reply)
    defer { f.cleanup() }
    try await f.connect()
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    #expect(inspection.attachment?.device == "/dev/disk900002")
    #expect(inspection.ownership == (reply.isConflict ? .conflicting : .verified))
    // Without a matching identity answer, the extension's state isn't trusted or read.
    #expect(inspection.connectionState == .unknown)
    #expect(
        f.replies.names
            == [ConnectionDescriptor.identityAttributeName]
            + (reply == .matching ? [ConnectionDescriptor.connectionStateAttributeName] : []))
    guard !reply.isConflict else {
        await #expect(throws: AttachmentError.ownershipUnverified) {
            try await f.backend.forcedReleaseIdentity(
                inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
        }
        #expect(f.state.innerForcedEjectionCount == 0 && f.state.isInnerAttached)
        // Even with the inner image gone, the bridge itself is never forced.
        f.state.detachInnerOutsideTheApp()
        await #expect(throws: AttachmentError.ownershipUnverified) {
            try await f.backend.forceReleaseBridge(
                ForcedReleaseIdentity(image: nil), descriptor: f.descriptor,
                bridgeURL: f.bridge)
        }
        #expect(f.state.forcedUnmountCount == 0 && f.state.markerEjectionCount == 0)
        #expect(f.state.isMarkerAttached)
        #expect(FileManager.default.fileExists(atPath: f.bridge.path))
        #expect(await f.metadata.count == 1)
        return
    }
    let identity = try await f.backend.forcedReleaseIdentity(
        inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(identity.image?.device == "/dev/disk900002")
    #expect(identity.bridgeMounted && identity.bridgeResource != nil)
    try await f.backend.forceReleaseImage(identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.innerForcedEjectionCount == 1 && !f.state.isInnerAttached)
    try await f.backend.forceReleaseBridge(identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.forcedUnmountCount == 1)
    #expect(f.state.markerEjectionCount == 1 && !f.state.isMarkerAttached)
    #expect(!FileManager.default.fileExists(atPath: f.bridge.path))
    #expect(!FileManager.default.fileExists(atPath: f.state.marker.path))
    #expect(await f.metadata.count == 0)
    #expect(f.state.unexpectedCommands.isEmpty)
}

@Test func aMatchingIdentityAnswerAlsoReportsTheExtensionsConnectionState() async throws {
    let f = try ForcedFixture(.matching, connectionState: .interrupted)
    defer { f.cleanup() }
    try await f.connect()
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    #expect(inspection.ownership == .verified && inspection.connectionState == .interrupted)
}

@Test(arguments: ["type", "source"])
func aMountAtTheBridgeThatIsNotThisRecordsMarkerIsNeverForced(_ change: String) async throws {
    let f = try ForcedFixture(.noAnswer)
    defer { f.cleanup() }
    try await f.connect()
    f.state.replaceMount(
        type: change == "type" ? "apfs" : nil,
        source: change == "source" ? "/dev/disk900001" : nil)
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    }
    f.state.detachInnerOutsideTheApp()
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await f.backend.forceReleaseBridge(
            ForcedReleaseIdentity(image: nil), descriptor: f.descriptor, bridgeURL: f.bridge)
    }
    // The attribute isn't even read for a mount the marker doesn't bind.
    #expect(f.replies.names.isEmpty)
    #expect(f.state.forcedUnmountCount == 0 && f.state.markerEjectionCount == 0)
}

@Test func anInnerImageWithoutItsBridgeMountIsAConflict() async throws {
    let f = try ForcedFixture(.noAnswer)
    defer { f.cleanup() }
    try await f.connect()
    f.state.unmountBridgeOutsideTheApp()
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    #expect(inspection.ownership == .conflicting && inspection.attachment != nil)
}

@Test func eachForcedStepSkipsWhatAnEarlierAttemptAlreadyReleased() async throws {
    let f = try ForcedFixture(.ioError)
    defer { f.cleanup() }
    try await f.connect()
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    let identity = try await f.backend.forcedReleaseIdentity(
        inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
    // The image and then the bridge went away before this attempt reached them.
    f.state.detachInnerOutsideTheApp()
    try await f.backend.forceReleaseImage(identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.innerForcedEjectionCount == 0)
    f.state.unmountBridgeOutsideTheApp()
    try await f.backend.forceReleaseBridge(identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.forcedUnmountCount == 0)
    // The remaining marker is ejected normally, then the local resources are discarded.
    #expect(f.state.markerEjectionCount == 1)
    #expect(!FileManager.default.fileExists(atPath: f.state.marker.path))
    #expect(await f.metadata.count == 0)
    // A repeated attempt finds nothing left and succeeds without acting.
    try await f.backend.forceReleaseBridge(
        ForcedReleaseIdentity(image: nil, bridgeMounted: false, bridgeResource: nil),
        descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.markerEjectionCount == 1)
}

@Test func discardingAnUnmountedBridgeWithdrawsItsResourceBeforeEjectingTheMarker()
    async throws
{
    // REC022: an extension instance still loading the marker, or holding it loaded but never
    // mounted, gives it up once its mount resource is gone; the marker is ejected after that.
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    f.state.unmountBridgeOutsideTheApp()
    f.state.detachInnerOutsideTheApp()
    let metadata = f.metadata
    await f.ejection.observeConfirmedEjections { await metadata.count }
    #expect(await metadata.count == 1)
    try await f.backend.discardEmptyBridge(f.descriptor, at: f.bridge)
    #expect(await f.ejection.observedAtConfirmedEjection == [0])
    #expect(f.state.markerEjectionCount == 1)
    #expect(!FileManager.default.fileExists(atPath: f.bridge.path))
    #expect(!FileManager.default.fileExists(atPath: f.state.marker.path))
    #expect(await metadata.count == 0)
}

@Test func aWithdrawnResourceStaysWithdrawnWhenTheMarkerIsStillBusy() async throws {
    // REC022: the withdrawal happens before the marker cleanup, so a marker still open past
    // the bounded wait leaves no mount resource behind; a later discard finishes the cleanup.
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    f.state.unmountBridgeOutsideTheApp()
    f.state.detachInnerOutsideTheApp()
    await f.ejection.failConfirmedEjections(1)
    await #expect(throws: POSIXError(.EBUSY)) {
        try await f.backend.discardEmptyBridge(f.descriptor, at: f.bridge)
    }
    #expect(await f.metadata.count == 0)
    #expect(!FileManager.default.fileExists(atPath: f.bridge.path))
    #expect(f.state.markerEjectionCount == 0)
    #expect(FileManager.default.fileExists(atPath: f.state.marker.path))
    try await f.backend.discardEmptyBridge(f.descriptor, at: f.bridge)
    #expect(f.state.markerEjectionCount == 1)
    #expect(!FileManager.default.fileExists(atPath: f.state.marker.path))
    #expect(await f.metadata.count == 0)
}

@Test(arguments: [AttachmentPhase.mountingBridge, .unmountingBridge])
func restoreCleansUpAMarkerWhoseResourceWasAlreadyWithdrawn(_ phase: AttachmentPhase)
    async throws
{
    // REC022 crash window: the app withdrew the mount resource and ended before it ejected the
    // marker. The bridge directory is gone; the marker is still attached; the resource is absent.
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    f.state.unmountBridgeOutsideTheApp()
    f.state.detachInnerOutsideTheApp()
    #expect(rmdir(f.bridge.path) == 0)
    try await f.metadata.remove(ConnectionResourceReference(descriptor: f.descriptor))
    #expect(await f.metadata.count == 0)
    #expect(f.state.isMarkerAttached)
    let journal = MemoryAttachmentJournal(entries: [
        try AttachmentJournalEntry(
            id: f.id, descriptor: f.descriptor, bridgeURL: f.bridge, phase: phase)
    ])
    let coordinator = try AttachmentCoordinator(backend: f.backend, journal: journal)
    try await coordinator.restore()
    #expect(await coordinator.disks.isEmpty && journal.load().isEmpty)
    #expect(await coordinator.recoveryReady)
    #expect(f.state.markerEjectionCount == 1 && !f.state.isMarkerAttached)
    #expect(!FileManager.default.fileExists(atPath: f.state.marker.path))
}

@Test func cleaningUpAFailedAttemptNeverWithdrawsTheRetryOfTheSameDisk() async throws {
    // Every connection attempt has its own mount ID, and the resource key includes it.
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    let retry = try f.descriptor.assigningMountID(UUID())
    let retryReference = try await f.metadata.save(retry)
    let failedReference = try ConnectionResourceReference(descriptor: f.descriptor)
    #expect(failedReference.account != retryReference.account)
    #expect(failedReference.mountID != retryReference.mountID)
    f.state.unmountBridgeOutsideTheApp()
    f.state.detachInnerOutsideTheApp()
    // The failed attempt's marker is still busy: its cleanup stays pending.
    await f.ejection.failConfirmedEjections(1)
    await #expect(throws: POSIXError(.EBUSY)) {
        try await f.backend.discardEmptyBridge(f.descriptor, at: f.bridge)
    }
    #expect(try await f.metadata.resolve(retryReference) == retry)
    await #expect(throws: (any Error).self) { try await f.metadata.resolve(failedReference) }
    try await f.backend.discardEmptyBridge(f.descriptor, at: f.bridge)
    #expect(f.state.markerEjectionCount == 1)
    #expect(try await f.metadata.resolve(retryReference) == retry)
    #expect(await f.metadata.count == 1)
}

@Test func aBridgeMountedAfterTheObservationIsNotTheOneConfirmed() async throws {
    let f = try ForcedFixture(.noAnswer)
    defer { f.cleanup() }
    try await f.connect()
    let observed = ForcedReleaseIdentity(image: nil, bridgeMounted: false, bridgeResource: nil)
    f.state.detachInnerOutsideTheApp()
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await f.backend.forceReleaseBridge(
            observed, descriptor: f.descriptor, bridgeURL: f.bridge)
    }
    #expect(f.state.forcedUnmountCount == 0 && f.state.isMarkerAttached)
}

/// The ordinary inspection can't verify the bridge, so launch recovery leaves it for an
/// explicit decision; the confirmed forced release then completes through every step.
@Test func theCoordinatorReleasesAnUnverifiableBridgeOnlyAfterConfirmation() async throws {
    let f = try ForcedFixture(.noDevice)
    defer { f.cleanup() }
    try await f.connect()
    let journal = MemoryAttachmentJournal(entries: [
        try AttachmentJournalEntry(
            id: f.id, descriptor: f.descriptor, bridgeURL: f.bridge, phase: .connected)
    ])
    let coordinator = try AttachmentCoordinator(backend: f.backend, journal: journal)
    await #expect(throws: (any Error).self) { try await coordinator.restore() }
    let disk = try #require(await coordinator.disks.first)
    #expect(disk.verificationFailed && disk.offersForcedRelease)
    #expect(f.state.forcedUnmountCount == 0 && f.state.innerForcedEjectionCount == 0)
    let request = try await coordinator.prepareForceEjection(f.id)
    #expect(request.reportsLostConnection && request.displayName == "Work")
    #expect(f.state.forcedUnmountCount == 0 && f.state.innerForcedEjectionCount == 0)
    try await coordinator.forceEject(request)
    #expect(f.state.innerForcedEjectionCount == 1)
    #expect(f.state.forcedUnmountCount == 1 && f.state.markerEjectionCount == 1)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.disks.isEmpty)
    #expect(await f.metadata.count == 0)
}

@Test func aBoundedAttributeReadReturnsAnAnswerOrItsError() async throws {
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try Data().write(to: file)
    defer { try? FileManager.default.removeItem(at: file) }
    let value: [UInt8] = [1, 2, 3]
    #expect(setxattr(file.path, "dev.soba.iscsi.test", value, value.count, 0, 0) == 0)
    #expect(
        await BridgeAttributeRead.bounded(
            path: file.path, name: "dev.soba.iscsi.test", capacity: 33)
            == .value(value))
    #expect(
        await BridgeAttributeRead.bounded(path: file.path, name: "dev.soba.iscsi.test", capacity: 2)
            == .failed(ERANGE))
    #expect(
        await BridgeAttributeRead.bounded(
            path: file.path, name: "dev.soba.iscsi.absent", capacity: 33) == .failed(ENOATTR))
}

@Test(arguments: IdentityReply.allCases)
private func onlyThisRecordsMountedBridgeIsAskedToStopReconnecting(_ reply: IdentityReply)
    async throws
{
    let f = try ForcedFixture(reply)
    defer { f.cleanup() }
    // Nothing is mounted yet: there is no extension to ask.
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    #expect(f.replies.writes.isEmpty)
    try await f.connect()
    let name = ConnectionDescriptor.connectionControlAttributeName
    let image = "\(f.bridge.appendingPathComponent("Disk.img").path):\(name)=abandon"
    let root = "\(f.bridge.path):\(name)=abandon"
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    // A bridge answering with another identity isn't this record's; never write to it.
    #expect(f.replies.writes == (reply.isConflict ? [] : [image]))
    // Only a refused write to the image is followed by one to the root directory.
    f.replies.refuseWrites(to: f.bridge.appendingPathComponent("Disk.img").path)
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    #expect(f.replies.writes == (reply.isConflict ? [] : [image, image, root]))
    // The request releases nothing by itself.
    #expect(f.state.forcedUnmountCount == 0 && f.state.innerForcedEjectionCount == 0)
}

@Test func aReleaseRefusedBeforeReleasingNeverAsksTheExtensionToStop() async throws {
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    let identity = try await f.backend.forcedReleaseIdentity(
        inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
    let backend = f.backend
    let descriptor = f.descriptor
    let bridge = f.bridge
    let stop: @Sendable () async -> Void = {
        await backend.abandonConnectionRecovery(descriptor, at: bridge)
    }
    // The bridge was replaced after confirmation: the image step refuses before releasing.
    f.state.replaceMount(source: "/dev/disk900001")
    await #expect(throws: AttachmentError.self) {
        try await f.backend.forceReleaseImage(
            identity, descriptor: f.descriptor, bridgeURL: f.bridge, beforeReleasing: stop)
    }
    #expect(f.replies.writes.isEmpty)
    #expect(f.state.innerForcedEjectionCount == 0 && f.state.isInnerAttached)
    // Unchanged, the request comes after every check and before the forced ejection.
    f.state.replaceMount(source: "/dev/disk900000")
    try await f.backend.forceReleaseImage(
        identity, descriptor: f.descriptor, bridgeURL: f.bridge, beforeReleasing: stop)
    let name = ConnectionDescriptor.connectionControlAttributeName
    #expect(
        f.replies.writes == ["\(f.bridge.appendingPathComponent("Disk.img").path):\(name)=abandon"])
    #expect(f.state.innerForcedEjectionCount == 1)
}

@Test func aForcedReleaseOfABridgeThatNeverAnswersEndsWithinItsDeadlines() async throws {
    let stuck = StuckBridge()
    defer { stuck.release() }
    let f = try ForcedFixture(.matching, stuck: stuck)
    defer { f.cleanup() }
    try await f.connect()
    let started = ContinuousClock.now
    let backend = f.backend
    let descriptor = f.descriptor
    let bridge = f.bridge
    // The identity read never returns: ownership is proven from local facts alone.
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    #expect(inspection.ownership == .verified && inspection.connectionState == .unknown)
    let identity = try await f.backend.forcedReleaseIdentity(
        inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
    try await f.backend.forceReleaseImage(
        identity, descriptor: f.descriptor, bridgeURL: f.bridge,
        beforeReleasing: { await backend.abandonConnectionRecovery(descriptor, at: bridge) })
    #expect(f.state.innerForcedEjectionCount == 1)
    // The bridge is unmounted; removing its directory doesn't finish in time either.
    await #expect(throws: POSIXError(.ETIMEDOUT)) {
        try await f.backend.forceReleaseBridge(
            identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    }
    #expect(f.state.forcedUnmountCount == 1)
    #expect(stuck.blockedCalls > 0)
    #expect(stuck.pathQueries == 0)
    #expect(ContinuousClock.now - started < .seconds(3))
}

@Test func aLegacyBridgeThatNeverAnswersFailsWithinItsDeadline() async throws {
    let stuck = StuckBridge()
    defer { stuck.release() }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:forced", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let bridge = root.appendingPathComponent(id.uuidString, isDirectory: true)
    let state = ForcedBridgeState(bridge: bridge, marker: root.appendingPathComponent("unused"))
    let commands = state
    // A URL bridge of this app, mounted at the bridge, with no marker to bind it locally.
    let mount = CachedMountTable.Entry(
        type: ApplicationIdentity.current.fileSystemType, source: "iscsi://example.invalid",
        path: bridge.path, owner: getuid(), flags: 0)
    let backend = SystemAttachmentBackend(
        root: root,
        diskImages: DiskImages(
            run: { try commands.run($0, $1, $2) }, fileSize: { _ in 0 },
            ejection: ForcedEjection(state), mediaIdentifiers: { _ in [:] }),
        mountCommand: { _, _, _ in throw ProtocolError.invalidState },
        readAttribute: { _, _, _ in await stuck.bounded(.timedOut, .failed(EIO)) },
        writeAttribute: { _, _, _ in await stuck.bounded(.timedOut, .written) },
        removeDirectory: { _ in await stuck.bounded(.timedOut, .removed) },
        mounts: { [mount] }, paths: stuck.paths)
    let started = ContinuousClock.now
    // Its ownership needs the extension's own answer, which never comes: no release.
    await #expect(throws: POSIXError(.ETIMEDOUT)) {
        try await backend.forcedReleaseInspection(descriptor, at: bridge)
    }
    await #expect(throws: POSIXError(.ETIMEDOUT)) {
        try await backend.forceReleaseBridge(
            ForcedReleaseIdentity(image: nil, bridgeMounted: true, bridgeResource: nil),
            descriptor: descriptor, bridgeURL: bridge)
    }
    await backend.abandonConnectionRecovery(descriptor, at: bridge)
    #expect(state.unexpectedCommands.isEmpty)
    #expect(stuck.pathQueries == 0)
    #expect(ContinuousClock.now - started < .seconds(3))
}

@Test func aReadOnlyBridgeIsAskedToStopReconnectingByReadingItsControl() async throws {
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    // As on a read-only mount, the kernel refuses every attribute write.
    f.replies.refuseEveryWrite(EROFS)
    let control = ConnectionDescriptor.readOnlyConnectionControlAttributeName
    func controlReads() -> Int { f.replies.names.filter { $0 == control }.count }
    // An extension without the read-only control: each path is written, then read, once.
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    #expect(f.replies.writes.count == 2 && controlReads() == 2)
    // With it, the image's answer is enough; the root isn't asked.
    f.replies.answerReadOnlyControl()
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    #expect(f.replies.writes.count == 3 && controlReads() == 3)
    // Any other refusal isn't a read-only mount: the control is never read for it.
    f.replies.refuseEveryWrite(EACCES)
    await f.backend.abandonConnectionRecovery(f.descriptor, at: f.bridge)
    #expect(f.replies.writes.count == 5 && controlReads() == 3)
    #expect(f.state.forcedUnmountCount == 0 && f.state.innerForcedEjectionCount == 0)
}

/// After an ordinary eject timed out, its Disk Arbitration request stays pending until the OS
/// answers it, typically once the file system's last writes, which wait for the server, end.
@Test func aForcedReleaseLooksThroughAnEarlierEjectionAndWaitsForItAfterStopping()
    async throws
{
    let f = try ForcedFixture(.matching)
    defer { f.cleanup() }
    try await f.connect()
    let image = f.bridge.appendingPathComponent("Disk.img")
    await f.ejection.setPending([image.path])
    // The ordinary inspection still refuses to act beside the earlier request...
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await f.backend.inspectBridge(f.descriptor, at: f.bridge)
    }
    // ...while the confirmed forced release identifies the same image through it.
    let inspection = try await f.backend.forcedReleaseInspection(f.descriptor, at: f.bridge)
    #expect(inspection.ownership == .verified)
    #expect(inspection.attachment?.device == "/dev/disk900002")
    let identity = try await f.backend.forcedReleaseIdentity(
        inspection.attachment, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.replies.writes.isEmpty)
    let backend = f.backend
    let descriptor = f.descriptor
    let bridge = f.bridge
    try await f.backend.forceReleaseImage(
        identity, descriptor: f.descriptor, bridgeURL: f.bridge,
        beforeReleasing: { await backend.abandonConnectionRecovery(descriptor, at: bridge) })
    // Stopped once every check passed, waited for the earlier request, then released.
    let name = ConnectionDescriptor.connectionControlAttributeName
    #expect(f.replies.writes == ["\(image.path):\(name)=abandon"])
    #expect(await f.ejection.waits == 1)
    #expect(f.state.innerForcedEjectionCount == 1)
    try await f.backend.forceReleaseBridge(identity, descriptor: f.descriptor, bridgeURL: f.bridge)
    #expect(f.state.forcedUnmountCount == 1)
}
