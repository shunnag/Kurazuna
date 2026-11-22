import Darwin
import DiskArbitration
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private func markerDescriptor(_ id: UUID) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:local-marker", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
}

private func mediaDescription() -> [String: Any] {
    [
        kDADiskDescriptionMediaWholeKey as String: true,
        kDADiskDescriptionMediaWritableKey as String: true,
        kDADiskDescriptionMediaSizeKey as String: UInt64(1_048_576),
        kDADiskDescriptionMediaBlockSizeKey as String: UInt64(512),
    ]
}

private final class MarkerMediaCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    let replaceAfter: Int?
    init(replaceAfter: Int? = nil) { self.replaceAfter = replaceAfter }
    func read(_ device: String) throws -> BlockResourceMedia {
        let changed = lock.withLock {
            calls += 1
            return replaceAfter.map { calls >= $0 } ?? false
        }
        return try BlockResourceMedia(
            device: device, identifier: changed ? 42 : 41, description: mediaDescription())
    }
}

private actor MarkerCommands {
    let image: URL
    let lsof: String
    let mountPoint: @Sendable () -> String?
    private(set) var attached = false
    private(set) var calls: [[String]] = []
    private(set) var lsofCalls = 0
    private var extraImage: URL?
    init(
        image: URL, lsof: String = "absent",
        mountPoint: @escaping @Sendable () -> String? = { nil }
    ) {
        self.image = image
        self.lsof = lsof
        self.mountPoint = mountPoint
    }
    func detached() { attached = false }
    func addImage(_ image: URL) { extraImage = image }
    func run(_ program: String, _ arguments: [String], _ timeout: TimeInterval) async throws -> Data
    {
        calls.append([program] + arguments)
        if program == "/usr/bin/hdiutil", arguments == ["info", "-plist"] {
            var entities: [[String: Any]] = [["dev-entry": "/dev/disk900000"]]
            if let mountPoint = mountPoint() { entities[0]["mount-point"] = mountPoint }
            var images: [[String: Any]] =
                attached ? [["image-path": image.path, "system-entities": entities]] : []
            if let extraImage {
                images.append([
                    "image-path": extraImage.path,
                    "system-entities": [["dev-entry": "/dev/disk900001"]],
                ])
            }
            return try PropertyListSerialization.data(
                fromPropertyList: ["images": images], format: .binary, options: 0)
        }
        if program == "/usr/bin/hdiutil", arguments.first == "attach" {
            #expect(
                arguments == [
                    "attach", "-kernel", "-nomount", "-plist", "-imagekey",
                    "diskimage-class=CRawDiskImage", "-readwrite", image.path,
                ])
            attached = true
            return try PropertyListSerialization.data(
                fromPropertyList: ["system-entities": [["dev-entry": "/dev/disk900000"]]],
                format: .binary, options: 0)
        }
        if program == "/usr/sbin/lsof" {
            #expect(arguments == ["-nP", "-t", "--", image.path])
            lsofCalls += 1
            if lsof == "open" || (lsof == "busy2" && lsofCalls <= 2) {
                return Data("12345\n".utf8)
            }
            throw SystemCommandError.failed(
                program: "lsof", status: 1, detail: lsof == "unknown" ? "permission denied" : "")
        }
        throw ProtocolError.invalidState
    }
}

private actor MarkerEjection: DiskEjectionService {
    let commands: MarkerCommands
    private(set) var confirmedCalls = 0
    private(set) var forcedCalls = 0
    private(set) var markerEjections = 0
    private var pending: Set<String> = []
    private var busyReplies: Int
    let onForceUnmount: @Sendable () -> Void
    init(
        _ commands: MarkerCommands, busyReplies: Int = 0,
        onForceUnmount: @escaping @Sendable () -> Void = {}
    ) {
        self.commands = commands
        self.busyReplies = busyReplies
        self.onForceUnmount = onForceUnmount
    }
    func pendingImagePaths() -> Set<String> { pending }
    func addPending(_ path: String) { pending.insert(path) }
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) throws {
        Issue.record("Marker cleanup must retain its confirmed media identity")
        throw ProtocolError.invalidState
    }
    func ejectConfirmed(
        device: String, image: URL, unmountDevices: [String], mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        confirmedCalls += 1
        #expect(device == "/dev/disk900000" && unmountDevices == [device])
        #expect(mediaIdentifiers == [device: 41])
        try await validate()
        if busyReplies > 0 {
            // Another process, such as an exiting file system extension, has it open.
            busyReplies -= 1
            throw POSIXError(.EBUSY)
        }
        markerEjections += 1
        await commands.detached()
    }
    func forceEject(
        device: String, image: URL, unmountDevices: [String], mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        forcedCalls += 1
        #expect(device == "/dev/disk900000" && unmountDevices == [device])
        #expect(mediaIdentifiers == [device: 41])
        pending.insert(image.path)
        defer { pending.remove(image.path) }
        onForceUnmount()
        try await validate()
        markerEjections += 1
        await commands.detached()
    }
}

private struct ResourceFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    let id = UUID()
    func cleanup() {
        _ = unlink(root.appendingPathComponent(".Resources/" + id.uuidString + ".img").path)
        _ = rmdir(root.appendingPathComponent(".Resources").path)
        _ = rmdir(root.path)
    }
}

@Test func aMarkerLifecycleRetainsConfirmedIdentityAndNormallyRemovesOnlyItsFile() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let descriptor = try markerDescriptor(fixture.id)
    let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
    let image = try files.imageURL(for: descriptor)
    let commands = MarkerCommands(image: image)
    let ejection = MarkerEjection(commands)
    let resources = BlockMountResources(
        files: files, run: commands.run, media: MarkerMediaCounter().read, ejection: ejection)
    let attachment = try await resources.prepare(descriptor)
    #expect(attachment.media.device == "/dev/disk900000" && attachment.media.identifier == 41)
    #expect(try files.inspect(descriptor, full: true) == attachment.file)
    try await resources.cleanup(descriptor)
    #expect(await ejection.confirmedCalls == 1)
    #expect(try files.inspect(descriptor) == nil)
    try await resources.cleanup(descriptor)
    #expect(await ejection.confirmedCalls == 1)
}

@Test(arguments: ["open", "unknown"])
func uncertainMarkerHandlesPreserveTheFileAfterNormalEjection(_ handles: String) async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let descriptor = try markerDescriptor(fixture.id)
    let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
    let commands = MarkerCommands(image: try files.imageURL(for: descriptor), lsof: handles)
    let ejection = MarkerEjection(commands)
    let clock = MarkerBusyClock()
    let resources = BlockMountResources(
        files: files, run: commands.run, media: MarkerMediaCounter().read, ejection: ejection,
        busyWait: clock.wait)
    _ = try await resources.prepare(descriptor)
    await #expect(throws: (any Error).self) { try await resources.cleanup(descriptor) }
    #expect(await ejection.confirmedCalls == 1)
    // Open handles are looked for again within the bounded wait; an unknown answer is not.
    #expect(clock.sleeps == (handles == "open" ? 40 : 0))
    #expect(try files.inspect(descriptor, full: true) != nil)
    #expect(await commands.attached == false)
}

@Test func aChangedMarkerMediaIdentityCannotStartEjection() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let descriptor = try markerDescriptor(fixture.id)
    let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
    let commands = MarkerCommands(image: try files.imageURL(for: descriptor))
    let ejection = MarkerEjection(commands)
    let resources = BlockMountResources(
        files: files, run: commands.run, media: MarkerMediaCounter(replaceAfter: 3).read,
        ejection: ejection)
    _ = try await resources.prepare(descriptor)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await resources.cleanup(descriptor)
    }
    #expect(await ejection.confirmedCalls == 0)
    #expect(await commands.attached)
    #expect(try files.inspect(descriptor, full: true) != nil)
}

@Test(arguments: [
    "whole", "writable", "size", "block", "boolSize", "device", "partition", "zeroID",
])
func aMarkerMediaDescriptionCannotSubstituteAnotherKindOfDisk(_ change: String) {
    var info = mediaDescription()
    switch change {
    case "whole": info[kDADiskDescriptionMediaWholeKey as String] = false
    case "writable": info[kDADiskDescriptionMediaWritableKey as String] = false
    case "size": info[kDADiskDescriptionMediaSizeKey as String] = 134_217_728
    case "block": info[kDADiskDescriptionMediaBlockSizeKey as String] = 4096
    case "boolSize": info[kDADiskDescriptionMediaSizeKey as String] = true
    default: break
    }
    let device =
        change == "device" ? "disk4" : change == "partition" ? "/dev/disk4s1" : "/dev/disk4"
    #expect(throws: AttachmentError.ownershipUnverified) {
        try BlockResourceMedia(
            device: device, identifier: change == "zeroID" ? 0 : 41, description: info)
    }
}

@Test(arguments: ["foreign", "extra", "wrongMount", "pending"])
func aMarkerInventoryMustDescribeExactlyItsOwnedSingleDevice(_ change: String) throws {
    let image = URL(fileURLWithPath: "/private/tmp/marker.img")
    var entities: [[String: Any]] = [["dev-entry": "/dev/disk4"]]
    if change == "extra" { entities.append(["dev-entry": "/dev/disk4s1"]) }
    if change == "wrongMount" { entities[0]["mount-point"] = "/Volumes/Other" }
    if change == "foreign" { entities[0]["dev-entry"] = "/dev/disk4s1" }
    let data = try PropertyListSerialization.data(
        fromPropertyList: ["images": [["image-path": image.path, "system-entities": entities]]],
        format: .binary, options: 0)
    let inventory = try DiskImageInventory(
        data, pendingEjections: change == "pending" ? [image.path] : [])
    #expect(throws: (any Error).self) {
        try inventory.blockMarkerDevice(at: image, expectedMount: nil)
    }
}

private final class ForceMarkerState: @unchecked Sendable {
    private let lock = NSLock()
    private let bridge: URL
    private var entries: [CachedMountTable.Entry]
    private var mediaID: UInt64 = 41
    private var fileSystemID: CachedMountTable.FileSystemID? = .init(first: 17, second: 24)
    private var unmountCalls = 0
    var forceUnmountCalls: Int { lock.withLock { unmountCalls } }
    func requestedForceUnmount() { lock.withLock { unmountCalls += 1 } }
    init(bridge: URL) {
        self.bridge = bridge
        entries = []
    }
    func mount() {
        lock.withLock {
            entries = [
                .init(
                    type: ApplicationIdentity.current.fileSystemType, source: "/dev/disk900000",
                    path: bridge.path, owner: getuid(), flags: 0, fileSystemID: fileSystemID)
            ]
        }
    }
    func mounts() -> [CachedMountTable.Entry] { lock.withLock { entries } }
    func mountPoint() -> String? {
        lock.withLock {
            entries.first { $0.source == "/dev/disk900000" && $0.path == bridge.path }?.path
        }
    }
    func media(_ device: String) throws -> BlockResourceMedia {
        try BlockResourceMedia(
            device: device, identifier: lock.withLock { mediaID }, description: mediaDescription())
    }
    func change(_ change: String) {
        lock.withLock {
            if change == "media" {
                mediaID += 1
                return
            }
            if change == "absent" {
                entries.removeAll()
                return
            }
            if change == "fsid" || change == "missingID" || change == "zeroID" {
                fileSystemID =
                    change == "missingID"
                    ? nil : .init(first: change == "zeroID" ? 0 : 18, second: 0)
                let original = entries[0]
                entries[0] = .init(
                    type: original.type, source: original.source, path: original.path,
                    owner: original.owner, flags: original.flags, fileSystemID: fileSystemID)
                return
            }
            let original = entries[0]
            if change == "nested" {
                entries.append(
                    .init(
                        type: "apfs", source: "/dev/disk900001", path: bridge.path + "/Other",
                        owner: getuid(), flags: 0))
            } else if change == "duplicate" {
                entries.append(original)
            } else {
                entries[0] = .init(
                    type: change == "type" ? "apfs" : original.type,
                    source: change == "source" ? "/dev/disk900001" : original.source,
                    path: change == "path" ? bridge.path + "-other" : original.path,
                    owner: change == "owner" ? getuid() + 1 : original.owner, flags: original.flags,
                    fileSystemID: original.fileSystemID)
            }
        }
    }
}

private struct ForceMarkerFixture {
    let fixture = ResourceFixture()
    let descriptor: ConnectionDescriptor
    let bridge: URL
    let commands: MarkerCommands
    let state: ForceMarkerState
    let ejection: MarkerEjection
    let resources: BlockMountResources
    init(
        afterUnmount: @escaping @Sendable (ForceMarkerState) -> Void = { $0.change("absent") },
        unmountError: POSIXError? = nil,
        waitForUnmount: @escaping @Sendable () async -> Void = {}
    ) throws {
        descriptor = try markerDescriptor(fixture.id)
        let bridge = fixture.root.appendingPathComponent(fixture.id.uuidString, isDirectory: true)
        self.bridge = bridge
        let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
        let state = ForceMarkerState(bridge: bridge)
        self.state = state
        let commands = MarkerCommands(
            image: try files.imageURL(for: descriptor), mountPoint: state.mountPoint)
        self.commands = commands
        ejection = MarkerEjection(commands, onForceUnmount: { afterUnmount(state) })
        resources = BlockMountResources(
            files: files,
            run: { program, arguments, timeout in
                if program == "/sbin/umount" {
                    #expect(arguments == ["-f", bridge.path] && timeout == 30)
                    state.requestedForceUnmount()
                    await waitForUnmount()
                    if let unmountError { throw unmountError }
                    afterUnmount(state)
                    return Data()
                }
                return try await commands.run(program, arguments, timeout)
            }, media: state.media, ejection: ejection,
            mounts: state.mounts)
    }
    func prepare() async throws -> BlockMountResources.ForceIdentity {
        _ = try await resources.prepare(descriptor)
        state.mount()
        return try await resources.captureForceIdentity(descriptor, at: bridge)
    }
}

@Test func confirmedBridgeForceUnmountUsesTheCapturedMediaAndNormallyEjectsItsMarker() async throws
{
    let f = try ForceMarkerFixture()
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    try await f.resources.confirmUnmountedIdentity(f.descriptor, at: f.bridge, expected: expected)
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.forcedCalls == 0)
    #expect(await f.ejection.confirmedCalls == 1)
    #expect(await f.ejection.markerEjections == 1)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
    try await f.resources.cleanup(f.descriptor)
    #expect(try f.resources.files.inspect(f.descriptor) == nil)
    #expect(await f.ejection.confirmedCalls == 1)
}

@Test(arguments: [
    "owner", "source", "type", "path", "nested", "duplicate", "absent", "media", "fsid",
    "missingID",
    "zeroID",
])
func changedBridgeBindingsCannotUseAnEarlierForceConfirmation(_ change: String) async throws {
    let f = try ForceMarkerFixture()
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    f.state.change(change)
    await #expect(throws: (any Error).self) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(await f.ejection.forcedCalls == 0)
    #expect(f.state.forceUnmountCalls == 0)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
}

@Test func aReplacementMarkerFileCannotUseTheOriginalForceConfirmation() async throws {
    let f = try ForceMarkerFixture()
    let retained = f.fixture.root.appendingPathComponent("OriginalMarker.img")
    defer {
        _ = unlink(retained.path)
        f.fixture.cleanup()
    }
    let expected = try await f.prepare()
    let image = try f.resources.files.imageURL(for: f.descriptor)
    try FileManager.default.moveItem(at: image, to: retained)
    let replacement = try f.resources.files.create(f.descriptor)
    #expect(replacement != expected.file)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(await f.ejection.forcedCalls == 0)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == replacement)
}

@Test(arguments: ["image", "pending"])
func innerAttachmentsMustFinishBeforeTheBridgeCanBeForced(_ kind: String) async throws {
    let f = try ForceMarkerFixture()
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    let image = f.bridge.appendingPathComponent("Disk.img")
    if kind == "image" {
        await f.commands.addImage(image)
    } else {
        await f.ejection.addPending(image.path)
    }
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(await f.ejection.forcedCalls == 0)
    #expect(await f.commands.attached)
}

@Test func replacementMediaAfterForcedUnmountCannotBeEjected() async throws {
    let f = try ForceMarkerFixture(afterUnmount: {
        $0.change("absent")
        $0.change("media")
    })
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.forcedCalls == 0)
    #expect(await f.ejection.markerEjections == 0)
    #expect(await f.commands.attached)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
}

@Test func anAlreadyUnmountedConfirmedBridgeUsesNormalMarkerCleanup() async throws {
    let f = try ForceMarkerFixture()
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    f.state.change("absent")
    try await f.resources.confirmUnmountedIdentity(f.descriptor, at: f.bridge, expected: expected)
    try await f.resources.cleanup(f.descriptor)
    #expect(await f.ejection.forcedCalls == 0)
    #expect(await f.ejection.confirmedCalls == 1)
    #expect(try f.resources.files.inspect(f.descriptor) == nil)
}

@Test func aSuccessfulUnmountReplyCannotEjectAStillMountedBridge() async throws {
    let f = try ForceMarkerFixture(afterUnmount: { _ in })
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    await #expect(throws: POSIXError(.EBUSY)) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(await f.ejection.markerEjections == 0)
    #expect(await f.commands.attached)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
}

@Test(arguments: [POSIXErrorCode.EIO, .EBUSY, .EPERM])
func aFailedConfirmedUnmountPreservesTheMarker(_ code: POSIXErrorCode) async throws {
    let error = POSIXError(code)
    let f = try ForceMarkerFixture(unmountError: error)
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    await #expect(throws: error) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.confirmedCalls == 0)
    #expect(await f.ejection.markerEjections == 0)
    #expect(await f.commands.attached)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
}

@Test(arguments: ["owner", "source", "type", "path", "nested", "duplicate", "fsid"])
func aMountRemainingOrReplacedAfterConfirmedUnmountCannotBeEjected(_ change: String) async throws {
    let f = try ForceMarkerFixture(afterUnmount: { $0.change(change) })
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    await #expect(throws: (any Error).self) {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.confirmedCalls == 0)
    #expect(await f.commands.attached)
}

@Test(arguments: ["missingID", "zeroID"])
func aForcePreviewRequiresAnObservedFileSystemID(_ change: String) async throws {
    let f = try ForceMarkerFixture()
    defer { f.fixture.cleanup() }
    _ = try await f.prepare()
    f.state.change(change)
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await f.resources.captureForceIdentity(f.descriptor, at: f.bridge)
    }
    #expect(f.state.forceUnmountCalls == 0)
    #expect(await f.ejection.confirmedCalls == 0)
}

@Test func cancellationWaitsForTheIssuedUnmountAndPreservesItsMarker() async throws {
    let started = AsyncStream<Void>.makeStream()
    let release = AsyncStream<Void>.makeStream()
    let f = try ForceMarkerFixture(waitForUnmount: {
        started.continuation.yield(())
        var iterator = release.stream.makeAsyncIterator()
        _ = await iterator.next()
    })
    defer { f.fixture.cleanup() }
    let expected = try await f.prepare()
    let task = Task {
        try await f.resources.forceEject(f.descriptor, at: f.bridge, expected: expected)
    }
    var iterator = started.stream.makeAsyncIterator()
    _ = await iterator.next()
    task.cancel()
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.confirmedCalls == 0)
    #expect(await f.commands.attached)
    release.continuation.yield(())
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(f.state.mounts().isEmpty)
    #expect(f.state.forceUnmountCalls == 1)
    #expect(await f.ejection.markerEjections == 0)
    #expect(await f.commands.attached)
    #expect(try f.resources.files.inspect(f.descriptor, full: true) == expected.file)
}

/// Injected time for the bounded wait while a marker is busy (REC022).
private final class MarkerBusyClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    private var count = 0
    private let cancelAfter: Int?
    init(cancelAfter: Int? = nil) { self.cancelAfter = cancelAfter }
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    var sleeps: Int { lock.withLock { count } }
    func sleep(_ duration: Duration) throws {
        try lock.withLock {
            if let cancelAfter, count >= cancelAfter { throw CancellationError() }
            count += 1
            instant = instant.advanced(by: duration)
        }
    }
    var wait: BlockMountResources.BusyMarkerWait {
        .init(
            limit: .seconds(20), interval: .milliseconds(500), now: { self.now },
            sleep: { try self.sleep($0) })
    }
}

private func busyMarker(
    busyReplies: Int, lsof: String = "absent", clock: MarkerBusyClock,
    mounted: Bool = false, fixture: ResourceFixture
) throws -> (BlockMountResources, MarkerCommands, MarkerEjection, ConnectionDescriptor) {
    let descriptor = try markerDescriptor(fixture.id)
    let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
    let commands = MarkerCommands(image: try files.imageURL(for: descriptor), lsof: lsof)
    let ejection = MarkerEjection(commands, busyReplies: busyReplies)
    let resources = BlockMountResources(
        files: files, run: commands.run, media: MarkerMediaCounter().read, ejection: ejection,
        mounts: {
            mounted
                ? [
                    CachedMountTable.Entry(
                        type: "hfs", source: "/dev/disk900000", path: "/Volumes/Marker",
                        owner: getuid(), flags: 0)
                ] : []
        }, busyWait: clock.wait)
    return (resources, commands, ejection, descriptor)
}

@Test func aBusyUnmountedMarkerIsEjectedOnceItsHolderLetsGo() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let clock = MarkerBusyClock()
    let (resources, commands, ejection, descriptor) = try busyMarker(
        busyReplies: 3, clock: clock, fixture: fixture)
    _ = try await resources.prepare(descriptor)
    try await resources.cleanup(descriptor)
    #expect(await ejection.confirmedCalls == 4)
    #expect(await ejection.markerEjections == 1)
    #expect(clock.sleeps == 3)
    #expect(await commands.attached == false)
    #expect(try OwnedBlockResourceFiles(bridgeRoot: fixture.root).inspect(descriptor) == nil)
}

@Test func aMarkerBusyBeyondTheBoundedWaitKeepsItsFile() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let clock = MarkerBusyClock()
    let (resources, commands, ejection, descriptor) = try busyMarker(
        busyReplies: 1000, clock: clock, fixture: fixture)
    _ = try await resources.prepare(descriptor)
    await #expect(throws: POSIXError(.EBUSY)) { try await resources.cleanup(descriptor) }
    // 20 s in 0.5 s steps, then one more attempt.
    #expect(clock.sleeps == 40)
    #expect(await ejection.confirmedCalls == 41)
    #expect(await ejection.markerEjections == 0)
    #expect(await commands.attached)
    let files = OwnedBlockResourceFiles(bridgeRoot: fixture.root)
    #expect(try files.inspect(descriptor, full: true) != nil)
}

@Test func aMountedMarkerIsNeverWaitedFor() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let clock = MarkerBusyClock()
    let (resources, commands, ejection, descriptor) = try busyMarker(
        busyReplies: 0, clock: clock, mounted: true, fixture: fixture)
    _ = try await resources.prepare(descriptor)
    await #expect(throws: POSIXError(.EBUSY)) { try await resources.cleanup(descriptor) }
    #expect(clock.sleeps == 0)
    #expect(await ejection.confirmedCalls == 0)
    #expect(await commands.attached)
}

@Test func aCancelledBusyWaitKeepsTheMarker() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let clock = MarkerBusyClock(cancelAfter: 2)
    let (resources, commands, ejection, descriptor) = try busyMarker(
        busyReplies: 1000, clock: clock, fixture: fixture)
    _ = try await resources.prepare(descriptor)
    await #expect(throws: CancellationError.self) { try await resources.cleanup(descriptor) }
    #expect(clock.sleeps == 2)
    #expect(await ejection.confirmedCalls == 3)
    #expect(await ejection.markerEjections == 0)
    #expect(await commands.attached)
}

@Test func brieflyOpenMarkerHandlesAreWaitedForBeforeRemoval() async throws {
    let fixture = ResourceFixture()
    defer { fixture.cleanup() }
    let clock = MarkerBusyClock()
    let (resources, commands, ejection, descriptor) = try busyMarker(
        busyReplies: 1, lsof: "busy2", clock: clock, fixture: fixture)
    _ = try await resources.prepare(descriptor)
    try await resources.cleanup(descriptor)
    // One busy ejection and two lsof answers with open handles share one bounded wait.
    #expect(clock.sleeps == 3)
    #expect(await commands.lsofCalls == 3)
    #expect(await ejection.markerEjections == 1)
    #expect(try OwnedBlockResourceFiles(bridgeRoot: fixture.root).inspect(descriptor) == nil)
}
