import Darwin
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private struct MarkerFilesFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    let mount = UUID()
    let profile = UUID()
    var files: OwnedBlockResourceFiles { OwnedBlockResourceFiles(bridgeRoot: root) }

    func descriptor(readOnly: Bool = false) throws -> ConnectionDescriptor {
        try ConnectionDescriptor(
            profileID: profile, portal: Portal("example.invalid"),
            initiatorName: "iqn.2026-10.test:marker-owner",
            targetName: "iqn.2026-10.test:marker-disk",
            lun: LogicalUnit(0), readOnly: readOnly, isid: [0x80, 1, 2, 3, 4, 5], mountID: mount)
    }
    func cleanup() {
        // These names belong to this fixture; never recursively traverse a marker namespace.
        for name in [mount.uuidString + ".img", "alias", "unexpected"] {
            _ = unlink(root.appendingPathComponent(".Resources/" + name).path)
        }
        _ = rmdir(root.appendingPathComponent(".Resources").path)
        _ = unlink(root.appendingPathComponent("sentinel").path)
        _ = rmdir(root.path)
    }
}

@Test func anAbsentMarkerInspectionCreatesNoDirectory() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    #expect(try fixture.files.inspect(fixture.descriptor()) == nil)
    #expect(try !fixture.files.hasUntrackedFiles(excluding: []))
    #expect(!FileManager.default.fileExists(atPath: fixture.root.path))
}

@Test func anOwnedMarkerHasExactBytesAndCannotBeOverwritten() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let data = try Data(contentsOf: url)
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    #expect(data.count == 1_048_576)
    #expect(try BlockMountResource(header: Data(data.prefix(8192))).reference == reference)
    #expect(data.dropFirst(8192).allSatisfy { $0 == 0 })
    #expect(try fixture.files.inspect(descriptor, full: true) == identity)
    #expect(throws: POSIXError(.EEXIST)) { try fixture.files.create(descriptor) }
    #expect(try Data(contentsOf: url) == data)
    #expect(try !fixture.files.hasUntrackedFiles(excluding: [fixture.mount]))
    #expect(try fixture.files.hasUntrackedFiles(excluding: []))
    try fixture.files.remove(descriptor, expected: identity)
    #expect(try fixture.files.inspect(descriptor) == nil)
}

@Test(arguments: ["header", "tail", "mode", "hardlink", "binding"])
func aChangedMarkerCannotBeRemovedAsAnOwnedFile(_ change: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    var data = try Data(contentsOf: url)
    if change == "header" || change == "tail" {
        data[change == "header" ? 0 : data.count - 1] ^= 1
        let handle = try FileHandle(forWritingTo: url)
        try handle.write(contentsOf: data)
        try handle.close()
    } else if change == "mode" {
        #expect(chmod(url.path, 0o644) == 0)
    } else if change == "hardlink" {
        #expect(link(url.path, fixture.root.appendingPathComponent(".Resources/alias").path) == 0)
    }
    let candidate = change == "binding" ? try fixture.descriptor(readOnly: true) : descriptor
    #expect(throws: AttachmentError.ownershipUnverified) {
        try fixture.files.remove(candidate, expected: identity)
    }
    #expect(try Data(contentsOf: url) == data)
}

@Test func markerRemovalRejectsAReplacedInodeEvenWithIdenticalBytes() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let data = try Data(contentsOf: url)
    let replacement = fixture.root.appendingPathComponent("sentinel")
    try data.write(to: replacement, options: .withoutOverwriting)
    #expect(chmod(replacement.path, 0o600) == 0)
    #expect(rename(replacement.path, url.path) == 0)
    #expect(throws: AttachmentError.imageIdentityChanged) {
        try fixture.files.remove(descriptor, expected: identity)
    }
    #expect(try Data(contentsOf: url) == data)
}

@Test func aMarkerSymlinkCannotSelectAnotherFile() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let other = fixture.root.appendingPathComponent("sentinel")
    let data = Data("retain this unrelated fixture sentinel".utf8)
    try data.write(to: other, options: .withoutOverwriting)
    #expect(unlink(url.path) == 0)
    #expect(symlink(other.path, url.path) == 0)
    #expect(throws: POSIXError.self) { try fixture.files.remove(descriptor, expected: identity) }
    #expect(try Data(contentsOf: other) == data)
}

@Test(arguments: ["root", "directory", "child"])
func mountedMarkerNamespacesAreRefusedBeforeCreation(_ location: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let directory = fixture.root.appendingPathComponent(".Resources")
    let path =
        location == "root"
        ? fixture.root.path : location == "directory" ? directory.path : directory.path + "/child"
    let files = OwnedBlockResourceFiles(
        bridgeRoot: fixture.root,
        mounts: {
            [.init(type: "apfs", source: "/dev/disk900000", path: path, owner: getuid(), flags: 0)]
        })
    #expect(throws: POSIXError(.EBUSY)) { try files.create(fixture.descriptor()) }
    #expect(!FileManager.default.fileExists(atPath: fixture.root.path))
}

private func markerWitness(at url: URL) throws -> Data {
    let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    #expect(fd >= 0)
    guard fd >= 0 else { throw POSIXError(.EIO) }
    defer { close(fd) }
    var bytes = Data(count: 60)
    let count = bytes.withUnsafeMutableBytes {
        fgetxattr(fd, "dev.soba.iscsi.marker-file", $0.baseAddress, $0.count, 0, 0)
    }
    guard count >= 0 else { throw POSIXError(.EIO) }
    return Data(bytes.prefix(count))
}

@Test func aMarkerWitnessUsesPersistentVolumeIdentity() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    _ = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    // Foundation resolves the UUID independently of the production FD attribute reader.
    let values = try url.resourceValues(forKeys: [.volumeUUIDStringKey])
    let volume = try #require(values.volumeUUIDString.flatMap { UUID(uuidString: $0) })
    var info = stat()
    #expect(lstat(url.path, &info) == 0)
    var expected = Data([2])
    var uuid = volume.uuid
    withUnsafeBytes(of: &uuid) { expected.append(contentsOf: $0) }
    expected.append(
        contentsOf: [56, 48, 40, 32, 24, 16, 8, 0].map {
            UInt8(truncatingIfNeeded: UInt64(info.st_ino) >> $0)
        })
    expected.append(try descriptor.resourceIdentity)
    let actual = try markerWitness(at: url)
    #expect(actual.count == 57)
    #expect(actual.first == 2)
    #expect(actual == expected)
}

private let markerTestVolume = UUID(
    uuid: (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
private let markerZeroVolume = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

private func markerTestStat() -> stat {
    var info = stat()
    info.st_dev = 16_777_230
    info.st_ino = 0x1234_5678_9abc_def0
    return info
}

@Test func persistentMarkerIdentitySurvivesDeviceRenumberingButLiveIdentityChanges() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let before = markerTestStat()
    var after = before
    after.st_dev = 16_777_233
    #expect(
        try OwnedBlockResourceFiles.identityBytes(
            before, volumeUUID: markerTestVolume, descriptor: descriptor)
            == OwnedBlockResourceFiles.identityBytes(
                after, volumeUUID: markerTestVolume, descriptor: descriptor))
    #expect(
        OwnedBlockResourceFiles.Identity(device: before.st_dev, inode: before.st_ino)
            != OwnedBlockResourceFiles.Identity(device: after.st_dev, inode: after.st_ino))
}

@Test(arguments: ["volume", "inode", "descriptor"])
func persistentMarkerIdentityRejectsADifferentFileBinding(_ change: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let original = try fixture.descriptor()
    let expected = try OwnedBlockResourceFiles.identityBytes(
        markerTestStat(), volumeUUID: markerTestVolume, descriptor: original)
    var changed = markerTestStat()
    if change == "inode" { changed.st_ino += 1 }
    let volume = change == "volume" ? UUID() : markerTestVolume
    let descriptor = change == "descriptor" ? try fixture.descriptor(readOnly: true) : original
    #expect(
        try OwnedBlockResourceFiles.identityBytes(
            changed, volumeUUID: volume, descriptor: descriptor) != expected)
}

@Test(arguments: ["volume", "inode"])
func missingPersistentMarkerIdentityIsRefused(_ missing: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    var info = markerTestStat()
    if missing == "inode" { info.st_ino = 0 }
    #expect(throws: AttachmentError.ownershipUnverified) {
        try OwnedBlockResourceFiles.identityBytes(
            info, volumeUUID: missing == "volume" ? markerZeroVolume : markerTestVolume,
            descriptor: fixture.descriptor())
    }
}

private func markerVolumeAttributeBuffer() -> Data {
    var bytes = Data()
    for var word in [UInt32(40), UInt32(ATTR_CMN_RETURNED_ATTRS), UInt32(ATTR_VOL_UUID), 0, 0, 0] {
        withUnsafeBytes(of: &word) { bytes.append(contentsOf: $0) }
    }
    var uuid = markerTestVolume.uuid
    withUnsafeBytes(of: &uuid) { bytes.append(contentsOf: $0) }
    return bytes
}

@Test(arguments: [
    "short", "long", "reported-short", "reported-long", "missing-common", "extra-common",
    "missing-volume", "extra-volume", "directory", "file", "fork", "zero-uuid",
])
func unsupportedOrMalformedVolumeIdentityCannotBecomeAMarkerIdentity(_ change: String) throws {
    var bytes = markerVolumeAttributeBuffer()
    #expect(try OwnedBlockResourceFiles.decodeVolumeUUID(bytes) == markerTestVolume)
    func setWord(_ value: UInt32, at offset: Int) {
        var value = value
        withUnsafeBytes(of: &value) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
    }
    switch change {
    case "short": bytes.removeLast()
    case "long": bytes.append(0)
    case "reported-short": setWord(36, at: 0)
    case "reported-long": setWord(44, at: 0)
    case "missing-common": setWord(0, at: 4)
    case "extra-common": setWord(UInt32(ATTR_CMN_RETURNED_ATTRS) | UInt32(ATTR_CMN_NAME), at: 4)
    case "missing-volume": setWord(0, at: 8)
    case "extra-volume": setWord(UInt32(ATTR_VOL_UUID) | UInt32(ATTR_VOL_NAME), at: 8)
    case "directory": setWord(1, at: 12)
    case "file": setWord(1, at: 16)
    case "fork": setWord(1, at: 20)
    default: bytes.replaceSubrange(24..<40, with: Data(count: 16))
    }
    #expect(throws: AttachmentError.ownershipUnverified) {
        try OwnedBlockResourceFiles.decodeVolumeUUID(bytes)
    }
}

@Test func anInvalidMarkerFDCannotFallbackToADeviceNumber() throws {
    #expect(throws: POSIXError(.EBADF)) { try OwnedBlockResourceFiles.readVolumeUUID(-1) }
}

private func setMarkerWitness(_ bytes: Data, at url: URL, create: Bool = false) throws {
    let fd = open(url.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
    guard fd >= 0 else { throw POSIXError(.EIO) }
    defer { close(fd) }
    let result = bytes.withUnsafeBytes {
        fsetxattr(
            fd, "dev.soba.iscsi.marker-file", $0.baseAddress, $0.count, 0,
            create ? XATTR_CREATE : XATTR_REPLACE)
    }
    guard result == 0 else { throw POSIXError(.EIO) }
}

private func legacyMarkerWitness(_ info: stat, descriptor: ConnectionDescriptor) throws -> Data {
    var bytes = Data([1])
    bytes.append(
        contentsOf: [24, 16, 8, 0].map {
            UInt8(truncatingIfNeeded: UInt32(bitPattern: info.st_dev) >> $0)
        })
    bytes.append(
        contentsOf: [56, 48, 40, 32, 24, 16, 8, 0].map {
            UInt8(truncatingIfNeeded: UInt64(info.st_ino) >> $0)
        })
    bytes.append(try descriptor.resourceIdentity)
    return bytes
}

@Test func aLegacyMarkerWithTheExactCurrentBindingCanBeRemovedWithoutMigration() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    var info = stat()
    #expect(lstat(url.path, &info) == 0)
    let witness = try legacyMarkerWitness(info, descriptor: descriptor)
    try setMarkerWitness(witness, at: url)
    #expect(try fixture.files.inspect(descriptor, full: true) == identity)
    #expect(try markerWitness(at: url) == witness)
    try fixture.files.remove(descriptor, expected: identity)
    #expect(try fixture.files.inspect(descriptor) == nil)
}

@Test(arguments: ["device", "inode", "descriptor"])
func aLegacyMarkerWithUnprovenIdentityIsNeverUpgradedOrRemoved(_ change: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let original = try Data(contentsOf: url)
    var info = stat()
    #expect(lstat(url.path, &info) == 0)
    if change == "device" { info.st_dev ^= 3 }
    if change == "inode" { info.st_ino += 1 }
    let bound = change == "descriptor" ? try fixture.descriptor(readOnly: true) : descriptor
    let witness = try legacyMarkerWitness(info, descriptor: bound)
    try setMarkerWitness(witness, at: url)
    #expect(throws: AttachmentError.ownershipUnverified) { try fixture.files.inspect(descriptor) }
    #expect(throws: AttachmentError.ownershipUnverified) {
        try fixture.files.remove(descriptor, expected: identity)
    }
    #expect(try markerWitness(at: url) == witness)
    #expect(try Data(contentsOf: url) == original)
}

@Test func aCopiedMarkerWitnessCannotIdentifyAReplacementFile() throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let original = try Data(contentsOf: url)
    let witness = try markerWitness(at: url)
    let replacement = fixture.root.appendingPathComponent("sentinel")
    try original.write(to: replacement, options: .withoutOverwriting)
    #expect(chmod(replacement.path, 0o600) == 0)
    try setMarkerWitness(witness, at: replacement, create: true)
    #expect(rename(replacement.path, url.path) == 0)
    #expect(throws: AttachmentError.ownershipUnverified) { try fixture.files.inspect(descriptor) }
    #expect(throws: AttachmentError.imageIdentityChanged) {
        try fixture.files.remove(descriptor, expected: identity)
    }
    #expect(try Data(contentsOf: url) == original)
    #expect(try markerWitness(at: url) == witness)
}

@Test(arguments: ["volume", "version", "short", "long", "oversized"])
func aChangedV2MarkerWitnessIsRetainedRatherThanRebound(_ change: String) throws {
    let fixture = MarkerFilesFixture()
    defer { fixture.cleanup() }
    let descriptor = try fixture.descriptor()
    let identity = try fixture.files.create(descriptor)
    let url = try fixture.files.imageURL(for: descriptor)
    let original = try Data(contentsOf: url)
    var witness = try markerWitness(at: url)
    #expect(witness.count == 57)
    switch change {
    case "volume": witness[1] ^= 1
    case "version": witness[0] = 3
    case "short": witness.removeLast()
    case "long": witness.append(0)
    default: witness.append(contentsOf: [0, 0])
    }
    try setMarkerWitness(witness, at: url)
    #expect(throws: AttachmentError.ownershipUnverified) { try fixture.files.inspect(descriptor) }
    #expect(throws: AttachmentError.ownershipUnverified) {
        try fixture.files.remove(descriptor, expected: identity)
    }
    #expect(try markerWitness(at: url) == witness)
    #expect(try Data(contentsOf: url) == original)
}
