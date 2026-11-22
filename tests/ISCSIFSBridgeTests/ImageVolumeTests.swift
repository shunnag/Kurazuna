import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

@Test func filesystemTypeFollowsTheCompiledEmbeddingContract() throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    #expect(volume.volumeStatistics.fileSystemTypeName == ISCSIFileSystem.shortName)
    #if ISCSI_OWNED_LIO_FIXTURE
        #expect(ISCSIFileSystem.isOwnedLIOFixture)
        #if ISCSI_OWNED_LIO_RECOVERY
            #expect(ISCSIFileSystem.shortName == "iscsirecovery")
            #expect(
                ISCSIFileSystem.extensionBundleID == "dev.soba.iscsi.ownedlio.recovery.FileSystem")
        #elseif ISCSI_OWNED_LIO_PARENT_SCOPE
            #expect(ISCSIFileSystem.shortName == "iscsiscope")
            #expect(ISCSIFileSystem.extensionBundleID == "dev.soba.iscsi.ownedlio.scope.FileSystem")
        #else
            #expect(ISCSIFileSystem.shortName == "iscsilab")
            #expect(ISCSIFileSystem.extensionBundleID == "dev.soba.iscsi.ownedlio.FileSystem")
        #endif
    #else
        #expect(!ISCSIFileSystem.isOwnedLIOFixture)
        #if DEBUG
            #expect(ISCSIFileSystem.shortName == "kurazunadev")
        #else
            #expect(ISCSIFileSystem.shortName == "kurazuna")
        #endif
    #endif
}

@Test func mountIdentityChangesWithoutChangingTheLogicalVolumesIdentity() throws {
    let profileID = UUID()
    func descriptor(_ lun: LogicalUnit) throws -> ConnectionDescriptor {
        try ConnectionDescriptor(
            profileID: profileID, portal: Portal("nas.local"),
            initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
            lun: lun, readOnly: true, isid: [0x80, 1, 2, 3, 4, 5])
    }
    let base = try descriptor(LogicalUnit(1))
    let first = try base.assigningMountID(UUID())
    let second = try base.assigningMountID(UUID())
    #expect(ISCSIFileSystem.identifier(for: first) == ISCSIFileSystem.identifier(for: second))
    #expect(try first.resourceIdentity != second.resourceIdentity)
    #expect(
        try ConnectionDescriptor(resourceURL: first.resourceURL).resourceIdentity
            == first.resourceIdentity)
    let flat = try descriptor(LogicalUnit(addressKey: "4001000000000000"))
    #expect(ISCSIFileSystem.identifier(for: flat) != ISCSIFileSystem.identifier(for: base))
}

@Test func resourceIdentityAttributeIsImmutableAndLocal() async throws {
    let identity = Data(repeating: 0x42, count: 32)
    // This is the identity-only contract; live diagnostics has its own isolated-owner test.
    let volume = LUNImageVolume(
        disk: try MemoryDisk(), identifier: UUID(), resourceIdentity: identity,
        lifecycleObserver: { _ in }, ioDiagnostics: nil)
    let name = FSFileName(string: ConnectionDescriptor.identityAttributeName)
    #expect(try await volume.xattr(named: name, of: volume.rootItem) == identity)
    #expect(try await volume.xattr(named: name, of: volume.imageItem) == identity)
    #expect(
        try await volume.xattrs(of: volume.rootItem).map(\.string) == [
            ConnectionDescriptor.identityAttributeName,
            ConnectionDescriptor.connectionStateAttributeName,
            ConnectionDescriptor.sourceBlockSizeAttributeName,
        ])
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.setXattr(
            named: name, to: Data(repeating: 0, count: 32), on: volume.rootItem, policy: .alwaysSet)
    }
    await #expect(throws: POSIXError(.ENOATTR)) {
        try await volume.xattr(named: FSFileName(string: "unrecognized"), of: volume.rootItem)
    }
}

actor MemoryDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly: Bool
    private var bytes = Data(repeating: 0, count: 4096)
    private(set) var flushes = 0
    private var state = DiskConnectionState.connected

    init(readOnly: Bool = false, blockSize: UInt32 = 512) throws {
        guard (512...4096).contains(blockSize), blockSize.nonzeroBitCount == 1 else {
            throw ProtocolError.unsupported("test disk geometry")
        }
        var response = Array(repeating: UInt8(0), count: 32)
        response.put(UInt64(4096 / blockSize - 1), at: 0)
        response.put(blockSize, at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(response))
        isReadOnly = readOnly
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        Data(bytes[Int(offset)..<(Int(offset) + length)])
    }
    func write(offset: Int64, data: Data) async throws {
        bytes.replaceSubrange(Int(offset)..<(Int(offset) + data.count), with: data)
    }
    func synchronize() async throws { flushes += 1 }
    func close() async { state = .closed }
    func connectionState() async -> DiskConnectionState { state }
}

@Test(arguments: [false, true], [false, true])
private func requestedMountOptionsExposeTheDiskAccessModeToFSKit(
    _ readOnly: Bool, _ sparse: Bool
) throws {
    let source = try MemoryDisk(readOnly: readOnly)
    let image: any ImageDisk = sparse ? try SparseImageDisk(source) : source
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    // FSKit calls this optional Objective-C protocol member, so a Swift-only
    // property with the same name would not establish the mount policy.
    try #require(volume.responds(to: NSSelectorFromString("requestedMountOptions")))
    let expected: FSVolume.MountOptions = readOnly ? .readOnly : []
    #expect((volume as any FSVolume.Operations).requestedMountOptions == expected)
}

@Test(arguments: [false, true])
private func sourceSectorSizeIsImmutableEvenWhenThePresentationUses512ByteBlocks(
    _ sparse: Bool
) async throws {
    let source = try MemoryDisk(blockSize: 4096)
    let image: any ImageDisk = sparse ? try SparseImageDisk(source) : source
    let volume = LUNImageVolume(
        disk: image, identifier: UUID(), sourceCapacity: source.capacity)
    let name = FSFileName(string: ConnectionDescriptor.sourceBlockSizeAttributeName)
    for item in [volume.rootItem, volume.imageItem] {
        #expect(try await volume.xattr(named: name, of: item) == Data([0, 0, 16, 0]))
        #expect(try await volume.xattrs(of: item).contains(name))
        for replacement: Data? in [Data([0, 0, 2, 0]), nil] {
            await #expect(throws: POSIXError(.EPERM)) {
                try await volume.setXattr(
                    named: name, to: replacement, on: item, policy: .alwaysSet)
            }
        }
    }
    if sparse { #expect(volume.volumeStatistics.blockSize == 512) }
}

@Test func rawImageLookupAndFixedLength() async throws {
    let disk = try MemoryDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let (item, name) = try await (volume as any FSVolume.Operations).lookupItem(
        named: FSFileName(string: "Disk.img"), inDirectory: volume.rootItem)
    #expect(name.string == "Disk.img")
    let attributes = try volume.makeAttributes(of: item)
    #expect(attributes.size == 4096)
    #expect(attributes.mode == 0o600)
    #expect(attributes.type == .file)
    try await volume.openItem(item, modes: [.read, .write])
    #expect(try await volume.write(contents: Data([1, 2, 3]), to: item, at: 17) == 3)
    #expect(try await disk.read(offset: 17, length: 3) == Data([1, 2, 3]))
    await #expect(throws: POSIXError(.ENOSPC)) {
        try await volume.write(contents: Data([1]), to: item, at: 4096)
    }
    try await volume.closeItem(item, modes: [])
    #expect(await disk.flushes == 2)
}

@Test func imageVolumeRejectsForeignItemsAndReadOnlyWrites() async throws {
    let disk = try MemoryDisk(readOnly: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let other = LUNImageVolume(disk: disk, identifier: UUID())
    #expect(throws: POSIXError(.ESTALE)) { try volume.makeAttributes(of: other.imageItem) }
    await #expect(throws: POSIXError(.EROFS)) {
        try await volume.openItem(volume.imageItem, modes: [.write])
    }
    await #expect(throws: POSIXError(.EROFS)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
    }
    await #expect(throws: POSIXError(.EISDIR)) {
        try await volume.write(contents: Data([1]), to: volume.rootItem, at: 0)
    }
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.removeItem(
            volume.imageItem, named: FSFileName(string: "Disk.img"), fromDirectory: volume.rootItem)
    }
}

/// A disk whose connection is being reestablished. Its I/O waits rather than failing.
private actor ReconnectingDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly: Bool
    private(set) var abandoned = false
    private var bytes = Data(repeating: 0x3C, count: 4096)

    init(readOnly: Bool = false) throws {
        isReadOnly = readOnly
        var response = Array(repeating: UInt8(0), count: 32)
        response.put(UInt64(7), at: 0)
        response.put(UInt32(512), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(response))
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        Data(bytes[Int(offset)..<(Int(offset) + length)])
    }
    func write(offset: Int64, data: Data) async throws {
        bytes.replaceSubrange(Int(offset)..<(Int(offset) + data.count), with: data)
    }
    func synchronize() async throws {}
    func close() async {}
    func connectionState() async -> DiskConnectionState {
        abandoned ? .interrupted : .reconnecting
    }
    func abandonConnectionRecovery() async { abandoned = true }
}

@Test(arguments: [false, true])
private func aReconnectingDiskIsAdmittedAndReportsItsState(_ sparse: Bool) async throws {
    let source = try ReconnectingDisk()
    let image: any ImageDisk = sparse ? try SparseImageDisk(source) : source
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    let state = FSFileName(string: ConnectionDescriptor.connectionStateAttributeName)
    #expect(
        try await volume.xattr(named: state, of: volume.rootItem)
            == DiskConnectionState.reconnecting.encoded)
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    let count = try await volume.readChunks(
        from: volume.imageItem, at: 0, length: 512, bufferLength: 512, consume: { _, _ in })
    #expect(count == 512)
    if !sparse {
        #expect(
            try await volume.write(
                contents: Data(repeating: 1, count: 512), to: volume.imageItem, at: 0)
                == 512)
    }
    // The control reaches the disk underneath, through a sparse presentation too.
    try await volume.setXattr(
        named: FSFileName(string: ConnectionDescriptor.connectionControlAttributeName),
        to: ConnectionDescriptor.abandonRecoveryControlValue, on: volume.rootItem,
        policy: .alwaysSet)
    #expect(await source.abandoned)
    #expect(
        try await volume.xattr(named: state, of: volume.rootItem)
            == DiskConnectionState.interrupted.encoded)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.openItem(volume.imageItem, modes: [.read])
    }
}

/// The kernel refuses every attribute write on a read-only mount (EROFS) before the extension
/// sees it, so a read-only volume stops reconnecting when its own control name is read. It is
/// never listed or stored, and a writable volume doesn't have it.
@Test(arguments: [false, true])
private func onlyAReadOnlyVolumeStopsReconnectingWhenItsControlIsRead(_ readOnly: Bool)
    async throws
{
    let source = try ReconnectingDisk(readOnly: readOnly)
    let volume = LUNImageVolume(disk: source, identifier: UUID())
    let name = FSFileName(string: ConnectionDescriptor.readOnlyConnectionControlAttributeName)
    for item in [volume.rootItem, volume.imageItem] {
        #expect(try await !volume.xattrs(of: item).contains(name))
        await #expect(throws: POSIXError(.EPERM)) {
            try await volume.setXattr(
                named: name, to: ConnectionDescriptor.abandonRecoveryControlValue, on: item,
                policy: .alwaysSet)
        }
    }
    #expect(await !source.abandoned)
    let state = FSFileName(string: ConnectionDescriptor.connectionStateAttributeName)
    guard readOnly else {
        await #expect(throws: POSIXError(.ENOATTR)) {
            try await volume.xattr(named: name, of: volume.imageItem)
        }
        #expect(await !source.abandoned)
        #expect(
            try await volume.xattr(named: state, of: volume.rootItem)
                == DiskConnectionState.reconnecting.encoded)
        return
    }
    #expect(
        try await volume.xattr(named: name, of: volume.imageItem)
            == ConnectionDescriptor.abandonRecoveryControlValue)
    #expect(await source.abandoned)
    #expect(
        try await volume.xattr(named: state, of: volume.rootItem)
            == DiskConnectionState.interrupted.encoded)
}
