import Foundation
import ISCSICore
import Testing
import zlib

@testable import ISCSIPlatform

private let imageURL = URL(fileURLWithPath: "/private/tmp/iscsi-diskimages-tests/Disk.img")
private let imageByteCount: UInt64 = 16_777_216
private let imageDevice = "/dev/disk900000"

private final class MediaIdentities: @unchecked Sendable {
    private let lock = NSLock()
    private var identifiers: [String: UInt64] = [imageDevice: 41, "/dev/disk900001": 42]
    func replace(_ device: String) { lock.withLock { identifiers[device] = 43 } }
    func read(_ devices: [String]) -> [String: UInt64] {
        lock.withLock { identifiers.filter { devices.contains($0.key) } }
    }
}

private actor ForceImageEjection: DiskEjectionService {
    private(set) var normalAttempts = 0
    private(set) var forced: [[String: UInt64]] = []
    func pendingImagePaths() -> Set<String> { [] }
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) throws {
        normalAttempts += 1
        throw POSIXError(.EBUSY)
    }
    func forceEject(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        forced.append(mediaIdentifiers)
        try await validate()
    }
}

@Test private func forceImageObservationIncludesTheAPFSContainerAndPhysicalMedia() async throws {
    let commands = ImageCommands(Array(repeating: .success(try snapshot()), count: 4))
    let identities = MediaIdentities()
    let service = ForceImageEjection()
    let images = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: service,
        mediaIdentifiers: identities.read)
    let proof = try await images.captureForceEjectionIdentity(
        DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    #expect(proof.unmountDevices == ["/dev/disk900001", imageDevice])
    #expect(proof.mediaIdentifiers == [imageDevice: 41, "/dev/disk900001": 42])
    #expect(await service.forced.isEmpty)
    try await images.forceDetach(proof, at: imageURL)
    #expect(await service.forced == [[imageDevice: 41, "/dev/disk900001": 42]])
}

@Test(arguments: [imageDevice, "/dev/disk900001"])
private func reusingEitherBSDDeviceNameAfterConfirmationStopsForceEjection(_ device: String)
    async throws
{
    let commands = ImageCommands(Array(repeating: .success(try snapshot()), count: 3))
    let identities = MediaIdentities()
    let service = ForceImageEjection()
    let images = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: service,
        mediaIdentifiers: identities.read)
    let proof = try await images.captureForceEjectionIdentity(
        DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    identities.replace(device)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await images.forceDetach(proof, at: imageURL)
    }
    #expect(await service.forced.isEmpty)
}

private func imagePlist(_ value: [String: Any]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0)
}
private func entities(device: String = imageDevice, mounted: Bool = false) -> [[String: Any]] {
    var entities: [[String: Any]] = [
        ["dev-entry": device, "content-hint": "GUID_partition_scheme"],
        ["dev-entry": device + "s1", "content-hint": "Apple_APFS"],
        ["dev-entry": "/dev/disk900001", "content-hint": "EF57347C-0000-11AA-AA11-00306543ECAC"],
    ]
    if mounted {
        entities.append(["dev-entry": "/dev/disk900001s1", "mount-point": "/Volumes/iSCSI Fixture"])
    }
    return entities
}
private func snapshot(
    device: String = imageDevice, mounted: Bool = false, path: URL = imageURL, copies: Int = 1
) throws -> Data {
    try imagePlist([
        "images": Array(
            repeating: [
                "image-path": path.path,
                "system-entities": entities(device: device, mounted: mounted),
            ], count: copies)
    ])
}

private final class ImageCommandCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var observed: Bool { lock.withLock { value } }
    func record() { lock.withLock { value = true } }
}

private actor ImageCommands {
    struct Call: Sendable, Equatable {
        let program: String
        let arguments: [String]
        let timeout: TimeInterval
    }
    private let replies: [Result<Data, any Error>]
    private let pauseAt: Int?
    private let observesCancellation: Bool
    private let cancellation = ImageCommandCancellation()
    private var paused: CheckedContinuation<Void, Never>?
    private(set) var calls: [Call] = []
    var isPaused: Bool { paused != nil }
    var cancellationObserved: Bool { cancellation.observed }
    init(
        _ replies: [Result<Data, any Error>], pauseAt: Int? = nil,
        observesCancellation: Bool = false
    ) {
        self.replies = replies
        self.pauseAt = pauseAt
        self.observesCancellation = observesCancellation
    }
    func run(_ program: String, _ arguments: [String], _ timeout: TimeInterval) async throws -> Data
    {
        let index = calls.count
        calls.append(Call(program: program, arguments: arguments, timeout: timeout))
        guard index < replies.count else { throw ProtocolError.invalidState }
        if index == pauseAt {
            let cancellation = cancellation
            let observing = observesCancellation
            try await withTaskCancellationHandler {
                await withCheckedContinuation { paused = $0 }
                if observing { try Task.checkCancellation() }
            } onCancel: {
                if observing { cancellation.record() }
            }
        }
        return try replies[index].get()
    }
    func release() {
        paused?.resume()
        paused = nil
    }
}

private func imageClient(_ commands: ImageCommands) -> DiskImages {
    DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount },
        header: { _ in Data(repeating: 0, count: 8192) }, sourceBlockSize: { _ in nil })
}

private func successfulCommands(readOnly: Bool = false, mounted: Bool = false) throws
    -> [Result<Data, any Error>]
{
    [
        .success(try imagePlist(["system-entities": entities()])),
        .success(try snapshot()),
        .success(
            try imagePlist([
                "TotalSize": imageByteCount, "WritableMedia": !readOnly, "DeviceBlockSize": 512,
            ])),
        .success(Data()), .success(try snapshot(mounted: mounted)),
    ]
}

@Test(arguments: [false, true])
private func sparseImageAttachmentChecksLUNCapacityInsteadOfContainerLength(_ readOnly: Bool)
    async throws
{
    let layout = try SparseImageLayout(capacity: imageByteCount)
    let header = try layout.header(at: 0)
    let commands = ImageCommands(try successfulCommands(readOnly: readOnly))
    let client = DiskImages(
        run: commands.run, fileSize: { _ in layout.imageByteCount }, header: { _ in header },
        sourceBlockSize: { _ in nil })
    let result = try await client.attachImage(at: imageURL, readOnly: readOnly, presentation: .udsp)
    #expect(result.device == imageDevice)
    let calls = await commands.calls
    #expect(calls[0].program == "/usr/bin/hdiutil")
    #expect(calls[0].arguments.contains("-nokernel"))
    #expect(calls[0].arguments.contains("diskimage-class=CSparseDiskImage"))
    #expect(calls[0].arguments.contains(readOnly ? "-readonly" : "-readwrite"))
}

@Test private func sparseImageMappingMustBeVerifiedBeforeDeviceCreation() async throws {
    let layout = try SparseImageLayout(capacity: imageByteCount)
    var malformed = try layout.header(at: 0)
    malformed[64] ^= 1
    let header = malformed
    let commands = ImageCommands([])
    let client = DiskImages(
        run: commands.run, fileSize: { _ in layout.imageByteCount }, header: { _ in header })
    await #expect(throws: ProtocolError.self) {
        try await client.attachImage(at: imageURL, readOnly: false, presentation: .udsp)
    }
    #expect(await commands.calls.isEmpty)
}

@Test(arguments: [UInt64(0), 511, 513, UInt64(Int64.max)])
private func invalidLUNByteCountsCannotCreateADevice(_ size: UInt64) async throws {
    let commands = ImageCommands([])
    let client = DiskImages(run: commands.run, fileSize: { _ in size })
    await #expect(throws: AttachmentError.invalidImageResponse) {
        try await client.attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.isEmpty)
}

@Test(arguments: [false, true])
private func nativeDeviceGeometryAndWritabilityMustMatchTheRequestedLUN(_ readOnly: Bool) throws {
    let valid: [String: Any] = [
        "TotalSize": imageByteCount, "WritableMedia": !readOnly, "DeviceBlockSize": 512,
    ]
    try DiskImages.verifyDeviceInfo(
        imagePlist(valid), byteCount: imageByteCount, readOnly: readOnly)
    let invalidSizes: [Any] = [
        0, -1, imageByteCount + 512, Double(imageByteCount),
        String(imageByteCount), true,
    ]
    for value in invalidSizes {
        var changed = valid
        changed["TotalSize"] = value
        #expect(throws: AttachmentError.invalidImageResponse) {
            try DiskImages.verifyDeviceInfo(
                imagePlist(changed), byteCount: imageByteCount, readOnly: readOnly)
        }
    }
    for key in ["TotalSize", "WritableMedia", "DeviceBlockSize"] {
        var changed = valid
        changed.removeValue(forKey: key)
        #expect(throws: AttachmentError.invalidImageResponse) {
            try DiskImages.verifyDeviceInfo(
                imagePlist(changed), byteCount: imageByteCount, readOnly: readOnly)
        }
    }
    for writable: Any in [readOnly, 1, "true"] {
        var changed = valid
        changed["WritableMedia"] = writable
        #expect(throws: AttachmentError.invalidImageResponse) {
            try DiskImages.verifyDeviceInfo(
                imagePlist(changed), byteCount: imageByteCount, readOnly: readOnly)
        }
    }
    for sector: Any in [0, -1, 4096, 512.0, "512", true] {
        var changed = valid
        changed["DeviceBlockSize"] = sector
        #expect(throws: AttachmentError.invalidImageResponse) {
            try DiskImages.verifyDeviceInfo(
                imagePlist(changed), byteCount: imageByteCount, readOnly: readOnly)
        }
    }
}

@Test private func largerSectorsUseAnExplicitReadOnlyHelperAndVerifyItsActualGeometry() async throws
{
    var replies = try successfulCommands(readOnly: true)
    replies[2] = .success(
        try imagePlist([
            "TotalSize": imageByteCount, "WritableMedia": false, "DeviceBlockSize": 4096,
        ]))
    let commands = ImageCommands(replies)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount },
        header: { _ in Data(repeating: 0, count: 8192) }, sourceBlockSize: { _ in 4096 })
    _ = try await client.attachRawImage(at: imageURL, readOnly: true)
    let calls = await commands.calls
    #expect(calls[0].arguments.contains("-nokernel"))
    #expect(calls[0].arguments.contains("-readonly"))
    #expect(calls[0].arguments.suffix(3) == ["-blocksize", "4096", imageURL.path])
    #expect(calls.count == 5)
}

@Test private func writableLargerSectorsAreRefusedBeforeCreatingAnyDevice() async throws {
    let commands = ImageCommands([])
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount },
        header: { _ in Data(repeating: 0, count: 8192) }, sourceBlockSize: { _ in 4096 })
    await #expect(throws: AttachmentError.readOnlyGeometryRequired) {
        try await client.attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.isEmpty)
}

@Test(arguments: [LUNImagePresentation.raw, .udsp])
private func genuine4KnPartitionGeometryCannotCreateAWritableDeviceThroughEitherPresentation(
    _ presentation: LUNImagePresentation
) async throws {
    // The OS-generated 512 MiB 4Kn header also used by DiskImageGeometryTests. Its CRC
    // and sector-addressed bounds must be recognized before any OS command.
    let capacity: UInt64 = 512 * 1_048_576
    let header = Data(
        try CHAP.decodeBinary(
            "0x4546492050415254000001005c000000daa5c213000000000100000000000000ffff0100000000000600000000000000faff010000000000cfdb1dadb1b6294ebb9e8535580ea40f02000000000000008000000080000000df8018d0"
        ))
    var rawPrefix = Data(repeating: 0, count: DiskImageGeometry.prefixByteCount)
    rawPrefix.replaceSubrange(4096..<(4096 + header.count), with: header)
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: rawPrefix, byteCount: capacity, sourceBlockSize: 4096) == 4096)
    let layout = try SparseImageLayout(capacity: capacity)
    let prefix =
        presentation == .raw
        ? rawPrefix
        : Data((try layout.header(at: 0) + rawPrefix).prefix(DiskImageGeometry.prefixByteCount))
    let commands = ImageCommands([])
    let size = presentation == .raw ? capacity : layout.imageByteCount
    let client = DiskImages(
        run: commands.run, fileSize: { _ in size }, header: { _ in prefix },
        sourceBlockSize: { _ in 4096 })
    await #expect(throws: AttachmentError.readOnlyGeometryRequired) {
        try await client.attachImage(at: imageURL, readOnly: false, presentation: presentation)
    }
    let calls = await commands.calls
    #expect(calls.isEmpty)
}

private func nativeSparseGeometryFixture(_ blockSize: Int) throws -> (
    UInt64, SparseImageLayout, Data
) {
    let capacity: UInt64 = blockSize == 512 ? 128 * 1_048_576 : 512 * 1_048_576
    let hex =
        blockSize == 512
        ? "4546492050415254000001005c000000cc83534a000000000100000000000000ffff0300000000002200000000000000deff030000000000887c56edab608f4397423bfc8465abf802000000000000008000000080000000bcec5d1c"
        : "4546492050415254000001005c000000daa5c213000000000100000000000000ffff0100000000000600000000000000faff010000000000cfdb1dadb1b6294ebb9e8535580ea40f02000000000000008000000080000000df8018d0"
    let gpt = Data(try CHAP.decodeBinary("0x" + hex))
    var raw = Data(repeating: 0, count: DiskImageGeometry.prefixByteCount)
    raw.replaceSubrange(blockSize..<(blockSize + gpt.count), with: gpt)
    let layout = try SparseImageLayout(capacity: capacity)
    let prefix = Data((try layout.header(at: 0) + raw).prefix(DiskImageGeometry.prefixByteCount))
    return (capacity, layout, prefix)
}

@Test(arguments: [false, true])
private func sparseReadOnly4KnUsesThePayloadGeometryAndChecksTheNativeDevice(
    _ hasSourceAttribute: Bool
) async throws {
    let (capacity, layout, prefix) = try nativeSparseGeometryFixture(4096)
    var replies = try successfulCommands(readOnly: true)
    replies[2] = .success(
        try imagePlist([
            "TotalSize": capacity, "WritableMedia": false, "DeviceBlockSize": 4096,
        ]))
    let commands = ImageCommands(replies)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in layout.imageByteCount }, header: { _ in prefix },
        sourceBlockSize: { _ in hasSourceAttribute ? 4096 : nil })
    _ = try await client.attachImage(at: imageURL, readOnly: true, presentation: .udsp)
    let calls = await commands.calls
    #expect(calls[0].arguments.contains("-readonly"))
    #expect(calls[0].arguments.suffix(3) == ["-blocksize", "4096", imageURL.path])
    #expect(calls.count == 5)
}

@Test(arguments: [false, true])
private func sparseLegacy512GPTOnLargerTransportBlocksKeepsItsExistingAccessMode(
    _ readOnly: Bool
) async throws {
    let (capacity, layout, prefix) = try nativeSparseGeometryFixture(512)
    var replies = try successfulCommands(readOnly: readOnly)
    replies[2] = .success(
        try imagePlist([
            "TotalSize": capacity, "WritableMedia": !readOnly, "DeviceBlockSize": 512,
        ]))
    let commands = ImageCommands(replies)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in layout.imageByteCount }, header: { _ in prefix },
        sourceBlockSize: { _ in 4096 })
    _ = try await client.attachImage(at: imageURL, readOnly: readOnly, presentation: .udsp)
    let calls = await commands.calls
    #expect(!calls[0].arguments.contains("-blocksize"))
    #expect(calls[0].arguments.contains(readOnly ? "-readonly" : "-readwrite"))
    #expect(calls.count == 5)
}

@Test private func sparseIgnored4KnRequestCannotLeadToMountingTheWrongGeometry() async throws {
    let (capacity, layout, prefix) = try nativeSparseGeometryFixture(4096)
    var replies = try successfulCommands(readOnly: true)
    replies[2] = .success(
        try imagePlist([
            "TotalSize": capacity, "WritableMedia": false, "DeviceBlockSize": 512,
        ]))
    let commands = ImageCommands(replies)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in layout.imageByteCount }, header: { _ in prefix },
        sourceBlockSize: { _ in 4096 })
    await #expect(throws: AttachmentError.invalidImageResponse) {
        try await client.attachImage(at: imageURL, readOnly: true, presentation: .udsp)
    }
    let calls = await commands.calls
    #expect(calls.count == 3)
    #expect(!calls.contains { $0.arguments.first == "mountDisk" })
}

@Test private func anIgnoredSectorSizeOptionCannotLeadToMountingTheWrongGeometry() async throws {
    let commands = ImageCommands(try successfulCommands(readOnly: true))
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount },
        header: { _ in Data(repeating: 0, count: 8192) }, sourceBlockSize: { _ in 4096 })
    await #expect(throws: AttachmentError.invalidImageResponse) {
        try await client.attachRawImage(at: imageURL, readOnly: true)
    }
    #expect(await commands.calls.count == 3)
}

@Test func inventoryIdentityDoesNotDependOnAURLDirectoryHint() throws {
    let inventory = try DiskImageInventory(snapshot())
    let hinted = URL(fileURLWithPath: imageURL.path, isDirectory: true)
    #expect(try inventory.attachment(at: hinted)?.device == imageDevice)
    #expect(!inventory.hasImage(under: imageURL.deletingLastPathComponent(), excluding: hinted))
    #expect(inventory.hasImage(under: imageURL.deletingLastPathComponent()))
}

@Test(arguments: [
    "EFI", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
])
private func efiSystemPartitionDoesNotPrecedeTheDataVolume(_ hint: String) throws {
    let mounted: [[String: Any]] = [
        ["dev-entry": imageDevice, "content-hint": "GUID_partition_scheme"],
        ["dev-entry": imageDevice + "s1", "content-hint": hint, "mount-point": "/Volumes/EFI"],
        ["dev-entry": "/dev/disk900001", "content-hint": "EF57347C-0000-11AA-AA11-00306543ECAC"],
        ["dev-entry": "/dev/disk900001s1", "mount-point": "/Volumes/Data"],
    ]
    let parsed = try DiskImages.parseAttachment(imagePlist(["system-entities": mounted]))
    #expect(parsed.device == imageDevice)
    #expect(parsed.volumeURLs.map(\.path) == ["/Volumes/Data"])
    let inventory = try DiskImageInventory(
        imagePlist(["images": [["image-path": imageURL.path, "system-entities": mounted]]]))
    #expect(try inventory.attachment(at: imageURL) == parsed)
}

/// `hdiutil attach` doesn't list the entities in a fixed order (seen on macOS 27.3); the
/// inventory lists the image's own whole disk first. Either answer names the same disk.
@Test private func theImageDiskIsChosenWhateverOrderTheEntitiesAreListedIn() throws {
    func orders(_ items: [[String: Any]]) -> [[[String: Any]]] {
        guard items.count > 1 else { return [items] }
        return items.indices.flatMap { index in
            var rest = items
            let first = rest.remove(at: index)
            return orders(rest).map { [first] + $0 }
        }
    }
    let listed = entities(mounted: true)
    for order in orders(listed) {
        let parsed = try DiskImages.parseAttachment(imagePlist(["system-entities": order]))
        #expect(parsed.device == imageDevice)
        #expect(parsed.volumeURLs.map(\.path) == ["/Volumes/iSCSI Fixture"])
    }
    // When no whole disk is told apart by its hint, the lowest-numbered one is the image's,
    // compared as a number rather than as text.
    let unpartitioned: [[String: Any]] = [
        ["dev-entry": "/dev/disk10", "content-hint": "EF57347C-0000-11AA-AA11-00306543ECAC"],
        ["dev-entry": "/dev/disk9", "content-hint": "ef57347c-0000-11aa-aa11-00306543ecac"],
    ]
    for order in orders(unpartitioned) {
        #expect(
            try DiskImages.parseAttachment(imagePlist(["system-entities": order])).device
                == "/dev/disk9")
    }
}

@Test private func anAttachThatListsTheAPFSContainerFirstMatchesTheInventory() async throws {
    var replies = try successfulCommands()
    replies[0] = .success(
        try imagePlist(["system-entities": Array(entities(mounted: true).reversed())]))
    let commands = ImageCommands(replies)
    let attached = try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    #expect(attached.device == imageDevice)
    #expect(await commands.calls.count == 5)
}

/// A container can take a lower number than the image's own disk, for one just freed; its
/// hint, not its number, keeps it from being chosen in any answer.
@Test private func anAPFSContainerNumberedBelowTheImageDiskIsNeverChosen() async throws {
    let device = "/dev/disk900002"
    let listed = entities(device: device, mounted: true)
    for order in [listed, Array(listed.reversed())] {
        #expect(
            try DiskImages.parseAttachment(imagePlist(["system-entities": order])).device
                == device)
    }
    #expect(
        try DiskImageInventory(snapshot(device: device, mounted: true)).attachment(at: imageURL)?
            .device == device)
    let commands = ImageCommands([
        .success(try imagePlist(["system-entities": Array(listed.reversed())])),
        .success(try snapshot(device: device)),
        .success(
            try imagePlist([
                "TotalSize": imageByteCount, "WritableMedia": true, "DeviceBlockSize": 512,
            ])),
        .success(Data()), .success(try snapshot(device: device, mounted: true)),
    ])
    let attached = try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    #expect(attached.device == device)
    #expect(attached.volumeURLs.map(\.path) == ["/Volumes/iSCSI Fixture"])
}

@Test private func dataVolumeNamedEFIRemainsAvailable() throws {
    for hint in ["Microsoft Basic Data", "Apple_HFS", "unknown", ""] {
        let parsed = try DiskImages.parseAttachment(
            imagePlist([
                "system-entities": [
                    ["dev-entry": imageDevice],
                    [
                        "dev-entry": imageDevice + "s1", "content-hint": hint,
                        "mount-point": "/Volumes/EFI",
                    ],
                ]
            ]))
        #expect(parsed.volumeURLs.map(\.path) == ["/Volumes/EFI"])
    }
}

@Test private func efiOnlyImageRetainsItsWholeDeviceForDetachment() throws {
    let mounted: [[String: Any]] = [
        ["dev-entry": imageDevice],
        [
            "dev-entry": imageDevice + "s1", "content-hint": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            "mount-point": "/Volumes/System",
        ],
    ]
    let inventory = try DiskImageInventory(
        imagePlist(["images": [["image-path": imageURL.path, "system-entities": mounted]]]))
    let attachment = try #require(try inventory.attachment(at: imageURL))
    #expect(attachment.device == imageDevice)
    #expect(attachment.volumeURLs.isEmpty)
    #expect(inventory.hasImage(under: imageURL.deletingLastPathComponent()))
}

@Test(arguments: [false, true], [false, true])
private func rawDiskAttachmentSeparatesDiskCreationFromMountingVolumes(
    _ readOnly: Bool, _ mounted: Bool
) async throws {
    let commands = ImageCommands(try successfulCommands(readOnly: readOnly, mounted: mounted))
    let result = try await imageClient(commands).attachRawImage(
        at: imageURL, readOnly: readOnly)
    #expect(result.device == imageDevice)
    #expect(result.volumeURLs.map(\.path) == (mounted ? ["/Volumes/iSCSI Fixture"] : []))
    let calls = await commands.calls
    #expect(calls.count == 5)
    #expect(calls[0].program == "/usr/bin/hdiutil")
    #expect(
        calls[0].arguments == [
            "attach", "-kernel", "-nomount", "-plist", "-imagekey", "diskimage-class=CRawDiskImage",
            readOnly ? "-readonly" : "-readwrite", imageURL.path,
        ])
    #expect(calls[1].arguments == ["info", "-plist"] && calls[4].arguments == ["info", "-plist"])
    #expect(calls[2].program == "/usr/sbin/diskutil")
    #expect(calls[2].arguments == ["info", "-plist", imageDevice])
    #expect(
        calls[3]
            == .init(
                program: "/usr/sbin/diskutil", arguments: ["mountDisk", imageDevice], timeout: 60))

}

private enum ImageChange { case missing, differentDevice, differentPath, duplicatePath }

@Test(arguments: [false, true], [false, true])
private func failedVolumeMountKeepsAVerifiedDiskAndReportsTheIssue(
    _ readOnly: Bool, _ partiallyMounted: Bool
) async throws {
    var replies = try successfulCommands(readOnly: readOnly, mounted: partiallyMounted)
    replies[3] = .failure(
        SystemCommandError.failed(program: "diskutil", status: 1, detail: "Mount failed"))
    replies.append(replies[2])
    let commands = ImageCommands(replies)
    let result = try await imageClient(commands).attachRawImage(at: imageURL, readOnly: readOnly)
    #expect(result.device == imageDevice)
    #expect(result.volumeURLs.count == (partiallyMounted ? 1 : 0))
    #expect(result.volumeMountIssue == VolumeMountIssue(status: 1, detail: "Mount failed"))
    let calls = await commands.calls
    #expect(calls.count == 6)
    #expect(calls.last?.arguments == ["info", "-plist", imageDevice])
    #expect(!calls.contains { $0.program.contains("fsck") || $0.arguments.contains("detach") })
}

@Test(arguments: [ImageChange.missing, .differentDevice, .differentPath, .duplicatePath])
private func aFailedVolumeMountCannotHideAChangedImageBinding(_ change: ImageChange) async throws {
    var replies = try successfulCommands()
    replies[3] = .failure(SystemCommandError.failed(program: "diskutil", status: 1, detail: ""))
    let changed: Data
    switch change {
    case .missing: changed = try imagePlist(["images": []])
    case .differentDevice: changed = try snapshot(device: "/dev/disk900002")
    case .differentPath:
        changed = try snapshot(
            path: imageURL.deletingLastPathComponent().appendingPathComponent("Other.img"))
    case .duplicatePath: changed = try snapshot(copies: 2)
    }
    replies[4] = .success(changed)
    let commands = ImageCommands(replies)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.count == 5)
}

@Test private func aFailedVolumeMountStillRequiresTheSameDeviceGeometry() async throws {
    var replies = try successfulCommands()
    replies[3] = .failure(SystemCommandError.failed(program: "diskutil", status: 1, detail: ""))
    replies.append(
        .success(
            try imagePlist([
                "TotalSize": imageByteCount + 512, "DeviceBlockSize": 512, "WritableMedia": true,
            ])))
    let commands = ImageCommands(replies)
    await #expect(throws: AttachmentError.invalidImageResponse) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
}

private enum MountCommandFailure: CaseIterable {
    case timeout, cancelled, otherStatus, otherProgram, permission
    var error: any Error {
        switch self {
        case .timeout: SystemCommandError.timedOut(program: "diskutil")
        case .cancelled: CancellationError()
        case .otherStatus: SystemCommandError.failed(program: "diskutil", status: 2, detail: "")
        case .otherProgram: SystemCommandError.failed(program: "hdiutil", status: 1, detail: "")
        case .permission: POSIXError(.EACCES)
        }
    }
}

@Test(arguments: MountCommandFailure.allCases)
private func incompleteOrUnexpectedMountCommandsStillFailTheConnection(
    _ failure: MountCommandFailure
)
    async throws
{
    var replies = try successfulCommands()
    replies[3] = .failure(failure.error)
    let commands = ImageCommands(replies)
    await #expect(throws: (any Error).self) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.count == 4)
}

@Test func aWrongDeviceCapacityStopsBeforeAnyVolumeIsMounted() async throws {
    var replies = try successfulCommands()
    replies[2] = .success(
        try imagePlist([
            "TotalSize": imageByteCount + 512, "WritableMedia": true, "DeviceBlockSize": 512,
        ]))
    let commands = ImageCommands(replies)
    await #expect(throws: AttachmentError.invalidImageResponse) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.count == 3)
}

@Test(arguments: [
    "disk123", "/dev/disk123s1", "/dev/disk123", "/dev/disk", "/dev/disk-1", "/dev/disk１２３",
    "/dev/disk1;exit", "/dev/disk1\n",
])
private func kernelImageDeviceNamesCannotSelectPartitionsOrArbitraryPaths(_ device: String) throws {
    let data = try imagePlist(["system-entities": [["dev-entry": device]]])
    if device == "/dev/disk123" {
        let parsed = try DiskImages.parseAttachment(data)
        #expect(parsed.device == "/dev/disk123" && parsed.volumeURLs.isEmpty)
    } else {
        #expect(throws: AttachmentError.invalidImageResponse) {
            try DiskImages.parseAttachment(data)
        }
    }
}

@Test(
    arguments: [ImageChange.missing, .differentDevice, .differentPath, .duplicatePath],
    [false, true])
private func imageIdentityIsRecheckedBeforeAndAfterMounting(
    _ change: ImageChange, _ afterMount: Bool
) async throws {
    let changed: Data
    switch change {
    case .missing: changed = try imagePlist(["images": []])
    case .differentDevice: changed = try snapshot(device: "/dev/disk900002")
    case .differentPath:
        changed = try snapshot(
            path: imageURL.deletingLastPathComponent().appendingPathComponent("Other.img"))
    case .duplicatePath: changed = try snapshot(copies: 2)
    }
    var replies = try successfulCommands()
    replies[afterMount ? 4 : 1] = .success(changed)
    let commands = ImageCommands(replies)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.count == (afterMount ? 5 : 2))
}

@Test(arguments: [0, 1, 2, 3, 4])
private func anImageCommandFailureStopsBeforeAnyFurtherCommand(_ index: Int) async throws {
    let failure = SystemCommandError.failed(program: "fixture", status: 1, detail: "failed")
    var replies = try successfulCommands()
    replies[index] = .failure(failure)
    let commands = ImageCommands(replies)
    await #expect(throws: SystemCommandError.self) {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: false)
    }
    #expect(await commands.calls.count == index + 1)
}

@Test(arguments: [0, 1, 2, 3, 4])
private func cancellingAnImageOperationDiscardsLateSuccessAndStopsFurtherCommands(_ index: Int)
    async throws
{
    let commands = ImageCommands(try successfulCommands(readOnly: true), pauseAt: index)
    let operation = Task {
        try await imageClient(commands).attachRawImage(at: imageURL, readOnly: true)
    }
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await commands.isPaused) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
    operation.cancel()
    await commands.release()
    await #expect(throws: CancellationError.self) { try await operation.value }
    #expect(await commands.calls.count == index + 1)
}

@Test(arguments: [0, 3], [LUNImagePresentation.raw, .udsp])
private func imageSideEffectCompletesBeforeCancellationIsReported(
    _ index: Int, _ presentation: LUNImagePresentation
) async throws {
    let commands = ImageCommands(
        try successfulCommands(readOnly: true), pauseAt: index, observesCancellation: true)
    let layout = try SparseImageLayout(capacity: imageByteCount)
    let header = try layout.header(at: 0)
    let client = DiskImages(
        run: commands.run,
        fileSize: { _ in presentation == .raw ? imageByteCount : layout.imageByteCount },
        header: { _ in presentation == .raw ? Data(repeating: 0, count: 8192) : header },
        sourceBlockSize: { _ in nil })
    let operation = Task {
        try await client.attachImage(at: imageURL, readOnly: true, presentation: presentation)
    }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await commands.isPaused) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(2))
    }
    operation.cancel()
    #expect(!(await commands.cancellationObserved))
    await commands.release()
    await #expect(throws: CancellationError.self) { try await operation.value }
    #expect(!(await commands.cancellationObserved))
    #expect(await commands.calls.count == index + 1)
}

@Test private func cancellationDuringHeaderReadingDoesNotStartAnAttachmentCommand() async throws {
    let commands = ImageCommands(try successfulCommands(readOnly: true))
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount },
        header: { _ in
            withUnsafeCurrentTask { $0?.cancel() }
            return Data(repeating: 0, count: 8192)
        }, sourceBlockSize: { _ in nil })
    let operation = Task { try await client.attachRawImage(at: imageURL, readOnly: true) }
    await #expect(throws: CancellationError.self) { try await operation.value }
    #expect(await commands.calls.isEmpty)
}

private enum DetachResult { case success, missing, replaced, busy, failure }

private enum ImageEjectionFailure: Error { case rejected }

private actor ImageEjections: DiskEjectionService {
    let result: DetachResult
    private(set) var devices: [String] = []
    private(set) var validated = false
    private(set) var unmountTargets: [String] = []
    init(_ result: DetachResult) { self.result = result }
    func pendingImagePaths() -> Set<String> { [] }
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        devices.append(device)
        unmountTargets = unmountDevices
        if result == .busy { throw POSIXError(.EBUSY) }
        if result == .failure { throw ImageEjectionFailure.rejected }
        try await validate()
        validated = true
    }
}

@Test(arguments: [DetachResult.success, .missing, .replaced, .busy, .failure])
private func imageEjectionVerifiesTheCurrentDeviceAndNeverForcesIt(_ result: DetachResult)
    async throws
{
    let inventory =
        try result == .missing
        ? imagePlist(["images": []])
        : snapshot(device: result == .replaced ? "/dev/disk900002" : imageDevice)
    let commands = ImageCommands([.success(inventory), .success(inventory)])
    let ejection = ImageEjections(result)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: ejection)
    let attachment = DiskAttachment(device: imageDevice, volumeURLs: [])
    switch result {
    case .success, .missing: try await client.detach(attachment, at: imageURL)
    case .replaced:
        await #expect(throws: AttachmentError.imageIdentityChanged) {
            try await client.detach(attachment, at: imageURL)
        }
    case .busy:
        await #expect(throws: POSIXError(.EBUSY)) {
            try await client.detach(attachment, at: imageURL)
        }
    case .failure:
        await #expect(throws: ImageEjectionFailure.rejected) {
            try await client.detach(attachment, at: imageURL)
        }
    }
    let calls = await commands.calls
    #expect(calls.count == (result == .success ? 2 : 1))
    #expect(calls.allSatisfy { $0.arguments == ["info", "-plist"] })
    #expect(
        await ejection.devices == (result == .missing || result == .replaced ? [] : [imageDevice]))
    #expect(await ejection.validated == (result == .success))
    #expect(
        await ejection.unmountTargets
            == (result == .missing || result == .replaced ? [] : ["/dev/disk900001", imageDevice]))
}

@Test private func anImageReplacedAfterUnmountCannotBeEjected() async throws {
    let commands = ImageCommands([
        .success(try snapshot()), .success(try snapshot(device: "/dev/disk900002")),
    ])
    let ejection = ImageEjections(.success)
    let client = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: ejection)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await client.detach(DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    }
    #expect(await ejection.devices == [imageDevice])
    #expect(await !ejection.validated)
}

@Test private func pendingEjectionsKeepTheirBridgeTrackedEvenWhenTheImageDisappears() throws {
    let inventory = try DiskImageInventory(
        imagePlist(["images": []]), pendingEjections: [imageURL.path])
    #expect(inventory.imagePaths == [imageURL.path])
    #expect(inventory.hasImage(under: imageURL.deletingLastPathComponent()))
    #expect(throws: AttachmentError.recoveryRequired) { try inventory.attachment(at: imageURL) }
}

@Test private func unmountTargetsIncludeOnlyWholeDevicesFromTheOwnedImage() throws {
    let inventory = try DiskImageInventory(
        imagePlist([
            "images": [
                ["image-path": imageURL.path, "system-entities": entities(mounted: true)],
                [
                    "image-path": imageURL.deletingLastPathComponent().appendingPathComponent(
                        "Other.img"
                    ).path,
                    "system-entities": [["dev-entry": "/dev/disk900002"]],
                ],
            ]
        ]))
    #expect(try inventory.unmountDevices(at: imageURL) == ["/dev/disk900001", imageDevice])
    #expect(
        try inventory.unmountDevices(at: URL(fileURLWithPath: "/private/tmp/missing.img")).isEmpty)
}

@Test(arguments: [LUNImagePresentation.raw, .udsp])
private func extendedGPTHeaderCannotBypassWritableGeometryPolicy(
    _ presentation: LUNImagePresentation
) async throws {
    // A synthetic boundary fixture: the largest supported GPT header fills
    // the second 64 KiB sector. This is not an OS-generated 64K disk.
    let block = 65_536
    let capacity: UInt64 = 512 * 1_048_576
    var gpt = Data(repeating: 0, count: block)
    func put(_ value: UInt64, at offset: Int, count: Int) {
        gpt.replaceSubrange(
            offset..<(offset + count),
            with: (0..<count).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
    }
    gpt.replaceSubrange(0..<8, with: Data("EFI PART".utf8))
    put(0x0001_0000, at: 8, count: 4)
    put(UInt64(block), at: 12, count: 4)
    put(1, at: 24, count: 8)
    put(capacity / UInt64(block) - 1, at: 32, count: 8)
    put(4, at: 40, count: 8)
    put(capacity / UInt64(block) - 2, at: 48, count: 8)
    put(2, at: 72, count: 8)
    put(128, at: 80, count: 4)
    put(128, at: 84, count: 4)
    let crc = gpt.withUnsafeBytes {
        crc32(0, $0.bindMemory(to: UInt8.self).baseAddress, uInt(gpt.count))
    }
    put(UInt64(crc), at: 16, count: 4)
    let raw = Data(repeating: 0, count: block) + gpt
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: raw, byteCount: capacity, sourceBlockSize: 512) == 65_536)
    let layout = try SparseImageLayout(capacity: capacity)
    let root = URL(
        fileURLWithPath: "/private/tmp/iscsi-prefix-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let image = root.appendingPathComponent("Disk.img")
    #expect(FileManager.default.createFile(atPath: image.path, contents: nil))
    let file = try FileHandle(forWritingTo: image)
    do {
        if presentation == .udsp { try file.write(contentsOf: layout.header(at: 0)) }
        try file.write(contentsOf: raw)
        try file.truncate(atOffset: presentation == .raw ? capacity : layout.imageByteCount)
        try file.close()
    } catch {
        try? file.close()
        throw error
    }
    let commands = ImageCommands([])
    // Exercise the actual bounded reader. Injecting the complete prefix would
    // hide the management page consuming part of the logical GPT read.
    let client = DiskImages(
        run: commands.run,
        fileSize: { _ in presentation == .raw ? capacity : layout.imageByteCount },
        sourceBlockSize: { _ in 512 })
    await #expect(throws: AttachmentError.readOnlyGeometryRequired) {
        try await client.attachImage(at: image, readOnly: false, presentation: presentation)
    }
    #expect(await commands.calls.isEmpty)
}

/// An earlier, timed-out ejection of the image that the OS hasn't answered yet.
private actor PendingImageEjection: DiskEjectionService {
    private var pending: Set<String> = [imageURL.path]
    private let ends: Bool
    private(set) var events: [String] = []
    private(set) var forced: [[String: UInt64]] = []
    private(set) var waited: [Duration] = []
    init(ends: Bool) { self.ends = ends }
    func pendingImagePaths() -> Set<String> { pending }
    func note(_ event: String) { events.append(event) }
    func waitForPendingEjection(of image: URL, timeout: Duration) -> Bool {
        events.append("wait")
        waited.append(timeout)
        if ends { pending.remove(image.standardizedFileURL.path) }
        return ends
    }
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) throws {
        Issue.record("A forced release never asks for an unconfirmed ejection")
        throw ProtocolError.invalidState
    }
    func forceEject(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        events.append("force")
        forced.append(mediaIdentifiers)
        try await validate()
    }
}

private enum PendingOutcome: String, CaseIterable { case ends, endsDetached, staysPending }

@Test(arguments: PendingOutcome.allCases)
private func aForcedReleaseStopsReconnectingThenWaitsForAnEarlierEjection(
    _ outcome: PendingOutcome
) async throws {
    let detached = try imagePlist(["images": [[String: Any]]()])
    // Two observations to confirm, one before and one after the wait, one to validate.
    let commands = ImageCommands([
        .success(try snapshot()), .success(try snapshot()), .success(try snapshot()),
        .success(outcome == .endsDetached ? detached : try snapshot()), .success(try snapshot()),
    ])
    let service = PendingImageEjection(ends: outcome != .staysPending)
    let images = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: service,
        mediaIdentifiers: MediaIdentities().read)
    let proof = try await images.captureForceEjectionIdentity(
        DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    #expect(proof.mediaIdentifiers == [imageDevice: 41, "/dev/disk900001": 42])
    let release = {
        try await images.forceDetach(proof, at: imageURL) { await service.note("stop") }
    }
    switch outcome {
    case .ends:
        try await release()
        #expect(await service.events == ["stop", "wait", "force"])
        #expect(await service.forced == [[imageDevice: 41, "/dev/disk900001": 42]])
    case .endsDetached:
        // The earlier request detached it after all: nothing is left to release here.
        try await release()
        #expect(await service.events == ["stop", "wait"])
    case .staysPending:
        await #expect(throws: ProtocolError.timedOut) { try await release() }
        #expect(await service.events == ["stop", "wait"])
    }
    #expect(await service.waited == [DiskImages.pendingEjectionWait])
}

@Test private func aChangedImageBehindAPendingEjectionIsNeverStoppedOrWaitedFor() async throws {
    let commands = ImageCommands(Array(repeating: .success(try snapshot()), count: 4))
    let identities = MediaIdentities()
    let service = PendingImageEjection(ends: true)
    let images = DiskImages(
        run: commands.run, fileSize: { _ in imageByteCount }, ejection: service,
        mediaIdentifiers: identities.read)
    let proof = try await images.captureForceEjectionIdentity(
        DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    identities.replace("/dev/disk900001")
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await images.forceDetach(proof, at: imageURL) { await service.note("stop") }
    }
    #expect(await service.events.isEmpty)
    // An ordinary detach still refuses to act beside the pending request.
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await images.detach(DiskAttachment(device: imageDevice, volumeURLs: []), at: imageURL)
    }
}
