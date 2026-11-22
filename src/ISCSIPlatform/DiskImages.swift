import CoreFoundation
import Darwin
import Foundation
import ISCSICore
import os

/// A read-only snapshot. Its property-list containers are private, immutable, and decoded
/// here from Data, so no externally mutable Any values cross a concurrency boundary.
public struct DiskImageInventory: @unchecked Sendable {
    private let images: [[String: Any]]
    private let pendingEjections: Set<String>
    public var imagePaths: [String] {
        let paths = images.compactMap { $0["image-path"] as? String }
        return paths + pendingEjections.subtracting(paths).sorted()
    }

    init(_ data: Data, pendingEjections: Set<String> = []) throws {
        guard data.count <= 1_048_576,
            let plist = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let images = plist["images"] as? [[String: Any]], images.count <= 1024
        else { throw AttachmentError.invalidImageResponse }
        self.images = images
        self.pendingEjections = pendingEjections
    }

    public func attachment(at imageURL: URL) throws -> DiskAttachment? {
        guard !pendingEjections.contains(imageURL.standardizedFileURL.path) else {
            throw AttachmentError.recoveryRequired
        }
        return try listedAttachment(at: imageURL)
    }

    /// Every device entry listed for the image, in order, for diagnostics only.
    func listedDevices(at imageURL: URL) throws -> [String] {
        images.filter {
            ($0["image-path"] as? String).map {
                URL(fileURLWithPath: $0).standardizedFileURL.path
            } == imageURL.standardizedFileURL.path
        }.flatMap { image in
            (image["system-entities"] as? [[String: Any]] ?? []).compactMap {
                $0["dev-entry"] as? String
            } + ["|"]
        }
    }

    /// Whether an ejection this process requested for the image is still waiting for the OS.
    func hasPendingEjection(at imageURL: URL) -> Bool {
        pendingEjections.contains(imageURL.standardizedFileURL.path)
    }

    /// As `attachment(at:)`, but through an ejection still pending for it. Only a confirmed
    /// forced release looks through one: it identifies the same image, then stops what holds
    /// the earlier request and waits for that request to end before it releases anything.
    func forcedAttachment(at imageURL: URL) throws -> DiskAttachment? {
        try listedAttachment(at: imageURL)
    }

    private func listedAttachment(at imageURL: URL) throws -> DiskAttachment? {
        let matches = images.filter { image in
            guard let path = image["image-path"] as? String else { return false }
            return URL(fileURLWithPath: path).standardizedFileURL.path
                == imageURL.standardizedFileURL.path
        }
        guard matches.count <= 1 else { throw AttachmentError.imageIdentityChanged }
        guard let image = matches.first else { return nil }
        return try DiskImages.parseAttachment(
            PropertyListSerialization.data(fromPropertyList: image, format: .binary, options: 0))
    }

    /// Synthesized whole disks (for example an APFS container) must be unmounted
    /// before the physical image. Every returned device comes from this image.
    /// `throughPendingEjection` is for a confirmed forced release; see `forcedAttachment`.
    func unmountDevices(at imageURL: URL, throughPendingEjection: Bool = false) throws -> [String] {
        let listed =
            throughPendingEjection
            ? try forcedAttachment(at: imageURL) : try attachment(at: imageURL)
        guard let attachment = listed else { return [] }
        let match = images.first {
            guard let path = $0["image-path"] as? String else { return false }
            return URL(fileURLWithPath: path).standardizedFileURL.path
                == imageURL.standardizedFileURL.path
        }
        guard let entities = match?["system-entities"] as? [[String: Any]], entities.count <= 1024
        else {
            throw AttachmentError.invalidImageResponse
        }
        var devices: [String] = []
        for entity in entities {
            if let device = entity["dev-entry"] as? String, DiskImages.isWholeDisk(device),
                device != attachment.device, !devices.contains(device)
            {
                devices.append(device)
            }
        }
        return devices + [attachment.device]
    }

    func hasImage(under directory: URL, excluding expected: URL? = nil) -> Bool {
        let root = directory.standardizedFileURL.path
        let expected = expected?.standardizedFileURL.path
        return imagePaths.contains { path in
            guard path.hasPrefix("/") else { return false }
            let path = URL(fileURLWithPath: path).standardizedFileURL.path
            return path != expected && (path == root || path.hasPrefix(root + "/"))
        }
    }

    /// A marker is one unpartitioned, owned image. Never accept another entity or mount.
    func blockMarkerDevice(at imageURL: URL, expectedMount: URL?) throws -> String? {
        guard !pendingEjections.contains(imageURL.standardizedFileURL.path) else {
            throw AttachmentError.recoveryRequired
        }
        let matches = images.filter {
            ($0["image-path"] as? String) == imageURL.standardizedFileURL.path
        }
        guard matches.count <= 1 else { throw AttachmentError.imageIdentityChanged }
        guard let image = matches.first else { return nil }
        guard let entities = image["system-entities"] as? [[String: Any]], entities.count == 1,
            let entity = entities.first, let device = entity["dev-entry"] as? String,
            DiskImages.isWholeDisk(device)
        else { throw AttachmentError.ownershipUnverified }
        let mounted = entity["mount-point"] as? String
        guard mounted == expectedMount?.path,
            entity["mount-point"] == nil || mounted != nil
        else { throw AttachmentError.ownershipUnverified }
        return device
    }
}

/// Raw attachment and normal volume mounting are separate operations: an unformatted LUN
/// remains a useful disk even when it has no mountable file system.
public struct DiskImages: Sendable {
    typealias Runner = @Sendable (String, [String], TimeInterval) async throws -> Data
    typealias SizeReader = @Sendable (URL) throws -> UInt64
    typealias HeaderReader = @Sendable (URL) throws -> Data
    typealias SourceBlockReader = @Sendable (URL) throws -> UInt32?
    typealias MediaReader = @Sendable ([String]) throws -> [String: UInt64]
    private let run: Runner
    private let fileSize: SizeReader
    private let header: HeaderReader
    private let sourceBlockSize: SourceBlockReader
    private let ejection: any DiskEjectionService
    private let readMediaIdentifiers: MediaReader

    public init() {
        run = { program, arguments, timeout in
            try await SystemCommand.run(program, arguments: arguments, timeout: timeout)
        }
        fileSize = Self.sourceByteCount
        header = Self.sourceHeader
        sourceBlockSize = Self.sourceBlockSize
        ejection = DiskEjection.shared
        readMediaIdentifiers = { try DiskArbitrationEjectionHandle.mediaIdentifiers(for: $0) }
    }
    init(
        run: @escaping Runner, fileSize: @escaping SizeReader, header: HeaderReader? = nil,
        sourceBlockSize: SourceBlockReader? = nil,
        ejection: any DiskEjectionService = DiskEjection.shared,
        mediaIdentifiers: @escaping MediaReader = {
            try DiskArbitrationEjectionHandle.mediaIdentifiers(for: $0)
        }
    ) {
        self.run = run
        self.fileSize = fileSize
        self.header = header ?? Self.sourceHeader
        self.sourceBlockSize = sourceBlockSize ?? Self.sourceBlockSize
        self.ejection = ejection
        readMediaIdentifiers = mediaIdentifiers
    }

    public func inventory() async throws -> DiskImageInventory {
        let data = try await run("/usr/bin/hdiutil", ["info", "-plist"], 30)
        let pending = await ejection.pendingImagePaths()
        try Task.checkCancellation()
        return try DiskImageInventory(data, pendingEjections: pending)
    }

    public func attachRawImage(at imageURL: URL, readOnly: Bool) async throws -> DiskAttachment {
        try await attachImage(at: imageURL, readOnly: readOnly, presentation: .raw)
    }

    public func attachImage(
        at imageURL: URL, readOnly: Bool, presentation: LUNImagePresentation
    ) async throws -> DiskAttachment {
        try validate(imageURL)
        let size = try fileSize(imageURL)
        guard size >= 512, size <= UInt64(Int64.max), size % 512 == 0 else {
            throw AttachmentError.invalidImageResponse
        }
        try Task.checkCancellation()
        let expectedSize: UInt64
        let expectedBlockSize: UInt32
        let attached: DiskAttachment
        let reported: [String]
        switch presentation {
        case .raw:
            expectedSize = size
            expectedBlockSize = try DiskImageGeometry.blockSize(
                prefix: Data(header(imageURL).prefix(DiskImageGeometry.prefixByteCount)),
                byteCount: size,
                sourceBlockSize: sourceBlockSize(imageURL))
            guard readOnly || expectedBlockSize == 512 else {
                throw AttachmentError.readOnlyGeometryRequired
            }
            var arguments = [
                "attach", expectedBlockSize == 512 ? "-kernel" : "-nokernel",
                "-nomount", "-plist", "-imagekey", "diskimage-class=CRawDiskImage",
                readOnly ? "-readonly" : "-readwrite",
            ]
            if expectedBlockSize != 512 {
                arguments += ["-blocksize", String(expectedBlockSize)]
            }
            arguments.append(imageURL.path)
            let data = try await runAttachmentCommand(
                "/usr/bin/hdiutil", arguments, 30)
            attached = try Self.parseAttachment(data)
            reported = Self.deviceEntries(data)
        case .udsp:
            let prefix = try header(imageURL)
            let layout = try SparseImageLayout(
                firstHeader: Data(prefix.prefix(4096)), imageByteCount: size)
            expectedSize = layout.capacity
            // The fixed first page precedes a contiguous payload prefix. Even
            // the smallest bands place the next management page beyond this
            // bounded read. Inspect the LUN's GPT, not the UDSP header's units.
            let payload = Data(
                prefix.dropFirst(Int(SparseImageLayout.headerByteCount))
                    .prefix(Int(min(layout.capacity, UInt64(DiskImageGeometry.prefixByteCount)))))
            expectedBlockSize = try DiskImageGeometry.blockSize(
                prefix: payload, byteCount: layout.capacity,
                sourceBlockSize: sourceBlockSize(imageURL))
            guard readOnly || expectedBlockSize == 512 else {
                throw AttachmentError.readOnlyGeometryRequired
            }
            var arguments = [
                "attach", "-nokernel", "-nomount", "-plist", "-imagekey",
                "diskimage-class=CSparseDiskImage", readOnly ? "-readonly" : "-readwrite",
            ]
            if expectedBlockSize != 512 {
                arguments += ["-blocksize", String(expectedBlockSize)]
            }
            arguments.append(imageURL.path)
            let data = try await runAttachmentCommand(
                "/usr/bin/hdiutil", arguments, 30)
            attached = try Self.parseAttachment(data)
            reported = Self.deviceEntries(data)
        }
        try Task.checkCancellation()
        _ = try await checkedAttachment(
            at: imageURL, attached: attached.device, reported: reported, stage: "attached")
        let information = try await run(
            "/usr/sbin/diskutil", ["info", "-plist", attached.device], 30)
        try Self.verifyDeviceInfo(
            information, byteCount: expectedSize, readOnly: readOnly, blockSize: expectedBlockSize)
        try Task.checkCancellation()
        let mountIssue: VolumeMountIssue?
        do {
            _ = try await runAttachmentCommand(
                "/usr/sbin/diskutil", ["mountDisk", attached.device], 60)
            mountIssue = nil
        } catch let SystemCommandError.failed(program, status, detail)
            where program == "diskutil" && status == 1
        {
            mountIssue = VolumeMountIssue(status: status, detail: detail)
        }
        try Task.checkCancellation()
        let current = try await checkedAttachment(
            at: imageURL, attached: attached.device, reported: reported, stage: "mounted")
        if let mountIssue {
            let information = try await run(
                "/usr/sbin/diskutil", ["info", "-plist", current.device], 30)
            try Self.verifyDeviceInfo(
                information, byteCount: expectedSize, readOnly: readOnly,
                blockSize: expectedBlockSize)
            try Task.checkCancellation()
            return DiskAttachment(
                device: current.device, volumeURLs: current.volumeURLs,
                volumeMountIssue: mountIssue)
        }
        return current
    }

    private static let logger = Logger(subsystem: "dev.soba.iscsi", category: "DiskImages")

    /// The attachment the inventory lists for an image this process just attached. Any other
    /// answer stops the connection; what the attach reported and the inventory showed is
    /// logged, without the path, so that a rare mismatch can be told apart afterwards.
    private func checkedAttachment(
        at imageURL: URL, attached device: String, reported: [String], stage: String
    ) async throws -> DiskAttachment {
        let snapshot = try await inventory()
        let listed: DiskAttachment?
        do {
            listed = try snapshot.attachment(at: imageURL)
        } catch {
            Self.logger.error(
                "attach identity \(stage, privacy: .public): attached=\(device, privacy: .public) listing failed: \(String(describing: error), privacy: .public)"
            )
            throw error
        }
        guard let listed, listed.device == device else {
            let devices = (try? snapshot.listedDevices(at: imageURL)) ?? []
            Self.logger.error(
                "attach identity \(stage, privacy: .public): attached=\(device, privacy: .public) reported=\(reported.joined(separator: ","), privacy: .public) listed=\(listed?.device ?? "none", privacy: .public) entities=\(devices.joined(separator: ","), privacy: .public)"
            )
            throw AttachmentError.imageIdentityChanged
        }
        return listed
    }

    /// Finish the bounded side effect before reporting cancellation, so recovery can inspect
    /// its registered device. Terminating an attach client midway can leave a busy backing file
    /// without a corresponding entry in the DiskImages inventory.
    private func runAttachmentCommand(
        _ program: String, _ arguments: [String], _ timeout: TimeInterval
    ) async throws -> Data {
        try Task.checkCancellation()
        let runner = run
        return try await Task.detached {
            try await runner(program, arguments, timeout)
        }.value
    }

    private static func sourceHeader(_ url: URL) throws -> Data {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        // UDSP places one management page before the logical LUN. Preserve the
        // parser's complete bounded prefix, including its largest GPT header.
        // Raw callers trim the additional page before invoking the same parser.
        let count = DiskImageGeometry.prefixByteCount + Int(SparseImageLayout.headerByteCount)
        return try file.read(upToCount: count) ?? Data()
    }

    private static func sourceBlockSize(_ url: URL) throws -> UInt32? {
        var bytes = [UInt8](repeating: 0, count: 5)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                url.path, ConnectionDescriptor.sourceBlockSizeAttributeName, $0.baseAddress,
                $0.count, 0, 0)
        }
        if count < 0 {
            if errno == ENOATTR || errno == ENOTSUP { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return try DiskImageGeometry.sourceBlockSize(from: Data(bytes.prefix(count)))
    }

    private static func sourceByteCount(_ url: URL) throws -> UInt64 {
        var status = stat()
        guard lstat(url.path, &status) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), status.st_size >= 0 else {
            throw POSIXError(.EINVAL)
        }
        return UInt64(status.st_size)
    }

    static func verifyDeviceInfo(
        _ data: Data, byteCount: UInt64, readOnly: Bool, blockSize: UInt32 = 512
    ) throws {
        guard data.count <= 1_048_576,
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let size = info["TotalSize"] as? NSNumber,
            ["q", "Q", "i", "I", "l", "L", "s", "S"].contains(String(cString: size.objCType)),
            size.int64Value > 0, size.uint64Value == byteCount,
            let sector = info["DeviceBlockSize"] as? NSNumber,
            ["q", "Q", "i", "I", "l", "L", "s", "S"].contains(String(cString: sector.objCType)),
            sector.int64Value > 0, sector.uint64Value == UInt64(blockSize),
            let writable = info["WritableMedia"] as? NSNumber,
            CFGetTypeID(writable) == CFBooleanGetTypeID(), writable.boolValue == !readOnly
        else { throw AttachmentError.invalidImageResponse }
    }

    public func detach(_ attachment: DiskAttachment, at imageURL: URL) async throws {
        try validate(imageURL)
        let snapshot = try await inventory()
        guard let current = try snapshot.attachment(at: imageURL) else { return }
        guard current.device == attachment.device else {
            throw AttachmentError.imageIdentityChanged
        }
        let devices = try snapshot.unmountDevices(at: imageURL)
        try await eject(current, devices: devices, at: imageURL, forceIdentity: nil)
    }

    /// Identifies the image for a confirmed forced release, through an ejection still pending
    /// for it (see `forcedAttachment`).
    func captureForceEjectionIdentity(
        _ attachment: DiskAttachment, at imageURL: URL
    ) async throws -> DiskAttachmentIdentity {
        try validate(imageURL)
        let before = try await inventory()
        guard try before.forcedAttachment(at: imageURL)?.device == attachment.device else {
            throw AttachmentError.imageIdentityChanged
        }
        let devices = try before.unmountDevices(at: imageURL, throughPendingEjection: true)
        let identifiers = try readMediaIdentifiers(devices)
        let after = try await inventory()
        guard try after.forcedAttachment(at: imageURL)?.device == attachment.device,
            try after.unmountDevices(at: imageURL, throughPendingEjection: true) == devices,
            try readMediaIdentifiers(devices) == identifiers
        else { throw AttachmentError.imageIdentityChanged }
        return DiskAttachmentIdentity(
            imageURL: imageURL, device: attachment.device, unmountDevices: devices,
            mediaIdentifiers: identifiers)
    }

    /// How long a confirmed forced release waits, after asking the extension to stop
    /// reconnecting, for an earlier ejection of the same image to end. That request usually
    /// waits for the file system's last writes, which fail at once once reconnecting stops.
    static let pendingEjectionWait = Duration.seconds(30)

    /// Whether no ejection this process requested for the image is pending any longer, waiting
    /// at most `timeout` for one to end.
    func waitForPendingEjection(at imageURL: URL, timeout: Duration) async -> Bool {
        await ejection.waitForPendingEjection(of: imageURL, timeout: timeout)
    }

    /// `beforeEjecting` runs once every identity check has passed, just before the forced
    /// unmount, which is the first step that can't be undone. An earlier, timed-out ejection
    /// of the image may still be pending: the OS can't take another request for it until that
    /// one ends, and it typically waits for writes that wait for the server. Then
    /// `beforeEjecting` runs once the checks have passed, as it would anyway, the earlier
    /// request is given `pendingEjectionWait` to end, and the image is observed and checked
    /// again before it is released. An image that request already detached is left alone.
    func forceDetach(
        _ identity: DiskAttachmentIdentity, at imageURL: URL,
        beforeEjecting: (@Sendable () async -> Void)? = nil,
        pendingEjectionWait: Duration = DiskImages.pendingEjectionWait
    ) async throws {
        guard imageURL == identity.imageURL else { throw AttachmentError.imageIdentityChanged }
        try validate(imageURL)
        var waited = false
        var stopped = false
        while true {
            let snapshot = try await inventory()
            guard let current = try snapshot.forcedAttachment(at: imageURL) else {
                if waited { return }
                throw AttachmentError.imageIdentityChanged
            }
            let devices = try snapshot.unmountDevices(at: imageURL, throughPendingEjection: true)
            guard identity.device == current.device, identity.unmountDevices == devices,
                try readMediaIdentifiers(devices) == identity.mediaIdentifiers
            else { throw AttachmentError.imageIdentityChanged }
            if !stopped {
                stopped = true
                await beforeEjecting?()
            }
            let pending = await ejection.pendingImagePaths()
            guard
                snapshot.hasPendingEjection(at: imageURL)
                    || pending.contains(imageURL.standardizedFileURL.path)
            else {
                try await eject(current, devices: devices, at: imageURL, forceIdentity: identity)
                return
            }
            // Still pending after the wait: the OS hasn't answered the earlier request.
            guard !waited,
                await ejection.waitForPendingEjection(of: imageURL, timeout: pendingEjectionWait)
            else { throw ProtocolError.timedOut }
            waited = true
        }
    }

    private func eject(
        _ current: DiskAttachment, devices: [String], at imageURL: URL,
        forceIdentity: DiskAttachmentIdentity?
    ) async throws {
        let validate: @Sendable () async throws -> Void = {
            let data = try await run("/usr/bin/hdiutil", ["info", "-plist"], 30)
            try Task.checkCancellation()
            guard try DiskImageInventory(data).attachment(at: imageURL)?.device == current.device
            else { throw AttachmentError.imageIdentityChanged }
        }
        if let forceIdentity {
            try await ejection.forceEject(
                device: current.device, image: imageURL, unmountDevices: devices,
                mediaIdentifiers: forceIdentity.mediaIdentifiers, validate: validate)
        } else {
            try await ejection.eject(
                device: current.device, image: imageURL, unmountDevices: devices,
                validate: validate)
        }
    }

    public static func parseAttachment(_ data: Data) throws -> DiskAttachment {
        guard data.count <= 1_048_576,
            let plist = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let entities = plist["system-entities"] as? [[String: Any]],
            let device = imageWholeDisk(entities)
        else { throw AttachmentError.invalidImageResponse }
        return DiskAttachment(
            device: device,
            volumeURLs: entities.compactMap { entity in
                // mountDisk can mount the EFI system partition before the data
                // volume. Its partition type, rather than its user-visible name,
                // determines whether it belongs in the app's volume list.
                if let hint = entity["content-hint"] as? String,
                    ["EFI", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"].contains(hint.uppercased())
                {
                    return nil
                }
                guard let path = entity["mount-point"] as? String, path.hasPrefix("/Volumes/")
                else { return nil }
                let url = URL(fileURLWithPath: path, isDirectory: true)
                guard url.standardizedFileURL.path.hasPrefix("/Volumes/") else { return nil }
                return url
            })
    }

    private func validate(_ url: URL) throws {
        guard url.isFileURL, url.host?.isEmpty != false, url.query == nil, url.fragment == nil,
            url.path.hasPrefix("/"), url.path != "/"
        else { throw POSIXError(.EINVAL) }
    }

    /// The image's own whole disk. `hdiutil attach` doesn't list the entities in a fixed
    /// order, and an attach has yielded the APFS container's whole disk first where the
    /// inventory listed the image's own. Both answers must name the same disk, so the choice
    /// doesn't depend on order: a whole disk that isn't an APFS container if there is one, and
    /// of those the lowest-numbered, which the image's own disk takes before anything is
    /// synthesized from it.
    private static func imageWholeDisk(_ entities: [[String: Any]]) -> String? {
        let wholeDisks = entities.compactMap { entity -> (device: String, container: Bool)? in
            guard let device = entity["dev-entry"] as? String, isWholeDisk(device) else {
                return nil
            }
            let hint = (entity["content-hint"] as? String)?.uppercased()
            return (device, hint == "EF57347C-0000-11AA-AA11-00306543ECAC")
        }
        let images = wholeDisks.filter { !$0.container }
        return (images.isEmpty ? wholeDisks : images).map(\.device).min { lhs, rhs in
            let left = lhs.dropFirst(9)
            let right = rhs.dropFirst(9)
            return (left.count, left) < (right.count, right)
        }
    }

    /// Every device entry an attach reported, in its order, for diagnostics only.
    private static func deviceEntries(_ data: Data) -> [String] {
        guard data.count <= 1_048_576,
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let entities = plist["system-entities"] as? [[String: Any]]
        else { return [] }
        return entities.compactMap { $0["dev-entry"] as? String }
    }

    fileprivate static func isWholeDisk(_ value: String) -> Bool {
        guard value.hasPrefix("/dev/disk") else { return false }
        let suffix = value.dropFirst(9)
        return !suffix.isEmpty && suffix.utf8.allSatisfy({ (48...57).contains($0) })
    }
}
