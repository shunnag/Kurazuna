import Darwin
import Foundation
import ISCSICore

/// Owns only the small local marker, independently of the remote Disk.img and its file system.
struct BlockMountResources: Sendable {
    struct Attachment: Sendable, Equatable {
        let file: OwnedBlockResourceFiles.Identity
        let media: BlockResourceMedia
    }
    struct ForceIdentity: Sendable, Equatable {
        let attachment: Attachment
        let mount: CachedMountTable.Entry
        var file: OwnedBlockResourceFiles.Identity { attachment.file }
        var media: BlockResourceMedia { attachment.media }
    }
    typealias Runner = @Sendable (String, [String], TimeInterval) async throws -> Data
    /// How long a marker cleanup keeps trying while the unmounted marker is still open
    /// (REC022). A file system extension instance that loaded the marker for a mount that never
    /// completed keeps its device open until it gives the load up: within seconds once the
    /// mount resource is withdrawn, at the latest at its own mount deadline. A marker that is
    /// mounted is never waited for.
    struct BusyMarkerWait: Sendable {
        var limit: Duration
        var interval: Duration
        var now: @Sendable () -> ContinuousClock.Instant
        /// Throws `CancellationError` when the cleanup is cancelled.
        var sleep: @Sendable (Duration) async throws -> Void

        static let system = Self(
            limit: .seconds(20), interval: .milliseconds(500), now: { ContinuousClock.now },
            sleep: { try await Task.sleep(for: $0) })
    }
    let files: OwnedBlockResourceFiles
    private let run: Runner
    private let readMedia: @Sendable (String) throws -> BlockResourceMedia
    private let ejection: any DiskEjectionService
    private let mounts: @Sendable () throws -> [CachedMountTable.Entry]
    private let busyWait: BusyMarkerWait

    init(bridgeRoot: URL) {
        self.init(
            files: OwnedBlockResourceFiles(bridgeRoot: bridgeRoot),
            run: { try await SystemCommand.run($0, arguments: $1, timeout: $2) },
            media: BlockResourceMedia.read, ejection: DiskEjection.shared,
            mounts: CachedMountTable.read)
    }

    init(
        files: OwnedBlockResourceFiles, run: @escaping Runner,
        media: @escaping @Sendable (String) throws -> BlockResourceMedia,
        ejection: any DiskEjectionService,
        mounts: @escaping @Sendable () throws -> [CachedMountTable.Entry] = CachedMountTable.read,
        busyWait: BusyMarkerWait = .system
    ) {
        self.files = files
        self.run = run
        readMedia = media
        self.ejection = ejection
        self.mounts = mounts
        self.busyWait = busyWait
    }

    func inventory() async throws -> DiskImageInventory {
        let data = try await run("/usr/bin/hdiutil", ["info", "-plist"], 30)
        return try DiskImageInventory(data, pendingEjections: await ejection.pendingImagePaths())
    }

    func current(
        _ descriptor: ConnectionDescriptor, inventory: DiskImageInventory, expectedMount: URL?
    ) throws -> Attachment? {
        let image = try files.imageURL(for: descriptor)
        let device = try inventory.blockMarkerDevice(at: image, expectedMount: expectedMount)
        guard let file = try files.inspect(descriptor) else {
            guard device == nil else { throw AttachmentError.ownershipUnverified }
            return nil
        }
        guard let device else { return nil }
        let media = try readMedia(device)
        guard media.device == device else { throw AttachmentError.ownershipUnverified }
        return Attachment(file: file, media: media)
    }

    func prepare(_ descriptor: ConnectionDescriptor) async throws -> Attachment {
        try Task.checkCancellation()
        let image = try files.imageURL(for: descriptor)
        let before = try await inventory()
        guard try before.blockMarkerDevice(at: image, expectedMount: nil) == nil else {
            throw AttachmentError.recoveryRequired
        }
        let identity = try files.create(descriptor)
        try Task.checkCancellation()
        let arguments = [
            "attach", "-kernel", "-nomount", "-plist", "-imagekey",
            "diskimage-class=CRawDiskImage", "-readwrite", image.path,
        ]
        let runner = run
        // Observe the bounded attach's result before reporting cancellation.
        let reply = try await Task.detached {
            try await runner("/usr/bin/hdiutil", arguments, 30)
        }.value
        let attached = try DiskImages.parseAttachment(reply)
        let after = try await inventory()
        guard let current = try current(descriptor, inventory: after, expectedMount: nil),
            current.file == identity, current.media.device == attached.device
        else { throw AttachmentError.imageIdentityChanged }
        try Task.checkCancellation()
        return current
    }

    func cleanup(_ descriptor: ConnectionDescriptor) async throws {
        let image = try files.imageURL(for: descriptor)
        let started = busyWait.now()
        // Whether a busy marker may be tried again, after waiting one interval.
        func waitWhileBusy() async throws -> Bool {
            guard started.duration(to: busyWait.now()) + busyWait.interval <= busyWait.limit
            else { return false }
            try await busyWait.sleep(busyWait.interval)
            return true
        }
        // Each attempt observes the marker again: its identity, and that nothing is mounted
        // from it. Only the ejection's own busy reply is tried again.
        while let current = try self.current(
            descriptor, inventory: await inventory(), expectedMount: nil)
        {
            guard try !mounts().contains(where: { $0.source == current.media.device }) else {
                throw POSIXError(.EBUSY)
            }
            let confirmed = try self.current(
                descriptor, inventory: await inventory(), expectedMount: nil)
            guard confirmed == current else { throw AttachmentError.imageIdentityChanged }
            let run = self.run
            let files = self.files
            let readMedia = self.readMedia
            let mounts = self.mounts
            do {
                try await ejection.ejectConfirmed(
                    device: current.media.device, image: image,
                    unmountDevices: [current.media.device],
                    mediaIdentifiers: [current.media.device: current.media.identifier]
                ) {
                    let snapshot = try DiskImageInventory(
                        await run("/usr/bin/hdiutil", ["info", "-plist"], 30))
                    guard
                        try snapshot.blockMarkerDevice(at: image, expectedMount: nil)
                            == current.media.device,
                        try files.inspect(descriptor) == current.file,
                        try readMedia(current.media.device) == current.media,
                        try !mounts().contains(where: { $0.source == current.media.device })
                    else { throw AttachmentError.imageIdentityChanged }
                }
                break
            } catch let error as POSIXError where error.code == .EBUSY {
                guard try await waitWhileBusy() else { throw error }
            }
        }
        let after = try await inventory()
        guard try after.blockMarkerDevice(at: image, expectedMount: nil) == nil else {
            throw AttachmentError.recoveryRequired
        }
        guard let identity = try files.inspect(descriptor, full: true) else { return }
        // The image may be absent from an inventory while an attach client still holds it.
        while true {
            do {
                _ = try await run("/usr/sbin/lsof", ["-nP", "-t", "--", image.path], 30)
            } catch let SystemCommandError.failed(program, status, detail)
                where program == "lsof" && status == 1 && detail.isEmpty
            {
                break
            }
            guard try await waitWhileBusy() else { throw POSIXError(.EBUSY) }
        }
        guard try await inventory().blockMarkerDevice(at: image, expectedMount: nil) == nil else {
            throw AttachmentError.recoveryRequired
        }
        try files.remove(descriptor, expected: identity)
    }

    /// The bridge's entry in the cached mount table when this record's own marker media backs
    /// it, or nil when nothing is mounted at or below the bridge. Uses only facts the app can
    /// check itself (the kernel's cached table, the private marker file and its attached
    /// media), so it neither asks nor waits for the file system extension. Anything mounted
    /// there that isn't exactly this record's marker is never reported as absent.
    func forcedBridgeMount(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, inventory: DiskImageInventory
    ) throws -> CachedMountTable.Entry? {
        guard let mountID = descriptor.mountID,
            bridgeURL.standardizedFileURL.path
                == files.bridgeRoot.appendingPathComponent(mountID.uuidString).path
        else { throw AttachmentError.ownershipUnverified }
        let table = try mounts()
        let relevant = table.filter {
            $0.path == bridgeURL.path || $0.path.hasPrefix(bridgeURL.path + "/")
        }
        guard let mount = relevant.first else { return nil }
        guard relevant.count == 1, mount.path == bridgeURL.path,
            mount.type == ApplicationIdentity.current.fileSystemType, mount.owner == getuid(),
            BlockMountIdentity.isValidBSDName(String(mount.source.dropFirst(5))),
            mount.source.hasPrefix("/dev/"),
            table.filter({ $0.source == mount.source }).count == 1,
            let marker = try current(descriptor, inventory: inventory, expectedMount: bridgeURL),
            marker.media.device == mount.source,
            try files.inspect(descriptor, full: true) == marker.file
        else { throw AttachmentError.ownershipUnverified }
        return mount
    }

    func captureForceIdentity(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> ForceIdentity
    {
        guard
            let current = try current(
                descriptor, inventory: await inventory(), expectedMount: bridgeURL),
            try files.inspect(descriptor, full: true) == current.file
        else { throw AttachmentError.ownershipUnverified }
        guard let mount = try forceMount(descriptor, at: bridgeURL, media: current.media),
            mount.fileSystemID?.isValid == true
        else { throw AttachmentError.ownershipUnverified }
        return ForceIdentity(attachment: current, mount: mount)
    }

    /// Called only for an explicitly confirmed interrupted connection after Disk.img
    /// has detached. Force applies to this bridge's unmount; media ejection is normal.
    /// `beforeUnmounting` runs once every identity check has passed, just before the unmount.
    func forceEject(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, expected: ForceIdentity,
        beforeUnmounting: (@Sendable () async -> Void)? = nil
    ) async throws {
        guard try await captureForceIdentity(descriptor, at: bridgeURL) == expected else {
            throw AttachmentError.imageIdentityChanged
        }
        try await validateForceIdentity(
            descriptor, at: bridgeURL, expected: expected, mounted: true)
        try Task.checkCancellation()
        await beforeUnmounting?()
        try Task.checkCancellation()
        let runner = run
        // A DA whole-disk unmount may report success while a path-mounted FSKit
        // volume remains. Address this confirmed mount explicitly and observe the
        // bounded command before allowing its backing marker to be ejected.
        _ = try await Task.detached {
            try await runner("/sbin/umount", ["-f", bridgeURL.path], 30)
        }.value
        try Task.checkCancellation()
        try await validateForceIdentity(
            descriptor, at: bridgeURL, expected: expected, mounted: false)
        let image = try files.imageURL(for: descriptor)
        try await ejection.ejectConfirmed(
            device: expected.media.device, image: image, unmountDevices: [expected.media.device],
            mediaIdentifiers: [expected.media.device: expected.media.identifier]
        ) {
            try await validateForceIdentity(
                descriptor, at: bridgeURL, expected: expected, mounted: false,
                pendingMarker: image.path)
        }
    }

    private func validateForceIdentity(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, expected: ForceIdentity,
        mounted: Bool, pendingMarker: String? = nil
    ) async throws {
        let pending = (await ejection.pendingImagePaths()).subtracting(
            pendingMarker.map { Set([$0]) } ?? [])
        let snapshot = try DiskImageInventory(
            await run("/usr/bin/hdiutil", ["info", "-plist"], 30), pendingEjections: pending)
        let mount = try forceMount(descriptor, at: bridgeURL, media: expected.media)
        if mounted {
            guard mount == expected.mount else { throw AttachmentError.imageIdentityChanged }
        } else if mount != nil {
            throw POSIXError(.EBUSY)
        }
        guard !snapshot.hasImage(under: bridgeURL),
            try current(
                descriptor, inventory: snapshot, expectedMount: mounted ? bridgeURL : nil)
                == expected.attachment,
            try files.inspect(descriptor, full: true) == expected.file
        else { throw AttachmentError.imageIdentityChanged }
    }

    func confirmUnmountedIdentity(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, expected: ForceIdentity
    ) async throws {
        let snapshot = try await inventory()
        guard !snapshot.hasImage(under: bridgeURL),
            try files.inspect(descriptor, full: true) == expected.file
        else { throw AttachmentError.imageIdentityChanged }
        if let current = try current(descriptor, inventory: snapshot, expectedMount: nil) {
            guard current == expected.attachment else { throw AttachmentError.imageIdentityChanged }
        }
        guard
            try forceMount(descriptor, at: bridgeURL, media: expected.media) == nil
        else { throw POSIXError(.EBUSY) }
    }

    private func forceMount(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, media: BlockResourceMedia
    ) throws -> CachedMountTable.Entry? {
        guard let mountID = descriptor.mountID,
            bridgeURL.standardizedFileURL.path
                == files.bridgeRoot.appendingPathComponent(mountID.uuidString).path
        else { throw AttachmentError.ownershipUnverified }
        let relevant = try mounts().filter {
            $0.path == bridgeURL.path || $0.path.hasPrefix(bridgeURL.path + "/")
                || $0.source == media.device
        }
        guard relevant.count <= 1,
            relevant.allSatisfy({
                $0.path == bridgeURL.path && $0.source == media.device
                    && $0.type == ApplicationIdentity.current.fileSystemType && $0.owner == getuid()
            })
        else { throw AttachmentError.ownershipUnverified }
        return relevant.first
    }
}
