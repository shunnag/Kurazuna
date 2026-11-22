import Darwin
import FSKitNativeDiagnostics
import Foundation
import ISCSICore
import ISCSIPlatform

/// OS-generated 4Kn GPT fixtures. Only reachable after the entry point validates
/// the private, nonce-named root; it never accepts a caller-supplied device.
enum GeometryFixture {
    static let byteCount = 512 * 1_048_576

    static func validateImage(_ image: URL, requireGPT: Bool = true) throws {
        guard image.resolvingSymlinksInPath().path == image.path,
            try image.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]).isRegularFile
                == true,
            try image.resourceValues(forKeys: [.fileSizeKey]).fileSize == byteCount
        else { throw ProtocolError.malformed("private 4Kn image") }
        if requireGPT {
            let file = try FileHandle(forReadingFrom: image)
            defer { try? file.close() }
            let prefix = try file.read(upToCount: 8192) ?? Data()
            guard prefix.count == 8192,
                prefix.subdata(in: 512..<520) != Data("EFI PART".utf8),
                prefix.subdata(in: 4096..<4104) == Data("EFI PART".utf8),
                prefix.subdata(in: 4120..<4128) == Data([1, 0, 0, 0, 0, 0, 0, 0])
            else { throw ProtocolError.malformed("native 4Kn GPT header") }
        }
    }

    static func attachLocal(
        _ image: URL, readOnly: Bool, preparing: Bool = false, uncached: Bool = false,
        innerSync: Bool = false
    ) async throws -> DiskAttachment {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "legacy-4k" else {
            throw ProtocolError.invalidState
        }
        try validateImage(image, requireGPT: !preparing)
        let images = DiskImages()
        guard try await images.inventory().attachment(at: image) == nil else {
            throw AttachmentError.imageIdentityChanged
        }
        var cacheFD: Int32 = -1
        defer { if cacheFD >= 0 { close(cacheFD) } }
        if uncached {
            guard !preparing, !readOnly else { throw ProtocolError.invalidState }
            cacheFD = open(image.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            guard cacheFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            // F_GLOBAL_NOCACHE affects this newly created private file's vnode,
            // including the helper's open. It is not a system-wide setting and
            // is not persisted in the image. Its lifetime ends with this vnode.
            let previous = fcntl(cacheFD, F_GLOBAL_NOCACHE, 1)
            guard previous >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            print("IMAGE_CACHE_CONTROL perFileNoCache=true previous=\(previous)")
        }
        do {
            _ = try await SystemCommand.run(
                "/usr/bin/hdiutil",
                arguments: [
                    "attach", "-nokernel", "-nomount", "-plist", "-blocksize", "4096",
                    "-imagekey", "diskimage-class=CRawDiskImage",
                    readOnly ? "-readonly" : "-readwrite", image.path,
                ])
            guard let attached = try await images.inventory().attachment(at: image) else {
                throw AttachmentError.invalidImageResponse
            }
            let data = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["info", "-plist", attached.device])
            guard
                let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                    as? [String: Any], info["TotalSize"] as? Int == byteCount,
                info["DeviceBlockSize"] as? Int == 4096,
                info["WritableMedia"] as? Bool == !readOnly
            else { throw AttachmentError.invalidImageResponse }
            guard !preparing || !innerSync else { throw ProtocolError.invalidState }
            if !preparing {
                if innerSync {
                    try await mountSynchronizedHFS(
                        image: image, attachment: attached, readOnly: readOnly)
                } else {
                    _ = try await SystemCommand.run(
                        "/usr/sbin/diskutil", arguments: ["mountDisk", attached.device])
                }
            }
            guard let current = try await images.inventory().attachment(at: image),
                current.device == attached.device
            else { throw AttachmentError.imageIdentityChanged }
            if !preparing, !readOnly,
                ProcessInfo.processInfo.environment["ISCSI_TEST_NATIVE_INNER_SYNC"] == "1"
            {
                guard !innerSync else { throw ProtocolError.invalidState }
                try await updateSynchronousHFS(image: image, attachment: current)
            }
            return current
        } catch {
            if let current = try? await images.inventory().attachment(at: image) {
                try? await images.detach(current, at: image)
            }
            throw error
        }
    }

    private static func updateSynchronousHFS(image: URL, attachment: DiskAttachment) async throws {
        let images = DiskImages()
        guard try await images.inventory().attachment(at: image)?.device == attachment.device,
            attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", volume.path])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any], let device = info["DeviceNode"] as? String,
            device.range(of: "^/dev/disk[0-9]+s[0-9]+$", options: .regularExpression) != nil
        else { throw AttachmentError.imageIdentityChanged }
        let inventory = try await SystemCommand.run(
            "/usr/bin/hdiutil", arguments: ["info", "-plist"])
        guard
            let plist = try PropertyListSerialization.propertyList(from: inventory, format: nil)
                as? [String: Any], let allImages = plist["images"] as? [[String: Any]],
            let own = allImages.first(where: { $0["image-path"] as? String == image.path }),
            own["owner-uid"] as? UInt32 == geteuid(),
            let entities = own["system-entities"] as? [[String: Any]],
            entities.contains(where: {
                $0["dev-entry"] as? String == device && $0["mount-point"] as? String == volume.path
            })
        else { throw AttachmentError.imageIdentityChanged }
        try FixtureFileSystem.hfsPlus.verifyVolume(volume, readOnly: false)
        let result = iscsi_test_hfs_sync_mount(volume.path, device)
        let report: [String: Any] = [
            "image": image.path, "device": device, "volume": volume.path,
            "errno": result.error, "syscallAttempted": result.syscallAttempted != 0,
            "beforeFlags": result.beforeFlags, "afterFlags": result.afterFlags,
            "synchronousBefore": result.beforeFlags & UInt32(MNT_SYNCHRONOUS) != 0,
            "synchronousAfter": result.afterFlags & UInt32(MNT_SYNCHRONOUS) != 0,
            "sameOwnedImageVerified": true, "readOnly": false,
        ]
        let root =
            image.path.contains("/Mounts/")
            ? image.deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
            : image.deletingLastPathComponent()
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(
                to: root.appendingPathComponent("NativeSyncMount.json"),
                options: .withoutOverwriting)
        guard result.error == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: result.error) ?? .EIO)
        }
        try FixtureFileSystem.hfsPlus.verifyVolume(volume, readOnly: false)
        print("PASS: native mount update established synchronous HFS+ on the owned private image")
    }

    /// Mount only the HFS+ partition of this validated, owned disposable 4Kn image.
    /// Recovery copies keep the normal mount path; this changes the test source only.
    private static func mountSynchronizedHFS(
        image: URL, attachment: DiskAttachment, readOnly: Bool
    ) async throws {
        let images = DiskImages()
        guard try await images.inventory().attachment(at: image)?.device == attachment.device else {
            throw AttachmentError.imageIdentityChanged
        }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["list", "-plist", attachment.device])
        guard data.count <= 1_048_576,
            let tree = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let disks = tree["AllDisksAndPartitions"] as? [[String: Any]], disks.count == 1,
            disks[0]["DeviceIdentifier"] as? String == String(attachment.device.dropFirst(5)),
            let partitions = disks[0]["Partitions"] as? [[String: Any]], partitions.count <= 32
        else { throw ProtocolError.malformed("private 4Kn HFS+ partition inventory") }
        let hfs = partitions.filter { $0["Content"] as? String == "Apple_HFS" }
        let prefix = String(attachment.device.dropFirst(5)) + "s"
        guard hfs.count == 1, let partition = hfs[0]["DeviceIdentifier"] as? String,
            partition.hasPrefix(prefix)
        else { throw ProtocolError.malformed("private 4Kn HFS+ partition") }
        let suffix = partition.dropFirst(prefix.count)
        guard !suffix.isEmpty, suffix.utf8.allSatisfy({ (48...57).contains($0) })
        else { throw ProtocolError.malformed("private 4Kn HFS+ partition") }
        _ = try await SystemCommand.run(
            "/usr/sbin/diskutil",
            arguments: ["mount", "-mountOptions", readOnly ? "sync,ro" : "sync", partition])
        guard let current = try await images.inventory().attachment(at: image),
            current.device == attachment.device, current.volumeURLs.count == 1,
            let volume = current.volumeURLs.first
        else { throw AttachmentError.imageIdentityChanged }
        var status = statfs()
        guard statfs(volume.path, &status) == 0,
            status.f_flags & UInt32(MNT_SYNCHRONOUS) != 0,
            (status.f_flags & UInt32(MNT_RDONLY) != 0) == readOnly
        else { throw ProtocolError.malformed("4Kn HFS+ inner sync mount flags") }
        let kind = withUnsafePointer(to: &status.f_fstypename) {
            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
        }
        guard kind == "hfs" else { throw ProtocolError.malformed("4Kn inner mount filesystem") }
        let report: [String: Any] = [
            "image": image.path, "device": current.device, "partition": partition,
            "filesystem": kind, "synchronous": true, "readOnly": readOnly,
            "nativeDeviceBlockSize": 4096, "mountFlags": status.f_flags,
        ]
        print(
            "INNER_GEOMETRY_MOUNT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: report, options: [.sortedKeys]), as: UTF8.self))
    }

    static func prepare(root: URL, nonce: UUID, marker: Data) async throws {
        let format = try FixtureFileSystem.at(root)
        let image = root.appendingPathComponent(format.imageName)
        guard !FileManager.default.fileExists(atPath: image.path),
            FileManager.default.createFile(
                atPath: image.path, contents: nil, attributes: [.posixPermissions: 0o600])
        else { throw ProtocolError.invalidState }
        let file = try FileHandle(forWritingTo: image)
        do {
            try file.truncate(atOffset: UInt64(byteCount))
            try file.close()
        } catch {
            try? file.close()
            throw error
        }
        let images = DiskImages()
        let attachment = try await attachLocal(image, readOnly: false, preparing: true)
        do {
            let nativeFormat =
                format == .hfsPlus
                ? (FixtureFileSystem.usesPlainHFSGeometryControl ? "HFS+" : "JHFS+")
                : format.displayName
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil",
                arguments: [
                    "partitionDisk", attachment.device, "GPT", nativeFormat,
                    "G4K" + nonce.uuidString.prefix(8), "100%",
                ], timeout: 120)
            guard let current = try await images.inventory().attachment(at: image),
                current.device == attachment.device, current.volumeURLs.count == 1,
                let volume = current.volumeURLs.first
            else { throw AttachmentError.invalidImageResponse }
            try format.verifyVolume(volume, readOnly: false)
            let markerURL = volume.appendingPathComponent("FSKit-validation.txt")
            try marker.write(to: markerURL)
            try SynchronizationBoundaryProbe.prepareIfRequested(at: volume)
            let output = try FileHandle(forWritingTo: markerURL)
            do {
                guard fcntl(output.fileDescriptor, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
                try output.close()
            } catch {
                try? output.close()
                throw error
            }
            try FixtureFileSystem.recordSpace(of: volume, at: root)
            try await images.detach(current, at: image)
            try validateImage(image)
            print("PASS: OS-generated 512 MiB \(format.displayName) fixture, GPT at byte 4096")
        } catch {
            if let current = try? await images.inventory().attachment(at: image) {
                try? await images.detach(current, at: image)
            }
            throw error
        }
    }

    /// Local APFS-backed control. This observes the visible pre-close copy;
    /// it does not simulate host power loss or prove physical media persistence.
    static func writeLocalSynchronizedSnapshot(
        root: URL, contents: Data, applePassthrough: Bool = false
    ) async throws {
        guard try FixtureFileSystem.at(root) == .hfsPlus else { throw ProtocolError.invalidState }
        let image = root.appendingPathComponent(
            applePassthrough ? "PassthroughMount/HFSPlus.cdr" : "HFSPlus.cdr")
        let copySource = root.appendingPathComponent(
            applePassthrough ? "PassthroughSource/HFSPlus.cdr" : "HFSPlus.cdr")
        let snapshot = root.appendingPathComponent("Stable.img")
        let images = DiskImages()
        let attachment = try await attachLocal(
            image, readOnly: false,
            uncached: ProcessInfo.processInfo.environment["ISCSI_TEST_UNCACHED_IMAGE"] == "1",
            innerSync: ProcessInfo.processInfo.environment["ISCSI_TEST_GEOMETRY_INNER_SYNC"] == "1")
        do {
            try await DeviceFeatureProbe.captureIfRequested(
                root: root, image: image, attachment: attachment,
                localRegularFile: !applePassthrough)
            guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first else {
                throw AttachmentError.invalidImageResponse
            }
            try FixtureFileSystem.hfsPlus.verifyVolume(volume, readOnly: false)
            let path = volume.appendingPathComponent("FSKit-written.txt")
            let descriptor = open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw POSIXError(.EIO) }
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            do {
                try file.write(contentsOf: contents)
                try file.synchronize()
                guard fcntl(descriptor, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
                let synchronized = DispatchTime.now().uptimeNanoseconds
                guard clonefile(copySource.path, snapshot.path, 0) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                let copied = DispatchTime.now().uptimeNanoseconds
                let report: [String: Any] = [
                    "nativeDeviceBlockSize": 4096, "localRegularFile": !applePassthrough,
                    "applePassthrough": applePassthrough, "remoteDurabilityTest": false,
                    "writtenHandleOpenAtCopy": true, "physicalPowerLossTest": false,
                    "plainHFSControl": FixtureFileSystem.usesPlainHFSGeometryControl,
                    "fullsyncReturnedUptimeNS": synchronized, "copyFinishedUptimeNS": copied,
                ]
                try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
                    .write(
                        to: root.appendingPathComponent(
                            applePassthrough
                                ? "PassthroughSyncControl.json" : "LocalSyncControl.json"))
                try file.close()
            } catch {
                try? file.close()
                throw error
            }
            try await images.detach(attachment, at: image)
        } catch {
            if let current = try? await images.inventory().attachment(at: image) {
                try? await images.detach(current, at: image)
            }
            throw error
        }
    }
}
