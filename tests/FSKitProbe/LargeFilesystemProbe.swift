import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Formats only the new 3 TiB loopback LUN created by the owning LIO test VM.
enum LargeFilesystemProbe {
    private static let capacity: UInt64 = 3 * 1024 * 1024 * 1024 * 1024

    private struct Specification: Decodable {
        let nonce: String
        let byteCount: UInt64
        let blockSize: Int
    }

    static func run(portal: Portal, root: URL, nonce: UUID, inspectOnly: Bool = false) async throws
    {
        let path = root.appendingPathComponent("LargeFilesystem.json")
        let file = try FileHandle(forReadingFrom: path)
        let manifest = try file.read(upToCount: 1025) ?? Data()
        try file.close()
        guard path.resolvingSymlinksInPath() == path, manifest.count <= 1024 else {
            throw ProtocolError.malformed("large filesystem manifest")
        }
        let spec = try JSONDecoder().decode(Specification.self, from: manifest)
        guard spec.nonce == nonce.uuidString.lowercased(), spec.byteCount == capacity,
            spec.blockSize == 512, portal.host == "127.0.0.1"
        else { throw ProtocolError.malformed("large filesystem ownership") }
        let format = try FixtureFileSystem.at(root)
        try await FSKitProbe.saveFixtureCredential(portal: portal, root: root, nonce: nonce)
        do {
            if inspectOnly {
                try await inspect(portal: portal, root: root, nonce: nonce)
            } else {
                try await verify(portal: portal, root: root, nonce: nonce, format: format)
            }
        } catch {
            do { try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce) } catch {
                FileHandle.standardError.write(
                    Data("Large filesystem credential cleanup failed: \(error)\n".utf8))
            }
            throw error
        }
        try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func inspect(portal: Portal, root: URL, nonce: UUID) async throws {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: SystemAttachmentBackend(root: mounts),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.dev.soba:lio-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: true, chapUsername: "test-user",
            isid: [0x80, 1, 2, 3, 4, 5], credentialID: nonce)
        do {
            let record = try await coordinator.connect(descriptor)
            let attachment = try await native(record, readOnly: true)
            let inventoryData = try await SystemCommand.run(
                "/usr/bin/hdiutil", arguments: ["info", "-plist"])
            guard
                let inventory = try PropertyListSerialization.propertyList(
                    from: inventoryData, format: nil) as? [String: Any],
                let images = inventory["images"] as? [[String: Any]],
                let image = images.first(where: {
                    $0["image-path"] as? String
                        == record.bridgeURL.appendingPathComponent("Disk.img").path
                })
            else { throw AttachmentError.imageIdentityChanged }
            try PropertyListSerialization.data(fromPropertyList: image, format: .xml, options: 0)
                .write(to: root.appendingPathComponent("LargeOwnImageInventory.plist"))
            let marker = Data("Large filesystem \(nonce.uuidString.lowercased())\n".utf8)
            var written = Data(repeating: 0xA7, count: 65_573)
            written.replaceSubrange(0..<marker.count, with: marker)
            var volumes: [[String: Any]] = []
            for url in attachment.volumeURLs {
                var status = statfs()
                guard statfs(url.path, &status) == 0 else { throw POSIXError(.EIO) }
                let type = withUnsafePointer(to: &status.f_fstypename) {
                    $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                var value: [String: Any] = [
                    "path": url.path, "filesystem": type,
                    "readOnly": status.f_flags & UInt32(MNT_RDONLY) != 0,
                    "hiddenFromFinder": status.f_flags & UInt32(MNT_DONTBROWSE) != 0,
                    "totalBytes": status.f_blocks * UInt64(status.f_bsize),
                ]
                for (name, expected) in [
                    ("FSKit-validation.txt", marker), ("FSKit-written.txt", written),
                ] {
                    let path = url.appendingPathComponent(name)
                    value[name + "Exists"] = FileManager.default.fileExists(atPath: path.path)
                    if FileManager.default.fileExists(atPath: path.path) {
                        let input = try FileHandle(forReadingFrom: path)
                        let contents = try input.read(upToCount: 65_574) ?? Data()
                        try input.close()
                        value[name + "Matches"] = contents == expected
                        value[name + "BytesRead"] = contents.count
                    }
                }
                volumes.append(value)
            }
            try JSONSerialization.data(
                withJSONObject: ["nativeDevice": attachment.device, "volumes": volumes],
                options: [.prettyPrinted, .sortedKeys]
            )
            .write(to: root.appendingPathComponent("LargeInspection.json"))
            try await coordinator.eject(record.id)
        } catch {
            for disk in await coordinator.disks { try? await coordinator.eject(disk.id) }
            throw error
        }
    }

    private static func verify(
        portal: Portal, root: URL, nonce: UUID, format: FixtureFileSystem
    ) async throws {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let backend = SystemAttachmentBackend(root: mounts)
        let coordinator = try AttachmentCoordinator(
            backend: backend,
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        func descriptor(_ readOnly: Bool) throws -> ConnectionDescriptor {
            try ConnectionDescriptor(
                profileID: nonce, portal: portal,
                initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + nonce.uuidString.lowercased(),
                targetName: "iqn.2026-10.dev.soba:lio-" + nonce.uuidString.lowercased(),
                lun: LogicalUnit(0), readOnly: readOnly, chapUsername: "test-user",
                isid: [0x80, 1, 2, 3, 4, 5], credentialID: nonce)
        }
        let marker = Data("Large filesystem \(nonce.uuidString.lowercased())\n".utf8)
        var written = Data(repeating: 0xA7, count: 65_573)
        written.replaceSubrange(0..<marker.count, with: marker)
        do {
            stage("connect-live")
            let initial = try await coordinator.connect(descriptor(false))
            let attached = try await native(initial, readOnly: false)
            let ownership = try await backend.inspectBridge(
                initial.descriptor, at: initial.bridgeURL)
            guard ownership.ownership == .verified, attached.volumeURLs.isEmpty else {
                throw AttachmentError.ownershipUnverified
            }
            // The only formatting call accepts the just-verified, nonce-owned
            // image's whole device. No device or LUN path is accepted as input.
            let nativeFormat = format == .hfsPlus ? "JHFS+" : format.displayName
            stage("format-owned-device")
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil",
                arguments: [
                    "partitionDisk", attached.device, "GPT", nativeFormat,
                    "LG" + nonce.uuidString.prefix(8), "100%",
                ], timeout: 120)
            guard
                let current = try await DiskImages().inventory().attachment(
                    at: initial.bridgeURL.appendingPathComponent("Disk.img")),
                current.device == attached.device, current.volumeURLs.count == 1,
                let volume = current.volumeURLs.first
            else { throw AttachmentError.imageIdentityChanged }
            try format.verifyVolume(volume, readOnly: false)
            try recordSpace(volume, root: root, phase: "formatted", readOnly: false)
            stage("formatted")
            let markerPath = volume.appendingPathComponent("FSKit-validation.txt")
            try marker.write(to: markerPath)
            let markerFile = try FileHandle(forWritingTo: markerPath)
            do {
                try markerFile.synchronize()
                guard fcntl(markerFile.fileDescriptor, F_FULLFSYNC) == 0 else {
                    throw POSIXError(.EIO)
                }
                try markerFile.close()
            } catch {
                try? markerFile.close()
                throw error
            }
            let outputPath = volume.appendingPathComponent("FSKit-written.txt")
            let fd = open(outputPath.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw POSIXError(.EIO) }
            let output = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            do {
                try output.write(contentsOf: written)
                try FSKitProbe.checkpoint("before-fsync")
                try output.synchronize()
                try FSKitProbe.checkpoint("after-fsync")
                try FSKitProbe.checkpoint("before-fullfsync")
                guard fcntl(fd, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
                try FSKitProbe.checkpoint("after-fullfsync")
                try output.close()
            } catch {
                try? output.close()
                throw error
            }
            try await coordinator.eject(initial.id)
            stage("reconnect-original-readonly")
            let reopened = try await coordinator.connect(descriptor(true))
            try await checkContents(
                reopened, root: root, format: format, readOnly: true,
                marker: marker, written: written, phase: "original-readonly")
            try await coordinator.eject(reopened.id)
            guard await coordinator.disks.isEmpty else { throw AttachmentError.recoveryRequired }
            try FSKitProbe.checkpoint("source-ejected")
            // The host has now replaced the guest backstore with an independent
            // copy of the pre-close snapshot. Only HFS+ needs writable replay.
            let readOnly = format != .hfsPlus
            stage("reconnect-snapshot")
            let snapshot = try await coordinator.connect(descriptor(readOnly))
            try await checkContents(
                snapshot, root: root, format: format, readOnly: readOnly,
                marker: marker, written: written, phase: "snapshot-recovery")
            try await coordinator.eject(snapshot.id)
            guard await coordinator.disks.isEmpty else { throw AttachmentError.recoveryRequired }
        } catch {
            for disk in await coordinator.disks { try? await coordinator.eject(disk.id) }
            throw error
        }
        print(
            "PASS: 3 TiB \(format.displayName), original RO reconnect and independent pre-close snapshot recovery"
        )
    }

    private static func stage(_ value: String) {
        FileHandle.standardOutput.write(Data("LARGE_FS_STAGE \(value)\n".utf8))
    }

    private static func native(_ record: AttachedDisk, readOnly: Bool) async throws
        -> DiskAttachment
    {
        guard let expected = record.attachment, expected.device.hasPrefix("/dev/disk"),
            expected.device.count > 9,
            expected.device.dropFirst(9).utf8.allSatisfy({ (48...57).contains($0) }),
            record.connectionState == .connected, !record.needsCleanup
        else { throw AttachmentError.invalidImageResponse }
        let image = record.bridgeURL.appendingPathComponent("Disk.img")
        var status = stat()
        guard lstat(image.path, &status) == 0, status.st_size == Int64(capacity),
            status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), status.st_uid == geteuid(),
            let current = try await DiskImages().inventory().attachment(at: image),
            current.device == expected.device
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", current.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["TotalSize"] as? UInt64 == capacity, info["DeviceBlockSize"] as? Int == 512,
            info["WritableMedia"] as? Bool == !readOnly
        else { throw AttachmentError.invalidImageResponse }
        return current
    }

    private static func checkContents(
        _ record: AttachedDisk, root: URL, format: FixtureFileSystem, readOnly: Bool,
        marker: Data, written: Data, phase: String
    ) async throws {
        let attachment = try await native(record, readOnly: readOnly)
        guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first,
            try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt")) == marker,
            try Data(contentsOf: volume.appendingPathComponent("FSKit-written.txt")) == written
        else { throw ProtocolError.malformed("large filesystem recovered contents") }
        try format.verifyVolume(volume, readOnly: readOnly)
        try recordSpace(volume, root: root, phase: phase, readOnly: readOnly)
        if readOnly {
            var rejected = false
            do {
                try Data("must fail".utf8).write(to: volume.appendingPathComponent("Forbidden.txt"))
            } catch { rejected = true }
            guard rejected else {
                throw ProtocolError.malformed("large filesystem read-only write accepted")
            }
        }
    }

    private static func recordSpace(_ volume: URL, root: URL, phase: String, readOnly: Bool) throws
    {
        var info = statfs()
        guard statfs(volume.path, &info) == 0, info.f_bsize > 0 else { throw POSIXError(.EIO) }
        let block = UInt64(info.f_bsize)
        let total = info.f_blocks * block
        guard total > 2 * 1024 * 1024 * 1024 * 1024, total <= capacity,
            info.f_bfree * block > 2 * 1024 * 1024 * 1024 * 1024,
            readOnly || info.f_bavail * block > 2 * 1024 * 1024 * 1024 * 1024
        else { throw ProtocolError.malformed("large filesystem space truncated") }
        let record: [String: Any] = [
            "totalBytes": total, "freeBytes": info.f_bfree * block,
            "availableBytes": info.f_bavail * block, "phase": phase,
        ]
        try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
            .write(to: root.appendingPathComponent("LargeSpace-\(phase).json"))
    }
}
