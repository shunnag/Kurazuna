import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Only an explicit comparison test can select the old helper-process path.
enum LegacyAttachmentProbe {
    static func matchesRawPrefix(_ actual: Data?, expected: Data?) -> Bool {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "asif-container"
        else { return actual == expected }
        // The native ASIF writer changes its instance UUID on a writable open.
        // This control compares the rest of the container prefix, not opaque LUN bytes.
        guard let actual, let expected, actual.count == 4096, expected.count == 4096 else {
            return false
        }
        return actual.prefix(32) == expected.prefix(32)
            && actual.suffix(from: 48) == expected.suffix(from: 48)
    }

    static func attachIfRequested(
        _ descriptor: ConnectionDescriptor, at bridge: URL, backend: SystemAttachmentBackend
    ) async throws -> DiskAttachment? {
        guard let method = ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] else {
            return nil
        }
        guard ["kernel", "legacy", "legacy-sync", "legacy-4k", "asif-container"].contains(method)
        else {
            throw ProtocolError.malformed("fixture attachment method")
        }
        let before = try await backend.inspectBridge(descriptor, at: bridge)
        guard before.ownership == .verified, before.attachment == nil else {
            throw AttachmentError.ownershipUnverified
        }
        let image = bridge.appendingPathComponent("Disk.img")
        if method == "legacy-4k" {
            guard descriptor.imagePresentation == .raw else { throw ProtocolError.invalidState }
            let result = try await GeometryFixture.attachLocal(
                image, readOnly: descriptor.readOnly,
                uncached: !descriptor.readOnly
                    && ProcessInfo.processInfo.environment["ISCSI_TEST_UNCACHED_IMAGE"] == "1",
                innerSync: ProcessInfo.processInfo.environment["ISCSI_TEST_GEOMETRY_INNER_SYNC"]
                    == "1")
            print("PASS: experimental raw 4Kn helper, exact capacity, block size and mode verified")
            return result
        }
        if method == "asif-container" {
            return try await attachASIFContainer(descriptor, image: image)
        }
        let size = try image.resourceValues(forKeys: [.fileSizeKey]).fileSize
        var arguments = [
            "attach", "-nomount", "-plist", "-imagekey", "diskimage-class=CRawDiskImage",
            descriptor.readOnly ? "-readonly" : "-readwrite",
        ]
        if method == "kernel" { arguments.append("-kernel") }
        arguments.append(image.path)
        let attachment = try DiskImages.parseAttachment(
            await SystemCommand.run("/usr/bin/hdiutil", arguments: arguments))
        let images = DiskImages()
        guard try await images.inventory().attachment(at: image)?.device == attachment.device else {
            throw AttachmentError.imageIdentityChanged
        }
        let info = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
        guard
            let properties = try PropertyListSerialization.propertyList(from: info, format: nil)
                as? [String: Any], let size, properties["TotalSize"] as? Int == size,
            properties["WritableMedia"] as? Bool == !descriptor.readOnly
        else { throw AttachmentError.invalidImageResponse }
        if method == "legacy-sync" {
            let data = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["list", "-plist", attachment.device])
            guard data.count <= 1_048_576,
                let tree = try PropertyListSerialization.propertyList(from: data, format: nil)
                    as? [String: Any],
                let disks = tree["AllDisksAndPartitions"] as? [[String: Any]], disks.count == 1,
                let partitions = disks[0]["Partitions"] as? [[String: Any]],
                partitions.count == 1, partitions[0]["Content"] as? String == "Apple_HFS",
                let partition = partitions[0]["DeviceIdentifier"] as? String,
                partition.hasPrefix(String(attachment.device.dropFirst(5)) + "s"),
                partition.utf8.allSatisfy({ (48...57).contains($0) || (97...122).contains($0) })
            else { throw ProtocolError.malformed("disposable HFS partition") }
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil",
                arguments: [
                    "mount", "-mountOptions", descriptor.readOnly ? "sync,ro" : "sync", partition,
                ])
        } else {
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["mountDisk", attachment.device])
        }
        guard let current = try await images.inventory().attachment(at: image),
            current.device == attachment.device
        else { throw AttachmentError.imageIdentityChanged }
        if method == "legacy-sync" {
            guard current.volumeURLs.count == 1 else { throw AttachmentError.invalidImageResponse }
            var status = statfs()
            guard statfs(current.volumeURLs[0].path, &status) == 0,
                status.f_flags & UInt32(MNT_SYNCHRONOUS) != 0
            else { throw ProtocolError.malformed("HFS sync mount was not applied") }
        }
        print("PASS: experimental \(method) raw attach, device size and writability verified")
        return current
    }

    /// This control exports a native ASIF container as the target, rather than
    /// translating a raw LUN. It isolates DiskImages2 over the existing FSKit bridge.
    private static func attachASIFContainer(
        _ descriptor: ConnectionDescriptor, image: URL
    ) async throws -> DiskAttachment {
        let file = try FileHandle(forReadingFrom: image)
        let header: Data
        do {
            header = try file.read(upToCount: 512) ?? Data()
            try file.close()
        } catch {
            try? file.close()
            throw error
        }
        guard descriptor.imagePresentation == .raw, header.count == 512,
            header.prefix(4) == Data("shdw".utf8),
            [UInt8](header).uint64(at: 48) == 128 * 1_048_576 / 512,
            try image.resourceValues(forKeys: [.fileSizeKey]).fileSize == 140_509_184
        else { throw ProtocolError.malformed("native ASIF container fixture") }
        var arguments = ["image", "attach", "--noMount", "--plist"]
        if descriptor.readOnly { arguments.append("--readOnly") }
        arguments.append(image.path)
        _ = try await SystemCommand.run("/usr/sbin/diskutil", arguments: arguments)
        let images = DiskImages()
        guard let attachment = try await images.inventory().attachment(at: image) else {
            throw AttachmentError.invalidImageResponse
        }
        let info = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
        guard
            let properties = try PropertyListSerialization.propertyList(from: info, format: nil)
                as? [String: Any], properties["TotalSize"] as? Int == 128 * 1_048_576,
            properties["WritableMedia"] as? Bool == !descriptor.readOnly
        else { throw AttachmentError.invalidImageResponse }
        _ = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["mountDisk", attachment.device])
        guard let current = try await images.inventory().attachment(at: image),
            current.device == attachment.device
        else { throw AttachmentError.imageIdentityChanged }
        print("PASS: native ASIF container control, capacity and writability verified")
        return current
    }
}
