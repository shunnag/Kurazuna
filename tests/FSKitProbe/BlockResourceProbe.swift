import Darwin
import Foundation
import ISCSICore

@testable import ISCSIPlatform

enum BlockResourceProbe {
    static var enabled: Bool {
        ProcessInfo.processInfo.environment["ISCSI_TEST_BLOCK_RESOURCE"] == "1"
    }

    static func recoverInitialMetadata(root: URL, nonce: UUID) async throws {
        guard enabled else { throw ProtocolError.invalidState }
        let files = try FileManager.default.contentsOfDirectory(
            at: root, includingPropertiesForKeys: nil
        )
        .filter { $0.lastPathComponent.hasPrefix("BlockMetadata-") && $0.pathExtension == "img" }
        guard files.count == 1, let image = files.first else { throw ProtocolError.invalidState }
        let idText = String(
            image.deletingPathExtension().lastPathComponent.dropFirst("BlockMetadata-".count))
        guard let id = UUID(uuidString: idText), image.resolvingSymlinksInPath() == image else {
            throw AttachmentError.imageIdentityChanged
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: image.path)
        let expectedSize = BlockResourceDescriptor.imageBytes + BlockResourceDescriptor.headerBytes
        guard attrs[.type] as? FileAttributeType == .typeRegular,
            (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attrs[.size] as? NSNumber)?.intValue == expectedSize
        else { throw AttachmentError.imageIdentityChanged }
        let bytes = try Data(contentsOf: image)
        let descriptor = try BlockResourceDescriptor.decode(
            Data(bytes.suffix(BlockResourceDescriptor.headerBytes)))
        guard descriptor.profileID == nonce, descriptor.mountID == id,
            bytes.prefix(BlockResourceDescriptor.imageBytes).allSatisfy({ $0 == 0 }),
            let attachment = try await DiskImages().inventory().attachment(at: image),
            attachment.volumeURLs.isEmpty
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["DeviceNode"] as? String == attachment.device,
            (info["TotalSize"] as? NSNumber)?.intValue == expectedSize,
            (info["DeviceBlockSize"] as? NSNumber)?.intValue == 512,
            info["Writable"] as? Bool == true
        else { throw AttachmentError.imageIdentityChanged }
        try await DiskImages().detach(attachment, at: image)
        guard try await DiskImages().inventory().attachment(at: image) == nil,
            try Data(contentsOf: image) == bytes
        else { throw AttachmentError.imageIdentityChanged }
        let report: [String: Any] = [
            "knownHeaderAtEOF": true, "normalDetachSucceeded": true,
            "sourceImageUnchanged": true, "device": attachment.device,
        ]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(
                to: root.appendingPathComponent("InitialMetadataRecovery.json"),
                options: .withoutOverwriting)
        print(
            "PASS: normally recovered only the verified initial metadata fixture with a header at EOF"
        )
    }

    static func checkMetadata(root: URL, nonce: UUID) async throws {
        guard enabled else { throw ProtocolError.invalidState }
        let id = UUID()
        let bridge = root.appendingPathComponent("Mounts", isDirectory: true)
            .appendingPathComponent(id.uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: bridge, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: Portal(host: "127.0.0.1", port: 3260),
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
        do {
            let device = try await prepare(descriptor, root: root, bridge: bridge)
            let image = try metadata(root: root, bridge: bridge)
            let bytes = try Data(contentsOf: image)
            guard bytes.count == BlockResourceDescriptor.imageBytes,
                try BlockResourceDescriptor.decode(
                    Data(bytes.prefix(BlockResourceDescriptor.headerBytes))) == descriptor,
                bytes.dropFirst(BlockResourceDescriptor.headerBytes).allSatisfy({ $0 == 0 })
            else { throw ProtocolError.invalidState }
            try await cleanup(bridge: bridge)
            guard try await DiskImages().inventory().attachment(at: image) == nil,
                try Data(contentsOf: image) == bytes
            else { throw AttachmentError.imageIdentityChanged }
            let report: [String: Any] = [
                "device": device, "image": image.path, "bytes": bytes.count,
                "normalDetachSucceeded": true, "imageBytesUnchanged": true,
                "FSKitMountStarted": false, "networkConnectionStarted": false,
            ]
            try JSONSerialization.data(
                withJSONObject: report, options: [.prettyPrinted, .sortedKeys]
            )
            .write(
                to: root.appendingPathComponent("MetadataCheck.json"), options: .withoutOverwriting)
            try FileManager.default.removeItem(at: bridge)
            try FileManager.default.removeItem(at: bridge.deletingLastPathComponent())
            print(
                "PASS: private metadata image attached as 512-byte block device and normally detached; no FSKit mount or network login"
            )
        } catch {
            try? await cleanup(bridge: bridge)
            throw error
        }
    }

    static func backend(root: URL) -> SystemAttachmentBackend {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        guard enabled else { return SystemAttachmentBackend(root: mounts) }
        return SystemAttachmentBackend(root: mounts) { program, arguments, timeout in
            guard program == "/sbin/mount", arguments.count >= 2,
                let url = URL(string: arguments[arguments.count - 2])
            else { throw ProtocolError.invalidState }
            let descriptor = try ConnectionDescriptor(resourceURL: url)
            let bridge = URL(fileURLWithPath: arguments.last!, isDirectory: true)
            let device = try await prepare(descriptor, root: root, bridge: bridge)
            var adjusted = arguments
            adjusted[adjusted.count - 2] = device
            return try await SystemCommand.run(program, arguments: adjusted, timeout: timeout)
        }
    }

    private static func metadata(root: URL, bridge: URL) throws -> URL {
        let attrs = try FileManager.default.attributesOfItem(atPath: root.path)
        guard root.resolvingSymlinksInPath() == root,
            root.lastPathComponent.hasPrefix("iSCSI-FSKit-"),
            root.deletingLastPathComponent().lastPathComponent == "FSKitFixtures",
            (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attrs[.posixPermissions] as? NSNumber)?.intValue == 0o700,
            bridge.deletingLastPathComponent()
                == root.appendingPathComponent("Mounts", isDirectory: true),
            UUID(uuidString: bridge.lastPathComponent) != nil
        else { throw ProtocolError.malformed("private block metadata path") }
        return root.appendingPathComponent("BlockMetadata-" + bridge.lastPathComponent + ".img")
    }

    private static func checked(_ image: URL) async throws -> DiskAttachment? {
        guard image.resolvingSymlinksInPath() == image else {
            throw AttachmentError.imageIdentityChanged
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: image.path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
            (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attrs[.size] as? NSNumber)?.intValue == BlockResourceDescriptor.imageBytes
        else { throw AttachmentError.imageIdentityChanged }
        guard let current = try await DiskImages().inventory().attachment(at: image) else {
            return nil
        }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", current.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["DeviceNode"] as? String == current.device,
            (info["TotalSize"] as? NSNumber)?.intValue == BlockResourceDescriptor.imageBytes,
            (info["DeviceBlockSize"] as? NSNumber)?.intValue == 512,
            info["Writable"] as? Bool == true
        else { throw AttachmentError.imageIdentityChanged }
        return current
    }

    private static func prepare(_ descriptor: ConnectionDescriptor, root: URL, bridge: URL)
        async throws -> String
    {
        guard descriptor.mountID?.uuidString == bridge.lastPathComponent,
            root.lastPathComponent.hasPrefix(
                "iSCSI-FSKit-" + descriptor.profileID.uuidString.lowercased() + "-")
        else { throw ProtocolError.invalidState }
        let image = try metadata(root: root, bridge: bridge)
        let bytes = try BlockResourceDescriptor.encode(descriptor)
        let fd = open(image.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        try file.truncate(atOffset: UInt64(BlockResourceDescriptor.imageBytes))
        try file.seek(toOffset: 0)
        try file.write(contentsOf: bytes)
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
        try file.close()
        let prepared = try FileManager.default.attributesOfItem(atPath: image.path)
        guard (prepared[.size] as? NSNumber)?.intValue == BlockResourceDescriptor.imageBytes else {
            throw AttachmentError.imageIdentityChanged
        }
        _ = try await SystemCommand.run(
            "/usr/bin/hdiutil",
            arguments: [
                "attach", "-kernel", "-nomount", "-plist", "-imagekey",
                "diskimage-class=CRawDiskImage", "-readwrite", image.path,
            ], timeout: 30)
        guard let attachment = try await checked(image), attachment.volumeURLs.isEmpty else {
            throw AttachmentError.invalidImageResponse
        }
        let record: [String: Any] = [
            "metadataImage": image.path, "device": attachment.device,
            "mountID": bridge.lastPathComponent, "headerBytes": bytes.count,
            "readOnlyLUN": descriptor.readOnly, "metadataDeviceBlockSize": 512,
        ]
        try JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys])
            .write(to: image.appendingPathExtension("json"), options: .withoutOverwriting)
        return attachment.device
    }

    static func cleanup(bridge: URL) async throws {
        guard enabled else { return }
        let root = bridge.deletingLastPathComponent().deletingLastPathComponent()
        let image = try metadata(root: root, bridge: bridge)
        if !FileManager.default.fileExists(atPath: image.path) {
            guard try await DiskImages().inventory().attachment(at: image) == nil else {
                throw AttachmentError.imageIdentityChanged
            }
            return
        }
        if let attachment = try await checked(image) {
            try await DiskImages().detach(attachment, at: image)
        }
        guard try await DiskImages().inventory().attachment(at: image) == nil else {
            throw AttachmentError.imageIdentityChanged
        }
    }
}
