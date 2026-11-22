import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Test-only bridge lifecycle for a fixed, privately generated FAT32 container.
/// The Python controller owns both nested image attachments and ejects them first.
enum NestedAppleBridgeProbe {
    static func mount(portal: Portal, root: URL, nonce: UUID, readOnly: Bool) async throws {
        guard portal.host == "127.0.0.1", portal.port > 1024 else {
            throw ProtocolError.invalidState
        }
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let backend = SystemAttachmentBackend(root: mounts)
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: readOnly, isid: [0x80, 0x53, 0x4f, 0x42, 0x41, 0x01],
            mountID: nonce)
        let bridge = try await backend.bridgeURL(for: nonce)
        let journal = try FileAttachmentJournal(
            directory: root.appendingPathComponent("State", isDirectory: true), bridgeRoot: mounts)
        guard try journal.load().isEmpty else { throw AttachmentError.recoveryRequired }
        try journal.save([
            AttachmentJournalEntry(
                id: nonce, descriptor: descriptor, bridgeURL: bridge, phase: .mountingBridge)
        ])
        try await backend.mountBridge(descriptor, at: bridge)
        try journal.save([
            AttachmentJournalEntry(
                id: nonce, descriptor: descriptor, bridgeURL: bridge, phase: .attachingImage)
        ])
        let state = try await backend.inspectBridge(descriptor, at: bridge)
        guard state.connectionState == .connected else { throw ProtocolError.invalidState }
        let file = try FileHandle(forReadingFrom: bridge.appendingPathComponent("Disk.img"))
        defer { try? file.close() }
        var status = stat()
        guard fstat(file.fileDescriptor, &status) == 0,
            status.st_size == 1_073_741_824,
            let sector = try file.read(upToCount: 512), sector.count == 512,
            sector[11] == 0, sector[12] == 2,
            sector[510] == 0x55, sector[511] == 0xaa
        else { throw ProtocolError.malformed("private nested FAT32 bridge") }
        print("PASS: private nested FAT32 bridge mounted readOnly=\(readOnly)")
    }

    static func eject(root: URL, nonce: UUID) async throws {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let backend = SystemAttachmentBackend(root: mounts)
        let journal = try FileAttachmentJournal(
            directory: root.appendingPathComponent("State", isDirectory: true), bridgeRoot: mounts)
        let entries = try journal.load()
        guard !entries.isEmpty else { return }
        let expectedBridge = try await backend.bridgeURL(for: nonce)
        guard entries.count == 1, let entry = entries.first, entry.id == nonce,
            entry.descriptor.portal.host == "127.0.0.1",
            entry.bridgeURL == expectedBridge
        else { throw ProtocolError.invalidState }
        try await backend.unmountBridge(entry.descriptor, at: entry.bridgeURL)
        try await backend.discardEmptyBridge(entry.descriptor, at: entry.bridgeURL)
        try journal.save([])
        print("PASS: private nested FAT32 bridge normally ejected")
    }

    static func inspectInner(root: URL) async throws {
        let image = root.appendingPathComponent("AppleMount/Disk.img")
        guard let attachment = try await DiskImages().inventory().attachment(at: image),
            attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first
        else { throw AttachmentError.imageIdentityChanged }
        try FixtureFileSystem.hfsPlus.verifyVolume(volume, readOnly: false)
        print("PASS: nested inner HFS+ is mounted writable with journaling")
    }

    static func detachOuter(root: URL, nonce: UUID) async throws {
        let image = root.appendingPathComponent("Mounts/\(nonce.uuidString)/Disk.img")
        let images = DiskImages()
        guard let attachment = try await images.inventory().attachment(at: image) else { return }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["DeviceNode"] as? String == attachment.device,
            (info["IOKitSize"] as? NSNumber)?.intValue == 1_073_741_824,
            (info["DeviceBlockSize"] as? NSNumber)?.intValue == 512
        else { throw AttachmentError.imageIdentityChanged }
        try await images.detach(attachment, at: image)
        print("PASS: nested outer image normally ejected")
    }
}
