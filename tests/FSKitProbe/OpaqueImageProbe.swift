import Foundation
import ISCSICore
import ISCSIPlatform

/// Only called after the entry point validates a private fixture and loopback portal.
enum OpaqueImageProbe {
    static func run(
        portal: Portal, root: URL, nonce: UUID, readOnlyOnly: Bool = false,
        expectedBlockSize: Int = 512
    ) async throws {
        let payload = root.appendingPathComponent("Payload.img")
        let properties = try payload.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard payload.resolvingSymlinksInPath().path == payload.path,
            properties.isRegularFile == true, let size = properties.fileSize,
            [128 * 1_048_576, 64 * 1_048_576 + 1536].contains(size)
        else { throw ProtocolError.malformed("opaque fixture payload") }
        var expected = try Data(contentsOf: payload)
        guard expected.count == size else { throw ProtocolError.malformed("opaque fixture size") }
        let presentation = try FSKitProbe.requestedImagePresentation()
        let boundary =
            try presentation == .udsp
            ? Int(SparseImageLayout(capacity: UInt64(size)).bandSize) : 64 * 1_048_576
        let offsets = [boundary - 512, boundary, size - 512]
        let intactUDIF = expected.suffix(512).prefix(4) == Data("koly".utf8)
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: FSKitProbe.StageBackend(
                base: SystemAttachmentBackend(root: mounts), stage: nil),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        let modes = readOnlyOnly ? [true] : (intactUDIF ? [true, false, true] : [false, true])
        for readOnly in modes {
            let descriptor = try ConnectionDescriptor(
                profileID: nonce, portal: portal,
                initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
                targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
                lun: LogicalUnit(0), readOnly: readOnly, isid: [0x80, 1, 2, 3, 4, 5],
                imagePresentation: FSKitProbe.requestedImagePresentation())
            let record = try await coordinator.connect(descriptor)
            do {
                guard let attachment = record.attachment, attachment.volumeURLs.isEmpty,
                    record.connectionState == .connected, !record.needsCleanup,
                    attachment.device.hasPrefix("/dev/disk"), attachment.device.count > 9,
                    attachment.device.dropFirst(9).utf8.allSatisfy({ (48...57).contains($0) })
                else { throw ProtocolError.malformed("opaque fixture attachment") }
                let image = record.bridgeURL.appendingPathComponent(
                    "Disk.img")
                guard
                    try await DiskImages().inventory().attachment(at: image)?.device
                        == attachment.device
                else { throw AttachmentError.imageIdentityChanged }
                let status = try await SystemCommand.run(
                    "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
                guard status.count <= 1_048_576,
                    let info = try PropertyListSerialization.propertyList(from: status, format: nil)
                        as? [String: Any], info["TotalSize"] as? Int == size,
                    info["WritableMedia"] as? Bool == !readOnly,
                    info["DeviceBlockSize"] as? Int == expectedBlockSize
                else {
                    throw ProtocolError.malformed("opaque fixture device capacity or writability")
                }
                if ProcessInfo.processInfo.environment["ISCSI_TEST_RAW_EOF"] == "1" {
                    try RawEOFProbe.validate(image, expected: expected)
                }
                let raw = URL(fileURLWithPath: "/dev/r" + attachment.device.dropFirst(5))
                let device =
                    try readOnly ? FileHandle(forReadingFrom: raw) : FileHandle(forUpdating: raw)
                do {
                    if readOnly {
                        try compare(device, expected: expected)
                    } else {
                        for offset in [0] + offsets {
                            try device.seek(toOffset: UInt64(offset))
                            guard
                                try device.read(upToCount: 512)
                                    == expected.subdata(in: offset..<(offset + 512))
                            else { throw ProtocolError.malformed("opaque initial sector bytes") }
                        }
                    }
                    if !readOnly {
                        for (index, offset) in offsets.enumerated() {
                            let bytes = Data(repeating: UInt8(0x51 + index), count: 512)
                            try device.seek(toOffset: UInt64(offset))
                            try device.write(contentsOf: bytes)
                            expected.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
                        }
                        try device.synchronize()
                        for offset in offsets {
                            try device.seek(toOffset: UInt64(offset))
                            guard
                                try device.read(upToCount: 512)
                                    == expected.subdata(in: offset..<(offset + 512))
                            else {
                                throw ProtocolError.malformed("opaque immediate sector readback")
                            }
                        }
                    }
                    try device.close()
                } catch {
                    try? device.close()
                    throw error
                }
                try await coordinator.eject(record.id)
            } catch {
                try? await coordinator.eject(record.id)
                throw error
            }
            print(
                "PASS: opaque \(size)-byte LUN, exact native device capacity, \(readOnly ? "full byte comparison" : "sector write/readback"), readOnly=\(readOnly)"
            )
        }
        guard await coordinator.disks.isEmpty else { throw AttachmentError.recoveryRequired }
        if readOnlyOnly {
            print("PASS: original opaque LUN fully compared in read-only mode")
        } else {
            print(
                "PASS: band boundary at \(boundary) bytes and final-sector writes survived normal eject and read-only reattachment"
            )
        }
    }

    private static func compare(_ device: FileHandle, expected: Data) throws {
        try device.seek(toOffset: 0)
        var offset = 0
        while offset < expected.count {
            let count = min(1_048_576, expected.count - offset)
            guard let bytes = try device.read(upToCount: count), bytes.count == count,
                bytes == expected.subdata(in: offset..<(offset + count))
            else { throw ProtocolError.malformed("opaque LUN device bytes at \(offset)") }
            offset += count
            if offset % (32 * 1_048_576) == 0 {
                FileHandle.standardOutput.write(Data("OPAQUE_READ_BYTES \(offset)\n".utf8))
            }
        }
    }
}
