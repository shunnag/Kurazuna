import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// A separate recovery experiment on a copied test snapshot. Never repairs a live LUN.
enum HFSRecoveryFixture {
    private struct OwnedImage {
        let whole: String
        let partition: String
    }

    static func attach(_ image: URL) async throws -> DiskAttachment {
        let root = image.deletingLastPathComponent()
        let attributes = try FileManager.default.attributesOfItem(atPath: image.path)
        let rootAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
        guard image.lastPathComponent == "Recovered.img",
            root.lastPathComponent.hasPrefix("iSCSI-FSKit-"),
            image.resolvingSymlinksInPath().path == image.path,
            attributes[.type] as? FileAttributeType == .typeRegular,
            (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (rootAttributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (rootAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700,
            let size = (attributes[.size] as? NSNumber)?.uint64Value,
            (8192...536_870_912).contains(size), size % 4096 == 0
        else { throw ProtocolError.malformed("private HFS+ recovery copy") }
        let file = try FileHandle(forReadingFrom: image)
        let prefix: Data
        do {
            defer { try? file.close() }
            prefix = try file.read(upToCount: DiskImageGeometry.prefixByteCount) ?? Data()
        }
        let blockSize = try DiskImageGeometry.blockSize(
            prefix: prefix, byteCount: size, sourceBlockSize: 512)
        guard [512, 4096].contains(blockSize),
            // Equal results with different fallbacks require a validated GPT header.
            try DiskImageGeometry.blockSize(prefix: prefix, byteCount: size, sourceBlockSize: 4096)
                == blockSize
        else { throw ProtocolError.malformed("512/4096-byte GPT HFS+ recovery copy required") }
        let report = root.appendingPathComponent("HFSJournalRecovery.txt")
        guard !FileManager.default.fileExists(atPath: report.path) else {
            throw ProtocolError.invalidState
        }
        let images = DiskImages()
        guard try await images.inventory().attachment(at: image) == nil else {
            throw AttachmentError.imageIdentityChanged
        }
        var device: String?
        do {
            var arguments = [
                "attach", blockSize == 512 ? "-kernel" : "-nokernel", "-nomount", "-plist",
                "-imagekey", "diskimage-class=CRawDiskImage", "-readwrite",
            ]
            if blockSize == 4096 { arguments += ["-blocksize", "4096"] }
            arguments.append(image.path)
            _ = try await SystemCommand.run("/usr/bin/hdiutil", arguments: arguments, timeout: 30)
            let attached = try await owned(image, bytes: size, blockSize: blockSize)
            device = attached.whole
            let data = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["info", "-plist", attached.whole])
            guard
                let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                    as? [String: Any], info["DeviceNode"] as? String == attached.whole,
                (info["TotalSize"] as? NSNumber)?.uint64Value == size,
                info["DeviceBlockSize"] as? Int == Int(blockSize),
                info["Writable"] as? Bool == true
            else { throw AttachmentError.invalidImageResponse }
            let current = try await owned(image, bytes: size, blockSize: blockSize)
            guard current.whole == attached.whole, current.partition == attached.partition else {
                throw AttachmentError.imageIdentityChanged
            }
            let rawPartition = "/dev/r" + attached.partition.dropFirst(5)
            // Standard journal replay/preening, only on this independent private copy.
            let preen = try await SystemCommand.run(
                "/sbin/fsck_hfs", arguments: ["-p", rawPartition], timeout: 60)
            try preen.write(to: report, options: .withoutOverwriting)
            let replayed = try await owned(image, bytes: size, blockSize: blockSize)
            guard replayed.whole == attached.whole, replayed.partition == attached.partition else {
                throw AttachmentError.imageIdentityChanged
            }
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["mountDisk", attached.whole], timeout: 60)
            let mounted = try await owned(image, bytes: size, blockSize: blockSize)
            guard mounted.whole == attached.whole, mounted.partition == attached.partition,
                let result = try await images.inventory().attachment(at: image),
                result.device == attached.whole
            else { throw AttachmentError.imageIdentityChanged }
            print(
                "HFS_JOURNAL_RECOVERY standardPreen=true privateCopyOnly=true sectorBytes=\(blockSize)"
            )
            return result
        } catch {
            if let current = try? await images.inventory().attachment(at: image),
                device == nil || device == current.device,
                let checked = try? await owned(image, bytes: size, blockSize: blockSize),
                checked.whole == current.device
            {
                try? await images.detach(current, at: image)
            }
            throw error
        }
    }

    private static func owned(_ image: URL, bytes: UInt64, blockSize: UInt32) async throws
        -> OwnedImage
    {
        let data = try await SystemCommand.run("/usr/bin/hdiutil", arguments: ["info", "-plist"])
        guard data.count <= 1_048_576,
            let inventory = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let entries = inventory["images"] as? [[String: Any]], entries.count <= 1024
        else { throw AttachmentError.invalidImageResponse }
        let matches = entries.filter { $0["image-path"] as? String == image.path }
        guard matches.count == 1, let entry = matches.first,
            (entry["owner-uid"] as? NSNumber)?.uint32Value == geteuid(),
            entry["writeable"] as? Bool == true, entry["blocksize"] as? Int == Int(blockSize),
            (entry["blockcount"] as? NSNumber)?.uint64Value == bytes / UInt64(blockSize),
            let entities = entry["system-entities"] as? [[String: Any]], entities.count <= 64
        else { throw AttachmentError.imageIdentityChanged }
        let whole = entities.compactMap { $0["dev-entry"] as? String }.filter {
            $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil
        }
        let partitions = entities.filter {
            ["Apple_HFS", "48465300-0000-11AA-AA11-00306543ECAC"].contains(
                $0["content-hint"] as? String ?? "")
        }.compactMap { $0["dev-entry"] as? String }
        guard whole.count == 1, partitions.count == 1,
            partitions[0].hasPrefix(whole[0] + "s")
        else { throw AttachmentError.imageIdentityChanged }
        let suffix = partitions[0].dropFirst(whole[0].count + 1)
        guard !suffix.isEmpty, suffix.utf8.allSatisfy({ (48...57).contains($0) }) else {
            throw AttachmentError.imageIdentityChanged
        }
        return OwnedImage(whole: whole[0], partition: partitions[0])
    }
}
