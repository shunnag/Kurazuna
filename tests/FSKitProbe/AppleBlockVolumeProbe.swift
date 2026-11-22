import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

enum AppleBlockVolumeProbe {
    static func detach(root: URL, relative: String) async throws {
        let shapes: [String: (Int, Int, Bool)] = [
            "Local.img": (536_870_912, 4096, true),
            "AppleMount/Disk.img": (536_870_912, 4096, true),
            "Outer.img": (1_073_741_824, 512, true),
            "OuterSnapshot.img": (1_073_741_824, 512, false),
        ]
        guard let shape = shapes[relative] else { throw ProtocolError.invalidState }
        let image = root.appendingPathComponent(relative)
        guard let current = try await DiskImages().inventory().attachment(at: image) else { return }
        let attrs = try FileManager.default.attributesOfItem(atPath: image.path)
        guard image.resolvingSymlinksInPath() == image,
            attrs[.type] as? FileAttributeType == .typeRegular,
            (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attrs[.size] as? NSNumber)?.intValue == shape.0
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", current.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["DeviceNode"] as? String == current.device,
            (info["IOKitSize"] as? NSNumber)?.intValue == shape.0,
            (info["Size"] as? NSNumber)?.intValue == shape.0,
            (info["DeviceBlockSize"] as? NSNumber)?.intValue == shape.1,
            info["Writable"] as? Bool == shape.2
        else { throw AttachmentError.imageIdentityChanged }
        try await DiskImages().detach(current, at: image)
        guard try await DiskImages().inventory().attachment(at: image) == nil else {
            throw AttachmentError.imageIdentityChanged
        }
        print("PASS: normally ejected only the mapped Apple block-control image \(relative)")
    }

    static func inspect(root: URL) throws {
        var found = false
        for name in ["AppleMount", "RecoveredOuter"] {
            let url = root.appendingPathComponent(name, isDirectory: true)
            var info = statfs()
            guard statfs(url.path, &info) == 0 else { continue }
            func string<T>(_ value: inout T, capacity: Int) -> String {
                withUnsafePointer(to: &value) {
                    $0.withMemoryRebound(to: CChar.self, capacity: capacity) { String(cString: $0) }
                }
            }
            let path = string(&info.f_mntonname, capacity: 1024)
            guard path == url.path else { continue }
            let type = string(&info.f_fstypename, capacity: 16)
            let source = string(&info.f_mntfromname, capacity: 1024)
            let fsKit = info.f_flags_ext & UInt32(MNT_EXT_FSKIT) != 0
            let record: [String: Any] = [
                "mount": path, "source": source, "type": type,
                "flags": info.f_flags, "extendedFlags": info.f_flags_ext,
                "FSKit": fsKit, "readOnly": info.f_flags & UInt32(MNT_RDONLY) != 0,
                "blockSize": info.f_bsize, "blocks": info.f_blocks,
            ]
            try JSONSerialization.data(
                withJSONObject: record, options: [.prettyPrinted, .sortedKeys]
            )
            .write(
                to: root.appendingPathComponent(name + "Info.json"), options: .withoutOverwriting)
            guard fsKit, type == "msdos",
                source.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil
            else { throw ProtocolError.malformed("Apple block FSKit mount identity") }
            found = true
        }
        guard found else { throw ProtocolError.invalidState }
        print("PASS: SDK statfs identifies the private Apple MS-DOS mount as FSKit")
    }
}
