import Darwin
import FSKitNativeDiagnostics
import Foundation
import ISCSICore
import ISCSIPlatform

/// Read-only feature queries, before writing the pre-close synchronization test.
enum DeviceFeatureProbe {
    static func captureIfRequested(
        root: URL, image: URL, attachment: DiskAttachment, localRegularFile: Bool
    ) async throws {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_DEVICE_FEATURES"] == "1" else {
            return
        }
        guard let current = try await DiskImages().inventory().attachment(at: image),
            current.device == attachment.device, current.volumeURLs.count == 1,
            let volume = current.volumeURLs.first
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", volume.path])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any], let partition = info["DeviceNode"] as? String,
            partition.range(of: "^/dev/disk[0-9]+(s[0-9]+)?$", options: .regularExpression) != nil
        else { throw AttachmentError.imageIdentityChanged }
        // APFS synthesizes a separate whole device. Match the mounted entity
        // inside this image's inventory rather than assuming a diskNsM prefix.
        let inventory = try await SystemCommand.run(
            "/usr/bin/hdiutil", arguments: ["info", "-plist"])
        guard inventory.count <= 1_048_576,
            let plist = try PropertyListSerialization.propertyList(from: inventory, format: nil)
                as? [String: Any], let images = plist["images"] as? [[String: Any]],
            let own = images.first(where: { $0["image-path"] as? String == image.path }),
            let entities = own["system-entities"] as? [[String: Any]],
            entities.contains(where: {
                $0["dev-entry"] as? String == partition
                    && $0["mount-point"] as? String == volume.path
            })
        else { throw AttachmentError.imageIdentityChanged }
        var devices: [[String: Any]] = []
        for path in [current.device, partition] {
            // A mounted block node can reject open with EBUSY. The corresponding
            // raw character node supports this read-only feature ioctl.
            let rawPath = "/dev/r" + path.dropFirst(5)
            let fd = open(rawPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            defer { close(fd) }
            var status = stat()
            guard fstat(fd, &status) == 0,
                status.st_mode & S_IFMT == S_IFCHR
            else { throw ProtocolError.invalidState }
            let features = iscsi_test_disk_features(fd)
            devices.append([
                "device": path, "queryNode": rawPath,
                "queryErrno": features.error, "mask": features.mask,
                "barrier": features.barrier != 0, "queuedFlush": features.queuedFlush != 0,
                "unmap": features.unmap != 0,
            ])
        }
        let outer = iscsi_test_volume_features(image.path)
        let inner = iscsi_test_volume_features(volume.path)
        func volumeFeatures(_ value: ISCSITestVolumeFeatures, at url: URL) throws -> [String: Any] {
            var info = statfs()
            guard statfs(url.path, &info) == 0 else { throw POSIXError(.EIO) }
            let kind = withUnsafePointer(to: &info.f_fstypename) {
                $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
            }
            return [
                "queryErrno": value.error, "interfaceCapabilities": value.interfaceCapabilities,
                "validInterfaces": value.validInterfaces,
                "barrierKnown": value.barrierKnown != 0,
                "barrierSupported": value.barrierSupported != 0,
                "filesystem": kind,
            ]
        }
        var report: [String: Any] = [
            "localRegularFile": localRegularFile, "capturedBeforeTestWrite": true,
            "additionalSynchronizationIssued": false, "devices": devices,
            "backingFilesystem": try volumeFeatures(outer, at: image),
            "mountedFilesystem": try volumeFeatures(inner, at: volume),
        ]
        if ProcessInfo.processInfo.environment["ISCSI_TEST_UNCACHED_IMAGE"] == "1" {
            let fd = open(image.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            defer { close(fd) }
            let previous = fcntl(fd, F_GLOBAL_NOCACHE, 1)
            guard previous >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            report["perFileNoCacheRetainedBeforeTestWrite"] = previous != 0
        }
        if ProcessInfo.processInfo.environment["ISCSI_TEST_BACKING_SYNC_PROBE"] == "1" {
            let fd = open(image.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            defer { close(fd) }
            var results: [[String: Any]] = []
            for (name, command) in [
                ("F_BARRIERFSYNC", F_BARRIERFSYNC), ("F_FULLFSYNC", F_FULLFSYNC),
            ] {
                errno = 0
                let value = fcntl(fd, command)
                let code = value == -1 ? errno : 0
                results.append(["operation": name, "returnValue": value, "errno": code])
            }
            errno = 0
            let value = fsync(fd)
            let code = value == -1 ? errno : 0
            results.append(["operation": "fsync", "returnValue": value, "errno": code])
            report["backingFileSyncBeforeTestWrite"] = results
            report["additionalSynchronizationIssued"] = true
        }
        let encoded = try JSONSerialization.data(
            withJSONObject: report, options: [.sortedKeys])
        try encoded.write(to: root.appendingPathComponent("DeviceFeatures.json"))
        print("DEVICE_FEATURES " + String(decoding: encoded, as: UTF8.self))
    }
}
