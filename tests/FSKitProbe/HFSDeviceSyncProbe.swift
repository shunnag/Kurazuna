import Darwin
import FSKitNativeDiagnostics
import Foundation
import ISCSICore
import ISCSIPlatform

/// Verify a mounted HFS+ fixture; synchronize only its private parent image cache.
final class HFSDeviceSyncProbe {
    private var cacheDescriptor: Int32
    private let approvedDeviceID: UInt64
    private var partitionDescriptor: Int32
    private let approvedPartitionID: UInt64

    private init(cache: Int32, deviceID: UInt64, partition: Int32 = -1, partitionID: UInt64 = 0) {
        cacheDescriptor = cache
        approvedDeviceID = deviceID
        partitionDescriptor = partition
        approvedPartitionID = partitionID
    }

    deinit {
        if cacheDescriptor >= 0 { Darwin.close(cacheDescriptor) }
        if partitionDescriptor >= 0 { Darwin.close(partitionDescriptor) }
    }

    func close() {
        if cacheDescriptor >= 0 { Darwin.close(cacheDescriptor) }
        if partitionDescriptor >= 0 { Darwin.close(partitionDescriptor) }
        cacheDescriptor = -1
        partitionDescriptor = -1
    }

    func synchronizeCache() -> ISCSITestCallResult {
        iscsi_test_hfs_device_cache_sync(cacheDescriptor, approvedDeviceID)
    }

    func synchronizeScope(_ control: String) -> ISCSITestCallResult {
        switch control {
        case "whole-zero":
            iscsi_test_hfs_device_cache_sync_zero(cacheDescriptor, approvedDeviceID)
        case "partition-zero":
            iscsi_test_hfs_partition_cache_sync_zero(partitionDescriptor, approvedPartitionID)
        case "whole-full":
            iscsi_test_hfs_device_cache_sync(cacheDescriptor, approvedDeviceID)
        default:
            ISCSITestCallResult(status: -1, error: EINVAL)
        }
    }

    static func prepareIfRequested(
        root: URL, volume: URL, image: URL, attachment: DiskAttachment
    ) async throws -> HFSDeviceSyncProbe? {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ISCSI_TEST_SYNC_BOUNDARY_SCOPE"] == "file-device" else { return nil }
        guard let mode = environment["ISCSI_TEST_SYNC_BOUNDARIES"],
            ["overwrite", "grow"].contains(mode),
            try FixtureFileSystem.at(root) == .hfsPlus,
            image.path.hasPrefix(root.path + "/"),
            attachment.device.range(of: "^/dev/disk[0-9]+$", options: .regularExpression) != nil
        else { throw ProtocolError.malformed("private HFS device synchronization fixture") }
        let control = environment["ISCSI_TEST_HFS_CACHE_CONTROL"]
        guard control == nil || ["whole-zero", "partition-zero", "whole-full"].contains(control!)
        else {
            throw ProtocolError.malformed("HFS cache control")
        }
        let source = root.appendingPathComponent("HFSPlus.cdr")
        let properties = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard source.resolvingSymlinksInPath() == source,
            properties.isRegularFile == true, properties.fileSize == 134_217_728,
            let current = try await DiskImages().inventory().attachment(at: image),
            current.device == attachment.device,
            current.volumeURLs.map(\.path) == [volume.path]
        else { throw AttachmentError.imageIdentityChanged }
        let infoData = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", volume.path])
        guard infoData.count <= 1_048_576,
            let info = try PropertyListSerialization.propertyList(from: infoData, format: nil)
                as? [String: Any], let partition = info["DeviceNode"] as? String,
            partition.range(
                of: "^" + NSRegularExpression.escapedPattern(for: current.device) + "s[0-9]+$",
                options: .regularExpression) != nil,
            info["WritableMedia"] as? Bool == true, info["DeviceBlockSize"] as? Int == 512,
            let bytes = info["TotalSize"] as? Int, bytes > 65_573, bytes < 134_217_728
        else { throw ProtocolError.malformed("private HFS partition identity") }
        let inventory = try await SystemCommand.run(
            "/usr/bin/hdiutil", arguments: ["info", "-plist"])
        guard inventory.count <= 1_048_576,
            let list = try PropertyListSerialization.propertyList(from: inventory, format: nil)
                as? [String: Any], let images = list["images"] as? [[String: Any]],
            let own = images.first(where: { $0["image-path"] as? String == image.path }),
            let entities = own["system-entities"] as? [[String: Any]],
            entities.contains(where: { $0["dev-entry"] as? String == current.device }),
            entities.contains(where: {
                $0["dev-entry"] as? String == partition
                    && $0["mount-point"] as? String == volume.path
            })
        else { throw AttachmentError.imageIdentityChanged }
        var mounted = statfs()
        var volumeStatus = stat()
        guard statfs(volume.path, &mounted) == 0, stat(volume.path, &volumeStatus) == 0,
            mounted.f_flags & UInt32(MNT_RDONLY) == 0, mounted.f_owner == getuid()
        else { throw ProtocolError.malformed("private writable HFS mount") }
        let kind = withUnsafePointer(to: &mounted.f_fstypename) {
            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
        }
        guard kind == "hfs" else { throw ProtocolError.malformed("HFS mount type") }
        var node = stat()
        guard lstat(partition, &node) == 0, node.st_mode & S_IFMT == S_IFBLK,
            node.st_rdev == volumeStatus.st_dev
        else { throw ProtocolError.malformed("HFS partition metadata identity") }
        var cacheFD: Int32 = -1
        var partitionFD: Int32 = -1
        var partitionID: UInt64 = 0
        do {
            let rawDevice = "/dev/r" + current.device.dropFirst(5)
            cacheFD = open(rawDevice, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard cacheFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let identity = iscsi_test_hfs_device_sync_identity(cacheFD)
            guard identity.error == 0 else {
                throw ProtocolError.malformed("128MiB HFS parent device geometry")
            }
            let rawPartition = "/dev/r" + partition.dropFirst(5)
            if control != nil {
                guard bytes == 134_176_768 else {
                    throw ProtocolError.malformed("fixed HFS fixture partition size")
                }
                partitionFD = open(rawPartition, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                guard partitionFD >= 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                let partitionIdentity = iscsi_test_hfs_partition_sync_identity(partitionFD)
                guard partitionIdentity.error == 0 else {
                    throw ProtocolError.malformed("fixed HFS partition geometry")
                }
                partitionID = partitionIdentity.deviceID
            }
            let local = image == source
            var report: [String: Any] = [
                "capturedBeforeWrite": true, "localPreparedImage": local,
                "image": image.path, "volume": volume.path,
                "partition": partition, "partitionBytes": bytes,
                "partitionBlockDescriptorOpened": false,
                "volumeWaitFlags": SYNC_VOLUME_WAIT,
                "volumeWaitRequestsFullsync": false,
                "partitionDeviceIDMatchesMountedFilesystem": true,
                "parentDevice": current.device, "cacheNode": rawDevice,
                "parentBytes": 134_217_728, "blockSize": 512,
                "cacheDescriptorReadOnly": true,
                "additionalSynchronizationIssued": false,
            ]
            if control != nil {
                func features(_ descriptor: Int32) -> [String: Any] {
                    let value = iscsi_test_disk_features(descriptor)
                    return [
                        "queryErrno": value.error, "mask": value.mask,
                        "barrier": value.barrier != 0, "queuedFlush": value.queuedFlush != 0,
                        "unmap": value.unmap != 0,
                    ]
                }
                report["rawHelper124Requested"] = environment["ISCSI_TEST_RAW_HELPER_124"] == "1"
                report["attachmentInventoryScalars"] = own.filter {
                    $0.value is NSNumber || $0.value is String
                }
                report["cacheControl"] = control!
                report["partitionCacheNode"] = rawPartition
                report["partitionCacheDescriptorReadOnly"] = true
                report["allControlNodesOpenedBeforeWrite"] = true
                report["wholeFeatures"] = features(cacheFD)
                report["partitionFeatures"] = features(partitionFD)
                report["forceUnitAccessBitDecoded"] = false
            }
            try JSONSerialization.data(
                withJSONObject: report, options: [.prettyPrinted, .sortedKeys]
            )
            .write(
                to: root.appendingPathComponent(
                    local ? "HFSDeviceAccessPreparation.json" : "HFSDeviceSyncPreparation.json"),
                options: .withoutOverwriting)
            return HFSDeviceSyncProbe(
                cache: cacheFD, deviceID: identity.deviceID, partition: partitionFD,
                partitionID: partitionID)
        } catch {
            if cacheFD >= 0 { Darwin.close(cacheFD) }
            if partitionFD >= 0 { Darwin.close(partitionFD) }
            throw error
        }
    }
}
