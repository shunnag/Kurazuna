import Darwin
import FSKitNativeDiagnostics
import Foundation
import ISCSICore
import ISCSIPlatform

enum DeviceLayerSyncProbe {
    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let api = environment["ISCSI_TEST_DEVICE_SYNC"],
            ["fsync", "fullfsync", "device-sync", "fsync-device-sync"].contains(api),
            let nodeKind = environment["ISCSI_TEST_DEVICE_NODE"],
            ["raw", "block"].contains(nodeKind)
        else { throw ProtocolError.malformed("opaque device synchronization mode") }
        let source = root.appendingPathComponent("Source.img")
        let properties = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard source.resolvingSymlinksInPath() == source, properties.isRegularFile == true,
            properties.fileSize == 1_048_576
        else { throw ProtocolError.malformed("opaque device source") }
        let initial = try Data(contentsOf: source)
        let payload = Data((0..<65536).map { UInt8(truncatingIfNeeded: $0 * 7 + 11) })
        let offset = 8192
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let owner = try AttachmentCoordinator(
            backend: SystemAttachmentBackend(root: mounts),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await owner.restore()
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5],
            imagePresentation: FSKitProbe.requestedImagePresentation())
        let disk = try await owner.connect(descriptor)
        do {
            guard let attachment = disk.attachment, attachment.volumeURLs.isEmpty,
                disk.connectionState == .connected, !disk.needsCleanup,
                attachment.device.hasPrefix("/dev/disk"), attachment.device.count > 9,
                attachment.device.dropFirst(9).utf8.allSatisfy({ (48...57).contains($0) })
            else { throw ProtocolError.malformed("opaque device attachment") }
            let image = disk.bridgeURL.appendingPathComponent("Disk.img")
            guard
                try await DiskImages().inventory().attachment(at: image)?.device
                    == attachment.device
            else { throw AttachmentError.imageIdentityChanged }
            let status = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
            guard status.count <= 1_048_576,
                let info = try PropertyListSerialization.propertyList(from: status, format: nil)
                    as? [String: Any], info["TotalSize"] as? Int == 1_048_576,
                info["WritableMedia"] as? Bool == true, info["DeviceBlockSize"] as? Int == 512
            else { throw ProtocolError.malformed("opaque device capacity, writability or sectors") }
            try status.write(
                to: root.appendingPathComponent("NativeDeviceInfo.plist"),
                options: .withoutOverwriting)
            let node =
                nodeKind == "raw" ? "/dev/r" + attachment.device.dropFirst(5) : attachment.device
            let handle = try FileHandle(forUpdating: URL(fileURLWithPath: node))
            do {
                guard
                    try await DiskImages().inventory().attachment(at: image)?.device
                        == attachment.device
                else { throw AttachmentError.imageIdentityChanged }
                try handle.seek(toOffset: UInt64(offset))
                guard
                    try handle.read(upToCount: payload.count)
                        == initial.subdata(in: offset..<(offset + payload.count))
                else { throw ProtocolError.malformed("opaque device initial bytes") }
                let media = iscsi_test_device_sync_identity(handle.fileDescriptor)
                guard media.error == 0 else {
                    throw ProtocolError.malformed("opaque device descriptor geometry")
                }
                let features = iscsi_test_disk_features(handle.fileDescriptor)
                try handle.seek(toOffset: UInt64(offset))
                let writeStartedNS = DispatchTime.now().uptimeNanoseconds
                try handle.write(contentsOf: payload)
                let writeReturnedNS = DispatchTime.now().uptimeNanoseconds
                errno = 0
                let startedNS = DispatchTime.now().uptimeNanoseconds
                var cacheStartedNS = startedNS
                var firstReturnedNS: UInt64 = 0
                var firstResult = ISCSITestCallResult(status: 0, error: 0)
                let result: ISCSITestCallResult
                if api == "fsync-device-sync" {
                    let code = Darwin.fsync(handle.fileDescriptor)
                    firstResult = ISCSITestCallResult(status: code, error: code == -1 ? errno : 0)
                    firstReturnedNS = DispatchTime.now().uptimeNanoseconds
                    cacheStartedNS = DispatchTime.now().uptimeNanoseconds
                    result = iscsi_test_device_cache_sync(handle.fileDescriptor, media.deviceID)
                } else if api == "device-sync" {
                    result = iscsi_test_device_cache_sync(handle.fileDescriptor, media.deviceID)
                } else if api == "fsync" {
                    let code = Darwin.fsync(handle.fileDescriptor)
                    result = ISCSITestCallResult(status: code, error: code == -1 ? errno : 0)
                } else {
                    let code = fcntl(handle.fileDescriptor, F_FULLFSYNC)
                    result = ISCSITestCallResult(status: code, error: code == -1 ? errno : 0)
                }
                let returnedNS = DispatchTime.now().uptimeNanoseconds
                var report: [String: Any] = [
                    "api": api, "nodeKind": nodeKind, "device": attachment.device,
                    "deviceNode": node,
                    "returnCode": result.status, "errno": result.error,
                    "errorDescription": String(cString: strerror(result.error)),
                    "writeStartedNS": writeStartedNS, "writeReturnedNS": writeReturnedNS,
                    "syncStartedNS": cacheStartedNS, "syncReturnedNS": returnedNS,
                    "sourceOffset": offset, "payloadBytes": payload.count,
                    "presentation": descriptor.imagePresentation.rawValue,
                    "nativeDeviceAttached": true, "innerFilesystemMounted": false,
                    "nativeBytes": 1_048_576, "nativeBlockSize": 512,
                    "featureQueryErrno": features.error, "featureMask": features.mask,
                    "featureBarrier": features.barrier != 0,
                    "featureQueuedFlush": features.queuedFlush != 0,
                    "bridgeURL": disk.bridgeURL.path,
                ]
                if api == "fsync-device-sync" {
                    report["sequenceStartedNS"] = startedNS
                    report["firstSync"] = [
                        "api": "fsync", "returnCode": firstResult.status,
                        "errno": firstResult.error, "syncStartedNS": startedNS,
                        "syncReturnedNS": firstReturnedNS,
                    ]
                    report["secondAPI"] = "DKIOCSYNCHRONIZE"
                }
                try JSONSerialization.data(
                    withJSONObject: report, options: [.prettyPrinted, .sortedKeys]
                )
                .write(
                    to: root.appendingPathComponent("DeviceSyncResult.json"),
                    options: .withoutOverwriting)
                try FSKitProbe.checkpoint("opaque-device-sync", fullsyncReturnedNS: returnedNS)
                try handle.seek(toOffset: UInt64(offset))
                guard try handle.read(upToCount: payload.count) == payload else {
                    throw ProtocolError.malformed("opaque device final bytes")
                }
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            try await owner.eject(disk.id)
        } catch {
            try? await owner.eject(disk.id)
            throw error
        }
        guard await owner.disks.isEmpty else { throw AttachmentError.recoveryRequired }
        print("PASS: opaque native-device synchronization result collected and normally ejected")
    }
}
