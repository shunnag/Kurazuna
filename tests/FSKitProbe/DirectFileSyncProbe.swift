import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Direct outer-file synchronization: no DiskImages device or inner filesystem.
enum DirectFileSyncProbe {
    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        guard let api = ProcessInfo.processInfo.environment["ISCSI_TEST_DIRECT_SYNC"],
            ["fsync", "fullfsync"].contains(api)
        else { throw ProtocolError.malformed("direct synchronization API") }
        let source = root.appendingPathComponent("Source.img")
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard source.resolvingSymlinksInPath() == source, values.isRegularFile == true,
            values.fileSize == 1_048_576
        else { throw ProtocolError.malformed("direct synchronization source") }
        let expected = try Data(contentsOf: source)
        let aligned = ProcessInfo.processInfo.environment["ISCSI_TEST_DIRECT_ALIGNED"] == "1"
        let length = aligned ? 65536 : 65573
        let payload = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 * 7 + 11) })
        let sourceOffset: UInt64 = aligned ? 8192 : 8191
        let presentation = try FSKitProbe.requestedImagePresentation()
        let physicalOffset =
            try presentation == .udsp
            ? SparseImageLayout(capacity: 1_048_576).physicalOffset(forLUNOffset: sourceOffset)
            : sourceOffset
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5],
            mountID: UUID(), imagePresentation: presentation)
        let backend = SystemAttachmentBackend(root: root.appendingPathComponent("Mounts"))
        let bridge = try await backend.bridgeURL(for: descriptor.mountID!)
        do {
            try await backend.mountBridge(descriptor, at: bridge)
            let handle = try FileHandle(forUpdating: bridge.appendingPathComponent("Disk.img"))
            do {
                try handle.seek(toOffset: physicalOffset)
                guard
                    try handle.read(upToCount: payload.count)
                        == expected.subdata(
                            in: Int(sourceOffset)..<(Int(sourceOffset) + payload.count))
                else { throw ProtocolError.malformed("direct synchronization initial bytes") }
                try handle.seek(toOffset: physicalOffset)
                let writeStartedNS = DispatchTime.now().uptimeNanoseconds
                try handle.write(contentsOf: payload)
                let writeReturnedNS = DispatchTime.now().uptimeNanoseconds
                errno = 0
                let startedNS = DispatchTime.now().uptimeNanoseconds
                let status =
                    api == "fsync"
                    ? Darwin.fsync(handle.fileDescriptor)
                    : fcntl(handle.fileDescriptor, F_FULLFSYNC)
                let savedErrno = status == -1 ? errno : 0
                let returnedNS = DispatchTime.now().uptimeNanoseconds
                let report: [String: Any] = [
                    "api": api, "returnCode": status, "errno": savedErrno,
                    "errorDescription": String(cString: strerror(savedErrno)),
                    "writeStartedNS": writeStartedNS, "writeReturnedNS": writeReturnedNS,
                    "syncStartedNS": startedNS, "syncReturnedNS": returnedNS,
                    "sourceOffset": sourceOffset, "physicalOffset": physicalOffset,
                    "payloadBytes": payload.count, "presentation": presentation.rawValue,
                    "nativeDeviceAttached": false, "innerFilesystemMounted": false,
                    "bridgeURL": bridge.path,
                    "resourceURL": try descriptor.resourceURL.absoluteString,
                ]
                try JSONSerialization.data(
                    withJSONObject: report, options: [.prettyPrinted, .sortedKeys]
                ).write(
                    to: root.appendingPathComponent("DirectSyncResult.json"),
                    options: .withoutOverwriting)
                try FSKitProbe.checkpoint("direct-file-sync", fullsyncReturnedNS: returnedNS)
                try handle.seek(toOffset: physicalOffset)
                guard try handle.read(upToCount: payload.count) == payload else {
                    throw ProtocolError.malformed("direct synchronization final bytes")
                }
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            try await backend.unmountBridge(descriptor, at: bridge)
        } catch {
            try? await backend.unmountBridge(descriptor, at: bridge)
            throw error
        }
        guard !MountedFSKitBridge.contains(descriptor),
            !FileManager.default.fileExists(atPath: bridge.path)
        else { throw AttachmentError.recoveryRequired }
        print("PASS: direct outer-file API result collected and normally ejected")
    }
}
