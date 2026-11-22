import Darwin
import FSKitNativeDiagnostics
import Foundation
import ISCSICore
import ISCSIPlatform

/// A mount capability diagnostic: no device attachment and no payload writes.
enum OuterSynchronousProbe {
    static func run(portal: Portal, root: URL, nonce: UUID, commandUpdate: Bool = false)
        async throws
    {
        let source = root.appendingPathComponent("Source.img")
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard source.resolvingSymlinksInPath() == source, values.isRegularFile == true,
            values.fileSize == 65536
        else { throw ProtocolError.malformed("outer sync fixture source") }
        let expected = try Data(contentsOf: source).prefix(4096)
        let presentation = try FSKitProbe.requestedImagePresentation()
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5],
            mountID: UUID(), imagePresentation: presentation)
        let backend = SystemAttachmentBackend(root: root.appendingPathComponent("Mounts"))
        let bridge = try await backend.bridgeURL(for: descriptor.mountID!)
        let resource = try descriptor.resourceURL.absoluteString
        let offset =
            try presentation == .udsp
            ? SparseImageLayout(capacity: 65536).physicalOffset(forLUNOffset: 0) : 0
        do {
            try await backend.mountBridge(descriptor, at: bridge)
            try readPayload(bridge, offset: offset, expected: expected)
            var report: [String: Any]
            if commandUpdate {
                report = try await updateUsingCommand(bridge: bridge, resource: resource)
            } else {
                let result = iscsi_test_fskit_sync_mount(
                    bridge.path, resource, ApplicationIdentity.current.fileSystemType)
                report = [
                    "method": "mount-syscall", "errno": result.error,
                    "errorDescription": String(cString: strerror(result.error)),
                    "syscallAttempted": result.syscallAttempted == 1,
                    "beforeFlags": result.beforeFlags, "afterFlags": result.afterFlags,
                    "synchronousBefore": result.beforeFlags & UInt32(MNT_SYNCHRONOUS) != 0,
                    "synchronousAfter": result.afterFlags & UInt32(MNT_SYNCHRONOUS) != 0,
                    "capabilityAvailable": result.error == 0,
                ]
            }
            try readPayload(bridge, offset: offset, expected: expected)
            report["presentation"] = presentation.rawValue
            report["knownPayloadReadBeforeAndAfter"] = true
            report["nativeDeviceAttached"] = false
            report["bridgeURL"] = bridge.path
            report["resourceURL"] = resource
            try JSONSerialization.data(
                withJSONObject: report, options: [.prettyPrinted, .sortedKeys]
            )
            .write(
                to: root.appendingPathComponent("OuterSyncMount.json"), options: .withoutOverwriting
            )
            try FSKitProbe.checkpoint("outer-sync-capability")
            try await backend.unmountBridge(descriptor, at: bridge)
        } catch {
            // The target stays alive while normal cleanup is attempted by this owner.
            try? await backend.unmountBridge(descriptor, at: bridge)
            throw error
        }
        guard !MountedFSKitBridge.contains(descriptor),
            !FileManager.default.fileExists(atPath: bridge.path)
        else { throw AttachmentError.recoveryRequired }
        print("PASS: outer FSKit synchronous-update diagnostic collected and normally ejected")
    }

    private static func updateUsingCommand(bridge: URL, resource: String) async throws
        -> [String: Any]
    {
        let before = try mountState(bridge: bridge, resource: resource)
        let arguments = [
            "-F", "-u", "-t", ApplicationIdentity.current.fileSystemType, "-o",
            "nobrowse,nosuid,nodev,noexec,sync",
            resource, bridge.path,
        ]
        var status: Int32 = 0
        var output = ""
        do {
            output = String(
                decoding: try await SystemCommand.run(
                    "/sbin/mount", arguments: arguments, timeout: 60),
                as: UTF8.self)
        } catch let SystemCommandError.failed(program, code, detail) {
            guard program == "mount" else { throw ProtocolError.invalidState }
            status = code
            output = detail
        }
        let after = try mountState(bridge: bridge, resource: resource)
        guard before.fsid == after.fsid else { throw AttachmentError.imageIdentityChanged }
        return [
            "method": "mount-command", "command": ["/sbin/mount"] + arguments,
            "commandAttempted": true, "commandExitStatus": status, "commandOutput": output,
            "beforeFlags": before.flags, "afterFlags": after.flags,
            "synchronousBefore": before.flags & UInt32(MNT_SYNCHRONOUS) != 0,
            "synchronousAfter": after.flags & UInt32(MNT_SYNCHRONOUS) != 0,
            "capabilityAvailable": status == 0 && after.flags & UInt32(MNT_SYNCHRONOUS) != 0,
            "mountIdentityMatched": true,
        ]
    }

    private static func mountState(bridge: URL, resource: String) throws
        -> (flags: UInt32, fsid: [Int32])
    {
        var directory = stat()
        var volume = statfs()
        guard lstat(bridge.path, &directory) == 0, statfs(bridge.path, &volume) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        func string<T>(_ value: inout T) -> String {
            withUnsafeBytes(of: &value) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        }
        guard directory.st_mode & S_IFMT == S_IFDIR,
            directory.st_uid == geteuid(), volume.f_owner == geteuid(),
            string(&volume.f_fstypename) == ApplicationIdentity.current.fileSystemType,
            string(&volume.f_mntonname) == bridge.path,
            string(&volume.f_mntfromname) == resource,
            volume.f_flags & UInt32(MNT_ROOTFS | MNT_RDONLY) == 0
        else { throw AttachmentError.ownershipUnverified }
        return (volume.f_flags, [volume.f_fsid.val.0, volume.f_fsid.val.1])
    }

    private static func readPayload(_ bridge: URL, offset: UInt64, expected: Data.SubSequence)
        throws
    {
        let handle = try FileHandle(forReadingFrom: bridge.appendingPathComponent("Disk.img"))
        defer { try? handle.close() }
        try handle.seek(toOffset: offset)
        guard try handle.read(upToCount: expected.count) == expected else {
            throw ProtocolError.malformed("outer sync payload readback")
        }
    }
}
