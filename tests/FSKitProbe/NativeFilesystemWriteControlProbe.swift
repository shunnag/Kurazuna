import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Only private preallocated fixture files are overwritten; no user media is accepted.
enum NativeFilesystemWriteControlProbe {
    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let mode = environment["ISCSI_TEST_NATIVE_CONTROL"],
            [
                "text-write", "text-invalid-length", "text-invalid-key", "text-invalid-tag",
            ].contains(mode), let auth = environment["ISCSI_TEST_NATIVE_AUTH"],
            ["none", "chap", "mutual"].contains(auth)
        else { throw ProtocolError.malformed("filesystem write control fixture") }
        if auth != "none" {
            try await FSKitProbe.saveFixtureCredential(
                portal: portal, root: root, nonce: nonce, mutualCHAP: auth == "mutual")
        }
        do {
            try await validate(portal: portal, root: root, nonce: nonce, mode: mode, auth: auth)
        } catch {
            try? await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
            throw error
        }
        try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func output(_ prefix: String, _ value: [String: Any]) throws {
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(Data(prefix.utf8) + bytes + Data([10]))
    }

    private static func validate(
        portal: Portal, root: URL, nonce: UUID, mode: String, auth: String
    ) async throws {
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
            lun: LogicalUnit(0), readOnly: false,
            chapUsername: auth == "none" ? nil : "test-user", isid: [0x80, 1, 2, 3, 4, 5],
            credentialID: auth == "none" ? nil : nonce,
            targetCHAPUsername: auth == "mutual" ? "test-server" : nil)
        let disk = try await owner.connect(descriptor)
        do {
            guard let volume = disk.attachment?.volumeURLs.first else {
                throw ProtocolError.malformed("write control filesystem not mounted")
            }
            let format = try FixtureFileSystem.at(root)
            try format.verifyVolume(volume, readOnly: false)
            let file = try FileHandle(
                forUpdating: volume.appendingPathComponent("FSKit-control.bin"))
            defer { try? file.close() }
            guard try file.seekToEnd() == 8 * 1_048_576 + 37,
                fcntl(file.fileDescriptor, F_NOCACHE, 1) == 0
            else { throw ProtocolError.malformed("write control uncached file") }
            var initial = Data(count: 16_384)
            guard
                initial.withUnsafeMutableBytes({
                    pread(file.fileDescriptor, $0.baseAddress, $0.count, 0)
                }) == initial.count,
                initial == Data((0..<16_384).map { UInt8(truncatingIfNeeded: $0 * 31 + 7) }),
                try state(at: disk.bridgeURL) == .connected
            else { throw ProtocolError.malformed("write control initial file contents") }
            let journal = root.appendingPathComponent("State/Connections.json")
            let saved = try Data(contentsOf: journal)
            try FSKitProbe.checkpoint("write-control-ready")
            let payload = Data(repeating: 0x6D, count: 65_536)
            let began = ContinuousClock.now
            errno = 0
            let written = payload.withUnsafeBytes {
                pwrite(file.fileDescriptor, $0.baseAddress, $0.count, 4 * 1_048_576)
            }
            let writeError = errno
            try output("FILESYSTEM_WRITE_IO ", ["writeBytes": written, "writeErrno": writeError])
            errno = 0
            let synced = fcntl(file.fileDescriptor, F_FULLFSYNC)
            let syncError = errno
            let elapsed = began.duration(to: .now)
            let health = try state(at: disk.bridgeURL)
            let failing = mode != "text-write"
            let io: [String: Any] = [
                "writeBytes": written, "writeErrno": writeError, "syncResult": synced,
                "syncErrno": syncError, "state": String(describing: health),
                "elapsedSeconds": Double(elapsed.components.seconds)
                    + Double(elapsed.components.attoseconds) / 1e18,
            ]
            try JSONSerialization.data(withJSONObject: io, options: [.sortedKeys]).write(
                to: root.appendingPathComponent("WriteControlIO.json"))
            try output("FILESYSTEM_WRITE_IO ", io)
            guard elapsed < .seconds(30) else { throw ProtocolError.timedOut }
            if failing {
                guard (written == -1 && writeError == EIO) || (synced == -1 && syncError == EIO),
                    health == .interrupted || health == .closed
                else { throw ProtocolError.malformed("write control failure was not reported") }
            } else {
                guard written == payload.count, synced == 0, health == .connected else {
                    throw ProtocolError.malformed("write control positive operation")
                }
                var check = Data(count: payload.count)
                guard
                    check.withUnsafeMutableBytes({
                        pread(file.fileDescriptor, $0.baseAddress, $0.count, 4 * 1_048_576)
                    }) == payload.count, check == payload
                else {
                    throw ProtocolError.malformed("write control positive file contents")
                }
            }
            try FSKitProbe.checkpoint("write-control-complete")
            var later = Data(count: 16_384)
            errno = 0
            let laterRead = later.withUnsafeMutableBytes {
                pread(file.fileDescriptor, $0.baseAddress, $0.count, 6 * 1_048_576)
            }
            let readError = errno
            var laterWrite = 0
            var laterWriteError: Int32 = 0
            if failing {
                errno = 0
                laterWrite = payload.withUnsafeBytes {
                    pwrite(file.fileDescriptor, $0.baseAddress, $0.count, 7 * 1_048_576)
                }
                laterWriteError = errno
                guard laterRead == -1, readError == EIO,
                    laterWrite == -1, laterWriteError == EIO
                else { throw ProtocolError.malformed("write control later I/O accepted") }
            } else {
                guard laterRead == later.count,
                    later
                        == Data(
                            (6 * 1_048_576..<(6 * 1_048_576 + later.count)).map {
                                UInt8(truncatingIfNeeded: $0 * 31 + 7)
                            })
                else { throw ProtocolError.malformed("write control later file contents") }
            }
            await owner.refreshHealth()
            let records = await owner.disks
            guard records.count == 1, records[0].id == disk.id,
                records[0].attachment == disk.attachment, !records[0].verificationFailed,
                records[0].connectionState == health, try Data(contentsOf: journal) == saved,
                try state(at: disk.bridgeURL.appendingPathComponent("Disk.img")) == health
            else { throw ProtocolError.malformed("write control health lost disk or journal") }
            try FSKitProbe.checkpoint("write-control-later-io")
            try file.close()
            var refusal: (description: String, errno: String)?
            var lostConnection = false
            if failing {
                // A fail-stopped read-write disk refuses the normal eject; the app then offers
                // the confirmed forced path, which this owner takes.
                do {
                    try await owner.eject(disk.id)
                } catch {
                    refusal = (
                        String(describing: error), NativeSessionControlProbe.errnoName(error)
                    )
                }
                guard let refusal else {
                    throw ProtocolError.malformed("fail-stopped disk ejected normally")
                }
                print("CHECK: normal eject of the stopped disk refused: \(refusal.description)")
                guard await owner.canPrepareForceEjection(disk.id) else {
                    throw ProtocolError.malformed("stopped disk offers no forced release")
                }
                let request = try await owner.prepareForceEjection(disk.id)
                lostConnection = request.reportsLostConnection
                try await owner.forceEject(request)
            } else {
                try await BridgeHolders.ejectRetryingBusy(owner, disk)
            }
            guard await owner.disks.isEmpty else { throw ProtocolError.invalidState }
            var result = io
            result.merge([
                "mode": mode, "authentication": auth, "filesystem": format.rawValue,
                "nativeFSKitUsed": true, "diskImagesUsed": true, "guiUsed": false,
                "readOnly": false, "innerFileUsed": true, "operationFailed": failing,
                "laterReadBytes": laterRead, "laterReadErrno": readError,
                "laterWriteBytes": laterWrite, "laterWriteErrno": laterWriteError,
                "diskAndJournalRetainedBeforeEjection": true, "normalEjectionCompleted": !failing,
                "normalEjectionRefused": refusal != nil,
                "normalEjectionError": refusal?.description ?? "",
                "normalEjectionErrno": refusal?.errno ?? "", "forcedReleaseCompleted": failing,
                "forcedReleaseReportsLostConnection": lostConnection,
            ]) { _, value in value }
            try output("FILESYSTEM_WRITE_RESULT ", result)
        } catch {
            var cleanupError = ""
            do { try await owner.eject(disk.id) } catch { cleanupError = String(describing: error) }
            let records = await owner.disks
            try? output(
                "FILESYSTEM_WRITE_FAILURE ",
                [
                    "originalError": String(describing: error), "cleanupError": cleanupError,
                    "phases": records.map { $0.phase.rawValue },
                    "verificationFailed": records.map(\.verificationFailed),
                ])
            throw error
        }
    }

    private static func state(at path: URL) throws -> DiskConnectionState {
        var bytes = Data(count: 3)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                path.path, ConnectionDescriptor.connectionStateAttributeName,
                $0.baseAddress, $0.count, 0, 0)
        }
        guard count == 2 else { throw ProtocolError.malformed("write control state") }
        return try DiskConnectionState(encoded: bytes.prefix(2))
    }
}
