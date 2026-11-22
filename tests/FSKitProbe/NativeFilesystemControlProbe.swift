import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Read-only inner filesystem I/O over the installed FSKit extension.
enum NativeFilesystemControlProbe {
    private static let name = "FSKit-control.bin"
    private static let length = 8 * 1_048_576 + 37

    private static func contents(offset: Int, count: Int) -> Data {
        Data((offset..<(offset + count)).map { UInt8(truncatingIfNeeded: $0 * 31 + 7) })
    }

    static func prepare(at volume: URL) throws {
        let url = volume.appendingPathComponent(name)
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw ProtocolError.invalidState
        }
        try contents(offset: 0, count: length).write(to: url)
        let file = try FileHandle(forWritingTo: url)
        defer { try? file.close() }
        guard fcntl(file.fileDescriptor, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
    }

    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let mode = environment["ISCSI_TEST_NATIVE_CONTROL"],
            [
                "text-read", "text-invalid-length", "text-invalid-key", "text-invalid-tag",
            ].contains(mode), let auth = environment["ISCSI_TEST_NATIVE_AUTH"],
            ["none", "chap", "mutual"].contains(auth)
        else { throw ProtocolError.malformed("filesystem control fixture") }
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
            lun: LogicalUnit(0), readOnly: true,
            chapUsername: auth == "none" ? nil : "test-user", isid: [0x80, 1, 2, 3, 4, 5],
            credentialID: auth == "none" ? nil : nonce,
            targetCHAPUsername: auth == "mutual" ? "test-server" : nil)
        let disk = try await owner.connect(descriptor)
        do {
            guard let volume = disk.attachment?.volumeURLs.first else {
                throw ProtocolError.malformed("control filesystem not mounted")
            }
            let format = try FixtureFileSystem.at(root)
            try format.verifyVolume(volume, readOnly: true)
            let file = try FileHandle(forReadingFrom: volume.appendingPathComponent(name))
            defer { try? file.close() }
            guard try file.seekToEnd() == UInt64(length),
                fcntl(file.fileDescriptor, F_NOCACHE, 1) == 0
            else { throw ProtocolError.malformed("control file uncached descriptor") }
            func read(at offset: Int) -> (Int, Int32, Data) {
                var data = Data(count: 16_384)
                errno = 0
                let count = data.withUnsafeMutableBytes {
                    pread(file.fileDescriptor, $0.baseAddress, $0.count, off_t(offset))
                }
                return (count, errno, data)
            }
            let initial = read(at: 0)
            guard initial.0 == 16_384, initial.2 == contents(offset: 0, count: 16_384),
                try state(at: disk.bridgeURL) == .connected
            else { throw ProtocolError.malformed("initial inner filesystem read") }
            let journal = root.appendingPathComponent("State/Connections.json")
            let saved = try Data(contentsOf: journal)
            try FSKitProbe.checkpoint("control-ready")
            let began = ContinuousClock.now
            let operation = read(at: 4 * 1_048_576)
            let elapsed = began.duration(to: .now)
            let health = try state(at: disk.bridgeURL)
            let failing = mode != "text-read"
            print(
                "FILESYSTEM_CONTROL_IO count=\(operation.0) errno=\(operation.1) elapsed=\(elapsed)"
            )
            guard elapsed < .seconds(10) else { throw ProtocolError.timedOut }
            if failing {
                guard operation.0 == -1, operation.1 == EIO,
                    health == .interrupted || health == .closed
                else { throw ProtocolError.malformed("inner filesystem failure was not EIO") }
            } else {
                guard operation.0 == 16_384,
                    operation.2 == contents(offset: 4 * 1_048_576, count: 16_384),
                    health == .connected
                else { throw ProtocolError.malformed("inner filesystem read after negotiation") }
            }
            try FSKitProbe.checkpoint("control-complete")
            let later = read(at: 6 * 1_048_576)
            if failing {
                guard later.0 == -1, later.1 == EIO else {
                    throw ProtocolError.malformed("later inner filesystem read accepted")
                }
            } else {
                guard later.0 == 16_384,
                    later.2 == contents(offset: 6 * 1_048_576, count: 16_384)
                else { throw ProtocolError.malformed("later inner filesystem contents") }
            }
            await owner.refreshHealth()
            let records = await owner.disks
            guard records.count == 1, records[0].id == disk.id,
                records[0].attachment == disk.attachment, !records[0].verificationFailed,
                records[0].connectionState == health, try Data(contentsOf: journal) == saved,
                try state(at: disk.bridgeURL.appendingPathComponent("Disk.img")) == health
            else { throw ProtocolError.malformed("control health refresh lost disk or journal") }
            try FSKitProbe.checkpoint("later-io-checked")
            try file.close()
            try await BridgeHolders.ejectRetryingBusy(owner, disk)
            guard await owner.disks.isEmpty else { throw ProtocolError.invalidState }
            let result: [String: Any] = [
                "mode": mode, "authentication": auth, "filesystem": format.rawValue,
                "nativeFSKitUsed": true, "diskImagesUsed": true, "guiUsed": false,
                "readOnly": true, "innerFileUsed": true, "uncachedFileDescriptor": true,
                "operationFailed": failing, "operationBytes": operation.0,
                "operationErrno": operation.1, "laterReadBytes": later.0,
                "laterReadErrno": later.1, "stateAfterOperation": String(describing: health),
                "diskAndJournalRetainedBeforeEjection": true,
                "elapsedSeconds": Double(elapsed.components.seconds)
                    + Double(elapsed.components.attoseconds) / 1e18,
                "normalEjectionCompleted": true,
            ]
            print(
                "FILESYSTEM_CONTROL_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
        } catch {
            // Which step refused: `detachingImage` is the inner image, `unmountingBridge` the
            // bridge; and who still holds each (ENV082).
            let records = await owner.disks.map { "\($0.phase) \($0.connectionState)" }
            print(
                "CHECK: filesystem control failed: \(error); records \(records); bridge held by \(BridgeHolders.list(disk.bridgeURL)); volume held by \(disk.attachment?.volumeURLs.first.map { BridgeHolders.list($0) } ?? [])"
            )
            try? await owner.eject(disk.id)
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
        guard count == 2 else { throw ProtocolError.malformed("filesystem control state") }
        return try DiskConnectionState(encoded: bytes.prefix(2))
    }
}
