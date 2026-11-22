import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Only used by the validated private-loopback entry point. This probes VFS, not GUI flows.
enum NativeSessionControlProbe {
    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let mode = environment["ISCSI_TEST_NATIVE_CONTROL"],
            [
                "text-read", "text-write", "text-fragmented", "text-outbound", "text-reset",
                "text-invalid-length", "text-invalid-key", "text-invalid-tag",
            ].contains(mode),
            let authentication = environment["ISCSI_TEST_NATIVE_AUTH"],
            ["none", "chap", "mutual"].contains(authentication)
        else { throw ProtocolError.malformed("native session control fixture") }
        let chap = authentication != "none"
        if chap {
            try await FSKitProbe.saveFixtureCredential(
                portal: portal, root: root, nonce: nonce, mutualCHAP: authentication == "mutual")
        }
        do {
            try await validate(
                portal: portal, root: root, nonce: nonce, mode: mode,
                authentication: authentication)
        } catch {
            try? await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
            throw error
        }
        try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func validate(
        portal: Portal, root: URL, nonce: UUID, mode: String, authentication: String
    ) async throws {
        let failing = mode.hasPrefix("text-invalid-")
        let writing = mode.hasSuffix("-write")
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let backend = SystemAttachmentBackend(root: mounts)
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal,
            initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
            targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
            lun: LogicalUnit(0), readOnly: false,
            chapUsername: authentication == "none" ? nil : "test-user",
            isid: [0x80, 1, 2, 3, 4, 5], credentialID: authentication == "none" ? nil : nonce,
            targetCHAPUsername: authentication == "mutual" ? "test-server" : nil
        ).assigningMountID(nonce)
        let bridge = try await backend.bridgeURL(for: nonce)
        let journal = try FileAttachmentJournal(
            directory: root.appendingPathComponent("State", isDirectory: true), bridgeRoot: mounts)
        func save(_ phase: AttachmentPhase) throws {
            try journal.save([
                AttachmentJournalEntry(
                    id: nonce, descriptor: descriptor, bridgeURL: bridge, phase: phase)
            ])
        }
        try save(.mountingBridge)
        do {
            try await backend.mountBridge(descriptor, at: bridge)
            var status = statfs()
            guard statfs(bridge.path, &status) == 0,
                status.f_flags & UInt32(MNT_SYNCHRONOUS) != 0
            else { throw ProtocolError.malformed("native control synchronous mount") }
            let raw = try FileHandle(forUpdating: bridge.appendingPathComponent("Disk.img"))
            defer { try? raw.close() }
            guard fcntl(raw.fileDescriptor, F_NOCACHE, 1) == 0 else { throw POSIXError(.EIO) }
            var seed = Data(count: 4096)
            guard
                seed.withUnsafeMutableBytes({
                    pread(raw.fileDescriptor, $0.baseAddress, $0.count, 32 * 1_048_576)
                }) == 4096, seed == Data(count: 4096), try state(at: bridge) == .connected
            else {
                throw ProtocolError.malformed("native control initial read")
            }
            try FSKitProbe.checkpoint("control-ready")
            var bytes = Data(count: 16_384)
            let payload = Data(repeating: 7, count: 16_384)
            let clock = ContinuousClock()
            let began = clock.now
            errno = 0
            let count: Int
            if writing {
                count = payload.withUnsafeBytes {
                    pwrite(raw.fileDescriptor, $0.baseAddress, $0.count, 64 * 1_048_576)
                }
            } else {
                count = bytes.withUnsafeMutableBytes {
                    pread(raw.fileDescriptor, $0.baseAddress, $0.count, 64 * 1_048_576)
                }
            }
            let code = errno
            let elapsed = began.duration(to: clock.now)
            let connectionState = try state(at: bridge)
            print("NATIVE_CONTROL_IO mode=\(mode) count=\(count) errno=\(code) elapsed=\(elapsed)")
            guard elapsed < .seconds(10) else { throw ProtocolError.timedOut }
            if failing {
                guard count == -1, code == EIO,
                    connectionState == .interrupted || connectionState == .closed
                else { throw ProtocolError.malformed("native control failed I/O or health") }
            } else {
                guard count == 16_384, connectionState == .connected,
                    writing || bytes == Data((0..<16_384).map { UInt8(truncatingIfNeeded: $0 * 3) })
                else { throw ProtocolError.malformed("native control successful I/O or contents") }
            }
            try FSKitProbe.checkpoint("control-complete")
            var later = Data(count: 16_384)
            errno = 0
            let read = later.withUnsafeMutableBytes {
                pread(raw.fileDescriptor, $0.baseAddress, $0.count, 96 * 1_048_576)
            }
            let readCode = errno
            var writeCode: Int32 = 0
            if failing {
                errno = 0
                let write = payload.withUnsafeBytes {
                    pwrite(raw.fileDescriptor, $0.baseAddress, $0.count, 80 * 1_048_576)
                }
                writeCode = errno
                guard read == -1, readCode == EIO, write == -1, writeCode == EIO else {
                    throw ProtocolError.malformed("native control later I/O accepted")
                }
            } else {
                guard read == 16_384, later == Data(count: 16_384),
                    try state(at: bridge) == .connected
                else { throw ProtocolError.malformed("native control later read") }
            }
            try FSKitProbe.checkpoint("later-io-checked")
            try raw.close()
            try save(.unmountingBridge)
            var refusal: (description: String, errno: String)?
            var forced = false
            if failing {
                // A fail-stopped read-write disk refuses the normal unmount: FSKit's final
                // synchronization reports the stop. The confirmed forced path releases it.
                do {
                    try await backend.unmountBridge(descriptor, at: bridge)
                } catch {
                    refusal = (String(describing: error), errnoName(error))
                }
                guard let refusal else {
                    throw ProtocolError.malformed("fail-stopped disk unmounted normally")
                }
                print("CHECK: normal unmount of the stopped disk refused: \(refusal.description)")
                let coordinator = try await FSKitProbe.releaseRecordedDisks(
                    root: root, journal: journal, requiringForcedRelease: true)
                guard await coordinator.disks.isEmpty else {
                    throw ProtocolError.malformed("stopped disk not force released")
                }
                forced = true
            } else {
                try await backend.unmountBridge(descriptor, at: bridge)
                try journal.save([])
            }
            let result: [String: Any] = [
                "mode": mode, "authentication": authentication, "nativeFSKitUsed": true,
                "diskImagesUsed": false, "guiUsed": false, "operationFailed": failing,
                "operationBytes": count, "operationErrno": code,
                "elapsedSeconds": Double(elapsed.components.seconds)
                    + Double(elapsed.components.attoseconds) / 1e18,
                "stateAfterOperation": String(describing: connectionState),
                "laterReadBytes": read, "laterReadErrno": readCode,
                "laterWriteErrno": writeCode, "normalUnmountCompleted": !failing,
                "normalUnmountRefused": refusal != nil,
                "normalUnmountError": refusal?.description ?? "",
                "normalUnmountErrno": refusal?.errno ?? "",
                "forcedReleaseCompleted": forced,
                "emptyConnectionJournal": try journal.load().isEmpty,
            ]
            print(
                "NATIVE_SESSION_CONTROL_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
        } catch {
            do {
                try save(.unmountingBridge)
                try await backend.unmountBridge(descriptor, at: bridge)
                try journal.save([])
            } catch {
                FileHandle.standardError.write(
                    Data("Native session fixture needs recovery at \(root.path): \(error)\n".utf8))
            }
            throw error
        }
    }

    /// The refusal arrives as a POSIX error or as umount/hdiutil output naming one.
    static func errnoName(_ error: any Error) -> String {
        if let code = (error as? POSIXError)?.code {
            switch code {
            case .EIO: return "EIO"
            case .EBUSY: return "EBUSY"
            default: return "errno \(code.rawValue)"
            }
        }
        let text = String(describing: error)
        if text.contains("Input/output error") { return "EIO" }
        if text.contains("Resource busy") { return "EBUSY" }
        return "other"
    }

    private static func state(at path: URL) throws -> DiskConnectionState {
        var bytes = [UInt8](repeating: 0, count: 3)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                path.path, ConnectionDescriptor.connectionStateAttributeName,
                $0.baseAddress, $0.count, 0, 0)
        }
        guard count == 2 else { throw ProtocolError.malformed("native control connection state") }
        return try DiskConnectionState(encoded: Data(bytes.prefix(2)))
    }
}
