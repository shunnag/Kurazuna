import Darwin
import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Security

@main
struct FSKitProbe {
    static func requestedImagePresentation() throws -> LUNImagePresentation {
        switch ProcessInfo.processInfo.environment["ISCSI_TEST_IMAGE_PRESENTATION"] {
        case nil, "raw": .raw
        case "udsp": .udsp
        default: throw Failure("Invalid test image presentation")
        }
    }
    private enum FixtureTarget: String {
        case ram, lio, tgt

        var lun: UInt16 { self == .tgt ? 1 : 0 }

        var initiatorPrefix: String {
            self == .ram
                ? "iqn.2026-10.test:fskit-probe-"
                : "iqn.2026-10.dev.soba:\(rawValue)-probe-"
        }

        var targetPrefix: String {
            self == .ram ? "iqn.2026-10.test:fskit-" : "iqn.2026-10.dev.soba:\(rawValue)-"
        }
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static func main() async {
        do { try await run() } catch {
            FileHandle.standardError.write(Data("FSKit validation failed: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func preflight(applicationURL: URL? = nil) async throws {
        let installed = try await FSClient.shared.installedExtensions
        let modules = installed.filter {
            $0.bundleIdentifier == FileSystemExtensionAvailability.bundleIdentifier
        }
        let systemInstall =
            ApplicationIdentity.current == .release
            && ProcessInfo.processInfo.environment["ISCSI_TEST_SYSTEM_INSTALL"] == "1"
        let applications =
            systemInstall
            ? URL(fileURLWithPath: "/Applications", isDirectory: true)
            : FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
                "Applications", isDirectory: true)
        let application =
            applicationURL
            ?? applications.appendingPathComponent(
                ApplicationIdentity.current.applicationName + ".app", isDirectory: true)
        let state = FileSystemExtensionAvailability.evaluate(
            installed.map {
                FileSystemExtensionRegistration(
                    bundleIdentifier: $0.bundleIdentifier, moduleURL: $0.url,
                    isEnabled: $0.isEnabled)
            }, applicationURL: application)
        guard state == .ready else {
            let inventory = installed.map {
                [
                    "bundleIdentifier": $0.bundleIdentifier,
                    "modulePath": $0.url.path,
                    "enabled": $0.isEnabled,
                ] as [String: Any]
            }
            let data = try JSONSerialization.data(
                withJSONObject: inventory, options: [.prettyPrinted, .sortedKeys])
            print("FSKIT_INVENTORY " + String(decoding: data, as: UTF8.self))
            if let expected = FileSystemExtensionAvailability.expectedModuleURL(in: application) {
                print("FSKIT_EXPECTED_MODULE " + expected.path)
            }
            print("FSKIT_AVAILABILITY \(state)")
            if state == .differentCopy {
                throw Failure(
                    "The registered iSCSI extension belongs to another copy of the app. No mount was started."
                )
            }
            throw Failure(
                "One enabled iSCSI extension from \(application.path) is required before this test. No mount was started."
            )
        }
        let identity = try JSONSerialization.data(
            withJSONObject: ["modulePath": modules[0].url.path], options: .sortedKeys)
        print("FSKIT_MODULE " + String(decoding: identity, as: UTF8.self))
        print(
            "PASS: FSKit reports one enabled \(FileSystemExtensionAvailability.bundleIdentifier) extension"
        )
    }

    private static func run() async throws {
        let arguments = CommandLine.arguments
        if arguments == [arguments[0], "--preflight"] {
            try await preflight()
            return
        }
        if arguments.count == 3, arguments[1] == "--preflight-app" {
            // Read-only diagnostics for the running-app location check. Native fixture
            // modes keep the fixed installed-app preflight and cannot override it.
            try await preflight(
                applicationURL: URL(fileURLWithPath: arguments[2], isDirectory: true))
            return
        }
        guard arguments.count == 4 || arguments.count == 5,
            let nonce = UUID(uuidString: arguments.last!)
        else { throw Failure("Invalid fixture arguments") }
        let root = URL(fileURLWithPath: arguments[arguments.count - 2], isDirectory: true)
            .resolvingSymlinksInPath()
        try validateRoot(root, nonce: nonce)
        let mode = arguments[1]
        if ["--app-credentials-check", "--app-credentials-missing"].contains(mode),
            arguments.count == 5
        {
            try await AppCredentialProbe.run(
                mode: mode, snapshot: arguments[2], root: root, nonce: nonce)
            return
        }
        if mode == "--verify-recovery-snapshot", arguments.count == 5 {
            try await RecoveryProbe.verifySnapshot(specName: arguments[2], root: root, nonce: nonce)
            return
        }
        // An existing external target (scripts/test-external-target.py): any portal, not only
        // a disposable loopback one.
        if mode == "--external-credential-remove", arguments.count == 4 {
            try await ExternalTargetProbe.removeCredentialCommand(root: root, nonce: nonce)
            return
        }
        if ["--external-inspect", "--external-session"].contains(mode), arguments.count == 5 {
            if mode == "--external-session" { try await preflight() }
            try await ExternalTargetProbe.run(
                mode: mode, specName: arguments[2], root: root, nonce: nonce)
            return
        }
        if mode == "--eject-nested-apple-bridge", arguments.count == 4 {
            try await NestedAppleBridgeProbe.eject(root: root, nonce: nonce)
            return
        }
        if mode == "--inspect-nested-apple-inner", arguments.count == 4 {
            try await NestedAppleBridgeProbe.inspectInner(root: root)
            return
        }
        if mode == "--detach-nested-apple-outer", arguments.count == 4 {
            try await NestedAppleBridgeProbe.detachOuter(root: root, nonce: nonce)
            return
        }
        if mode == "--inspect-apple-block-volume", arguments.count == 4 {
            try AppleBlockVolumeProbe.inspect(root: root)
            return
        }
        if mode == "--detach-apple-block-image", arguments.count == 5 {
            try await AppleBlockVolumeProbe.detach(root: root, relative: arguments[2])
            return
        }
        if mode == "--block-resource-codec-check", arguments.count == 4 {
            try BlockResourceDescriptor.check(root: root, nonce: nonce)
            return
        }
        if mode == "--block-resource-metadata-check", arguments.count == 4 {
            try await BlockResourceProbe.checkMetadata(root: root, nonce: nonce)
            return
        }
        if mode == "--recover-initial-block-metadata", arguments.count == 4 {
            try await BlockResourceProbe.recoverInitialMetadata(root: root, nonce: nonce)
            return
        }
        if ["--local-bulk-control", "--local-bulk-require-fskit-control"].contains(mode),
            arguments.count == 4
        {
            try BulkAttributesProbe.validate(
                root.appendingPathComponent("Directory", isDirectory: true),
                requireFSKit: mode == "--local-bulk-require-fskit-control")
            return
        }
        if ["--local-directory-control", "--local-directory-require-fskit-control"].contains(mode),
            arguments.count == 4
        {
            try DirectoryEnumerationProbe.validate(
                root.appendingPathComponent("Directory", isDirectory: true),
                requireFSKit: mode == "--local-directory-require-fskit-control")
            print("PASS: ordinary directory enumeration control; no FSKit mount used")
            return
        }
        if mode.hasPrefix("--mutual-credentials-"), arguments.count == 4 {
            try await MutualCredentialProbe.run(mode: mode, nonce: nonce)
            return
        }
        if mode.hasPrefix("--discovery-credentials-"), arguments.count == 4 {
            let action = "--mutual-credentials-" + mode.dropFirst("--discovery-credentials-".count)
            try await MutualCredentialProbe.run(mode: action, nonce: nonce, use: .discovery)
            return
        }
        if try requestedImagePresentation() == .udsp,
            mode != "--opaque-loopback", !mode.hasPrefix("--mount-"),
            !mode.hasPrefix("--soak-"),
            ![
                "--prepare-fixture", "--prepare-geometry-fixture", "--preflight",
                "--expect-geometry-write-refusal-loopback",
                "--outer-sync-mount-loopback",
                "--outer-sync-command-loopback",
                "--direct-file-sync-loopback",
                "--opaque-device-sync-loopback",
                "--local-raw-eof-control",
                "--validate-durable-fixture", "--validate-soak-durable-fixture",
                "--recover-fixture", "--force-recover-fixture",
                "--validate-disposable-loopback", "--validate-lio-loopback",
                "--validate-tgt-loopback",
            ].contains(mode)
        {
            throw Failure("This fixture mode has not been adapted for the UDSP view")
        }
        if mode == "--local-raw-eof-control", arguments.count == 4 {
            try RawEOFProbe.validate(
                root.appendingPathComponent("Control.raw"), expected: RawEOFProbe.controlData())
            print("PASS: ordinary-file EOF control; no FSKit mount used")
        } else if mode == "--apple-passthrough-sync-control", arguments.count == 4 {
            try await preflight()
            try await PassthroughControlProbe.run(root: root, contents: writtenData(nonce))
        } else if mode == "--recover-passthrough-fixture", arguments.count == 4 {
            try await PassthroughControlProbe.recover(root: root)
        } else if mode == "--native-geometry-existing-control", arguments.count == 4 {
            try await GeometryFixture.writeLocalSynchronizedSnapshot(
                root: root, contents: writtenData(nonce))
            try await validateDurableFixture(root: root, nonce: nonce)
            print("PASS: supplied local 4Kn HFS+ pre-close snapshot recovered")
        } else if mode == "--native-geometry-sync-control", arguments.count == 4 {
            try await GeometryFixture.prepare(root: root, nonce: nonce, marker: marker(nonce))
            try await GeometryFixture.writeLocalSynchronizedSnapshot(
                root: root, contents: writtenData(nonce))
            try await validateDurableFixture(root: root, nonce: nonce)
            print("PASS: local 4Kn HFS+ pre-close visible snapshot recovered; no FSKit mount used")
        } else if mode == "--prepare-geometry-fixture", arguments.count == 4 {
            try await GeometryFixture.prepare(root: root, nonce: nonce, marker: marker(nonce))
        } else if mode == "--prepare-fixture", arguments.count == 4 {
            try await prepare(root: root, nonce: nonce)
        } else if mode == "--validate-durable-fixture", arguments.count == 4 {
            try await validateDurableFixture(root: root, nonce: nonce)
        } else if mode == "--validate-hfs-journal-recovery", arguments.count == 4 {
            try await validateDurableFixture(root: root, nonce: nonce, hfsJournalRecovery: true)
        } else if mode == "--validate-cancelled-mount", arguments.count == 4 {
            try await validateCancelledMount(root: root, nonce: nonce)
        } else if mode == "--validate-soak-durable-fixture", arguments.count == 4 {
            try await validateDurableFixture(root: root, nonce: nonce, soak: true)
        } else if mode == "--assert-fixture-locked", arguments.count == 4 {
            do {
                _ = try coordinator(root: root)
                throw Failure("Another process acquired the live connection journal")
            } catch let error as POSIXError where error.code == .EWOULDBLOCK {
                print("PASS: live connection journal excludes another process")
            }
        } else if mode.hasPrefix("--restore-stage-fixture-"), arguments.count == 4,
            let stage = AttachmentPhase(
                rawValue: String(mode.dropFirst("--restore-stage-fixture-".count)))
        {
            let coordinator = try coordinator(root: root)
            try await coordinator.restore()
            let disks = await coordinator.disks
            if stage == .unmountingBridge {
                guard disks.isEmpty else {
                    throw Failure("Removed bridge record was not reconciled")
                }
            } else {
                guard disks.count == 1, let disk = disks.first,
                    disk.descriptor.profileID == nonce, !disk.verificationFailed,
                    disk.connectionState == .connected
                else { throw Failure("The existing FSKit fixture was not restored") }
                let hasImage = stage == .connected || stage == .attachingImage
                guard (disk.attachment != nil) == hasImage,
                    disk.phase == (hasImage ? .connected : .unmountingBridge)
                else { throw Failure("Restored fixture phase differs") }
                if hasImage {
                    guard disk.attachment?.volumeURLs.count == 1,
                        let volume = disk.attachment?.volumeURLs.first,
                        try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                            == marker(nonce)
                    else { throw Failure("The restored fixture marker differs") }
                }
                try verifyIdentity(disk)
                try await coordinator.eject(disk.id)
            }
            guard await coordinator.disks.isEmpty else {
                throw Failure("Restored fixture remains connected")
            }
            print(
                "PASS: crashed owner at \(stage.rawValue) replaced, current resources verified and normally ejected"
            )
        } else if mode == "--restore-held-bridge-fixture", arguments.count == 4 {
            try await BridgeHolderProbe.restore(root: root, nonce: nonce)
        } else if mode == "--recover-fixture", arguments.count == 4 {
            let coordinator = try coordinator(root: root)
            try await coordinator.restore()
            for disk in await coordinator.disks { try await coordinator.eject(disk.id) }
            guard await coordinator.disks.isEmpty else {
                throw Failure("Fixture recovery is incomplete")
            }
            let images = DiskImages()
            for path in try await images.inventory().imagePaths
            where path.hasPrefix(root.path + "/") {
                let image = URL(fileURLWithPath: path)
                if let current = try await images.inventory().attachment(at: image) {
                    try await images.detach(current, at: image)
                }
            }
            try await removeFixtureCredential(root: root, nonce: nonce)
            print("PASS: fixture connection records recovered and ejected")
        } else if mode == "--force-recover-fixture", arguments.count == 4 {
            let coordinator = try await releaseRecordedDisks(root: root)
            guard await coordinator.disks.isEmpty else {
                throw Failure("Forced fixture recovery is incomplete")
            }
            let images = DiskImages()
            for path in try await images.inventory().imagePaths
            where path.hasPrefix(root.path + "/") {
                let image = URL(fileURLWithPath: path)
                if let current = try await images.inventory().attachment(at: image) {
                    try await images.detach(current, at: image)
                }
            }
            try await removeFixtureCredential(root: root, nonce: nonce)
            print("PASS: fixture connection records recovered and force ejected")
        } else if arguments.count == 5 {
            let portal = try Portal(arguments[2])
            guard portal.host == "127.0.0.1" else {
                throw Failure("A disposable loopback target is required")
            }
            if mode.hasPrefix("--leave-stage-loopback-"),
                let stage = AttachmentPhase(
                    rawValue: String(mode.dropFirst("--leave-stage-loopback-".count)))
            {
                try await preflight()
                let configuration = try configuration(nonce)
                let coordinator = try coordinator(root: root, stage: stage)
                try await coordinator.restore()
                let descriptor = try ConnectionDescriptor(
                    profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
                    targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: true,
                    isid: configuration.isid)
                let disk = try await coordinator.connect(descriptor)
                do {
                    if stage == .connected { try stageCheckpoint(stage) }
                    try await coordinator.eject(disk.id)
                    throw Failure("Fixture did not reach its crash checkpoint")
                } catch {
                    try? await coordinator.eject(disk.id)
                    throw error
                }
            }
            switch mode {
            case "--opaque-device-sync-loopback":
                try await preflight()
                try await DeviceLayerSyncProbe.run(portal: portal, root: root, nonce: nonce)
            case "--direct-file-sync-loopback":
                try await preflight()
                try await DirectFileSyncProbe.run(portal: portal, root: root, nonce: nonce)
            case "--outer-sync-mount-loopback", "--outer-sync-command-loopback":
                try await preflight()
                try await OuterSynchronousProbe.run(
                    portal: portal, root: root, nonce: nonce,
                    commandUpdate: mode == "--outer-sync-command-loopback")
            case "--nested-apple-bridge-loopback", "--nested-apple-bridge-readonly-loopback":
                try await preflight()
                try await NestedAppleBridgeProbe.mount(
                    portal: portal, root: root, nonce: nonce,
                    readOnly: mode == "--nested-apple-bridge-readonly-loopback")
            case "--expect-geometry-write-refusal-loopback",
                "--expect-geometry-write-refusal-lio-loopback",
                "--expect-geometry-write-refusal-tgt-loopback":
                try await preflight()
                // The disposable LIO and TGT VMs (scripts/test-lio.py --native-4kn) use their
                // own names, and TGT serves its disk at LUN 1.
                let target: FixtureTarget =
                    mode.contains("-lio-") ? .lio : (mode.contains("-tgt-") ? .tgt : .ram)
                let owner = try coordinator(root: root)
                try await owner.restore()
                let config = try configuration(nonce, target: target)
                let descriptor = try ConnectionDescriptor(
                    profileID: nonce, portal: portal, initiatorName: config.initiatorName,
                    targetName: config.targetName!, lun: LogicalUnit(target.lun), readOnly: false,
                    isid: config.isid, imagePresentation: requestedImagePresentation())
                do {
                    let connected = try await owner.connect(descriptor)
                    try await owner.eject(connected.id)
                    throw Failure("Unsupported writable geometry was accepted")
                } catch AttachmentError.readOnlyGeometryRequired {
                    guard await owner.disks.isEmpty,
                        !(try await DiskImages().inventory()).imagePaths.contains(where: {
                            $0.hasPrefix(root.appendingPathComponent("Mounts").path + "/")
                        })
                    else {
                        throw Failure("Refused writable geometry left a connection record")
                    }
                    print(
                        "PASS: larger-sector write connection refused before device creation; bridge normally ejected"
                    )
                }
            case "--opaque-loopback":
                try await preflight()
                try await OpaqueImageProbe.run(portal: portal, root: root, nonce: nonce)
            case "--opaque-readonly-4kn-loopback":
                try await preflight()
                try await OpaqueImageProbe.run(
                    portal: portal, root: root, nonce: nonce, readOnlyOnly: true,
                    expectedBlockSize: 4096)
            case "--raw-write-fault-loopback-write-eof", "--raw-write-fault-loopback-flush-eof",
                "--raw-write-fault-loopback-write-silent":
                try await preflight()
                try await validateUncertainWrite(
                    portal, root: root, nonce: nonce, silent: mode.hasSuffix("-silent"))
            case "--raw-deferred-sense-loopback":
                try await preflight()
                try await validateUncertainWrite(
                    portal, root: root, nonce: nonce, silent: false, deferredSense: true)
            case "--mounted-route-loopback":
                try await preflight()
                try await NativeMountedRouteProbe.run(portal: portal, root: root, nonce: nonce)
            case "--recovery-lio-loopback", "--recovery-lio-loopback-chap",
                "--recovery-lio-loopback-mutual-chap", "--recovery-lio-loopback-readonly",
                "--recovery-lio-loopback-chap-readonly":
                try await preflight()
                try await RecoveryProbe.run(
                    portal: portal, root: root, nonce: nonce, chap: mode.contains("-chap"),
                    mutualCHAP: mode.hasSuffix("-mutual-chap"),
                    readOnly: mode.hasSuffix("-readonly"))
            case "--native-session-control-loopback":
                try await preflight()
                try await NativeSessionControlProbe.run(portal: portal, root: root, nonce: nonce)
            case "--native-filesystem-control-loopback":
                try await preflight()
                try await NativeFilesystemControlProbe.run(portal: portal, root: root, nonce: nonce)
            case "--native-filesystem-write-control-loopback":
                try await preflight()
                try await NativeFilesystemWriteControlProbe.run(
                    portal: portal, root: root, nonce: nonce)
            case "--disconnect-loopback-eof", "--disconnect-loopback-silent":
                try await preflight()
                try await validateDisconnection(
                    portal, root: root, nonce: nonce, silent: mode.hasSuffix("-silent"))
            case "--bridge-holder-loopback-short", "--bridge-holder-loopback-long",
                "--bridge-holder-loopback-relaunch":
                try await preflight()
                guard
                    let hold = BridgeHolderProbe.Hold(
                        rawValue: String(mode.dropFirst("--bridge-holder-loopback-".count)))
                else { throw Failure("Unknown fixture mode") }
                try await BridgeHolderProbe.run(
                    portal: portal, root: root, nonce: nonce, hold: hold)
            case "--validate-disposable-loopback":
                try await validateTarget(portal, root: root, nonce: nonce)
            case "--validate-lio-loopback":
                try await validateTarget(portal, root: root, nonce: nonce, target: .lio)
            case "--validate-tgt-loopback":
                try await validateTarget(portal, root: root, nonce: nonce, target: .tgt)
            case "--large-filesystem-lio-loopback":
                try await preflight()
                try await LargeFilesystemProbe.run(portal: portal, root: root, nonce: nonce)
            case "--inspect-large-filesystem-lio-loopback":
                try await preflight()
                try await LargeFilesystemProbe.run(
                    portal: portal, root: root, nonce: nonce, inspectOnly: true)
            case "--large-lio-loopback", "--large-lio-loopback-rw",
                "--large-lio-loopback-chap", "--large-lio-loopback-rw-chap":
                try await preflight()
                try await LargeLUNProbe.run(
                    portal: portal, root: root, nonce: nonce,
                    readOnly: !mode.contains("-rw"), chap: mode.hasSuffix("-chap"))
            case "--soak-lio-loopback-chap", "--soak-tgt-loopback-chap":
                try await preflight()
                guard
                    let seconds = Int(
                        ProcessInfo.processInfo.environment["ISCSI_SOAK_SECONDS"] ?? "600"),
                    (60...3600).contains(seconds)
                else { throw Failure("Invalid soak duration") }
                try await mount(
                    portal, root: root, nonce: nonce, readOnly: false, chap: true,
                    target: mode.contains("-tgt-") ? .tgt : .lio,
                    soakSeconds: seconds)
            case "--mount-disposable-loopback", "--mount-disposable-loopback-rw",
                "--mount-disposable-loopback-chap", "--mount-disposable-loopback-rw-chap",
                "--mount-disposable-loopback-mutual-chap",
                "--mount-disposable-loopback-rw-mutual-chap",
                "--mount-lio-loopback", "--mount-lio-loopback-rw",
                "--mount-lio-loopback-chap", "--mount-lio-loopback-rw-chap",
                "--mount-lio-loopback-mutual-chap", "--mount-lio-loopback-rw-mutual-chap",
                "--mount-tgt-loopback", "--mount-tgt-loopback-rw",
                "--mount-tgt-loopback-chap", "--mount-tgt-loopback-rw-chap":
                try await preflight()
                try await mount(
                    portal, root: root, nonce: nonce, readOnly: !mode.contains("-rw"),
                    chap: mode.hasSuffix("-chap"),
                    mutualCHAP: mode.hasSuffix("-mutual-chap"),
                    target: mode.contains("-tgt-") ? .tgt : (mode.contains("-lio-") ? .lio : .ram))
            default: throw Failure("Unknown fixture mode")
            }
        } else {
            throw Failure("Unknown fixture mode")
        }
    }

    private static func validateRoot(_ root: URL, nonce: UUID) throws {
        guard root.path.hasPrefix("/"),
            root.lastPathComponent.hasPrefix("iSCSI-FSKit-" + nonce.uuidString.lowercased() + "-"),
            root.resolvingSymlinksInPath().path == root.path
        else { throw Failure("Invalid private fixture directory") }
        let attributes = try FileManager.default.attributesOfItem(atPath: root.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory,
            (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700
        else { throw Failure("Fixture directory must be private and owned by this user") }
    }

    static func marker(_ nonce: UUID) -> Data {
        Data("FSKit validation \(nonce.uuidString.lowercased())\n".utf8)
    }

    private static func imageDataLocation(_ disk: AttachedDisk, at offset: UInt64 = 0)
        throws -> (url: URL, offset: UInt64)
    {
        let physical =
            try disk.descriptor.imagePresentation == .udsp
            ? SparseImageLayout(capacity: 128 * 1_048_576).physicalOffset(forLUNOffset: offset)
            : offset
        return (disk.bridgeURL.appendingPathComponent("Disk.img"), physical)
    }

    private static func verifyBridgeMountMode(_ disk: AttachedDisk) throws {
        var status = statfs()
        guard statfs(disk.bridgeURL.path, &status) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let readOnly = status.f_flags & UInt32(MNT_RDONLY) != 0
        guard readOnly == disk.descriptor.readOnly else {
            throw Failure("FSKit mount access mode differs from the connection descriptor")
        }
        print("FSKIT_MOUNT_MODE readOnly=\(readOnly) flags=\(status.f_flags)")
    }

    private static func verifyIdentity(_ disk: AttachedDisk) throws {
        let expected = try disk.descriptor.resourceIdentity
        for path in [
            disk.bridgeURL,
            disk.bridgeURL.appendingPathComponent("Disk.img"),
        ] {
            var actual = Data(count: 32)
            let count = actual.withUnsafeMutableBytes {
                getxattr(
                    path.path, ConnectionDescriptor.identityAttributeName, $0.baseAddress, $0.count,
                    0, 0)
            }
            guard count == 32, actual == expected else {
                throw Failure("VFS fixture identity differs")
            }
            var replacement = [UInt8](repeating: 0x5A, count: 32)
            let result = replacement.withUnsafeMutableBytes {
                setxattr(
                    path.path, ConnectionDescriptor.identityAttributeName, $0.baseAddress, $0.count,
                    0, 0)
            }
            guard result == -1 else { throw Failure("Fixture identity accepted a write") }
            let removed = removexattr(path.path, ConnectionDescriptor.identityAttributeName, 0)
            guard removed == -1 else { throw Failure("Fixture identity accepted removal") }
            let after = actual.withUnsafeMutableBytes {
                getxattr(
                    path.path, ConnectionDescriptor.identityAttributeName, $0.baseAddress, $0.count,
                    0, 0)
            }
            guard after == 32, actual == expected else { throw Failure("Fixture identity changed") }
        }
    }

    private static func writtenData(_ nonce: UUID) -> Data {
        var data = Data(repeating: 0xA7, count: 65_573)
        data.replaceSubrange(0..<marker(nonce).count, with: marker(nonce))
        return data
    }

    private static func validateCancelledMount(root: URL, nonce: UUID) async throws {
        let image = root.appendingPathComponent("AfterCancelledMount.img")
        let before = try FixtureFileSystem.digest(of: image)
        let format = try FixtureFileSystem.at(root)
        let images = DiskImages()
        let attachment = try await images.attachRawImage(at: image, readOnly: true)
        do {
            guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first,
                try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                    == marker(nonce),
                !FileManager.default.fileExists(
                    atPath: volume.appendingPathComponent("FSKit-written.txt").path)
            else { throw Failure("Cancelled mount changed fixture contents") }
            try format.verifyVolume(volume, readOnly: true)
            try await BridgeHolders.detachWhenFree(images, attachment, at: image, volume: volume)
        } catch {
            try? await images.detach(attachment, at: image)
            throw error
        }
        guard try FixtureFileSystem.digest(of: image) == before else {
            throw Failure("Cancelled mount validation changed its snapshot")
        }
        print(
            "PASS: cancelled mount snapshot preserves marker, no new file, readOnly=true, originalSnapshotUnchanged=true"
        )
    }

    private static func validateDurableFixture(
        root: URL, nonce: UUID, soak: Bool = false, hfsJournalRecovery: Bool = false
    ) async throws {
        let format = try FixtureFileSystem.at(root)
        guard
            !hfsJournalRecovery
                || (format == .hfsPlus && !FixtureFileSystem.usesPlainHFSGeometryControl
                    && ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == nil)
        else { throw Failure("Journal recovery requires the ordinary HFS+ test snapshot") }
        let images = DiskImages()
        let stable = root.appendingPathComponent("Stable.img")
        let before = try FixtureFileSystem.digest(of: stable)
        let replay = format == .hfsPlus
        let image = replay ? root.appendingPathComponent("Recovered.img") : stable
        if replay {
            // HFS+ recovery opens only an independent private copy writable.
            // The captured snapshot must never be changed or repaired in place.
            try FileManager.default.copyItem(at: stable, to: image)
        }
        let attachment: DiskAttachment
        if hfsJournalRecovery {
            attachment = try await HFSRecoveryFixture.attach(image)
        } else if ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "legacy-4k" {
            attachment = try await GeometryFixture.attachLocal(image, readOnly: !replay)
        } else {
            attachment = try await images.attachRawImage(at: image, readOnly: !replay)
        }
        do {
            guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first else {
                throw Failure(
                    "F_FULLFSYNC left incomplete contents in the target's stable snapshot")
            }
            let expected = writtenData(nonce)
            let actual = try Data(contentsOf: volume.appendingPathComponent("FSKit-written.txt"))
            try SynchronizationBoundaryProbe.recordRecoveryIfRequested(
                root: root, actual: actual, expected: expected)
            guard actual == expected,
                try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                    == marker(nonce)
            else {
                throw Failure(
                    "F_FULLFSYNC left incomplete contents in the target's stable snapshot")
            }
            try format.verifyVolume(volume, readOnly: !replay)
            if soak {
                try SoakWorkload.verify(
                    at: volume, report: SoakWorkload.load(root: root, nonce: nonce))
            }
            try await BridgeHolders.detachWhenFree(images, attachment, at: image, volume: volume)
        } catch {
            try? await images.detach(attachment, at: image)
            throw error
        }
        guard try FixtureFileSystem.digest(of: stable) == before else {
            throw Failure("Durability validation changed the original stable snapshot")
        }
        print(
            "PASS: \(format.displayName) file and marker recovered from the supplied target snapshot, journalReplay=\(replay && !FixtureFileSystem.usesPlainHFSGeometryControl), standardPreen=\(hfsJournalRecovery), writableRecoveryCopy=\(replay), originalSnapshotUnchanged=true"
        )
    }

    private static func prepare(root: URL, nonce: UUID) async throws {
        let format = try FixtureFileSystem.at(root)
        let image = root.appendingPathComponent(format.imageName)
        try await format.create(at: root, volumeName: "ISC" + nonce.uuidString.prefix(8))
        let trace = AttachmentCommandTrace(root: root)
        let images = trace.images()
        do {
            let attachment = try await images.attachRawImage(at: image, readOnly: false)
            guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first else {
                throw Failure("Fixture volume is missing")
            }
            try format.verifyVolume(volume, readOnly: false)
            let fileURL = volume.appendingPathComponent("FSKit-validation.txt")
            try marker(nonce).write(to: fileURL)
            try SynchronizationBoundaryProbe.prepareIfRequested(at: volume)
            let deviceAccess = try await HFSDeviceSyncProbe.prepareIfRequested(
                root: root, volume: volume, image: image, attachment: attachment)
            deviceAccess?.close()
            if ProcessInfo.processInfo.environment["ISCSI_TEST_FILESYSTEM_CONTROL"] == "1" {
                try NativeFilesystemControlProbe.prepare(at: volume)
            }
            let file = try FileHandle(forWritingTo: fileURL)
            do {
                try file.synchronize()
                try file.close()
            } catch {
                try? file.close()
                throw error
            }
            try FixtureFileSystem.recordSpace(of: volume, at: root)
            try await BridgeHolders.detachWhenFree(images, attachment, at: image, volume: volume)
            try trace.save(name: "PreparationCommands.json")
        } catch {
            try? trace.save(name: "PreparationCommandsBeforeRecovery.json")
            // The attach may have succeeded before a later verification threw.
            // Keep the bytes and normally recover only this nonce-owned image.
            let snapshot = root.appendingPathComponent("PreparationFailure.img")
            if clonefile(image.path, snapshot.path, 0) != 0 {
                FileHandle.standardError.write(
                    Data("Fixture failure byte clone could not be created\n".utf8))
            }
            do {
                if let current = try await images.inventory().attachment(at: image) {
                    try await images.detach(current, at: image)
                }
                try trace.save(name: "PreparationCommandsAfterRecovery.json")
            } catch {
                FileHandle.standardError.write(
                    Data("Fixture normal recovery needs attention: \(error)\n".utf8))
                try? trace.save(name: "PreparationCommandsAfterRecovery.json")
            }
            throw error
        }
        print("PASS: private \(format.displayName) raw fixture prepared with persistent marker")
    }

    /// The disposable RAM target's names, for probes in other files.
    static func ramConfiguration(_ nonce: UUID) throws -> LoginConfiguration {
        try configuration(nonce)
    }

    private static func configuration(_ nonce: UUID, target: FixtureTarget = .ram) throws
        -> LoginConfiguration
    {
        try LoginConfiguration(
            initiatorName: target.initiatorPrefix + nonce.uuidString.lowercased(),
            targetName: target.targetPrefix + nonce.uuidString.lowercased())
    }

    private static func validateTarget(
        _ portal: Portal, root: URL, nonce: UUID, target: FixtureTarget = .ram
    ) async throws {
        let transport = try TCPTransport(portal: portal)
        let session = try ISCSISession(
            transport: transport, configuration: configuration(nonce, target: target))
        do {
            try await transport.connect()
            try await session.login()
            let units = try await DiskProbe.logicalUnits(session: session)
            let expected = try (target == .tgt ? [UInt16(0), 1] : [UInt16(0)]).map {
                try LogicalUnit($0)
            }
            guard units == expected else { throw Failure("Fixture LUN list differs") }
            let information = try await DiskProbe.diskInformation(
                session: session, lun: LogicalUnit(target.lun))
            guard information.capacity.byteCount == 128 * 1_048_576 else {
                throw Failure("Fixture target capacity differs")
            }
            let disk = RemoteDisk(
                session: session, lun: try LogicalUnit(target.lun), capacity: information.capacity,
                readOnly: true)
            let file = try FileHandle(
                forReadingFrom: root.appendingPathComponent(FixtureFileSystem.at(root).imageName))
            do {
                for offset in [UInt64(0), information.capacity.byteCount - 4096] {
                    try file.seek(toOffset: offset)
                    let expected = try file.read(upToCount: 4096)
                    let actual = try await disk.read(offset: Int64(offset), length: 4096)
                    guard actual == expected else { throw Failure("Fixture target bytes differ") }
                }
                try file.close()
            } catch {
                try? file.close()
                throw error
            }
            try await session.logout()
        } catch {
            await session.close()
            throw error
        }
        print("PASS: disposable TCP target LUN list, capacity, first and last bytes, logout")
    }

    private static func coordinator(root: URL, stage: AttachmentPhase? = nil) throws
        -> AttachmentCoordinator
    {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        return try AttachmentCoordinator(
            backend: StageBackend(base: BlockResourceProbe.backend(root: root), stage: stage),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
    }

    private static func stageCheckpoint(_ stage: AttachmentPhase) throws {
        FileHandle.standardOutput.write(Data("FSKIT_STAGE \(stage.rawValue)\n".utf8))
        _ = readLine()  // The harness kills only this private owner process.
        throw Failure("Crash fixture owner must be terminated by the harness")
    }

    struct StageBackend: AttachmentBackend {
        let base: SystemAttachmentBackend
        let stage: AttachmentPhase?
        /// Before unmounting, wait (bounded) until no other process holds the bridge, and retry
        /// an inner image detach that reports EBUSY (bounded), so that another app's brief hold
        /// doesn't fail a fixture's teardown (ENV082). The held-bridge regression turns this off
        /// to exercise the product's own wait.
        var waitsForHolders = true
        var beforeUnmount: (@Sendable (URL) async -> Void)? = nil
        func bridgeURL(for id: UUID) async throws -> URL { try await base.bridgeURL(for: id) }
        func untrackedBridges(excluding urls: [URL]) async throws -> [URL] {
            try await base.untrackedBridges(excluding: urls)
        }
        func mountBridge(_ descriptor: ConnectionDescriptor, at url: URL) async throws {
            try await base.mountBridge(descriptor, at: url)
            if stage == .mountingBridge {
                let raw = try FileHandle(forReadingFrom: url.appendingPathComponent("Disk.img"))
                defer { try? raw.close() }
                guard try raw.read(upToCount: 4096)?.count == 4096 else {
                    throw Failure("Fixture raw read failed")
                }
                try stageCheckpoint(.mountingBridge)
            }
        }
        func inspectBridge(_ descriptor: ConnectionDescriptor, at url: URL) async throws
            -> AttachmentInspection
        {
            try await base.inspectBridge(descriptor, at: url)
        }
        func inspectBridges(_ entries: [AttachmentJournalEntry]) async throws -> [UUID: Result<
            AttachmentInspection, any Error
        >] {
            try await base.inspectBridges(entries)
        }
        func attachImage(_ descriptor: ConnectionDescriptor, at url: URL) async throws
            -> DiskAttachment
        {
            let block = try FSKitProbe.sourceBlockSize(at: url)
            guard
                try FSKitProbe.sourceBlockSize(at: url.appendingPathComponent("Disk.img")) == block
            else {
                throw Failure("Source geometry differs between bridge and image")
            }
            print("FSKIT_SOURCE_BLOCK_SIZE \(block)")
            let image: DiskAttachment
            if let experimental = try await LegacyAttachmentProbe.attachIfRequested(
                descriptor, at: url, backend: base)
            {
                image = experimental
            } else {
                do {
                    image = try await base.attachImage(descriptor, at: url)
                } catch {
                    if descriptor.imagePresentation == .udsp {
                        let file = url.appendingPathComponent("Disk.img")
                        if let current = try? await DiskImages().inventory().attachment(at: file) {
                            let data = try? await SystemCommand.run(
                                "/usr/sbin/diskutil", arguments: ["info", "-plist", current.device])
                            if let data,
                                let info = try? PropertyListSerialization.propertyList(
                                    from: data, format: nil) as? [String: Any]
                            {
                                print(
                                    "FSKIT_FAILED_DEVICE size=\(String(describing: info["TotalSize"])) writable=\(String(describing: info["WritableMedia"]))"
                                )
                            }
                        }
                    }
                    throw error
                }
            }
            if stage == .attachingImage { try stageCheckpoint(.attachingImage) }
            return image
        }
        func detachImage(_ image: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
            async throws
        {
            if waitsForHolders {
                // A freshly mounted inner volume can be busy for about 2 s (ENV082).
                try await BridgeHolders.retryingBusy(
                    "inner image detach", bridge: bridgeURL, volume: image.volumeURLs.first
                ) {
                    try await base.detachImage(image, descriptor: descriptor, bridgeURL: bridgeURL)
                }
            } else {
                try await base.detachImage(image, descriptor: descriptor, bridgeURL: bridgeURL)
            }
            if stage == .detachingImage { try stageCheckpoint(.detachingImage) }
        }
        func unmountBridge(_ descriptor: ConnectionDescriptor, at url: URL) async throws {
            if waitsForHolders { await BridgeHolders.waitUntilFree(url) }
            await beforeUnmount?(url)
            try await base.unmountBridge(descriptor, at: url)
            try await BlockResourceProbe.cleanup(bridge: url)
            if stage == .unmountingBridge { try stageCheckpoint(.unmountingBridge) }
        }
        func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at url: URL) async throws {
            try await base.discardEmptyBridge(descriptor, at: url)
            try await BlockResourceProbe.cleanup(bridge: url)
        }
    }

    /// A disposable mutual CHAP pair a harness supplied (RecoveryProbe.suppliedSecrets). It is
    /// never printed: every description of it is redacted.
    struct SuppliedSecrets: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
        CustomReflectable
    {
        let password: String
        let targetPassword: String
        var description: String { "SuppliedSecrets(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: [:]) }
    }

    /// `secrets`: a disposable mutual CHAP pair to save instead of the public fixture pair.
    /// The file written here holds the context only.
    static func saveFixtureCredential(
        portal: Portal, root: URL, nonce: UUID, mutualCHAP: Bool = false,
        secrets: SuppliedSecrets? = nil
    ) async throws {
        guard secrets == nil || mutualCHAP else {
            throw Failure("Supplied secrets need mutual CHAP")
        }
        let context = CredentialContext(
            profileID: nonce, portal: portal, username: "test-user", credentialID: nonce,
            targetUsername: mutualCHAP ? "test-server" : nil)
        let file = root.appendingPathComponent("Credential.json")
        try JSONEncoder().encode(context).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let store = KeychainCredentialStore.sharedForCurrentBundle()
        if mutualCHAP {
            try await store.save(
                password: secrets?.password ?? "correct horse battery staple",
                targetPassword: secrets?.targetPassword ?? "independent server password",
                context: context)
        } else {
            try await store.save(password: "correct horse battery staple", context: context)
        }
    }

    static func removeFixtureCredential(root: URL, nonce: UUID) async throws {
        let file = root.appendingPathComponent("Credential.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return }
        let context = try JSONDecoder().decode(CredentialContext.self, from: Data(contentsOf: file))
        guard context.profileID == nonce, context.credentialID == nonce,
            context.portal.host == "127.0.0.1", context.username == "test-user",
            context.use == .connection,
            context.targetUsername == nil || context.targetUsername == "test-server"
        else { throw Failure("Invalid fixture credential context") }
        let store = KeychainCredentialStore.sharedForCurrentBundle()
        try await store.remove(context: context)
        do {
            _ = try await store.credentials(context: context)
            throw Failure("Fixture credential remains in the keychain")
        } catch let error as NSError
            where error.domain == NSOSStatusErrorDomain && error.code == Int(errSecItemNotFound)
        {}
        try FileManager.default.removeItem(at: file)
        print("PASS: private fixture credential removed from the shared keychain")
    }

    private static func validateUncertainWrite(
        _ portal: Portal, root: URL, nonce: UUID, silent: Bool, deferredSense: Bool = false
    ) async throws {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let backend = SystemAttachmentBackend(root: mounts)
        let configuration = try configuration(nonce)
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
            targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: false,
            isid: configuration.isid
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
            var mountStatus = statfs()
            guard statfs(bridge.path, &mountStatus) == 0,
                mountStatus.f_flags & UInt32(MNT_SYNCHRONOUS) != 0
            else { throw Failure("The raw FSKit bridge is not mounted synchronously") }
            let raw = try FileHandle(forUpdating: bridge.appendingPathComponent("Disk.img"))
            defer { try? raw.close() }
            guard fcntl(raw.fileDescriptor, F_NOCACHE, 1) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let offset: off_t = 64 * 1_048_576
            var buffer = Data(count: 4096)
            guard
                buffer.withUnsafeMutableBytes({
                    pread(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
                }) == 4096
            else {
                throw Failure("Live raw fault fixture cannot be read")
            }
            var payload = Data(repeating: 0xD3, count: 4096)
            let identity = Data(nonce.uuidString.lowercased().utf8)
            payload.replaceSubrange(0..<identity.count, with: identity)
            try checkpoint("before-uncertain-write")
            let clock = ContinuousClock()
            let began = clock.now
            let result = payload.withUnsafeBytes {
                pwrite(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
            }
            let code = errno
            print(
                "CHECK: raw pwrite returned \(result), errno \(code), elapsed \(began.duration(to: clock.now))"
            )
            try checkpoint("after-write-return")
            let synchronized = fcntl(raw.fileDescriptor, F_FULLFSYNC)
            let syncCode = errno
            print(
                "CHECK: raw F_FULLFSYNC returned \(synchronized), errno \(syncCode), elapsed \(began.duration(to: clock.now))"
            )
            if !deferredSense && !silent {
                // The connection closed before the write's or flush's status arrived. A lost
                // connection is recovered: the same ISID logs in again, the logical unit is
                // revalidated, and the whole write callback (chunks and flush) is redone
                // within one session epoch. The application sees success.
                guard result == payload.count, synchronized == 0,
                    began.duration(to: clock.now) < .seconds(60)
                else {
                    throw Failure("A write interrupted by a closed connection was not redone")
                }
                guard try state(at: bridge) == .connected else {
                    throw Failure("The recovered VFS session does not report connected")
                }
                print(
                    "PASS: interrupted VFS write/sync redone on a new session after \(began.duration(to: clock.now))"
                )
                try checkpoint("after-redone-write")
                var check = Data(count: 4096)
                guard
                    check.withUnsafeMutableBytes({
                        pread(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
                    }) == 4096, check == payload,
                    buffer.withUnsafeMutableBytes({
                        pread(raw.fileDescriptor, $0.baseAddress, $0.count, 96 * 1_048_576)
                    }) == 4096
                else { throw Failure("I/O after the recovered write failed") }
                try checkpoint("after-recovered-io")
                try? raw.close()
                try save(.unmountingBridge)
                await BridgeHolders.waitUntilFree(bridge)
                try await backend.unmountBridge(descriptor, at: bridge)
                try journal.save([])
                print(
                    "PASS: lost write status recovered by reconnecting and redoing the write; later I/O succeeds, normal FSKit unmount"
                )
                return
            }
            // A silent target answers neither the write nor any new login: the command times
            // out (30 s), recovery waits its window (120 s of awake time), then the write
            // fails with EIO and the disk latches.
            let writeFailed =
                (result == -1 && (code == EIO || code == ETIMEDOUT))
                || (silent && synchronized == -1 && (syncCode == EIO || syncCode == ETIMEDOUT))
            guard writeFailed, !deferredSense || code == EIO,
                began.duration(to: clock.now) < .seconds(silent ? 240 : 10)
            else {
                throw Failure(
                    "Uncertain synchronous raw write did not report an I/O error within its deadline"
                )
            }
            guard try state(at: bridge) == .interrupted else {
                throw Failure("Uncertain write did not interrupt the VFS session")
            }
            print(
                "PASS: uncertain VFS write/sync reported an I/O error after \(began.duration(to: clock.now))"
            )
            try checkpoint("after-uncertain-write")
            let retry = payload.withUnsafeBytes {
                pwrite(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
            }
            let retryCode = errno
            guard retry == -1, retryCode == EIO || retryCode == ETIMEDOUT else {
                throw Failure("Failed VFS session accepted a later write")
            }
            if deferredSense, retryCode != EIO {
                throw Failure("Deferred VFS failure was not retained as EIO")
            }
            let cached = buffer.withUnsafeMutableBytes {
                pread(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
            }
            let cachedCode = errno
            print(
                "CHECK: previously accessed raw region returned \(cached) bytes, errno \(cachedCode); cached data is not a health or durability check"
            )
            let read = buffer.withUnsafeMutableBytes {
                pread(raw.fileDescriptor, $0.baseAddress, $0.count, 96 * 1_048_576)
            }
            let readCode = errno
            guard read == -1, readCode == EIO || readCode == ETIMEDOUT else {
                throw Failure("Failed VFS session accepted a fresh uncached read")
            }
            if deferredSense, readCode != EIO {
                throw Failure("Deferred VFS read failure was not retained as EIO")
            }
            try checkpoint("after-failed-write-retry")
            try? raw.close()
            try save(.unmountingBridge)
            if silent || deferredSense {
                // The expired recovery window, or the deferred error, stopped the disk; its final
                // synchronization fails, so the normal unmount is refused and the forced path
                // releases it. A deferred error always stops the disk, so require the refusal.
                let coordinator = try await releaseRecordedDisks(
                    root: root, journal: journal, requiringForcedRelease: deferredSense)
                guard await coordinator.disks.isEmpty else {
                    throw Failure("The stopped disk was not released")
                }
                print("PASS: the stopped disk was released through the confirmed forced path")
                if deferredSense {
                    print(
                        "PASS: deferred sense reached native pwrite as EIO; later read/write EIO, no replay, normal unmount refused, forced release"
                    )
                }
                return
            }
            await BridgeHolders.waitUntilFree(bridge)
            try await backend.unmountBridge(descriptor, at: bridge)
            try journal.save([])
        } catch {
            do {
                try save(.unmountingBridge)
                do {
                    await BridgeHolders.waitUntilFree(bridge)
                    try await backend.unmountBridge(descriptor, at: bridge)
                    try journal.save([])
                } catch {
                    _ = try await releaseRecordedDisks(root: root, journal: journal)
                }
            } catch {
                FileHandle.standardError.write(
                    Data("Uncertain write fixture needs recovery at \(root.path): \(error)\n".utf8))
            }
            throw error
        }
        print("PASS: uncertain raw write is not replayed, later I/O fails, normal FSKit unmount")
        if deferredSense {
            print(
                "PASS: deferred sense reached native pwrite as EIO; later read/write EIO, no replay, normal unmount"
            )
        }
    }

    /// A stopped (latched) disk refuses a normal eject: its final synchronization fails. An
    /// owner process (this one or a later one) restores the journal record and, after a failed
    /// normal eject, takes the forced path the app offers after confirmation. StageBackend
    /// doesn't forward the forced-release observations (their protocol defaults refuse with
    /// recoveryRequired), so this uses the system backend itself. With `requiringForcedRelease`,
    /// a normal eject that succeeds is a failure: the caller expects every recorded disk stopped.
    static func releaseRecordedDisks(
        root: URL, journal: FileAttachmentJournal? = nil, requiringForcedRelease: Bool = false
    ) async throws -> AttachmentCoordinator {
        // A process holding the journal passes its own instance; a second one would find
        // the journal's lock taken (EAGAIN).
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: BlockResourceProbe.backend(root: root),
            journal: journal
                ?? FileAttachmentJournal(
                    directory: root.appendingPathComponent("State", isDirectory: true),
                    bridgeRoot: mounts))
        try await coordinator.restore()
        for disk in await coordinator.disks {
            let began = DispatchTime.now().uptimeNanoseconds
            do {
                try await coordinator.eject(disk.id)
                guard !requiringForcedRelease else {
                    throw Failure("A disk expected to be stopped was ejected normally")
                }
                print("PASS: recovered disk ejected normally")
                continue
            } catch let failure as Failure {
                throw failure
            } catch {
                let elapsed = Double(DispatchTime.now().uptimeNanoseconds - began) / 1e6
                print(
                    "CHECK: normal eject of the recovered disk failed after \(elapsed) ms: \(error)"
                )
            }
            guard await coordinator.canPrepareForceEjection(disk.id) else {
                throw Failure("The recovered disk cannot be force ejected")
            }
            let request: ForceEjectionRequest
            do {
                request = try await coordinator.prepareForceEjection(disk.id)
            } catch {
                throw Failure("Preparing the forced release failed: \(error)")
            }
            do {
                try await coordinator.forceEject(request)
            } catch {
                throw Failure("The forced release failed: \(error)")
            }
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - began) / 1e6
            print(
                "PASS: recovered disk force ejected in \(elapsed) ms"
                    + " (reportsLostConnection=\(request.reportsLostConnection))")
        }
        return coordinator
    }

    private static func validateDisconnection(
        _ portal: Portal, root: URL, nonce: UUID, silent: Bool
    ) async throws {
        let configuration = try configuration(nonce)
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
            targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: true,
            isid: configuration.isid)
        let coordinator = try coordinator(root: root)
        try await coordinator.restore()
        do {
            let disk = try await coordinator.connect(descriptor)
            guard let volume = disk.attachment?.volumeURLs.first,
                try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                    == marker(nonce)
            else { throw Failure("The fixture is not readable before interruption") }
            let journal = root.appendingPathComponent("State/Connections.json")
            let saved = try Data(contentsOf: journal)
            let raw = try FileHandle(
                forReadingFrom: disk.bridgeURL.appendingPathComponent("Disk.img"))
            defer { try? raw.close() }
            guard fcntl(raw.fileDescriptor, F_NOCACHE, 1) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let offset: off_t = 64 * 1_048_576
            var data = Data(count: 4096)
            try checkpoint("before-live-raw-read")
            let count = data.withUnsafeMutableBytes {
                pread(raw.fileDescriptor, $0.baseAddress, $0.count, offset)
            }
            guard count == 4096 else { throw Failure("Uncached live VFS read failed") }
            let local = try FileHandle(
                forReadingFrom: root.appendingPathComponent(FixtureFileSystem.at(root).imageName))
            defer { try? local.close() }
            try local.seek(toOffset: UInt64(offset))
            guard try local.read(upToCount: 4096) == data else {
                throw Failure("Live raw bytes differ")
            }
            try checkpoint("disconnect")
            let clock = ContinuousClock()
            let started = clock.now
            let image = disk.bridgeURL.appendingPathComponent("Disk.img")
            if !silent {
                // The target closed the connection but still answers. The disk logs in again
                // with the same ISID, revalidates the logical unit, and the waiting uncached
                // read is issued again on the new session.
                let next = offset + 4096
                let count = data.withUnsafeMutableBytes {
                    pread(raw.fileDescriptor, $0.baseAddress, $0.count, next)
                }
                try local.seek(toOffset: UInt64(next))
                guard count == 4096, try local.read(upToCount: 4096) == data,
                    started.duration(to: clock.now) < .seconds(60)
                else { throw Failure("Uncached read after a closed connection did not recover") }
                guard try state(at: disk.bridgeURL) == .connected,
                    try state(at: image) == .connected
                else { throw Failure("The recovered VFS session does not report connected") }
                await coordinator.refreshHealth()
                let current = await coordinator.disks
                guard current.count == 1, current[0].connectionState == .connected,
                    current[0].attachment == disk.attachment, !current[0].verificationFailed,
                    try Data(contentsOf: journal) == saved
                else { throw Failure("Health refresh after recovery differs") }
                print(
                    "PASS: closed connection recovered transparently; uncached read after \(started.duration(to: clock.now)); disk and journal retained"
                )
                try checkpoint("after-recovery")
            } else {
                // A silent target: the heartbeat times out, logins go unanswered and I/O waits
                // for the recovery window. Writing the control attribute stops reconnecting,
                // so the waiting read fails at once instead of after the window.
                let deadline = started.advanced(by: .seconds(60))
                while try state(at: disk.bridgeURL) != .reconnecting {
                    guard clock.now < deadline else {
                        throw Failure(
                            "VFS did not report reconnecting after the target went silent")
                    }
                    try await clock.sleep(for: .milliseconds(50))
                }
                guard try state(at: image) == .reconnecting else {
                    throw Failure("Raw image health differs from the root health")
                }
                await coordinator.refreshHealth()
                let current = await coordinator.disks
                guard current.count == 1, current[0].connectionState == .reconnecting,
                    current[0].attachment == disk.attachment, !current[0].verificationFailed,
                    try Data(contentsOf: journal) == saved
                else { throw Failure("Health refresh lost the reconnecting disk or its journal") }
                print(
                    "PASS: VFS and coordinator report reconnecting after \(started.duration(to: clock.now)); disk and journal retained"
                )
                let descriptor = raw.fileDescriptor
                async let waiting = RecoveryProbe.blocking { () -> [Int] in
                    var buffer = [UInt8](repeating: 0, count: 4096)
                    let began = RecoveryProbe.now()
                    let count = pread(descriptor, &buffer, buffer.count, offset + 4096)
                    let code = errno
                    return [count, Int(code), Int(RecoveryProbe.now() &- began)]
                }
                try await clock.sleep(for: .seconds(2))
                let requested = clock.now
                // As SystemAttachmentBackend.abandonConnectionRecovery does: Disk.img first, then
                // the bridge root. This disk is mounted read-only: the kernel refuses every
                // attribute write (EROFS) before the extension sees it, so the volume answers a
                // read of its read-only control instead.
                let control = ConnectionDescriptor.abandonRecoveryControlValue
                var failures: [String] = []
                for path in [image.path, disk.bridgeURL.path] {
                    let written = control.withUnsafeBytes {
                        setxattr(
                            path, ConnectionDescriptor.connectionControlAttributeName,
                            $0.baseAddress, $0.count, 0, 0)
                    }
                    if written == 0 { break }
                    failures.append(
                        "\(URL(fileURLWithPath: path).lastPathComponent): errno \(errno)")
                }
                if failures.count == 2 {
                    guard failures.allSatisfy({ $0.hasSuffix("errno \(EROFS)") }) else {
                        throw Failure("The stop-reconnecting request failed: \(failures)")
                    }
                    var answer = [UInt8](repeating: 0, count: 16)
                    let count = answer.withUnsafeMutableBytes {
                        getxattr(
                            image.path, ConnectionDescriptor.readOnlyConnectionControlAttributeName,
                            $0.baseAddress, $0.count, 0, 0)
                    }
                    guard count >= 0, Data(answer.prefix(count)) == control else {
                        throw Failure("The read-only control did not answer: errno \(errno)")
                    }
                    print(
                        "CHECK: control writes refused on the read-only mount (\(failures)); its read-only control answered"
                    )
                }
                let read = await waiting
                print(
                    "CHECK: waiting read returned \(read[0]), errno \(read[1]), \(read[2] / 1_000_000) ms; abandon answered after \(requested.duration(to: clock.now))"
                )
                guard read[0] == -1, read[1] == Int(EIO),
                    requested.duration(to: clock.now) < .seconds(10)
                else { throw Failure("A waiting read did not fail promptly after abandon") }
                guard try state(at: disk.bridgeURL) == .interrupted else {
                    throw Failure("An abandoned recovery does not report interrupted")
                }
                let began = clock.now
                let later = data.withUnsafeMutableBytes {
                    pread(raw.fileDescriptor, $0.baseAddress, $0.count, offset + 8192)
                }
                let code = errno
                guard later == -1, code == EIO, began.duration(to: clock.now) < .seconds(5)
                else { throw Failure("Uncached read after abandon did not fail promptly") }
                try checkpoint("after-recovery")
            }
            try raw.close()
            try await coordinator.eject(disk.id)
            guard await coordinator.disks.isEmpty else {
                throw Failure("Disconnected fixture remains recorded")
            }
        } catch {
            for disk in await coordinator.disks { try? await coordinator.eject(disk.id) }
            throw error
        }
        print(
            "PASS: silent=\(silent), \(silent ? "waiting read failed with EIO" : "closed connection recovered"), normal file system and FSKit ejection"
        )
    }

    private static func sourceBlockSize(at path: URL) throws -> UInt32 {
        var bytes = [UInt8](repeating: 0, count: 5)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                path.path, ConnectionDescriptor.sourceBlockSizeAttributeName, $0.baseAddress,
                $0.count, 0, 0)
        }
        guard count == 4 else { throw Failure("Source sector size is unavailable") }
        return try DiskImageGeometry.sourceBlockSize(from: Data(bytes.prefix(count)))
    }

    private static func state(at path: URL) throws -> DiskConnectionState {
        var bytes = [UInt8](repeating: 0, count: 3)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                path.path, ConnectionDescriptor.connectionStateAttributeName, $0.baseAddress,
                $0.count, 0, 0)
        }
        guard count == 2 else { throw Failure("VFS connection state is unavailable") }
        return try DiskConnectionState(encoded: Data(bytes.prefix(2)))
    }

    private static func mount(
        _ portal: Portal, root: URL, nonce: UUID, readOnly: Bool, chap: Bool,
        mutualCHAP: Bool = false,
        target: FixtureTarget = .ram,
        soakSeconds: Int? = nil
    ) async throws {
        guard !mutualCHAP || chap else { throw Failure("Mutual CHAP requires fixture credentials") }
        if chap {
            try await saveFixtureCredential(
                portal: portal, root: root, nonce: nonce, mutualCHAP: mutualCHAP)
        }
        do {
            try await mountVolumes(
                portal, root: root, nonce: nonce, readOnly: readOnly, chap: chap, target: target,
                soakSeconds: soakSeconds, mutualCHAP: mutualCHAP)
        } catch {
            do { try await removeFixtureCredential(root: root, nonce: nonce) } catch {
                FileHandle.standardError.write(
                    Data("Fixture credential cleanup failed: \(error)\n".utf8))
            }
            throw error
        }
        try await removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func mountVolumes(
        _ portal: Portal, root: URL, nonce: UUID, readOnly: Bool, chap: Bool,
        target: FixtureTarget = .ram,
        soakSeconds: Int? = nil, mutualCHAP: Bool = false
    ) async throws {
        let format = try FixtureFileSystem.at(root)
        let configuration = try configuration(nonce, target: target)
        func descriptor(readOnly: Bool) throws -> ConnectionDescriptor {
            try ConnectionDescriptor(
                profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
                targetName: configuration.targetName!, lun: LogicalUnit(target.lun),
                readOnly: readOnly,
                chapUsername: chap ? "test-user" : nil, isid: configuration.isid,
                credentialID: chap ? nonce : nil,
                imagePresentation: requestedImagePresentation(),
                targetCHAPUsername: mutualCHAP ? "test-server" : nil)
        }
        let coordinator = try coordinator(root: root)
        try await coordinator.restore()
        do {
            if soakSeconds != nil {
                let idle = try await coordinator.connect(descriptor(readOnly: true))
                try verifyBridgeMountMode(idle)
                guard let volume = idle.attachment?.volumeURLs.first,
                    try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                        == marker(nonce)
                else { throw Failure("Idle fixture was not connected") }
                try checkpoint("before-idle")
                try await Task.sleep(for: .seconds(32))
                guard try state(at: idle.bridgeURL) == .connected
                else {
                    throw Failure("FSKit session did not remain connected while idle")
                }
                try checkpoint("after-idle")
                let location = try imageDataLocation(idle, at: 96 * 1_048_576)
                let raw = try FileHandle(forReadingFrom: location.url)
                do {
                    guard fcntl(raw.fileDescriptor, F_NOCACHE, 1) == 0 else {
                        throw POSIXError(.EIO)
                    }
                    try raw.seek(toOffset: location.offset)
                    let actual = try raw.read(upToCount: 4096)
                    let local = try FileHandle(
                        forReadingFrom: root.appendingPathComponent(
                            FixtureFileSystem.at(root).imageName))
                    defer { try? local.close() }
                    try local.seek(toOffset: 96 * 1_048_576)
                    guard try actual == local.read(upToCount: 4096) else {
                        throw Failure("Post-idle raw bytes differ")
                    }
                    try raw.close()
                } catch {
                    try? raw.close()
                    throw error
                }
                try await coordinator.eject(idle.id)
            }
            let record = try await coordinator.connect(descriptor(readOnly: readOnly))
            try verifyBridgeMountMode(record)
            if ProcessInfo.processInfo.environment["ISCSI_TEST_GEOMETRY_RUNTIME"] == "1" {
                guard readOnly, let attachment = record.attachment else {
                    throw Failure("Read-only geometry checkpoint requires an attached disk")
                }
                let data = try await SystemCommand.run(
                    "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
                let source = root.appendingPathComponent(format.imageName)
                let file = try FileHandle(forReadingFrom: source)
                let prefix = try file.read(upToCount: DiskImageGeometry.prefixByteCount) ?? Data()
                try file.close()
                let size = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize!
                let expected = try DiskImageGeometry.blockSize(
                    prefix: prefix, byteCount: UInt64(size),
                    sourceBlockSize: sourceBlockSize(
                        at: record.bridgeURL.appendingPathComponent("Disk.img")))
                guard
                    let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                        as? [String: Any], info["DeviceBlockSize"] as? Int == Int(expected),
                    info["TotalSize"] as? Int == size, info["WritableMedia"] as? Bool == false
                else { throw Failure("Native read-only geometry differs from the source") }
                print("FSKIT_DEVICE_GEOMETRY bytes=\(size) blockSize=\(expected) readOnly=true")
                try checkpoint("connected-geometry")
            }
            if ProcessInfo.processInfo.environment["ISCSI_TEST_BULK_ATTRIBUTES"] == "1" {
                try checkpoint("before-bulk-attributes")
                try BulkAttributesProbe.validate(record.bridgeURL, requireFSKit: true)
                try checkpoint("after-bulk-attributes")
            }
            if ProcessInfo.processInfo.environment["ISCSI_TEST_DIRECTORY_ENUMERATION"] == "1" {
                try DirectoryEnumerationProbe.validate(record.bridgeURL, requireFSKit: true)
            }
            var bridgeSpace = statfs()
            guard statfs(record.bridgeURL.path, &bridgeSpace) == 0 else { throw POSIXError(.EIO) }
            print(
                "FSKIT_BRIDGE_SPACE blocks=\(bridgeSpace.f_blocks) free=\(bridgeSpace.f_bfree) available=\(bridgeSpace.f_bavail)"
            )
            guard record.connectionState == .connected, !record.needsCleanup,
                record.attachment?.volumeURLs.count == 1,
                let volume = record.attachment?.volumeURLs.first
            else { throw Failure("FSKit-backed fixture volume was not connected") }
            try FixtureFileSystem.verifySpace(of: volume, at: root, readOnly: readOnly)
            try HandlerControlProbe.captureIfRequested(
                root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                beforeWrite: true)
            try CallbackTraceProbe.captureIfRequested(
                root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                beforeWrite: true)
            try MemorySnapshotProbe.verifyIfRequested(
                root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"))
            if let attachment = record.attachment {
                try await DeviceFeatureProbe.captureIfRequested(
                    root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                    attachment: attachment, localRegularFile: false)
            }
            let location = try imageDataLocation(record)
            let raw = try FileHandle(forReadingFrom: location.url)
            do {
                try raw.seek(toOffset: location.offset)
                let local = try FileHandle(
                    forReadingFrom: root.appendingPathComponent(
                        FixtureFileSystem.at(root).imageName))
                defer { try? local.close() }
                let actual = try raw.read(upToCount: 4096)
                let expected = try local.read(upToCount: 4096)
                guard LegacyAttachmentProbe.matchesRawPrefix(actual, expected: expected) else {
                    throw Failure("VFS raw bytes differ")
                }
                try raw.close()
            } catch {
                try? raw.close()
                throw error
            }
            try format.verifyVolume(volume, readOnly: readOnly)
            let file = volume.appendingPathComponent("FSKit-validation.txt")
            guard try Data(contentsOf: file) == marker(nonce) else {
                throw Failure("FSKit-backed fixture marker differs")
            }
            let written = writtenData(nonce)
            var soakReport: SoakWorkload.Report?
            if let soakSeconds {
                soakReport = try await SoakWorkload.run(
                    at: volume, root: root, nonce: nonce, seconds: soakSeconds)
            }
            if readOnly {
                var rejected = false
                do { try Data("must not be written".utf8).write(to: file) } catch {
                    rejected = true
                }
                guard rejected, try Data(contentsOf: file) == marker(nonce) else {
                    throw Failure("Read-only write was not rejected")
                }
            } else {
                if ProcessInfo.processInfo.environment["ISCSI_TEST_FILESYSTEM_TEXT"] == "1" {
                    try checkpoint("before-filesystem-write")
                }
                let target = volume.appendingPathComponent("FSKit-written.txt")
                var space = statfs()
                guard statfs(volume.path, &space) == 0 else { throw POSIXError(.EIO) }
                print(
                    "FSKIT_VOLUME_SPACE blocks=\(space.f_blocks) free=\(space.f_bfree) available=\(space.f_bavail)"
                )
                if SynchronizationBoundaryProbe.mode != nil {
                    guard let attachment = record.attachment else {
                        throw Failure("Synchronization fixture has no private device")
                    }
                    let deviceSync = try await HFSDeviceSyncProbe.prepareIfRequested(
                        root: root, volume: volume,
                        image: record.bridgeURL.appendingPathComponent("Disk.img"),
                        attachment: attachment)
                    try SynchronizationBoundaryProbe.run(
                        root: root, volume: volume, contents: written, deviceSync: deviceSync
                    ) {
                        try checkpoint("sync-boundaries")
                    }
                } else {
                    let fd = open(target.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                    guard fd >= 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                    do {
                        try handle.write(contentsOf: written)
                        try checkpoint("before-fsync")
                        try handle.synchronize()
                        try checkpoint("after-fsync")
                        try checkpoint("before-fullfsync")
                        guard fcntl(handle.fileDescriptor, F_FULLFSYNC) == 0 else {
                            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                        }
                        let fullsyncReturned = DispatchTime.now().uptimeNanoseconds
                        try MemorySnapshotProbe.captureIfRequested(
                            root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                            cutoff: fullsyncReturned)
                        try checkpoint("after-fullfsync", fullsyncReturnedNS: fullsyncReturned)
                        try HandlerControlProbe.captureIfRequested(
                            root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                            beforeWrite: false, fullsyncReturned: fullsyncReturned)
                        try CallbackTraceProbe.captureIfRequested(
                            root: root, image: record.bridgeURL.appendingPathComponent("Disk.img"),
                            beforeWrite: false, fullsyncReturned: fullsyncReturned)
                        try await JournalViewProbe.captureIfRequested(
                            root: root, bridge: record.bridgeURL, attachment: record.attachment)
                        try handle.close()
                    } catch {
                        try? handle.close()
                        throw error
                    }
                }
                guard try Data(contentsOf: target) == written else {
                    throw Failure("Written fixture data differs")
                }
            }
            try await coordinator.eject(record.id)
            if !readOnly && !MemorySnapshotProbe.enabled {
                let reopened = try await coordinator.connect(descriptor(readOnly: true))
                try verifyBridgeMountMode(reopened)
                guard let volume = reopened.attachment?.volumeURLs.first,
                    try Data(contentsOf: volume.appendingPathComponent("FSKit-written.txt"))
                        == written,
                    try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                        == marker(nonce)
                else {
                    throw Failure("Written data did not survive FSKit ejection and reattachment")
                }
                try format.verifyVolume(volume, readOnly: true)
                if let soakReport { try SoakWorkload.verify(at: volume, report: soakReport) }
                try await coordinator.eject(reopened.id)
            }
            guard await coordinator.disks.isEmpty else {
                throw Failure("Fixture record remains after ejection")
            }
        } catch {
            for disk in await coordinator.disks {
                do { try await coordinator.eject(disk.id) } catch {
                    FileHandle.standardError.write(
                        Data("Fixture cleanup requires recovery at \(root.path): \(error)\n".utf8))
                }
            }
            throw error
        }
        print(
            "PASS: FSKit VFS raw bytes, \(format.displayName) marker, readOnly=\(readOnly), CHAP=\(chap), mutualCHAP=\(mutualCHAP), I/O, normal ejection"
        )
    }

    static func checkpoint(_ phase: String, fullsyncReturnedNS: UInt64? = nil) throws {
        var report: [String: Any] = [
            "phase": phase, "uptimeNS": DispatchTime.now().uptimeNanoseconds,
        ]
        if let fullsyncReturnedNS { report["fullsyncReturnedNS"] = fullsyncReturnedNS }
        let data = try JSONSerialization.data(
            withJSONObject: report, options: .sortedKeys)
        FileHandle.standardOutput.write(Data("FSKIT_CHECKPOINT ".utf8) + data + Data([10]))
        guard let line = readLine(), let bytes = line.data(using: .utf8),
            let response = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        else { throw Failure("Missing fixture checkpoint acknowledgment") }
        guard response["ok"] as? Bool == true else {
            throw Failure(response["error"] as? String ?? "Fixture checkpoint failed")
        }
    }
}
