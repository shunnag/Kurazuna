import CryptoKit
import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

@testable import ISCSINetwork

/// Drives an existing external iSCSI target that no harness creates or controls, for
/// scripts/test-external-target.py. Three modes take a JSON specification in the private root:
///
/// - `--external-inspect`: SendTargets without and with CHAP, the app's LUN inspection and the
///   FSKit extension's open sequence, each on the probe's own connections through a recorder
///   (RecordingTransport.swift). Writes the specification's `output` file to the root.
/// - `--external-session`: one disk connected through the production `AttachmentCoordinator`
///   and `SystemAttachmentBackend`, as the app does, then served interactively by
///   `RecoveryProbe.Session` (workload, ledger, eject, force eject, inventory) with a few
///   commands of its own. A blank LUN is formatted only when the specification allows it, after
///   the same device checks as `LargeFilesystemProbe.native()`.
/// - `--external-credential-remove`: removes the CHAP credential a session left in the shared
///   keychain, after a failure.
///
/// The CHAP secret is read from a private file named in the specification and is never printed.
enum ExternalTargetProbe {
    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static let markerName = "iSCSI-External-Target.json"
    static let harnessName = "scripts/test-external-target.py"
    static let credentialFile = "ExternalCredential.json"

    struct Spec: Decodable {
        let nonce: String
        let portal: String
        let portalGroupTag: UInt16?
        let targetName: String?
        let initiatorName: String
        let isid: String?
        let chapUser: String?
        let secretFile: String?
        /// Mutual CHAP: the name the target answers with and the file holding its secret.
        let targetChapUser: String?
        let targetSecretFile: String?
        let luns: [UInt16]?
        let lun: UInt16?
        let readOnly: Bool?
        let expectedCapacity: UInt64?
        let expectedBlockSize: Int?
        let volumePolicy: String?
        let allowErase: Bool?
        let volumeName: String?
        let requiredFreeBytes: UInt64?
        let output: String?
    }

    static func removeCredentialCommand(root: URL, nonce: UUID) async throws {
        let removed = try await removeCredential(root: root, nonce: nonce)
        print(
            removed
                ? "PASS: the external CHAP credential was removed from the shared keychain"
                : "PASS: no external CHAP credential was recorded in this root")
    }

    static func run(mode: String, specName: String, root: URL, nonce: UUID) async throws {
        let spec = try load(specName, root: root, nonce: nonce)
        switch mode {
        case "--external-inspect": try await inspect(spec, root: root, nonce: nonce)
        case "--external-session": try await session(spec, root: root, nonce: nonce)
        default: throw Failure("Unknown external target mode")
        }
    }

    // MARK: Specification and secret

    static func load(_ name: String, root: URL, nonce: UUID) throws -> Spec {
        guard name.range(of: "^[A-Za-z0-9._-]{1,64}\\.json$", options: .regularExpression) != nil
        else { throw Failure("Invalid specification name") }
        let path = root.appendingPathComponent(name)
        guard path.resolvingSymlinksInPath() == path else {
            throw Failure("The specification must not be a link")
        }
        let handle = try FileHandle(forReadingFrom: path)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 65_537) ?? Data()
        guard data.count <= 65_536 else { throw Failure("The specification is too large") }
        let spec = try JSONDecoder().decode(Spec.self, from: data)
        guard spec.nonce == nonce.uuidString.lowercased() else {
            throw Failure("The specification belongs to another run")
        }
        guard (spec.chapUser == nil) == (spec.secretFile == nil) else {
            throw Failure("A CHAP user and a secret file are required together")
        }
        guard (spec.targetChapUser == nil) == (spec.targetSecretFile == nil),
            spec.targetChapUser == nil || spec.chapUser != nil
        else {
            throw Failure("A mutual CHAP user and secret file need each other and a CHAP user")
        }
        return spec
    }

    /// Reads the CHAP secret: a regular file of this user, without group or other permissions.
    /// One trailing newline is removed. The secret never enters an error message.
    static func readSecret(_ path: String) throws -> String {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            throw Failure("The CHAP secret file cannot be opened (errno \(errno))")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw Failure("The CHAP secret file is not a regular file")
        }
        guard info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            throw Failure("The CHAP secret file must belong to this user with mode 0600")
        }
        guard (1...4096).contains(info.st_size) else {
            throw Failure("The CHAP secret file must hold 1 to 4096 bytes")
        }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard count == bytes.count else { throw Failure("The CHAP secret file could not be read") }
        if bytes.last == 10 { bytes.removeLast() }
        if bytes.last == 13 { bytes.removeLast() }
        guard let secret = String(bytes: bytes, encoding: .utf8),
            secret.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }),
            (12...1024).contains(secret.utf8.count)
        else {
            throw Failure(
                "The CHAP secret must be 12 to 1024 bytes of printable UTF-8 on one line")
        }
        return secret
    }

    static func parseISID(_ text: String) throws -> [UInt8] {
        guard text.range(of: "^[0-9a-f]{12}$", options: .regularExpression) != nil else {
            throw Failure("Invalid ISID")
        }
        var bytes: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            bytes.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        guard bytes[0] & 0xC0 == 0x80 else { throw Failure("The ISID must use the random format") }
        return bytes
    }

    /// A stable random-format ISID per initiator, target and LUN, so that a later login to the
    /// same LUN reinstates an earlier session as the app's stable identity does.
    static func stableISID(initiator: String, target: String, lun: UInt16) -> String {
        let digest = SHA256.hash(data: Data("\(initiator)\u{0}\(target)\u{0}\(lun)".utf8))
        return "80" + WireRecorder.hex(Array(digest.prefix(5)))
    }

    static func errorText(_ error: any Error) -> String {
        if case ProtocolError.scsiFailure(let status, let data) = error {
            let sense = WireRecorder.sense([UInt8](data.dropFirst(2)))
            return "ProtocolError: scsiFailure(status: \(status), sense: \(sense ?? [:]))"
        }
        return RecoveryProbe.errorText(error)
    }

    static func line(_ kind: String, _ object: [String: Any]) {
        let data =
            (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        FileHandle.standardOutput.write(Data("EXTERNAL_\(kind) ".utf8) + data + Data([10]))
    }

    // MARK: Inspection

    static func connect(
        addresses: [TargetAddress], configuration: LoginConfiguration, label: String,
        recorder: WireRecorder, wait: LocalNetworkAccessWait
    ) async throws -> SessionConnection {
        try await SessionConnector.connect(
            addresses: addresses, configuration: configuration, timeout: .seconds(45),
            maximumRedirects: 4, maximumAttempts: 16, cachedRedirects: [], clock: .continuous,
            localNetworkAccessWait: wait,
            factory: { portal, timeout in
                try RecordingTransport(
                    portal: portal, timeout: timeout, label: label, recorder: recorder,
                    localNetworkAccessWait: wait)
            })
    }

    static func describe(_ connection: SessionConnection) -> [String: Any] {
        [
            "connectedPortal": connection.portal.description,
            "contactedPortals": connection.contactedPortals.map(\.description),
            "redirects": connection.redirects.map {
                ["kind": "\($0.kind)", "addresses": $0.addresses.map(\.description)]
            },
            "permanentRedirects": connection.permanentRedirects.map {
                [
                    "source": $0.source.description,
                    "destinations": $0.destinations.map(\.description),
                ]
            },
        ]
    }

    static func describe(_ information: DiskInformation) -> [String: Any] {
        [
            "vendor": information.device.vendor, "product": information.device.product,
            "revision": information.device.revision,
            "deviceType": Int(information.device.peripheralDeviceType),
            "removable": information.device.removable,
            "version": Int(information.device.version),
            "capacityBytes": information.capacity.byteCount,
            "blockCount": information.capacity.blockCount,
            "blockSize": Int(information.capacity.blockSize),
            "writeProtected": information.isWriteProtected.map { $0 as Any } ?? NSNull(),
        ]
    }

    static func designators(_ data: Data) -> [[String: Any]] {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { return [] }
        let end = min(bytes.count, 4 + (Int(bytes[2]) << 8 | Int(bytes[3])))
        var offset = 4
        var rows: [[String: Any]] = []
        while offset + 4 <= end, rows.count < 32 {
            let length = Int(bytes[offset + 3])
            guard offset + 4 + length <= end else { break }
            let identifier = Array(bytes[(offset + 4)..<(offset + 4 + length)])
            let codeSet = Int(bytes[offset] & 0x0F)
            var row: [String: Any] = [
                "protocol": Int(bytes[offset] >> 4), "codeSet": codeSet,
                "piv": bytes[offset + 1] & 0x80 != 0,
                "association": Int((bytes[offset + 1] >> 4) & 3),
                "type": Int(bytes[offset + 1] & 0x0F), "identifier": WireRecorder.hex(identifier),
            ]
            if codeSet == 2 || codeSet == 3 {
                row["text"] = String(decoding: identifier.prefix { $0 != 0 }, as: UTF8.self)
            }
            rows.append(row)
            offset += 4 + length
        }
        return rows
    }

    static func readCapacity16(_ data: Data) -> [String: Any] {
        let bytes = [UInt8](data)
        guard bytes.count >= 16 else { return ["error": "short READ CAPACITY(16) data"] }
        let exponent = Int(bytes[13] & 0x0F)
        let logical = Int(bytes.uint32(at: 8))
        return [
            "lastLBA": bytes.uint64(at: 0), "logicalBlockSize": logical,
            "physicalBlockExponent": exponent, "physicalBlockSize": logical << exponent,
            "lbpme": bytes[14] & 0x80 != 0, "lbprz": bytes[14] & 0x40 != 0,
            "lowestAlignedLBA": Int(bytes[14] & 0x3F) << 8 | Int(bytes[15]),
        ]
    }

    static func blockLimitsPage(_ data: Data) -> [String: Any] {
        let bytes = [UInt8](data)
        guard bytes.count >= 16, bytes[1] == 0xB0 else { return ["error": "malformed page"] }
        var value: [String: Any] = [
            "pageLength": Int(bytes.uint16(at: 2)),
            "maximumTransferBlocks": bytes.uint32(at: 8),
            "optimalTransferBlocks": bytes.uint32(at: 12),
        ]
        if bytes.count >= 28 {
            value["maximumUnmapLBACount"] = bytes.uint32(at: 20)
            value["maximumUnmapDescriptorCount"] = bytes.uint32(at: 24)
        }
        if bytes.count >= 32 { value["optimalUnmapGranularity"] = bytes.uint32(at: 28) }
        return value
    }

    static func inspect(_ spec: Spec, root: URL, nonce: UUID) async throws {
        let portal = try Portal(spec.portal)
        let chap: CHAPCredentials? = try spec.chapUser.map { user in
            try CHAPCredentials(
                username: user, password: readSecret(spec.secretFile ?? ""),
                targetUsername: spec.targetChapUser,
                targetPassword: spec.targetSecretFile.map(readSecret))
        }
        let output = spec.output ?? "Inspection.json"
        guard output.range(of: "^[A-Za-z0-9._-]{1,64}\\.json$", options: .regularExpression) != nil
        else { throw Failure("Invalid output name") }
        let recorder = WireRecorder()
        let wait = LocalNetworkAccessWait {
            ExternalTargetProbe.line("LOCAL_NETWORK", ["changed": true])
        }
        var report: [String: Any] = [
            "portal": portal.description, "initiatorName": spec.initiatorName,
            "chap": chap != nil, "stage": "discovery",
        ]
        func save() throws {
            var value = report
            value["wire"] = recorder.report
            value["localNetworkWaiting"] = wait.isWaiting
            try JSONSerialization.data(
                withJSONObject: value, options: [.prettyPrinted, .sortedKeys]
            )
            .write(to: root.appendingPathComponent(output), options: .atomic)
        }
        do {
            var attempts: [(String, CHAPCredentials?)] = [("none", nil)]
            if let chap { attempts.append(("chap", chap)) }
            var discoveries: [[String: Any]] = []
            var order: [DiscoveredTarget] = []
            for (auth, credentials) in attempts {
                recorder.setPhase("discovery-" + auth)
                let began = RecoveryProbe.now()
                var row: [String: Any] = ["auth": auth]
                do {
                    let connection = try await connect(
                        addresses: [TargetAddress(portal: portal)],
                        configuration: LoginConfiguration(
                            initiatorName: spec.initiatorName, credentials: credentials),
                        label: "discovery-" + auth, recorder: recorder, wait: wait)
                    row.merge(describe(connection)) { $1 }
                    let targets: [DiscoveredTarget]
                    do {
                        targets = try await connection.session.discover()
                        try await connection.session.logout()
                    } catch {
                        _ = await connection.session.closeGracefully()
                        throw error
                    }
                    row["ok"] = true
                    row["targets"] = targets.map { ["name": $0.name, "addresses": $0.addresses] }
                    for target in targets where !order.contains(where: { $0.name == target.name }) {
                        order.append(target)
                    }
                } catch {
                    row["ok"] = false
                    row["error"] = errorText(error)
                }
                row["elapsedMS"] = RecoveryProbe.milliseconds(began, RecoveryProbe.now())
                discoveries.append(row)
            }
            report["discovery"] = discoveries
            try save()

            report["stage"] = "target-choice"
            let name: String
            if let wanted = spec.targetName {
                name = wanted
            } else {
                guard order.count == 1 else {
                    throw Failure(
                        order.isEmpty
                            ? "SendTargets listed no target for this initiator name"
                            : "SendTargets listed \(order.count) targets (\(order.map(\.name).joined(separator: ", "))); choose one with --target"
                    )
                }
                name = order[0].name
            }
            let discovered = order.first { $0.name == name }
            report["target"] = name
            report["targetListed"] = discovered != nil
            let addresses =
                try discovered?.connectionAddresses(fallback: portal) ?? [
                    TargetAddress(portal: portal)
                ]
            report["addresses"] = addresses.map {
                [
                    "portal": $0.portal.description,
                    "portalGroupTag": $0.portalGroupTag.map { Int($0) as Any } ?? NSNull(),
                ]
            }
            let luns = spec.luns ?? []
            report["isids"] = Dictionary(
                uniqueKeysWithValues: luns.map {
                    (
                        String($0),
                        stableISID(initiator: spec.initiatorName, target: name, lun: $0)
                    )
                })
            try save()

            // The app's "Show disks": the discovered addresses, REPORT LUNS and each LUN.
            report["stage"] = "app-inspection"
            recorder.setPhase("app-inspection")
            let configuration = try LoginConfiguration(
                initiatorName: spec.initiatorName, targetName: name, credentials: chap)
            let began = RecoveryProbe.now()
            let connection = try await connect(
                addresses: addresses, configuration: configuration, label: "app-inspection",
                recorder: recorder, wait: wait)
            var inspection = describe(connection)
            let group = await connection.session.targetPortalGroupTag
            do {
                let units = try await DiskProbe.inspectLogicalUnits(session: connection.session)
                inspection["luns"] = units.map { unit -> [String: Any] in
                    var row: [String: Any] = ["lun": unit.lun.stableIdentifier]
                    switch unit.result {
                    case .success(let information): row.merge(describe(information)) { $1 }
                    case .failure(let issue): row["issue"] = "\(issue)"
                    }
                    return row
                }
                try await connection.session.logout()
            } catch {
                _ = await connection.session.closeGracefully()
                throw error
            }
            inspection["portalGroupTag"] = group.map { Int($0) as Any } ?? NSNull()
            inspection["elapsedMS"] = RecoveryProbe.milliseconds(began, RecoveryProbe.now())
            report["inspection"] = inspection
            try save()

            // The FSKit extension's open sequence (LUNVolumeFactory.openSession) on a new login to
            // the connected address with the LUN's stable ISID, then read-only extras.
            report["stage"] = "extension-open"
            var opens: [[String: Any]] = []
            for lun in luns {
                recorder.setPhase("extension-open")
                var row: [String: Any] = ["lun": Int(lun)]
                let isid = try parseISID(
                    stableISID(initiator: spec.initiatorName, target: name, lun: lun))
                let opened = try await connect(
                    addresses: [TargetAddress(portal: connection.portal, portalGroupTag: group)],
                    configuration: LoginConfiguration(
                        initiatorName: spec.initiatorName, targetName: name, credentials: chap,
                        isid: isid),
                    label: "extension-open-lun\(lun)", recorder: recorder, wait: wait)
                let session = opened.session
                do {
                    let unit = try LogicalUnit(lun)
                    var wouldOpen = true
                    do {
                        let information = try await DiskProbe.diskInformation(
                            session: session, lun: unit)
                        row["information"] = describe(information)
                    } catch {
                        wouldOpen = false
                        row["informationError"] = errorText(error)
                    }
                    if wouldOpen {
                        do {
                            let limits = try await DiskProbe.blockLimits(
                                session: session, lun: unit)
                            row["blockLimits"] =
                                limits.map {
                                    ["maximumTransferBlocks": $0.maximumTransferBlocks] as Any
                                } ?? NSNull()
                        } catch {
                            wouldOpen = false
                            row["blockLimitsError"] = errorText(error)
                        }
                    }
                    if wouldOpen {
                        do {
                            let designator = try await DiskProbe.logicalUnitDesignator(
                                session: session, lun: unit)
                            row["designator"] =
                                designator.map { WireRecorder.hex([UInt8]($0)) as Any } ?? NSNull()
                        } catch is DiskProbeIssue {
                            row["designator"] = "notCaptured"
                        } catch {
                            wouldOpen = false
                            row["designatorError"] = errorText(error)
                        }
                    }
                    row["extensionWouldOpen"] = wouldOpen
                    recorder.setPhase("extra")
                    if let value = try? await DiskProbe.readOnly(
                        .readCapacity16(), session: session, lun: unit)
                    {
                        row["readCapacity16"] = readCapacity16(value.data)
                    }
                    do {
                        let value = try await DiskProbe.readOnly(
                            .deviceIdentification(), session: session, lun: unit)
                        row["vpd83"] = designators(value.data)
                    } catch {
                        row["vpd83Error"] = errorText(error)
                    }
                    do {
                        let value = try await DiskProbe.readOnly(
                            .blockLimits(), session: session, lun: unit)
                        row["vpdB0"] = blockLimitsPage(value.data)
                    } catch {
                        row["vpdB0Error"] = errorText(error)
                    }
                    try await session.logout()
                } catch {
                    _ = await session.closeGracefully()
                    row["error"] = errorText(error)
                }
                opens.append(row)
                report["open"] = opens
                try save()
            }
            report["stage"] = "done"
            report["ok"] = true
            try save()
            line(
                "INSPECT",
                [
                    "ok": true, "target": name, "output": output,
                    "connectedPortal": connection.portal.description,
                ])
        } catch {
            report["ok"] = false
            report["error"] = errorText(error)
            try? save()
            line("FAILED", ["stage": report["stage"] ?? "", "error": errorText(error)])
            throw error
        }
    }

    // MARK: Session

    static func stage(_ value: String) {
        RecoveryProbe.emit("STAGE", ["stage": value])
    }

    /// Every disk name that exists before this connection (diskutil list).
    static func wholeDisks() async throws -> Set<String> {
        let data: Data
        do {
            data = try await SystemCommand.run(
                "/usr/sbin/diskutil", arguments: ["list", "-plist"], timeout: 30)
        } catch {
            throw Failure(
                "diskutil list did not answer within 30 s or failed (\(RecoveryProbe.errorText(error)))"
            )
        }
        guard
            let value = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            let disks = value["AllDisks"] as? [String]
        else { throw Failure("diskutil list returned no disk list") }
        return Set(disks)
    }

    /// The checks `LargeFilesystemProbe.native()` makes, with this LUN's geometry: the device is
    /// the one the coordinator attached for this bridge's Disk.img (per hdiutil), it did not
    /// exist before the connection (when a baseline is given: always before formatting), and
    /// its size, block size and writability are the LUN's.
    static func ownedDevice(
        _ record: AttachedDisk, readOnly: Bool, capacity: UInt64, blockSize: Int,
        baseline: Set<String>?
    ) async throws -> (DiskAttachment, [String: Any]) {
        guard let expected = record.attachment, expected.device.hasPrefix("/dev/disk"),
            expected.device.count > 9,
            expected.device.dropFirst(9).utf8.allSatisfy({ (48...57).contains($0) })
        else { throw Failure("The connected disk has no attached device") }
        guard record.connectionState == .connected, !record.needsCleanup else {
            throw Failure(
                "The connected disk is \(record.connectionState), phase \(record.phase)")
        }
        let image = record.bridgeURL.appendingPathComponent("Disk.img")
        var status = stat()
        guard lstat(image.path, &status) == 0, status.st_mode & S_IFMT == S_IFREG,
            status.st_uid == geteuid()
        else { throw Failure("The bridge's Disk.img is missing or not this user's file") }
        guard UInt64(status.st_size) == capacity else {
            throw Failure(
                "The bridge's Disk.img has \(status.st_size) bytes; the LUN reported \(capacity)")
        }
        guard let current = try await DiskImages().inventory().attachment(at: image),
            current.device == expected.device
        else { throw Failure("hdiutil does not list \(expected.device) for this Disk.img") }
        let name = String(expected.device.dropFirst("/dev/".count))
        if let baseline, baseline.contains(name) {
            throw Failure("\(name) existed before this connection")
        }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", current.device], timeout: 30)
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any]
        else { throw Failure("diskutil info returned no information") }
        let total = (info["TotalSize"] as? NSNumber)?.uint64Value
        let block = (info["DeviceBlockSize"] as? NSNumber)?.intValue
        let writable = info["WritableMedia"] as? Bool
        guard total == capacity, block == blockSize, writable == !readOnly else {
            throw Failure(
                "diskutil reports \(current.device) as \(total ?? 0) bytes, \(block ?? 0)-byte blocks, writable=\(writable.map(String.init(describing:)) ?? "unknown"); expected \(capacity), \(blockSize), writable=\(!readOnly)"
            )
        }
        return (
            current,
            [
                "device": current.device, "totalSize": capacity, "deviceBlockSize": blockSize,
                "writableMedia": !readOnly, "content": info["Content"] as? String ?? "",
                "absentFromBaseline": baseline == nil ? "not checked" : "yes",
                "hdiutilListsImage": true,
            ]
        )
    }

    /// Whether the first and the last MiB of the LUN are zero, read uncached through the bridge.
    static func rawBlank(_ image: URL, capacity: UInt64) async -> [String: Any] {
        let path = image.path
        return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
            let fd = open(path, O_RDONLY | O_CLOEXEC)
            guard fd >= 0 else { return RecoveryProbe.CommandBox(["errno": Int(errno)]) }
            defer { close(fd) }
            _ = fcntl(fd, F_NOCACHE, 1)
            let span = Int(min(capacity, 1_048_576))
            var blank = true
            for offset in [UInt64(0), capacity - UInt64(span)] {
                var buffer = [UInt8](repeating: 0, count: span)
                let count = buffer.withUnsafeMutableBytes {
                    pread(fd, $0.baseAddress, $0.count, off_t(offset))
                }
                guard count == span else {
                    return RecoveryProbe.CommandBox(["errno": Int(errno), "offset": offset])
                }
                if buffer.contains(where: { $0 != 0 }) { blank = false }
            }
            return RecoveryProbe.CommandBox(["blank": blank, "bytesChecked": span * 2])
        }.value
    }

    static func readMarker(_ volume: URL) -> [String: Any]? {
        let path = volume.appendingPathComponent(markerName)
        guard let handle = try? FileHandle(forReadingFrom: path) else { return nil }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: 4097), data.count <= 4096 else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    static func ownsVolume(_ marker: [String: Any]?, target: String, lun: UInt16) -> Bool {
        guard let marker else { return false }
        return marker["harness"] as? String == harnessName && marker["version"] as? Int == 1
            && marker["targetName"] as? String == target && marker["lun"] as? Int == Int(lun)
    }

    static func writeMarker(_ volume: URL, target: String, lun: UInt16, nonce: UUID) throws {
        let value: [String: Any] = [
            "harness": harnessName, "version": 1, "targetName": target, "lun": Int(lun),
            "formattedRun": nonce.uuidString.lowercased(),
            "formattedAt": ISO8601DateFormatter().string(from: Date()),
        ]
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let path = volume.appendingPathComponent(markerName).path
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o644)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard written == data.count, fcntl(fd, F_FULLFSYNC) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    static func space(_ path: String) -> [String: Any] {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return ["errno": Int(errno)] }
        let block = UInt64(info.f_bsize)
        let type = withUnsafeBytes(of: &info.f_fstypename) {
            String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
        }
        return [
            "totalBytes": info.f_blocks * block, "freeBytes": info.f_bfree * block,
            "availableBytes": info.f_bavail * block, "fileSystem": type,
            "readOnly": info.f_flags & UInt32(MNT_RDONLY) != 0,
        ]
    }

    static func session(_ spec: Spec, root: URL, nonce: UUID) async throws {
        var current = "validate"
        var removeCredential: (@Sendable () async throws -> Void)?
        var owner: AttachmentCoordinator?
        do {
            stage(current)
            let portal = try Portal(spec.portal)
            guard let target = spec.targetName, let lun = spec.lun, let readOnly = spec.readOnly,
                let capacity = spec.expectedCapacity, let blockSize = spec.expectedBlockSize,
                let policy = spec.volumePolicy,
                ["format-or-reuse", "reuse", "observe"].contains(policy), let isidText = spec.isid
            else { throw Failure("Incomplete session specification") }
            guard policy != "format-or-reuse" || !readOnly else {
                throw Failure("Formatting needs a read-write connection")
            }
            let volumeName = spec.volumeName ?? "iSCSI-XT"
            guard volumeName.range(of: "^[A-Za-z0-9-]{1,27}$", options: .regularExpression) != nil
            else { throw Failure("Invalid volume name") }
            let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
            let coordinator = try AttachmentCoordinator(
                backend: SystemAttachmentBackend(root: mounts),
                journal: FileAttachmentJournal(
                    directory: root.appendingPathComponent("State", isDirectory: true),
                    bridgeRoot: mounts))
            try await coordinator.restore()
            guard await coordinator.disks.isEmpty else {
                throw Failure("A connection of an earlier session in this root remains")
            }
            owner = coordinator
            // Only a connection that may format needs the baseline. `diskutil list` has stopped
            // answering on this Mac before (ENV086) while `diskutil info` still did.
            var baseline: Set<String>?
            if policy == "format-or-reuse" {
                current = "baseline"
                stage(current)
                baseline = try await wholeDisks()
            }

            current = "credential"
            if let user = spec.chapUser {
                stage(current)
                let secret = try readSecret(spec.secretFile ?? "")
                let context = CredentialContext(
                    profileID: nonce, portal: portal, username: user, credentialID: nonce,
                    targetUsername: spec.targetChapUser)
                let file = root.appendingPathComponent(credentialFile)
                try JSONEncoder().encode(context).write(to: file, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600], ofItemAtPath: file.path)
                removeCredential = {
                    _ = try await ExternalTargetProbe.removeCredential(root: root, nonce: nonce)
                }
                let store = KeychainCredentialStore.sharedForCurrentBundle()
                // An interrupted earlier session of this run may have left the same item.
                try? await store.remove(context: context)
                if let targetFile = spec.targetSecretFile {
                    try await store.save(
                        password: secret, targetPassword: readSecret(targetFile), context: context)
                } else {
                    try await store.save(password: secret, context: context)
                }
            }
            let descriptor = try ConnectionDescriptor(
                profileID: nonce, portal: portal, initiatorName: spec.initiatorName,
                targetName: target, lun: LogicalUnit(lun), readOnly: readOnly,
                chapUsername: spec.chapUser, isid: parseISID(isidText),
                credentialID: spec.chapUser == nil ? nil : nonce,
                targetCHAPUsername: spec.targetChapUser, portalGroupTag: spec.portalGroupTag)

            current = "connect"
            stage(current)
            let started = RecoveryProbe.now()
            let disk = try await coordinator.connect(descriptor)
            var ready: [String: Any] = [
                "diskID": disk.id.uuidString, "bridge": disk.bridgeURL.path,
                "image": disk.bridgeURL.appendingPathComponent("Disk.img").path,
                "connectMS": RecoveryProbe.milliseconds(started, RecoveryProbe.now()),
                "mountID": disk.descriptor.mountID?.uuidString ?? "",
                "readOnly": disk.descriptor.readOnly, "connectionState": "\(disk.connectionState)",
                "volumePolicy": policy,
            ]
            if let route = disk.connectionRoute {
                ready["connectedPortal"] = route.connectedPortal.description
                ready["contactedPortals"] = route.contactedPortals.map(\.description)
                ready["permanentRedirects"] = route.permanentRedirects.count
            }
            let volume: URL
            do {
                current = "device-checks"
                stage(current)
                let (attachment, device) = try await ownedDevice(
                    disk, readOnly: readOnly, capacity: capacity, blockSize: blockSize,
                    baseline: baseline)
                ready["deviceChecks"] = device
                ready["device"] = attachment.device
                ready["volumeCount"] = attachment.volumeURLs.count
                let image = disk.bridgeURL.appendingPathComponent("Disk.img")
                var found: URL?
                if attachment.volumeURLs.count == 1, let only = attachment.volumeURLs.first {
                    let marker = readMarker(only)
                    ready["marker"] = marker.map { $0 as Any } ?? NSNull()
                    if ownsVolume(marker, target: target, lun: lun) {
                        found = only
                        ready["volumeState"] = "reused"
                    } else if policy == "observe" {
                        found = only
                        ready["volumeState"] = "present-unowned"
                    } else {
                        throw Failure(
                            "The LUN holds a volume this harness did not create (no matching \(markerName)); refusing to use or erase it"
                        )
                    }
                } else if attachment.volumeURLs.count > 1 {
                    guard policy == "observe" else {
                        throw Failure(
                            "The LUN holds \(attachment.volumeURLs.count) volumes; refusing to use or erase it"
                        )
                    }
                    ready["volumeState"] = "several"
                } else {
                    current = "blank-check"
                    stage(current)
                    let blank = await rawBlank(image, capacity: capacity)
                    ready["raw"] = blank
                    let isBlank =
                        blank["blank"] as? Bool == true
                        && (device["content"] as? String ?? "").isEmpty
                    ready["volumeState"] = isBlank ? "blank" : "unrecognized"
                    if policy == "format-or-reuse" {
                        guard isBlank else {
                            throw Failure(
                                "The LUN has no volume this Mac can mount but is not blank (partition map or data in its first or last MiB); refusing to erase it"
                            )
                        }
                        guard spec.allowErase == true else {
                            throw Failure("The LUN is blank; pass --allow-erase to format it")
                        }
                        current = "format"
                        stage(current)
                        let began = RecoveryProbe.now()
                        // The only formatting call takes the device just verified above.
                        let arguments = [
                            "partitionDisk", attachment.device, "GPT", "APFS", volumeName, "100%",
                        ]
                        _ = try await SystemCommand.run(
                            "/usr/sbin/diskutil", arguments: arguments, timeout: 120)
                        guard
                            let formatted = try await DiskImages().inventory().attachment(
                                at: image), formatted.device == attachment.device,
                            formatted.volumeURLs.count == 1, let only = formatted.volumeURLs.first
                        else {
                            throw Failure(
                                "After formatting, hdiutil does not list exactly one volume on \(attachment.device)"
                            )
                        }
                        try writeMarker(only, target: target, lun: lun, nonce: nonce)
                        ready["format"] = [
                            "command": ["/usr/sbin/diskutil"] + arguments,
                            "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                        ]
                        ready["volumeState"] = "formatted"
                        ready["marker"] = readMarker(only).map { $0 as Any } ?? NSNull()
                        found = only
                    } else if policy == "reuse" {
                        throw Failure(
                            "The LUN has no volume; an earlier step of this run should have formatted it"
                        )
                    }
                }
                volume = found ?? disk.bridgeURL
                ready["volume"] = found?.path ?? ""
                ready["space"] = found.map { space($0.path) as Any } ?? NSNull()
                if let required = spec.requiredFreeBytes, let found {
                    let available = space(found.path)["availableBytes"] as? UInt64 ?? 0
                    guard available >= required else {
                        throw Failure(
                            "The volume has \(available / 1_048_576) MiB available; this run needs \(required / 1_048_576) MiB. Remove files of earlier runs or erase the LUN on the target"
                        )
                    }
                }
            } catch {
                // Release before reporting; the harness takes the forced path if this fails.
                do { try await coordinator.eject(disk.id) } catch {
                    RecoveryProbe.emit(
                        "CLEANUP", ["eject": "failed", "error": RecoveryProbe.errorText(error)])
                }
                throw error
            }
            let image = disk.bridgeURL.appendingPathComponent("Disk.img").path
            let session = RecoveryProbe.Session(
                coordinator: coordinator, disk: disk, volume: volume, root: root, nonce: nonce,
                removeCredential: removeCredential,
                extraCommands: { name, box in
                    await ExternalTargetProbe.command(
                        name, box.value, volume: volume, image: image, root: root, nonce: nonce)
                })
            RecoveryProbe.emit("READY", ready)
            session.sampler.start()
            session.startHealthTask()
            await session.serve()
        } catch {
            RecoveryProbe.emit("FAILED", ["stage": current, "error": errorText(error)])
            // Only when no disk of this root remains; otherwise the harness recovers the disk
            // first and then removes the credential (--external-credential-remove).
            if let removeCredential, await owner?.disks.isEmpty ?? true {
                try? await removeCredential()
            }
            throw error
        }
    }

    // MARK: Commands

    static func validName(_ name: Any?) -> String? {
        guard let name = name as? String,
            name.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$", options: .regularExpression)
                != nil
        else { return nil }
        return name
    }

    static func command(
        _ name: String, _ command: [String: Any], volume: URL, image: String, root: URL,
        nonce: UUID
    ) async -> [String: Any]? {
        switch name {
        case "file-hash":
            guard let file = validName(command["name"]) else {
                return ["ok": false, "error": "invalid name"]
            }
            let path = volume.appendingPathComponent(file).path
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                let began = RecoveryProbe.now()
                let fd = open(path, O_RDONLY | O_CLOEXEC)
                guard fd >= 0 else {
                    return RecoveryProbe.CommandBox(["ok": false, "errno": Int(errno)])
                }
                defer { close(fd) }
                _ = fcntl(fd, F_NOCACHE, 1)
                var hasher = SHA256()
                var buffer = [UInt8](repeating: 0, count: 1_048_576)
                var total = 0
                while true {
                    let count = buffer.withUnsafeMutableBytes {
                        pread(fd, $0.baseAddress, $0.count, off_t(total))
                    }
                    if count < 0 {
                        return RecoveryProbe.CommandBox([
                            "ok": false, "errno": Int(errno), "bytes": total,
                        ])
                    }
                    if count == 0 { break }
                    hasher.update(data: buffer[0..<count])
                    total += count
                }
                let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
                return RecoveryProbe.CommandBox([
                    "ok": true, "bytes": total, "sha256": digest,
                    "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                ])
            }.value
        case "write-attempt":
            // Never writes data: an open for writing that succeeds is closed (and a new file
            // removed) at once and reported.
            let created = validName(command["name"])
            let existing = validName(command["existing"])
            guard created != nil || existing != nil else {
                return ["ok": false, "error": "invalid name"]
            }
            let base = volume.path
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                var result: [String: Any] = ["ok": true]
                if let created {
                    let path = base + "/" + created
                    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                    let code = errno
                    if fd >= 0 {
                        close(fd)
                        result["createRemoved"] = unlink(path) == 0
                    }
                    result["createOpened"] = fd >= 0
                    result["createErrno"] = fd >= 0 ? 0 : Int(code)
                }
                if let existing {
                    let fd = open(base + "/" + existing, O_WRONLY | O_CLOEXEC)
                    let code = errno
                    if fd >= 0 { close(fd) }
                    result["existingOpened"] = fd >= 0
                    result["existingErrno"] = fd >= 0 ? 0 : Int(code)
                }
                return RecoveryProbe.CommandBox(result)
            }.value
        case "raw-write-attempt":
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                let fd = open(image, O_WRONLY | O_CLOEXEC)
                let code = errno
                if fd >= 0 { close(fd) }
                return RecoveryProbe.CommandBox([
                    "ok": true, "opened": fd >= 0, "errno": fd >= 0 ? 0 : Int(code),
                ])
            }.value
        case "statfs":
            let path = volume.path
            return await RecoveryProbe.blocking {
                RecoveryProbe.CommandBox(["ok": true, "space": space(path)])
            }.value
        case "delete-file":
            guard let file = validName(command["name"]) else {
                return ["ok": false, "error": "invalid name"]
            }
            let directory = volume.path
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                let before = space(directory)
                let began = RecoveryProbe.now()
                let removed = unlink(directory + "/" + file)
                let code = errno
                var synchronized: Int32 = -1
                let fd = open(directory, O_RDONLY | O_CLOEXEC)
                if fd >= 0 {
                    synchronized = fcntl(fd, F_FULLFSYNC)
                    if synchronized != 0 { synchronized = fsync(fd) }
                    close(fd)
                }
                return RecoveryProbe.CommandBox([
                    "ok": removed == 0, "errno": removed == 0 ? 0 : Int(code),
                    "directorySynchronized": synchronized == 0,
                    "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                    "before": before, "after": space(directory),
                ])
            }.value
        case "verify-ledgers":
            guard let names = command["ledgers"] as? [String], !names.isEmpty, names.count <= 16,
                names.allSatisfy({
                    $0.range(
                        of: "^RecoveryLedger-[A-Za-z0-9-]{1,32}\\.json$",
                        options: .regularExpression) != nil
                })
            else { return ["ok": false, "error": "invalid ledgers"] }
            // An earlier run's ledgers (--verify-prior) carry that run's nonce.
            let ledgerNonce: UUID
            if let text = command["nonce"] as? String {
                guard let other = UUID(uuidString: text) else {
                    return ["ok": false, "error": "invalid nonce"]
                }
                ledgerNonce = other
            } else {
                ledgerNonce = nonce
            }
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                var failures: [String] = []
                var observations: [String] = []
                var results: [[String: Any]] = []
                for name in names {
                    do {
                        let data = try Data(contentsOf: root.appendingPathComponent(name))
                        let ledger =
                            try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
                        let result = try RecoveryProbe.verifyLedger(
                            ledger, volume: volume, nonce: ledgerNonce, cutoff: nil, grace: 0,
                            strictSyncs: ["fullfsync", "fsync"])
                        failures += result["failures"] as? [String] ?? []
                        observations += result["observations"] as? [String] ?? []
                        results.append(["ledger": name, "counts": result["counts"] ?? [:]])
                    } catch {
                        failures.append("\(name): \(RecoveryProbe.errorText(error))")
                    }
                }
                return RecoveryProbe.CommandBox([
                    "ok": failures.isEmpty, "failures": Array(failures.prefix(32)),
                    "failureCount": failures.count,
                    "observations": Array(observations.prefix(32)), "ledgers": results,
                ])
            }.value
        case "list-volume":
            let path = volume.path
            return await RecoveryProbe.blocking { () -> RecoveryProbe.CommandBox in
                let names =
                    ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted()
                return RecoveryProbe.CommandBox([
                    "ok": true, "names": Array(names.prefix(256)), "count": names.count,
                ])
            }.value
        default:
            return nil
        }
    }

    // MARK: Credential

    /// Removes the session's CHAP credential, confirms that the keychain no longer has it and
    /// deletes the context file. False when this root recorded none.
    @discardableResult
    static func removeCredential(root: URL, nonce: UUID) async throws -> Bool {
        let file = root.appendingPathComponent(credentialFile)
        guard FileManager.default.fileExists(atPath: file.path) else { return false }
        let context = try JSONDecoder().decode(CredentialContext.self, from: Data(contentsOf: file))
        guard context.profileID == nonce, context.credentialID == nonce,
            context.use == .connection
        else { throw Failure("Invalid external credential context") }
        let store = KeychainCredentialStore.sharedForCurrentBundle()
        try await store.remove(context: context)
        do {
            _ = try await store.credentials(context: context)
            throw Failure("The external CHAP credential remains in the keychain")
        } catch let error as NSError
            where error.domain == NSOSStatusErrorDomain && error.code == Int(errSecItemNotFound)
        {}
        try FileManager.default.removeItem(at: file)
        return true
    }
}
