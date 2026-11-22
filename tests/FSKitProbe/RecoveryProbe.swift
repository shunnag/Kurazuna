import CryptoKit
import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// An interactive connection owner for real-target fault injection (scripts/test-lio-recovery.py).
///
/// The harness sends one JSON command per stdin line and reads `RECOVERY_<KIND> <json>` lines.
/// Every event carries `uptimeNS` (mach absolute time in nanoseconds), the clock Python's
/// `time.monotonic_ns()` uses on macOS. The disk is connected, ejected and force ejected through
/// the production `AttachmentCoordinator` and `SystemAttachmentBackend`, as the app does.
enum RecoveryProbe {
    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    private static let outputLock = NSLock()

    static func emit(_ kind: String, _ object: [String: Any]) {
        var value = object
        if value["uptimeNS"] == nil { value["uptimeNS"] = now() }
        guard JSONSerialization.isValidJSONObject(value),
            let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        else {
            outputLock.withLock {
                FileHandle.standardOutput.write(Data("RECOVERY_INVALID_EVENT \(kind)\n".utf8))
            }
            return
        }
        outputLock.withLock {
            FileHandle.standardOutput.write(Data("RECOVERY_\(kind) ".utf8) + data + Data([10]))
        }
    }

    static func milliseconds(_ start: UInt64, _ end: UInt64) -> Double {
        Double(end &- start) / 1_000_000
    }

    static func errorText(_ error: any Error) -> String {
        "\(type(of: error)): \(error)"
    }

    // MARK: Deterministic contents

    /// Bytes of one version of one slot. Verification recomputes them from the ledger alone.
    static func content(nonce: UUID, writer: Int, slot: Int, version: Int, size: Int) -> Data {
        var state: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in nonce.uuidString.lowercased().utf8 {
            state = (state ^ UInt64(byte)) &* 0x0000_0100_0000_01b3
        }
        for value in [UInt64(writer), UInt64(slot), UInt64(version), UInt64(size)] {
            state = (state ^ value) &* 0x0000_0100_0000_01b3
        }
        var data = Data(count: size)
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            var index = 0
            while index < size {
                state &+= 0x9e37_79b9_7f4a_7c15
                var z = state
                z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
                z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
                z ^= z >> 31
                for shift in stride(from: 0, to: 64, by: 8) where index < size {
                    raw[index] = UInt8(truncatingIfNeeded: z >> UInt64(shift))
                    index += 1
                }
            }
        }
        return data
    }

    /// Runs blocking file system calls on a dedicated thread, never on the cooperative pool.
    static func blocking<Value: Sendable>(_ body: @escaping @Sendable () -> Value) async -> Value {
        await withCheckedContinuation { continuation in
            let thread = Thread { continuation.resume(returning: body()) }
            thread.name = "recovery-blocking"
            thread.start()
        }
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Unaligned and aligned sizes up to one large chunk, repeated, so APFS and DiskImages
    /// issue partial-sector, multi-sector and multi-chunk writes.
    static let slotSizes: [Int] = {
        let group = [1, 511, 512, 513, 4093, 4096, 4097, 65_536, 65_573, 131_077]
        return Array((0..<3).map { _ in group }.joined())
    }()

    static func slotOffsets(_ sizes: [Int]) -> [Int] {
        var offsets: [Int] = []
        var cursor = 0
        for size in sizes {
            offsets.append(cursor)
            cursor += size
        }
        return offsets
    }

    // MARK: Session

    /// The disposable mutual CHAP pair of a `-mutual-chap` run: the first stdin line, a JSON
    /// object with exactly `password` and `targetPassword`, read before any command. Neither
    /// secret is printed; the Keychain store checks both (12 to 1024 bytes, different).
    static func suppliedSecrets() async throws -> FSKitProbe.SuppliedSecrets {
        let line: String? = await blocking { readLine(strippingNewline: true) }
        guard let data = line?.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            object.count == 2, let password = object["password"] as? String,
            let targetPassword = object["targetPassword"] as? String
        else { throw Failure("The mutual CHAP secrets were not supplied on standard input") }
        return FSKitProbe.SuppliedSecrets(password: password, targetPassword: targetPassword)
    }

    static func run(
        portal: Portal, root: URL, nonce: UUID, chap: Bool, mutualCHAP: Bool,
        readOnly: Bool = false
    ) async throws {
        let lowered = nonce.uuidString.lowercased()
        let configuration = try LoginConfiguration(
            initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + lowered,
            targetName: "iqn.2026-10.dev.soba:lio-" + lowered)
        if chap {
            // Mutual CHAP uses the harness's disposable pair (scripts/test-lio-recovery.py).
            let secrets = mutualCHAP ? try await suppliedSecrets() : nil
            try await FSKitProbe.saveFixtureCredential(
                portal: portal, root: root, nonce: nonce, mutualCHAP: mutualCHAP,
                secrets: secrets)
        }
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
            targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: readOnly,
            chapUsername: chap ? "test-user" : nil, isid: configuration.isid,
            credentialID: chap ? nonce : nil,
            targetCHAPUsername: mutualCHAP ? "test-server" : nil)
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: SystemAttachmentBackend(root: mounts),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        let started = now()
        let disk: AttachedDisk
        do {
            disk = try await coordinator.connect(descriptor)
        } catch {
            if chap { try? await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce) }
            throw error
        }
        guard let volume = disk.attachment?.volumeURLs.first,
            disk.attachment?.volumeURLs.count == 1
        else {
            try? await coordinator.eject(disk.id)
            throw Failure("The recovery fixture volume was not attached")
        }
        let marker = Data("FSKit validation \(lowered)\n".utf8)
        guard try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt")) == marker
        else {
            try? await coordinator.eject(disk.id)
            throw Failure("The recovery fixture marker differs")
        }
        var removeCredential: (@Sendable () async throws -> Void)?
        if chap {
            removeCredential = {
                try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
            }
        }
        let session = Session(
            coordinator: coordinator, disk: disk, volume: volume, root: root, nonce: nonce,
            removeCredential: removeCredential)
        emit(
            "READY",
            [
                "diskID": disk.id.uuidString, "bridge": disk.bridgeURL.path,
                "image": disk.bridgeURL.appendingPathComponent("Disk.img").path,
                "volume": volume.path, "device": disk.attachment?.device ?? "",
                "connectMS": milliseconds(started, now()),
                "mountID": disk.descriptor.mountID?.uuidString ?? "",
                "readOnly": disk.descriptor.readOnly,
            ])
        session.sampler.start()
        session.startHealthTask()
        await session.serve()
    }

    // MARK: State sampling

    final class StateSampler: @unchecked Sendable {
        private let lock = NSLock()
        private let path: String
        private var running = false
        private var last: String?
        private var maximumLatency = 0.0
        private var slowSamples = 0
        private var samples = 0
        private var thread: Thread?

        init(path: String) { self.path = path }

        static func read(_ path: String) -> (String, Double) {
            let began = RecoveryProbe.now()
            var bytes = [UInt8](repeating: 0, count: 3)
            let count = bytes.withUnsafeMutableBytes {
                getxattr(
                    path, ConnectionDescriptor.connectionStateAttributeName, $0.baseAddress,
                    $0.count, 0, 0)
            }
            let code = errno
            let latency = RecoveryProbe.milliseconds(began, RecoveryProbe.now())
            guard count == 2 else { return ("unavailable-errno-\(code)", latency) }
            guard let state = try? DiskConnectionState(encoded: Data(bytes.prefix(2))) else {
                return ("malformed", latency)
            }
            return ("\(state)", latency)
        }

        func start() {
            lock.withLock { running = true }
            let thread = Thread { [self] in loop() }
            thread.name = "recovery-state"
            lock.withLock { self.thread = thread }
            thread.start()
        }

        func stop() { lock.withLock { running = false } }

        var summary: [String: Any] {
            lock.withLock {
                [
                    "last": last ?? "none", "maximumLatencyMS": maximumLatency,
                    "slowSamples": slowSamples, "samples": samples,
                ]
            }
        }

        private func loop() {
            while lock.withLock({ running }) {
                let (state, latency) = Self.read(path)
                let changed = lock.withLock {
                    samples += 1
                    maximumLatency = max(maximumLatency, latency)
                    if latency > 1000 { slowSamples += 1 }
                    defer { last = state }
                    return last != state
                }
                if changed { RecoveryProbe.emit("STATE", ["state": state, "latencyMS": latency]) }
                if latency > 1000 {
                    RecoveryProbe.emit("STATE_SLOW", ["state": state, "latencyMS": latency])
                }
                usleep(100_000)
            }
        }
    }

    // MARK: Command server

    final class Session: @unchecked Sendable {
        let coordinator: AttachmentCoordinator
        let disk: AttachedDisk
        let volume: URL
        let root: URL
        let nonce: UUID
        /// Removes this session's CHAP credential once no disk remains (on "exit").
        let removeCredential: (@Sendable () async throws -> Void)?
        /// Commands a caller adds (scripts/test-external-target.py); nil means unknown.
        let extraCommands: (@Sendable (String, CommandBox) async -> [String: Any]?)?
        let sampler: StateSampler
        private let lock = NSLock()
        private var workloads: [String: Workload] = [:]
        private var ejectTask: Task<EjectOutcome, Never>?
        private var healthTask: Task<Void, Never>?

        init(
            coordinator: AttachmentCoordinator, disk: AttachedDisk, volume: URL, root: URL,
            nonce: UUID, removeCredential: (@Sendable () async throws -> Void)?,
            extraCommands: (@Sendable (String, CommandBox) async -> [String: Any]?)? = nil
        ) {
            self.coordinator = coordinator
            self.disk = disk
            self.volume = volume
            self.root = root
            self.nonce = nonce
            self.removeCredential = removeCredential
            self.extraCommands = extraCommands
            sampler = StateSampler(path: disk.bridgeURL.appendingPathComponent("Disk.img").path)
        }

        var image: String { disk.bridgeURL.appendingPathComponent("Disk.img").path }

        func startHealthTask() {
            let coordinator = coordinator
            let id = disk.id
            healthTask = Task {
                var last = ""
                while !Task.isCancelled {
                    await coordinator.refreshHealth()
                    let record = await coordinator.disks.first { $0.id == id }
                    let text =
                        record.map {
                            "\($0.connectionState)/\($0.phase)/verificationFailed=\($0.verificationFailed)"
                        } ?? "absent"
                    if text != last {
                        RecoveryProbe.emit("COORDINATOR", ["record": text])
                        last = text
                    }
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }

        func stopHealthTask() async {
            let task = healthTask
            healthTask = nil
            task?.cancel()
            await task?.value
        }

        func serve() async {
            let lines = AsyncStream<String> { continuation in
                let thread = Thread {
                    while let line = readLine() { continuation.yield(line) }
                    continuation.finish()
                }
                thread.name = "recovery-commands"
                thread.start()
            }
            var tasks: [Task<Void, Never>] = []
            for await line in lines {
                guard let data = line.data(using: .utf8),
                    let command = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                    let id = command["id"] as? Int, let name = command["cmd"] as? String
                else {
                    RecoveryProbe.emit("RESULT", ["id": -1, "ok": false, "error": "malformed"])
                    continue
                }
                if name == "exit" {
                    for task in tasks { await task.value }
                    let result = await finish()
                    var response = result
                    response["id"] = id
                    RecoveryProbe.emit("RESULT", response)
                    return
                }
                let boxed = CommandBox(command)
                tasks.append(
                    Task {
                        RecoveryProbe.emit("ACCEPTED", ["id": id, "cmd": name])
                        var response = await self.handle(name, boxed.value)
                        response["id"] = id
                        response["cmd"] = name
                        if response["ok"] == nil { response["ok"] = true }
                        RecoveryProbe.emit("RESULT", response)
                    })
            }
            // The harness exited without an exit command. Leave resources for --recover-fixture.
            sampler.stop()
            for (_, workload) in lock.withLock({ workloads }) { workload.requestStop() }
            RecoveryProbe.emit("ABANDONED", ["reason": "stdin closed"])
        }

        private func finish() async -> [String: Any] {
            sampler.stop()
            await stopHealthTask()
            let remaining = await coordinator.disks
            var result: [String: Any] = ["ok": true, "remainingDisks": remaining.count]
            if remaining.isEmpty, let removeCredential {
                do {
                    try await removeCredential()
                    result["credentialRemoved"] = true
                } catch {
                    result["ok"] = false
                    result["error"] = RecoveryProbe.errorText(error)
                }
            }
            return result
        }

        private func handle(_ name: String, _ command: [String: Any]) async -> [String: Any] {
            switch name {
            case "ping":
                return [:]
            case "state":
                let image = image
                let read =
                    await RecoveryProbe.blocking {
                        CommandBox(["sample": StateSampler.read(image)])
                    }.value["sample"] as! (String, Double)
                return ["state": read.0, "latencyMS": read.1, "sampler": sampler.summary]
            case "workload-start":
                return startWorkload(command)
            case "workload-status":
                guard let workload = workload(command) else { return missingWorkload }
                return workload.status()
            case "workload-stop":
                guard let workload = workload(command) else { return missingWorkload }
                let timeout = command["timeoutSeconds"] as? Double ?? 300
                return await workload.stop(timeoutSeconds: timeout, root: root)
            case "file-write":
                return await fileWrite(command)
            case "abandon":
                // The write-only control on Disk.img, or with "root" on the bridge root.
                let path = command["root"] as? Bool == true ? disk.bridgeURL.path : image
                return await RecoveryProbe.blocking { () -> CommandBox in
                    let value = ConnectionDescriptor.abandonRecoveryControlValue
                    let began = RecoveryProbe.now()
                    let result = value.withUnsafeBytes {
                        setxattr(
                            path, ConnectionDescriptor.connectionControlAttributeName,
                            $0.baseAddress, $0.count, 0, 0)
                    }
                    let code = errno
                    return CommandBox([
                        "ok": result == 0, "errno": result == 0 ? 0 : Int(code),
                        "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                    ])
                }.value
            case "abandon-read":
                // The read-only volume's control: reading it stops reconnecting.
                let path = command["root"] as? Bool == true ? disk.bridgeURL.path : image
                return await RecoveryProbe.blocking { () -> CommandBox in
                    var bytes = [UInt8](repeating: 0, count: 16)
                    let began = RecoveryProbe.now()
                    let count = bytes.withUnsafeMutableBytes {
                        getxattr(
                            path, ConnectionDescriptor.readOnlyConnectionControlAttributeName,
                            $0.baseAddress, $0.count, 0, 0)
                    }
                    let code = errno
                    return CommandBox([
                        "ok": count >= 0, "errno": count >= 0 ? 0 : Int(code),
                        "value": count > 0
                            ? String(decoding: bytes.prefix(count), as: UTF8.self) : "",
                        "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                    ])
                }.value
            case "raw-read":
                return await rawRead(command)
            case "volfs-path":
                // Whether the bridge can be reached by file ID (/.vol/<fsid>/<inode>), which
                // would bypass the search permission of the directories above the mount.
                let image = image
                let bridge = disk.bridgeURL.path
                return await RecoveryProbe.blocking { () -> CommandBox in
                    var mount = statfs()
                    var info = stat()
                    guard statfs(bridge, &mount) == 0, lstat(image, &info) == 0 else {
                        return CommandBox(["ok": false, "errno": Int(errno)])
                    }
                    var results: [String: Any] = [:]
                    for (label, inode) in [("root", UInt64(2)), ("image", UInt64(info.st_ino))] {
                        let path = "/.vol/\(mount.f_fsid.val.0)/\(inode)"
                        var found = stat()
                        let statted = stat(path, &found)
                        let statErrno = statted == 0 ? 0 : Int(errno)
                        var bytes = [UInt8](repeating: 0, count: 3)
                        let count = bytes.withUnsafeMutableBytes {
                            getxattr(
                                path, ConnectionDescriptor.connectionStateAttributeName,
                                $0.baseAddress, $0.count, 0, 0)
                        }
                        results[label] = [
                            "path": path, "stat": statErrno, "getxattr": count,
                            "getxattrErrno": count >= 0 ? 0 : Int(errno),
                        ]
                    }
                    return CommandBox(["ok": true, "results": results])
                }.value
            case "stat-paths":
                // Who could reach the bridge's control attributes: every path component's
                // owner and mode, and the bridge mount's owner and flags.
                let paths = [
                    root.deletingLastPathComponent().path, root.path,
                    root.appendingPathComponent("Mounts").path, disk.bridgeURL.path, image,
                ]
                return await RecoveryProbe.blocking { () -> CommandBox in
                    var rows: [[String: Any]] = []
                    for path in paths {
                        var info = stat()
                        guard lstat(path, &info) == 0 else {
                            rows.append(["path": path, "errno": Int(errno)])
                            continue
                        }
                        rows.append([
                            "path": path, "uid": Int(info.st_uid), "gid": Int(info.st_gid),
                            "mode": String(info.st_mode & 0o7777, radix: 8),
                        ])
                    }
                    var mount = statfs()
                    let mounted = statfs(paths[3], &mount) == 0
                    return CommandBox([
                        "paths": rows, "processUID": Int(getuid()),
                        "bridgeOwner": mounted ? Int(mount.f_owner) : -1,
                        "bridgeFlags": mounted ? String(mount.f_flags, radix: 16) : "",
                    ])
                }.value
            case "eject":
                return await eject(timeoutSeconds: command["timeoutSeconds"] as? Double ?? 300)
            case "eject-wait":
                return await waitForEject(
                    timeoutSeconds: command["timeoutSeconds"] as? Double ?? 300)
            case "can-force":
                return ["canPrepare": await coordinator.canPrepareForceEjection(disk.id)]
            case "force-eject":
                return await forceEject()
            case "stop-sampler":
                sampler.stop()
                await stopHealthTask()
                return ["sampler": sampler.summary]
            case "inventory":
                return await inventory()
            default:
                if let extraCommands, let result = await extraCommands(name, CommandBox(command)) {
                    return result
                }
                return ["ok": false, "error": "unknown command"]
            }
        }

        private var missingWorkload: [String: Any] { ["ok": false, "error": "unknown workload"] }

        private func workload(_ command: [String: Any]) -> Workload? {
            guard let label = command["label"] as? String else { return nil }
            return lock.withLock { workloads[label] }
        }

        private func startWorkload(_ command: [String: Any]) -> [String: Any] {
            guard let label = command["label"] as? String,
                label.range(of: "^[A-Za-z0-9-]{1,32}$", options: .regularExpression) != nil
            else { return ["ok": false, "error": "invalid label"] }
            let syncs = command["writers"] as? [String] ?? ["fullfsync", "fsync"]
            guard !syncs.isEmpty, syncs.count <= 4,
                syncs.allSatisfy({ ["fullfsync", "fsync"].contains($0) })
            else { return ["ok": false, "error": "invalid writers"] }
            let options = Workload.Options(
                label: label, syncs: syncs, readers: command["readers"] as? Int ?? 1,
                rawReader: command["rawReader"] as? Bool ?? true,
                pauseMilliseconds: command["pauseMS"] as? Int ?? 20)
            let workload = Workload(
                options: options, volume: volume, image: image, nonce: nonce)
            let inserted = lock.withLock {
                guard workloads[label] == nil else { return false }
                workloads[label] = workload
                return true
            }
            guard inserted else { return ["ok": false, "error": "duplicate workload"] }
            do {
                try workload.prepare()
            } catch {
                // prepare() closed every file it opened; a failed workload stays unregistered,
                // so nothing of it can keep the volume busy.
                lock.withLock {
                    if workloads[label] === workload { workloads[label] = nil }
                }
                return ["ok": false, "error": RecoveryProbe.errorText(error)]
            }
            workload.start()
            return ["ok": true, "files": workload.fileNames]
        }

        /// Writes one new file of deterministic contents. `sync` is "none" (dirty data left in
        /// the cache for an unmount to flush), "fsync" or "fullfsync". Runs on its own thread.
        private func fileWrite(_ command: [String: Any]) async -> [String: Any] {
            let size = command["bytes"] as? Int ?? 1_048_576
            let sync = command["sync"] as? String ?? "none"
            guard (1...67_108_864).contains(size), ["none", "fsync", "fullfsync"].contains(sync),
                let label = command["label"] as? String,
                label.range(of: "^[A-Za-z0-9-]{1,32}$", options: .regularExpression) != nil
            else { return ["ok": false, "error": "invalid file write"] }
            let name = "RECOVERY-\(label)-file.bin"
            let path = volume.appendingPathComponent(name).path
            let data = RecoveryProbe.content(
                nonce: nonce, writer: 98, slot: 0, version: 1, size: size)
            let digest = RecoveryProbe.sha256(data)
            let box = CommandBox(["data": data])
            return await RecoveryProbe.blocking { () -> CommandBox in
                let data = box.value["data"] as! Data
                let began = RecoveryProbe.now()
                let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                guard fd >= 0 else { return CommandBox(["ok": false, "errno": Int(errno)]) }
                let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
                let writeCode = errno
                let wrote = RecoveryProbe.now()
                var synchronized: Int32 = 0
                var syncCode: Int32 = 0
                if written == data.count, sync != "none" {
                    synchronized = sync == "fullfsync" ? fcntl(fd, F_FULLFSYNC) : fsync(fd)
                    syncCode = errno
                }
                let synced = RecoveryProbe.now()
                let closed = close(fd)
                let closeCode = errno
                return CommandBox([
                    "ok": written == data.count && synchronized == 0 && closed == 0,
                    "written": written, "writeErrno": written == data.count ? 0 : Int(writeCode),
                    "syncErrno": synchronized == 0 ? 0 : Int(syncCode),
                    "closeErrno": closed == 0 ? 0 : Int(closeCode), "name": name,
                    "size": data.count, "sha256": digest, "sync": sync, "startNS": began,
                    "writeMS": RecoveryProbe.milliseconds(began, wrote),
                    "syncMS": RecoveryProbe.milliseconds(wrote, synced),
                    "syncReturnedNS": synced,
                ])
            }.value
        }

        /// One uncached read of the raw Disk.img, by default from the bridge (the FSKit file) or
        /// with "volume" a file in the inner volume, on its own thread. During an outage it
        /// waits in the extension, as an application's read would.
        private func rawRead(_ command: [String: Any]) async -> [String: Any] {
            let offset = command["offset"] as? Int ?? 0
            let length = command["length"] as? Int ?? 4096
            guard offset >= 0, (1...1_048_576).contains(length) else {
                return ["ok": false, "error": "invalid read"]
            }
            let path: String
            if let name = command["volume"] as? String {
                guard name.range(of: "^[A-Za-z0-9.-]{1,64}$", options: .regularExpression) != nil
                else { return ["ok": false, "error": "invalid name"] }
                path = volume.appendingPathComponent(name).path
            } else {
                path = image
            }
            return await RecoveryProbe.blocking { () -> CommandBox in
                let began = RecoveryProbe.now()
                let fd = open(path, O_RDONLY | O_CLOEXEC)
                guard fd >= 0 else {
                    return CommandBox(["ok": false, "errno": Int(errno), "phase": "open"])
                }
                _ = fcntl(fd, F_NOCACHE, 1)
                var buffer = [UInt8](repeating: 0, count: length)
                let count = buffer.withUnsafeMutableBytes {
                    pread(fd, $0.baseAddress, $0.count, off_t(offset))
                }
                let code = errno
                let ended = RecoveryProbe.now()
                close(fd)
                return CommandBox([
                    "ok": count >= 0, "count": count, "errno": count >= 0 ? 0 : Int(code),
                    "startNS": began, "endNS": ended,
                    "elapsedMS": RecoveryProbe.milliseconds(began, ended),
                ])
            }.value
        }

        private func eject(timeoutSeconds: Double) async -> [String: Any] {
            let existing = lock.withLock { ejectTask }
            guard existing == nil else { return ["ok": false, "error": "eject already started"] }
            await stopHealthTask()
            let coordinator = coordinator
            let id = disk.id
            let started = RecoveryProbe.now()
            let task = Task { () -> EjectOutcome in
                do {
                    try await coordinator.eject(id)
                    return EjectOutcome(
                        status: "succeeded", error: nil,
                        elapsedMS: RecoveryProbe.milliseconds(started, RecoveryProbe.now()))
                } catch {
                    return EjectOutcome(
                        status: "failed", error: RecoveryProbe.errorText(error),
                        elapsedMS: RecoveryProbe.milliseconds(started, RecoveryProbe.now()))
                }
            }
            lock.withLock { ejectTask = task }
            RecoveryProbe.emit("EJECT_STARTED", ["startedNS": started])
            return await waitForEject(timeoutSeconds: timeoutSeconds)
        }

        private func waitForEject(timeoutSeconds: Double) async -> [String: Any] {
            guard let task = lock.withLock({ ejectTask }) else {
                return ["ok": false, "error": "no eject"]
            }
            let deadline = ContinuousClock.now.advanced(
                by: .milliseconds(Int(timeoutSeconds * 1000)))
            let done = Completion<EjectOutcome>()
            Task {
                let value = await task.value
                done.finish(value)
            }
            while ContinuousClock.now < deadline {
                if let value = done.value {
                    lock.withLock { ejectTask = nil }
                    var result: [String: Any] = [
                        "status": value.status, "elapsedMS": value.elapsedMS,
                        "error": value.error ?? NSNull(),
                    ]
                    result["remainingDisks"] = await coordinator.disks.count
                    result["canPrepareForce"] = await coordinator.canPrepareForceEjection(
                        disk.id)
                    RecoveryProbe.emit("EJECT_FINISHED", result)
                    return result
                }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return ["status": "pending"]
        }

        private func forceEject() async -> [String: Any] {
            await stopHealthTask()
            var result: [String: Any] = [:]
            let began = RecoveryProbe.now()
            let id = disk.id
            result["canPrepareBefore"] = await coordinator.canPrepareForceEjection(id)
            do {
                let request = try await coordinator.prepareForceEjection(id)
                result["prepareMS"] = RecoveryProbe.milliseconds(began, RecoveryProbe.now())
                result["reportsLostConnection"] = request.reportsLostConnection
                result["displayName"] = request.displayName
                let confirmed = RecoveryProbe.now()
                try await coordinator.forceEject(request)
                result["forceMS"] = RecoveryProbe.milliseconds(confirmed, RecoveryProbe.now())
                result["status"] = "succeeded"
            } catch {
                result["status"] = "failed"
                result["error"] = RecoveryProbe.errorText(error)
            }
            result["elapsedMS"] = RecoveryProbe.milliseconds(began, RecoveryProbe.now())
            result["remainingDisks"] = await coordinator.disks.count
            result["ok"] = result["status"] as? String == "succeeded"
            return result
        }

        private func inventory() async -> [String: Any] {
            var result: [String: Any] = [:]
            let disks = await coordinator.disks
            result["disks"] = disks.map {
                "\($0.phase)/\($0.connectionState)/verificationFailed=\($0.verificationFailed)"
            }
            let journal = root.appendingPathComponent("State/Connections.json")
            if let data = try? Data(contentsOf: journal),
                let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let entries = value["entries"] as? [Any]
            {
                result["journalEntries"] = entries.count
            } else {
                result["journalEntries"] = -1
            }
            var mounted: [String] = []
            var count = getfsstat(nil, 0, MNT_NOWAIT)
            if count > 0 {
                var buffer: [statfs] = .init(repeating: statfs(), count: Int(count) + 16)
                count = buffer.withUnsafeMutableBufferPointer {
                    getfsstat(
                        $0.baseAddress, Int32($0.count * MemoryLayout<statfs>.stride),
                        MNT_NOWAIT)
                }
                for var entry in buffer.prefix(Int(max(count, 0))) {
                    let path = withUnsafeBytes(of: &entry.f_mntonname) {
                        String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                    }
                    let source = withUnsafeBytes(of: &entry.f_mntfromname) {
                        String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                    }
                    if path.hasPrefix(root.path + "/") || path == volume.path
                        || source.hasPrefix(root.path + "/")
                    {
                        mounted.append(path)
                    }
                }
            }
            result["mounts"] = mounted
            do {
                let images = try await DiskImages().inventory().imagePaths
                result["images"] = images.filter { $0.hasPrefix(root.path + "/") }
            } catch {
                result["imagesError"] = RecoveryProbe.errorText(error)
            }
            let resources = root.appendingPathComponent("Mounts/.Resources", isDirectory: true)
            result["markerFiles"] =
                (try? FileManager.default.contentsOfDirectory(atPath: resources.path)) ?? []
            result["bridgeDirectoryExists"] = FileManager.default.fileExists(
                atPath: disk.bridgeURL.path)
            do {
                let reference = try ConnectionResourceReference(descriptor: disk.descriptor)
                _ = try await KeychainMountResourceStore.sharedForCurrentBundle().resolve(
                    reference)
                result["keychainItem"] = "present"
            } catch let error as NSError
                where error.domain == NSOSStatusErrorDomain
                && error.code == Int(errSecItemNotFound)
            {
                result["keychainItem"] = "absent"
            } catch {
                result["keychainItem"] = "error: " + RecoveryProbe.errorText(error)
            }
            return result
        }
    }

    /// A parsed command, handed to the one task that handles it.
    final class CommandBox: @unchecked Sendable {
        let value: [String: Any]
        init(_ value: [String: Any]) { self.value = value }
    }

    struct EjectOutcome: Sendable {
        let status: String
        let error: String?
        let elapsedMS: Double
    }

    final class Completion<Value: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        func finish(_ value: Value) { lock.withLock { stored = value } }
        var value: Value? { lock.withLock { stored } }
    }

    // MARK: Workload

    /// Writers overwrite fixed slots of their own file with new versions, each followed by
    /// F_FULLFSYNC or fsync. The ledger records when each version was issued and when its
    /// synchronization returned, which defines what a snapshot of the target must contain.
    final class Workload: @unchecked Sendable {
        struct Options {
            let label: String
            let syncs: [String]
            let readers: Int
            let rawReader: Bool
            let pauseMilliseconds: Int
        }

        struct Version {
            let slot: Int
            let version: Int
            let issuedNS: UInt64
            var writeReturnedNS: UInt64?
            var syncReturnedNS: UInt64?
            var errorOperation: String?
            var errorNumber: Int32?
        }

        final class Writer: @unchecked Sendable {
            let index: Int
            let sync: String
            let path: String
            var fd: Int32 = -1
            var versions: [Version] = []
            var current: [Int]
            var acknowledged: [Int]
            var busySlot: Int?
            /// Slots a reader is verifying; the writer waits before overwriting one.
            var readerSlots: [Int: Int] = [:]
            var stopped = false
            var failure: String?
            var steps = 0
            init(index: Int, sync: String, path: String, slots: Int) {
                self.index = index
                self.sync = sync
                self.path = path
                current = Array(repeating: 0, count: slots)
                acknowledged = Array(repeating: -1, count: slots)
            }
        }

        struct Stat {
            var count = 0
            var errors = 0
            var maximumMS = 0.0
            var totalMS = 0.0
            var slow: [[String: Any]] = []
        }

        let options: Options
        let volume: URL
        let image: String
        let nonce: UUID
        let offsets: [Int]
        private let lock = NSLock()
        private var running = false
        private var writers: [Writer] = []
        private var threads: [Thread] = []
        private var finished = 0
        private var stats: [String: Stat] = [:]
        private var errors: [[String: Any]] = []
        private var inflight: [String: (String, UInt64)] = [:]
        private var readMismatches = 0
        private let startedNS = RecoveryProbe.now()

        init(options: Options, volume: URL, image: String, nonce: UUID) {
            self.options = options
            self.volume = volume
            self.image = image
            self.nonce = nonce
            offsets = RecoveryProbe.slotOffsets(RecoveryProbe.slotSizes)
        }

        var fileNames: [String] { writers.map { URL(fileURLWithPath: $0.path).lastPathComponent } }

        func requestStop() { lock.withLock { running = false } }

        /// Creates every writer file and synchronizes version 0 of every slot before the
        /// scenario's fault, so each slot has an acknowledged base version. If that fails, it
        /// closes every file it opened before it rethrows the error, unchanged.
        func prepare() throws {
            do {
                try createWriters()
            } catch {
                for writer in writers where writer.fd >= 0 {
                    close(writer.fd)
                    writer.fd = -1
                }
                throw error
            }
        }

        private func createWriters() throws {
            for (index, sync) in options.syncs.enumerated() {
                let path = volume.appendingPathComponent(
                    "RECOVERY-\(options.label)-w\(index).bin"
                ).path
                let writer = Writer(
                    index: index, sync: sync, path: path, slots: RecoveryProbe.slotSizes.count)
                writer.fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                guard writer.fd >= 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                writers.append(writer)  // Before any write, so that a failure closes it too.
                for (slot, size) in RecoveryProbe.slotSizes.enumerated() {
                    let issued = RecoveryProbe.now()
                    let data = RecoveryProbe.content(
                        nonce: nonce, writer: index, slot: slot, version: 0, size: size)
                    let written = data.withUnsafeBytes {
                        pwrite(writer.fd, $0.baseAddress, $0.count, off_t(offsets[slot]))
                    }
                    guard written == size else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    writer.versions.append(
                        Version(
                            slot: slot, version: 0, issuedNS: issued,
                            writeReturnedNS: RecoveryProbe.now()))
                }
                guard fcntl(writer.fd, F_FULLFSYNC) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                let synchronized = RecoveryProbe.now()
                for index in writer.versions.indices {
                    writer.versions[index].syncReturnedNS = synchronized
                    writer.acknowledged[writer.versions[index].slot] = 0
                }
            }
        }

        func start() {
            lock.withLock { running = true }
            for writer in writers {
                spawn("writer-\(writer.index)") { [self] in writerLoop(writer) }
            }
            for reader in 0..<max(0, options.readers) {
                spawn("reader-\(reader)") { [self] in readerLoop(reader) }
            }
            if options.rawReader { spawn("raw-reader") { [self] in rawReaderLoop() } }
        }

        private func spawn(_ name: String, _ body: @escaping @Sendable () -> Void) {
            let thread = Thread { [self] in
                body()
                lock.withLock { finished += 1 }
            }
            thread.name = "recovery-\(options.label)-\(name)"
            lock.withLock { threads.append(thread) }
            thread.start()
        }

        private var isRunning: Bool { lock.withLock { running } }

        private func begin(_ key: String, _ operation: String) -> UInt64 {
            let began = RecoveryProbe.now()
            lock.withLock { inflight[key] = (operation, began) }
            return began
        }

        private func end(
            _ key: String, _ operation: String, began: UInt64, failed: Int32?,
            detail: [String: Any] = [:]
        ) {
            let ended = RecoveryProbe.now()
            let elapsed = RecoveryProbe.milliseconds(began, ended)
            var slowEvent: [String: Any]?
            lock.withLock {
                inflight[key] = nil
                var stat = stats[operation] ?? Stat()
                stat.count += 1
                stat.totalMS += elapsed
                stat.maximumMS = max(stat.maximumMS, elapsed)
                if failed != nil { stat.errors += 1 }
                if elapsed >= 1000, stat.slow.count < 256 {
                    let event: [String: Any] = [
                        "operation": operation, "thread": key, "startNS": began,
                        "endNS": ended, "elapsedMS": elapsed,
                        "errno": failed.map { Int($0) } ?? 0,
                    ]
                    stat.slow.append(event)
                    slowEvent = event
                }
                stats[operation] = stat
                if let failed, errors.count < 256 {
                    var event = detail
                    event["operation"] = operation
                    event["thread"] = key
                    event["errno"] = Int(failed)
                    event["startNS"] = began
                    event["endNS"] = ended
                    event["elapsedMS"] = elapsed
                    errors.append(event)
                }
            }
            if let failed {
                var event = detail
                event["operation"] = operation
                event["thread"] = key
                event["errno"] = Int(failed)
                event["elapsedMS"] = elapsed
                event["startNS"] = began
                RecoveryProbe.emit("IO_ERROR", event)
            } else if let slowEvent {
                RecoveryProbe.emit("IO_SLOW", slowEvent)
            }
        }

        private func writerLoop(_ writer: Writer) {
            let key = "writer-\(writer.index)"
            let sizes = RecoveryProbe.slotSizes
            var step = 0
            while isRunning {
                let slot = step % sizes.count
                step += 1
                var version: Int?
                while version == nil {
                    version = lock.withLock { () -> Int? in
                        guard writer.readerSlots[slot, default: 0] == 0 else { return nil }
                        writer.current[slot] += 1
                        writer.busySlot = slot
                        return writer.current[slot]
                    }
                    if version == nil { usleep(1_000) }
                }
                guard let version else { break }
                let data = RecoveryProbe.content(
                    nonce: nonce, writer: writer.index, slot: slot, version: version,
                    size: sizes[slot])
                let began = begin(key, "write")
                let index = lock.withLock { () -> Int in
                    writer.versions.append(
                        Version(slot: slot, version: version, issuedNS: began))
                    return writer.versions.count - 1
                }
                let written = data.withUnsafeBytes {
                    pwrite(writer.fd, $0.baseAddress, $0.count, off_t(offsets[slot]))
                }
                let writeCode = errno
                let writeFailed = written != data.count
                end(
                    key, "write", began: began, failed: writeFailed ? writeCode : nil,
                    detail: ["slot": slot, "version": version, "written": written])
                lock.withLock { writer.versions[index].writeReturnedNS = RecoveryProbe.now() }
                if writeFailed {
                    lock.withLock {
                        writer.versions[index].errorOperation = "write"
                        writer.versions[index].errorNumber = writeCode
                        writer.failure = "write errno \(writeCode)"
                        writer.busySlot = nil
                    }
                    break
                }
                let operation = writer.sync
                let syncBegan = begin(key, operation)
                let synchronized =
                    operation == "fullfsync" ? fcntl(writer.fd, F_FULLFSYNC) : fsync(writer.fd)
                let syncCode = errno
                end(
                    key, operation, began: syncBegan,
                    failed: synchronized == 0 ? nil : syncCode,
                    detail: ["slot": slot, "version": version])
                let returned = RecoveryProbe.now()
                let failedSync = lock.withLock { () -> Bool in
                    writer.busySlot = nil
                    writer.steps += 1
                    if synchronized == 0 {
                        writer.versions[index].syncReturnedNS = returned
                        writer.acknowledged[slot] = version
                        return false
                    }
                    writer.versions[index].errorOperation = operation
                    writer.versions[index].errorNumber = syncCode
                    writer.failure = "\(operation) errno \(syncCode)"
                    return true
                }
                if failedSync { break }
                if options.pauseMilliseconds > 0 {
                    usleep(useconds_t(options.pauseMilliseconds) * 1000)
                }
            }
            lock.withLock { writer.stopped = true }
        }

        private func readerLoop(_ reader: Int) {
            let key = "reader-\(reader)"
            var generator = SystemRandomNumberGenerator()
            var descriptors: [Int32] = writers.map {
                let fd = open($0.path, O_RDONLY | O_CLOEXEC)
                if fd >= 0 { _ = fcntl(fd, F_NOCACHE, 1) }
                return fd
            }
            defer { for fd in descriptors where fd >= 0 { close(fd) } }
            while isRunning {
                guard !writers.isEmpty else { break }
                let index = Int.random(in: 0..<writers.count, using: &generator)
                let writer = writers[index]
                let slot = Int.random(in: 0..<RecoveryProbe.slotSizes.count, using: &generator)
                // Read only a slot whose acknowledged version can't change during the read.
                let version = lock.withLock { () -> Int? in
                    guard writer.busySlot != slot, !writer.stopped,
                        writer.acknowledged[slot] == writer.current[slot]
                    else { return nil }
                    writer.readerSlots[slot, default: 0] += 1
                    return writer.acknowledged[slot]
                }
                guard let version else {
                    usleep(2_000)
                    continue
                }
                let size = RecoveryProbe.slotSizes[slot]
                var buffer = Data(count: size)
                let began = begin(key, "read")
                let count = buffer.withUnsafeMutableBytes {
                    pread(descriptors[index], $0.baseAddress, $0.count, off_t(offsets[slot]))
                }
                let code = errno
                end(
                    key, "read", began: began, failed: count == size ? nil : code,
                    detail: ["slot": slot, "writer": index, "read": count])
                lock.withLock { writer.readerSlots[slot, default: 1] -= 1 }
                if count == size {
                    let expected = RecoveryProbe.content(
                        nonce: nonce, writer: index, slot: slot, version: version, size: size)
                    if buffer != expected {
                        lock.withLock {
                            readMismatches += 1
                            if errors.count < 256 {
                                errors.append([
                                    "operation": "read-verify", "thread": key, "slot": slot,
                                    "writer": index, "version": version,
                                    "endNS": RecoveryProbe.now(),
                                ])
                            }
                        }
                        RecoveryProbe.emit(
                            "IO_ERROR",
                            [
                                "operation": "read-verify", "thread": key, "slot": slot,
                                "writer": index, "version": version,
                            ])
                    }
                } else {
                    usleep(200_000)
                    // Reopen once after an error; a file descriptor may stay unusable.
                    close(descriptors[index])
                    descriptors[index] = open(writer.path, O_RDONLY | O_CLOEXEC)
                    if descriptors[index] >= 0 { _ = fcntl(descriptors[index], F_NOCACHE, 1) }
                }
                usleep(10_000)
            }
        }

        private func rawReaderLoop() {
            let key = "raw-reader"
            let fd = open(image, O_RDONLY | O_CLOEXEC)
            guard fd >= 0 else {
                end(key, "raw-open", began: RecoveryProbe.now(), failed: errno)
                return
            }
            defer { close(fd) }
            _ = fcntl(fd, F_NOCACHE, 1)
            var generator = SystemRandomNumberGenerator()
            var buffer = Data(count: 4096)
            while isRunning {
                let block = Int.random(in: 0..<(128 * 256), using: &generator)
                let began = begin(key, "raw-read")
                let count = buffer.withUnsafeMutableBytes {
                    pread(fd, $0.baseAddress, $0.count, off_t(block) * 4096)
                }
                let code = errno
                end(
                    key, "raw-read", began: began, failed: count == 4096 ? nil : code,
                    detail: ["offset": block * 4096, "read": count])
                usleep(count == 4096 ? 50_000 : 500_000)
            }
        }

        func status() -> [String: Any] {
            let now = RecoveryProbe.now()
            return lock.withLock {
                [
                    "running": running, "finishedThreads": finished,
                    "threads": threads.count,
                    "inflight": inflight.map {
                        [
                            "thread": $0.key, "operation": $0.value.0,
                            "ageMS": RecoveryProbe.milliseconds($0.value.1, now),
                        ] as [String: Any]
                    },
                    "steps": writers.map(\.steps), "errors": errors.count,
                    "readMismatches": readMismatches,
                    "writerFailures": writers.map { $0.failure ?? "" },
                ]
            }
        }

        func stop(timeoutSeconds: Double, root: URL) async -> [String: Any] {
            requestStop()
            let deadline = ContinuousClock.now.advanced(
                by: .milliseconds(Int(timeoutSeconds * 1000)))
            while lock.withLock({ finished < threads.count }), ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(50))
            }
            let stuck = lock.withLock { finished < threads.count }
            var result = status()
            result["stuck"] = stuck
            if !stuck {
                for writer in writers where writer.fd >= 0 {
                    let closed = close(writer.fd)
                    if closed != 0 { result["closeErrno"] = Int(errno) }
                    writer.fd = -1
                }
            }
            let ledger = lock.withLock { () -> [String: Any] in
                [
                    "nonce": nonce.uuidString.lowercased(), "label": options.label,
                    "startedNS": startedNS, "stoppedNS": RecoveryProbe.now(),
                    "slotSizes": RecoveryProbe.slotSizes, "slotOffsets": offsets,
                    "writers": writers.map { writer in
                        [
                            "index": writer.index, "sync": writer.sync,
                            "file": URL(fileURLWithPath: writer.path).lastPathComponent,
                            "failure": writer.failure ?? NSNull(),
                            "versions": writer.versions.map { version in
                                [
                                    "slot": version.slot, "version": version.version,
                                    "issuedNS": version.issuedNS,
                                    "writeReturnedNS": version.writeReturnedNS.map {
                                        $0 as Any
                                    } ?? NSNull(),
                                    "syncReturnedNS": version.syncReturnedNS.map { $0 as Any }
                                        ?? NSNull(),
                                    "error": version.errorOperation.map {
                                        "\($0) errno \(version.errorNumber ?? 0)" as Any
                                    } ?? NSNull(),
                                ] as [String: Any]
                            },
                        ] as [String: Any]
                    },
                    "stats": stats.mapValues { stat in
                        [
                            "count": stat.count, "errors": stat.errors,
                            "maximumMS": stat.maximumMS,
                            "meanMS": stat.count > 0 ? stat.totalMS / Double(stat.count) : 0,
                            "slow": stat.slow,
                        ] as [String: Any]
                    },
                    "errors": errors, "readMismatches": readMismatches,
                ]
            }
            let name = "RecoveryLedger-\(options.label).json"
            do {
                let data = try JSONSerialization.data(
                    withJSONObject: ledger, options: [.sortedKeys])
                try data.write(to: root.appendingPathComponent(name), options: .withoutOverwriting)
                result["ledger"] = name
            } catch {
                result["ledgerError"] = RecoveryProbe.errorText(error)
            }
            result["stats"] = (ledger["stats"] as? [String: Any]) ?? [:]
            result["errorList"] = Array(errors.prefix(32))
            result["ok"] = !stuck
            return result
        }
    }

    // MARK: Snapshot verification

    /// Attaches a target-side snapshot read-only and checks every slot of every ledger:
    /// each must hold the latest version whose synchronization returned before the cutoff, or,
    /// per 4 KiB block, a newer version issued before the cutoff (an unacknowledged write).
    static func verifySnapshot(specName: String, root: URL, nonce: UUID) async throws {
        guard
            specName.range(of: "^[A-Za-z0-9._-]{1,96}\\.json$", options: .regularExpression)
                != nil
        else { throw Failure("Invalid verification specification name") }
        let spec =
            try JSONSerialization.jsonObject(
                with: Data(contentsOf: root.appendingPathComponent(specName))) as? [String: Any]
            ?? [:]
        guard let imageName = spec["image"] as? String, !imageName.contains("/"),
            let ledgerNames = spec["ledgers"] as? [String],
            ledgerNames.allSatisfy({ !$0.contains("/") })
        else { throw Failure("Invalid verification specification") }
        let cutoff = (spec["cutoffNS"] as? NSNumber)?.uint64Value
        let grace = (spec["graceNS"] as? NSNumber)?.uint64Value ?? 0
        let recent = (spec["recentNS"] as? NSNumber)?.uint64Value
        let strictSyncs = Set(spec["strictSyncs"] as? [String] ?? ["fullfsync", "fsync"])
        let image = root.appendingPathComponent(imageName)
        let before = try FixtureFileSystem.digest(of: image)
        let images = DiskImages()
        // The product's attach refuses an image the inventory doesn't confirm right after the
        // attach (imageIdentityChanged); its log says what was listed. A failed attach fails
        // the verification, after releasing whatever it left attached.
        var attachNotes: [String] = []
        func attach() async throws -> DiskAttachment {
            do {
                return try await images.attachRawImage(at: image, readOnly: true)
            } catch {
                attachNotes.append("snapshot attach failed: \(RecoveryProbe.errorText(error))")
                if let left = try? await images.inventory().attachment(at: image) {
                    do {
                        try await images.detach(left, at: image)
                        attachNotes.append("released \(left.device) left by the failed attach")
                    } catch {
                        attachNotes.append("release failed: \(RecoveryProbe.errorText(error))")
                    }
                }
                throw error
            }
        }
        let attachment: DiskAttachment
        do { attachment = try await attach() } catch {
            throw Failure(attachNotes.joined(separator: "; "))
        }
        var report: [String: Any] = [
            "image": imageName, "cutoffNS": cutoff.map { $0 as Any } ?? NSNull(),
            "graceNS": grace,
        ]
        var failures: [String] = []
        var observations: [String] = attachNotes
        do {
            guard attachment.volumeURLs.count == 1, let volume = attachment.volumeURLs.first
            else { throw Failure("Snapshot volume is missing") }
            let marker = Data("FSKit validation \(nonce.uuidString.lowercased())\n".utf8)
            if (try? Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt")))
                != marker
            {
                failures.append("fixture marker differs")
            }
            var ledgers: [[String: Any]] = []
            for name in ledgerNames {
                let ledger =
                    try JSONSerialization.jsonObject(
                        with: Data(contentsOf: root.appendingPathComponent(name)))
                    as? [String: Any] ?? [:]
                let result = try verifyLedger(
                    ledger, volume: volume, nonce: nonce, cutoff: cutoff, grace: grace,
                    recent: recent, strictSyncs: strictSyncs)
                ledgers.append(result)
                failures += (result["failures"] as? [String]) ?? []
                observations += (result["observations"] as? [String]) ?? []
            }
            report["ledgers"] = ledgers
            var files: [[String: Any]] = []
            for file in spec["files"] as? [[String: Any]] ?? [] {
                guard let name = file["name"] as? String, !name.contains("/"),
                    let digest = file["sha256"] as? String
                else { throw Failure("Invalid file expectation") }
                let required = file["required"] as? Bool ?? true
                let data = try? Data(contentsOf: volume.appendingPathComponent(name))
                let actual = data.map { sha256($0) }
                let matches = actual == digest
                files.append([
                    "name": name, "present": data != nil, "bytes": data?.count ?? -1,
                    "matches": matches, "required": required,
                ])
                if !matches {
                    let text =
                        "file \(name): \(data == nil ? "missing" : "content differs (\(data!.count) bytes)")"
                    if required { failures.append(text) } else { observations.append(text) }
                }
            }
            report["files"] = files
            try await images.detach(attachment, at: image)
        } catch {
            try? await images.detach(attachment, at: image)
            throw error
        }
        guard try FixtureFileSystem.digest(of: image) == before else {
            throw Failure("Snapshot verification changed the snapshot")
        }
        report["failures"] = Array(failures.prefix(64))
        report["failureCount"] = failures.count
        report["observations"] = Array(observations.prefix(64))
        report["passed"] = failures.isEmpty
        let output = root.appendingPathComponent(
            specName.replacingOccurrences(of: ".json", with: "-result.json"))
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(to: output, options: .withoutOverwriting)
        let summary = try JSONSerialization.data(
            withJSONObject: [
                "passed": failures.isEmpty, "failureCount": failures.count,
                "result": output.lastPathComponent,
            ], options: [.sortedKeys])
        print("RECOVERY_VERIFY " + String(decoding: summary, as: UTF8.self))
        guard failures.isEmpty else {
            throw Failure("Snapshot verification failed: \(failures.prefix(4))")
        }
    }

    static func verifyLedger(
        _ ledger: [String: Any], volume: URL, nonce: UUID, cutoff: UInt64?, grace: UInt64,
        recent: UInt64? = nil,
        strictSyncs: Set<String>
    ) throws -> [String: Any] {
        guard ledger["nonce"] as? String == nonce.uuidString.lowercased(),
            let label = ledger["label"] as? String,
            let sizes = ledger["slotSizes"] as? [Int],
            let offsets = ledger["slotOffsets"] as? [Int],
            sizes.count == offsets.count, sizes == slotSizes,
            let writers = ledger["writers"] as? [[String: Any]]
        else { throw Failure("Invalid recovery ledger") }
        var failures: [String] = []
        var observations: [String] = []
        var counts: [String: Int] = [
            "exact": 0, "pendingComplete": 0, "pendingTorn": 0, "mismatch": 0,
            "acknowledgedVersions": 0,
        ]
        for writer in writers {
            guard let index = writer["index"] as? Int, let sync = writer["sync"] as? String,
                let file = writer["file"] as? String, !file.contains("/"),
                let versions = writer["versions"] as? [[String: Any]]
            else { throw Failure("Invalid recovery ledger writer") }
            let strict = strictSyncs.contains(sync)
            let path = volume.appendingPathComponent(file)
            guard let handle = try? FileHandle(forReadingFrom: path) else {
                failures.append("\(label) w\(index): file missing")
                continue
            }
            defer { try? handle.close() }
            var bySlot: [Int: [[String: Any]]] = [:]
            for version in versions {
                guard let slot = version["slot"] as? Int else { continue }
                bySlot[slot, default: []].append(version)
            }
            for slot in 0..<sizes.count {
                let entries = bySlot[slot] ?? []
                func number(_ value: Any?) -> UInt64? { (value as? NSNumber)?.uint64Value }
                let acknowledged = entries.filter {
                    guard let returned = number($0["syncReturnedNS"]) else { return false }
                    return cutoff.map { returned < $0 } ?? true
                }
                guard let base = acknowledged.compactMap({ $0["version"] as? Int }).max() else {
                    failures.append("\(label) w\(index) slot \(slot): no acknowledged version")
                    continue
                }
                counts["acknowledgedVersions", default: 0] += acknowledged.count
                let pending = entries.compactMap { entry -> Int? in
                    guard let version = entry["version"] as? Int, version > base,
                        let issued = number(entry["issuedNS"])
                    else { return nil }
                    if let cutoff, issued >= cutoff &+ grace { return nil }
                    return version
                }
                try handle.seek(toOffset: UInt64(offsets[slot]))
                let actual = try handle.read(upToCount: sizes[slot]) ?? Data()
                let expected = content(
                    nonce: nonce, writer: index, slot: slot, version: base, size: sizes[slot])
                if actual == expected {
                    counts["exact", default: 0] += 1
                    // Acknowledged shortly before the cutoff: durable only through the
                    // initiator's flush, not the guest's periodic writeback.
                    if let recent, let cutoff,
                        let returned = acknowledged.first(where: {
                            $0["version"] as? Int == base
                        }).flatMap({ number($0["syncReturnedNS"]) }),
                        returned &+ recent >= cutoff
                    {
                        counts["exactRecent", default: 0] += 1
                    }
                    continue
                }
                let candidates = pending.map {
                    (
                        $0,
                        content(
                            nonce: nonce, writer: index, slot: slot, version: $0, size: sizes[slot])
                    )
                }
                if let match = candidates.first(where: { $0.1 == actual }) {
                    counts["pendingComplete", default: 0] += 1
                    observations.append(
                        "\(label) w\(index) slot \(slot): unacknowledged version \(match.0) is complete"
                    )
                    continue
                }
                if actual.count == sizes[slot], !candidates.isEmpty,
                    tornMatches(
                        actual, base: expected, candidates: candidates.map(\.1),
                        fileOffset: offsets[slot])
                {
                    counts["pendingTorn", default: 0] += 1
                    observations.append(
                        "\(label) w\(index) slot \(slot): unacknowledged versions \(pending) are torn by 4 KiB block"
                    )
                    continue
                }
                counts["mismatch", default: 0] += 1
                let text =
                    "\(label) w\(index) (\(sync)) slot \(slot) size \(sizes[slot]): content is neither acknowledged version \(base) nor unacknowledged \(pending); read \(actual.count) bytes"
                if strict {
                    failures.append(text)
                } else {
                    observations.append("NON-STRICT " + text)
                }
            }
        }
        return [
            "label": label, "counts": counts, "failures": failures, "observations": observations,
        ]
    }

    /// Every 4 KiB block of the file range holds the base version or one candidate version.
    private static func tornMatches(
        _ actual: Data, base: Data, candidates: [Data], fileOffset: Int
    ) -> Bool {
        var start = 0
        while start < actual.count {
            let next = min(actual.count, ((fileOffset + start) / 4096 + 1) * 4096 - fileOffset)
            let range = start..<next
            let segment = actual.subdata(in: range)
            guard
                segment == base.subdata(in: range)
                    || candidates.contains(where: { $0.subdata(in: range) == segment })
            else { return false }
            start = next
        }
        return true
    }
}
