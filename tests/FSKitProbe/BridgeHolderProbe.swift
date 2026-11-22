import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Other processes with a file open on a mounted bridge, as the kernel reports them to this
/// user. Another app reading the bridge's Disk.img makes its unmount busy: Parallels Desktop's
/// OS detection runs 7z on the backing image of every newly mounted volume (ENV082).
enum BridgeHolders {
    /// Longer than Parallels Desktop lets its detection run (30 s).
    static let limit = Duration.seconds(45)

    /// Whether `bridge` is a mount point in the kernel's cached table, which never asks it.
    static func isMounted(_ bridge: URL) -> Bool {
        var table: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&table, MNT_NOWAIT)
        guard count > 0, let table else { return false }
        let path = bridge.standardizedFileURL.path
        return (0..<Int(count)).contains { index in
            var entry = table[index]
            return withUnsafeBytes(of: &entry.f_mntonname) {
                String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
            } == path
        }
    }

    /// `name[pid]` of every other process with a file open on the mounted bridge.
    static func list(_ bridge: URL) -> [String] {
        // On a path that isn't a mount point, the volume would be the one containing it.
        guard isMounted(bridge) else { return [] }
        return processes(bridge.path, flags: UInt32(PROC_LISTPIDSPATH_PATH_IS_VOLUME))
    }

    /// `name[pid]` of every other process with this file open.
    static func list(file: URL) -> [String] { processes(file.path, flags: 0) }

    private static func processes(_ path: String, flags: UInt32) -> [String] {
        var pids = [pid_t](repeating: 0, count: 8192)
        let bytes = pids.withUnsafeMutableBytes {
            proc_listpidspath(
                UInt32(PROC_ALL_PIDS), 0, path, flags, $0.baseAddress, Int32($0.count))
        }
        guard bytes > 0 else { return [] }
        let own = getpid()
        return pids.prefix(Int(bytes) / MemoryLayout<pid_t>.stride)
            .filter { $0 > 0 && $0 != own }
            .map { pid in
                var name = [UInt8](repeating: 0, count: 256)
                _ = proc_name(pid, &name, UInt32(name.count))
                return "\(String(decoding: name.prefix { $0 != 0 }, as: UTF8.self))[\(pid)]"
            }
    }

    /// Waits until no other process holds the bridge, at most `limit`. It never fails: an
    /// unmount that follows reports a holder that stayed.
    static func waitUntilFree(_ bridge: URL, limit: Duration = limit) async {
        let clock = ContinuousClock()
        let started = clock.now
        var reported: [String] = []
        while true {
            let holders = list(bridge)
            if holders.isEmpty {
                if !reported.isEmpty {
                    print(
                        "CHECK: bridge free after \(started.duration(to: clock.now)); it was held by \(reported)"
                    )
                }
                return
            }
            if holders != reported {
                print("CHECK: bridge \(bridge.lastPathComponent) held by \(holders); waiting")
                reported = holders
            }
            guard started.duration(to: clock.now) < limit else {
                print("CHECK: bridge still held after \(limit) by \(holders); unmounting anyway")
                return
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// Runs `step` again within `limit` while it reports EBUSY: another app can hold a freshly
    /// mounted inner volume for about 2 s, which makes its image's detach report EBUSY
    /// (ENV082). Each refusal is logged with who held the bridge and the volume; any other
    /// failure is thrown at once.
    static func retryingBusy(
        _ name: String, bridge: URL, volume: URL?, limit: Duration = limit,
        _ step: () async throws -> Void
    ) async throws {
        let clock = ContinuousClock()
        let started = clock.now
        while true {
            do {
                try await step()
                return
            } catch let error as POSIXError where error.code == .EBUSY {
                print(
                    "CHECK: \(name) busy after \(started.duration(to: clock.now)); bridge held by \(list(bridge)); volume held by \(volume.map { list($0) } ?? [])"
                )
                guard started.duration(to: clock.now) < limit else { throw error }
                try await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// A normal ejection, tried again within `limit` while it reports EBUSY: Parallels
    /// Desktop's VM process can hold a freshly mounted inner volume for about 2 s, which makes
    /// the inner image's ejection report EBUSY (ENV082). Each refusal is logged with its step
    /// and who held the bridge and the volume; any other failure is thrown at once.
    static func ejectRetryingBusy(
        _ owner: AttachmentCoordinator, _ disk: AttachedDisk, limit: Duration = limit
    ) async throws {
        let clock = ContinuousClock()
        let started = clock.now
        while true {
            do {
                try await owner.eject(disk.id)
                return
            } catch let error as POSIXError where error.code == .EBUSY {
                let records = await owner.disks.filter { $0.id == disk.id }.map {
                    "\($0.phase) \($0.connectionState)"
                }
                print(
                    "CHECK: normal eject busy after \(started.duration(to: clock.now)) at \(records); bridge held by \(list(disk.bridgeURL)); volume held by \(disk.attachment?.volumeURLs.first.map { list($0) } ?? [])"
                )
                guard started.duration(to: clock.now) < limit else { throw error }
                try await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// Detaches a local fixture image, retrying within `limit` while its volume is busy and
    /// logging who holds the volume and the image: another app can keep a newly mounted
    /// volume busy for a while (ENV082).
    static func detachWhenFree(
        _ images: DiskImages, _ attachment: DiskAttachment, at image: URL, volume: URL,
        limit: Duration = limit
    ) async throws {
        let clock = ContinuousClock()
        let started = clock.now
        while true {
            do {
                try await images.detach(attachment, at: image)
                if started.duration(to: clock.now) > .seconds(1) {
                    print("CHECK: fixture image detached after \(started.duration(to: clock.now))")
                }
                return
            } catch let error as POSIXError where error.code == .EBUSY {
                print(
                    "CHECK: fixture volume busy after \(started.duration(to: clock.now)); volume held by \(list(volume)), image held by \(list(file: image))"
                )
                guard started.duration(to: clock.now) < limit else { throw error }
                try await Task.sleep(for: .seconds(1))
            }
        }
    }
}

/// Mounted regression for ENV082: a process holds the bridge's Disk.img while the disk is
/// ejected normally, as Parallels Desktop does for a few seconds after a volume mounts. The
/// fixture's own wait for holders is off, so the product's bounded wait
/// (`SystemAttachmentBackend.busyBridgeWait`) is what runs.
///
/// - `short`: the holder leaves within the bound; the eject succeeds once it has left.
/// - `long`: the holder stays past the bound; the eject reports EBUSY and keeps the disk
///   verified and connected; once the holder is gone, a second eject succeeds.
/// - `relaunch`: as `long`, but the record is left for a new process
///   (`--restore-held-bridge-fixture`), which restores it from the journal and ejects it.
enum BridgeHolderProbe {
    enum Hold: String { case short, long, relaunch }

    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    /// A reader like 7z: it opens Disk.img, reads its first 64 KiB, then keeps it open for
    /// `seconds`. The hold, not the reading, is what makes the bridge busy; a short read
    /// keeps the hold's length known.
    private final class Holder: @unchecked Sendable {
        private let lock = NSLock()
        private let process = Process()
        private var exit: ContinuousClock.Instant?

        init(image: URL, seconds: Int) throws {
            let file = try FileHandle(forReadingFrom: image)
            defer { try? file.close() }
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = [
                "-c", "/usr/bin/head -c 65536 >/dev/null && exec /bin/sleep \"$0\"",
                String(seconds),
            ]
            process.standardInput = file
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            process.terminationHandler = { [lock] _ in
                lock.withLock { self.exit = ContinuousClock.now }
            }
            try process.run()
        }

        var pid: pid_t { process.processIdentifier }
        var running: Bool { process.isRunning }
        var exited: ContinuousClock.Instant? { lock.withLock { exit } }

        /// Ends the hold if it hasn't ended, and returns the exit status (15 when stopped).
        func release() -> Int32 {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
            return process.terminationStatus
        }
    }

    /// When each ordinary unmount began and which processes held the bridge then, and when
    /// the bridge left the mount table.
    private final class Watch: @unchecked Sendable {
        private let lock = NSLock()
        private var starts: [(ContinuousClock.Instant, [String])] = []
        private var gone: ContinuousClock.Instant?

        func unmountBegins(_ bridge: URL) {
            let holders = BridgeHolders.list(bridge)
            lock.withLock { starts.append((ContinuousClock.now, holders)) }
        }
        var unmounts: [(ContinuousClock.Instant, [String])] { lock.withLock { starts } }
        var unmounted: ContinuousClock.Instant? { lock.withLock { gone } }

        /// Polls the cached mount table until the bridge is gone or the task is cancelled.
        func observe(_ bridge: URL) -> Task<Void, Never> {
            Task.detached {
                while !Task.isCancelled {
                    if !BridgeHolders.isMounted(bridge) {
                        self.lock.withLock { self.gone = ContinuousClock.now }
                        return
                    }
                    try? await Task.sleep(for: .milliseconds(20))
                }
            }
        }
    }

    private static func coordinator(root: URL, watch: Watch?) throws -> AttachmentCoordinator {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        var backend = FSKitProbe.StageBackend(
            base: BlockResourceProbe.backend(root: root), stage: nil)
        backend.waitsForHolders = false
        if let watch { backend.beforeUnmount = { watch.unmountBegins($0) } }
        return try AttachmentCoordinator(
            backend: backend,
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
    }

    private static func seconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
    }

    /// The disk left behind by a held bridge: only the bridge remains, verified and connected.
    private static func requireHeldRecord(_ disk: AttachedDisk) throws {
        guard disk.phase == .unmountingBridge, disk.attachment == nil, !disk.verificationFailed,
            disk.connectionState == .connected, !disk.offersForcedRelease,
            BridgeHolders.isMounted(disk.bridgeURL)
        else {
            throw Failure(
                "Held bridge record differs: phase=\(disk.phase) attached=\(disk.attachment != nil) unverified=\(disk.verificationFailed) state=\(disk.connectionState) forceOffered=\(disk.offersForcedRelease)"
            )
        }
    }

    /// Watches who else opens the bridge after its volume mounted (Parallels Desktop's 7z, for
    /// example) until nobody does, at most `BridgeHolders.limit`, so that the held ejection
    /// that follows measures this probe's holder alone. Returns, for each other process, when
    /// it was first and last seen holding the bridge, in seconds after `since`.
    private static func otherHolders(_ bridge: URL, since: ContinuousClock.Instant) async
        -> [[String: Any]]
    {
        let clock = ContinuousClock()
        var seen: [String: (Duration, Duration)] = [:]
        var order: [String] = []
        while since.duration(to: clock.now) < BridgeHolders.limit {
            let now = since.duration(to: clock.now)
            // DiskImages may hold the backing file of the attached inner image.
            let holders = BridgeHolders.list(bridge).filter { !$0.hasPrefix("diskimages") }
            for holder in holders {
                if let (first, _) = seen[holder] {
                    seen[holder] = (first, now)
                } else {
                    seen[holder] = (now, now)
                    order.append(holder)
                }
            }
            if holders.isEmpty { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
        let result: [[String: Any]] = order.map {
            [
                "process": $0, "firstSeconds": seconds(seen[$0]!.0),
                "lastSeconds": seconds(seen[$0]!.1),
            ]
        }
        print("CHECK: other holders of the bridge after its connection: \(result)")
        return result
    }

    private static func report(_ values: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: values, options: .sortedKeys)
        print("BRIDGE_HOLDER_RESULT " + String(decoding: data, as: UTF8.self))
    }

    static func run(portal: Portal, root: URL, nonce: UUID, hold: Hold) async throws {
        let configuration = try FSKitProbe.ramConfiguration(nonce)
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
            targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: true,
            isid: configuration.isid)
        let watch = Watch()
        let coordinator = try coordinator(root: root, watch: watch)
        try await coordinator.restore()
        let clock = ContinuousClock()
        let bound = SystemAttachmentBackend.busyBridgeWait
        var holder: Holder?
        do {
            let disk = try await coordinator.connect(descriptor)
            let connected = clock.now
            guard let volume = disk.attachment?.volumeURLs.first,
                try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                    == FSKitProbe.marker(nonce)
            else { throw Failure("The fixture is not readable before the held ejection") }
            let others = await otherHolders(disk.bridgeURL, since: connected)
            let current = try Holder(
                image: disk.bridgeURL.appendingPathComponent("Disk.img"),
                seconds: hold == .short ? 4 : 600)
            holder = current
            let observer = watch.observe(disk.bridgeURL)
            defer { observer.cancel() }
            let began = clock.now
            var failure: (any Error)?
            do { try await coordinator.eject(disk.id) } catch { failure = error }
            let returned = clock.now
            guard let first = watch.unmounts.first else {
                throw Failure(
                    "The ejection never reached the bridge unmount: \(String(describing: failure))")
            }
            let (unmountBegan, holders) = first
            // Without the holder on the bridge when its unmount began, the case proves nothing.
            guard holders.contains(where: { $0.hasSuffix("[\(current.pid)]") }) else {
                throw Failure(
                    "The holder wasn't holding the bridge when its unmount began: \(holders)")
            }
            print(
                "CHECK: bridge unmount began \(began.duration(to: unmountBegan)) after the eject; held by \(holders)"
            )
            switch hold {
            case .short:
                if let failure {
                    throw Failure(
                        "A briefly held bridge wasn't ejected after \(unmountBegan.duration(to: returned)): \(failure); holder running=\(current.running), holders now \(BridgeHolders.list(disk.bridgeURL)), records \(await coordinator.disks.map { "\($0.phase) \($0.connectionState) unverified=\($0.verificationFailed)" })"
                    )
                }
                let status = current.release()
                var exit = current.exited
                for _ in 0..<50 where exit == nil {
                    try await Task.sleep(for: .milliseconds(20))
                    exit = current.exited
                }
                guard status == 0, let exited = exit, let unmounted = watch.unmounted else {
                    throw Failure(
                        "The hold (status \(status)) or the unmount wasn't observed to end")
                }
                let afterRelease = exited.duration(to: unmounted)
                // Unmounted only after the hold ended, and within one retry interval or so.
                guard afterRelease >= .zero, afterRelease < .seconds(2),
                    unmountBegan.duration(to: returned) < bound + .seconds(5),
                    await coordinator.disks.isEmpty
                else {
                    throw Failure(
                        "Briefly held bridge timing differs: unmounted \(afterRelease) after the holder left"
                    )
                }
                try report([
                    "hold": hold.rawValue, "ejected": true,
                    "unmountBeganAfterEjectSeconds": seconds(began.duration(to: unmountBegan)),
                    "holderExitAfterUnmountBeganSeconds": seconds(
                        unmountBegan.duration(to: exited)),
                    "unmountedAfterHolderExitSeconds": seconds(afterRelease),
                    "ejectSeconds": seconds(began.duration(to: returned)),
                    "holdersAtUnmount": holders, "otherHoldersAfterConnect": others,
                ])
                print(
                    "PASS: a bridge held briefly during ejection was unmounted once the holder left"
                )
            case .long, .relaunch:
                guard (failure as? POSIXError)?.code == .EBUSY else {
                    throw Failure(
                        "A bridge held past the bound wasn't reported busy: \(String(describing: failure))"
                    )
                }
                let waited = unmountBegan.duration(to: returned)
                guard waited >= bound - .seconds(1), waited < bound + .seconds(5), current.running
                else { throw Failure("The busy bridge's wait differs from its bound: \(waited)") }
                let disks = await coordinator.disks
                guard disks.count == 1, disks[0].id == disk.id else {
                    throw Failure("The held disk's record wasn't kept")
                }
                try requireHeldRecord(disks[0])
                let offered = await coordinator.canPrepareForceEjection(disk.id)
                let stopped = current.release()
                var retried: Duration?
                if hold == .long {
                    let again = clock.now
                    try await coordinator.eject(disk.id)
                    retried = again.duration(to: clock.now)
                    guard await coordinator.disks.isEmpty,
                        !BridgeHolders.isMounted(disk.bridgeURL)
                    else { throw Failure("The released bridge wasn't ejected") }
                }
                try report([
                    "hold": hold.rawValue, "error": "EBUSY",
                    "unmountBeganAfterEjectSeconds": seconds(began.duration(to: unmountBegan)),
                    "busyWaitSeconds": seconds(waited), "boundSeconds": seconds(bound),
                    "keptVerifiedConnected": true, "rowOffersForceEject": false,
                    "alertOffersForceEject": offered, "holderStatus": Int(stopped),
                    "secondEjectSeconds": retried.map { seconds($0) as Any } ?? NSNull(),
                    "holdersAtUnmount": holders, "otherHoldersAfterConnect": others,
                ])
                if hold == .long {
                    print(
                        "PASS: a bridge held past \(bound) reported EBUSY with the disk verified and connected; ejected once released"
                    )
                } else {
                    print("FSKIT_HELD_BRIDGE_LEFT \(disk.id.uuidString)")
                }
            }
        } catch {
            _ = holder?.release()
            throw error
        }
    }

    /// A new owner process restores the journal of a disk left in `unmountingBridge` by a held
    /// bridge, as the app does on launch, and finishes the ejection normally.
    static func restore(root: URL, nonce: UUID) async throws {
        let coordinator = try coordinator(root: root, watch: nil)
        try await coordinator.restore()
        let disks = await coordinator.disks
        guard await coordinator.recoveryState == .ready, disks.count == 1,
            disks[0].descriptor.profileID == nonce
        else { throw Failure("The held disk wasn't restored as ready") }
        try requireHeldRecord(disks[0])
        let clock = ContinuousClock()
        let began = clock.now
        try await coordinator.eject(disks[0].id)
        guard await coordinator.disks.isEmpty, !BridgeHolders.isMounted(disks[0].bridgeURL) else {
            throw Failure("The restored bridge wasn't ejected")
        }
        try report([
            "hold": "restore", "restoredVerifiedConnected": true,
            "ejectSeconds": seconds(began.duration(to: clock.now)),
        ])
        print("PASS: a relaunch restored the held bridge's record and ejected it normally")
    }
}
