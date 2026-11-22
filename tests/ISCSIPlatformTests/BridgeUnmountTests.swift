import Darwin
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

/// A mounted bridge for the ordinary unmount: a private directory carrying the identity and
/// connection-state attributes the extension would answer, a mount table that reports it
/// mounted until an unmount succeeds, and scripted unmount(2) results.
private final class HeldBridge: @unchecked Sendable {
    private let lock = NSLock()
    let root: URL
    let bridge: URL
    let descriptor: ConnectionDescriptor
    private var mounted = true
    private var mountType = ApplicationIdentity.current.fileSystemType
    private var replies: [BridgeUnmount]
    private var unmounts = 0
    private var instant = ContinuousClock.now
    private var sleeps: [Duration] = []

    /// After `replies` run out, the bridge stays busy.
    init(replies: [BridgeUnmount], state: DiskConnectionState = .connected) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            .resolvingSymlinksInPath()
        let id = UUID()
        descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: Portal("example.invalid"),
            initiatorName: "iqn.2026-11.test:bridge", targetName: "iqn.2026-11.test:disk",
            lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
        bridge = root.appendingPathComponent(id.uuidString, isDirectory: true)
        self.replies = replies
        try FileManager.default.createDirectory(
            at: bridge, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try set(ConnectionDescriptor.identityAttributeName, descriptor.resourceIdentity)
        try setConnectionState(state)
    }

    var unmountCount: Int { lock.withLock { unmounts } }
    var slept: [Duration] { lock.withLock { sleeps } }
    var isMounted: Bool { lock.withLock { mounted } }
    var directoryExists: Bool { FileManager.default.fileExists(atPath: bridge.path) }

    func setConnectionState(_ state: DiskConnectionState) throws {
        try set(ConnectionDescriptor.connectionStateAttributeName, state.encoded)
    }
    func replaceMount(type: String) { lock.withLock { mountType = type } }
    func unmountOutsideTheApp() { lock.withLock { mounted = false } }

    private func set(_ name: String, _ value: Data) throws {
        let result = value.withUnsafeBytes {
            setxattr(bridge.path, name, $0.baseAddress, $0.count, 0, XATTR_NOFOLLOW)
        }
        guard result == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    func unmount(_ path: String) -> BridgeUnmount {
        lock.withLock {
            #expect(path == bridge.path)
            unmounts += 1
            let reply = replies.isEmpty ? .failed(EBUSY) : replies.removeFirst()
            if reply == .unmounted { mounted = false }
            return reply
        }
    }

    var paths: SystemAttachmentBackend.PathQueries {
        .init(
            resolve: { $0.resolvingSymlinksInPath().path },
            status: { path in
                self.lock.withLock {
                    .success(
                        .init(
                            mountPath: self.mounted && path == self.bridge.path
                                ? path : self.root.path,
                            source: "iscsi://example.invalid/disk", type: self.mountType,
                            owner: getuid(), flags: 0))
                }
            })
    }

    /// A manual clock: each wait advances it at once.
    func wait(
        limit: Duration = SystemAttachmentBackend.busyBridgeWait,
        interval: Duration = SystemAttachmentBackend.BusyBridgeWait.system.interval
    ) -> SystemAttachmentBackend.BusyBridgeWait {
        .init(
            limit: limit, interval: interval, now: { self.lock.withLock { self.instant } },
            sleep: { duration in
                self.lock.withLock {
                    self.sleeps.append(duration)
                    self.instant = self.instant.advanced(by: duration)
                }
            })
    }

    func backend(wait: SystemAttachmentBackend.BusyBridgeWait? = nil) -> SystemAttachmentBackend {
        let empty = try! PropertyListSerialization.data(
            fromPropertyList: ["images": [[String: Any]]()], format: .binary, options: 0)
        return SystemAttachmentBackend(
            root: root,
            diskImages: DiskImages(run: { _, _, _ in empty }, fileSize: { _ in 0 }),
            mountCommand: { _, _, _ in throw ProtocolError.invalidState },
            paths: paths, unmountPath: { self.unmount($0) }, busyWait: wait ?? self.wait())
    }

    func cleanup() {
        _ = rmdir(bridge.path)
        _ = rmdir(root.path)
    }
}

/// The production bound and interval: the attempts a persistently busy bridge gets.
private let busyAttempts =
    Int(
        SystemAttachmentBackend.busyBridgeWait
            / SystemAttachmentBackend.BusyBridgeWait.system.interval) + 1

@Test func aBridgeHeldForAMomentIsUnmountedOnceItIsReleased() async throws {
    let held = try HeldBridge(replies: [.failed(EBUSY), .failed(EBUSY), .unmounted])
    defer { held.cleanup() }
    try await held.backend().unmountBridge(held.descriptor, at: held.bridge)
    #expect(held.unmountCount == 3)
    #expect(held.slept == [.milliseconds(500), .milliseconds(500)])
    #expect(!held.isMounted && !held.directoryExists)
}

@Test func aBridgeStillHeldAfterTheBoundIsReportedInUse() async throws {
    #expect(SystemAttachmentBackend.busyBridgeWait == .seconds(10))
    let held = try HeldBridge(replies: [])
    defer { held.cleanup() }
    await #expect(throws: POSIXError(.EBUSY)) {
        try await held.backend().unmountBridge(held.descriptor, at: held.bridge)
    }
    #expect(held.unmountCount == busyAttempts && busyAttempts == 21)
    #expect(held.slept.reduce(.zero, +) == SystemAttachmentBackend.busyBridgeWait)
    // Nothing was discarded: the bridge, its directory and its record stay for another eject.
    #expect(held.isMounted && held.directoryExists)
}

@Test func anEjectionRetriedAfterTheHolderLeftUnmountsTheBridge() async throws {
    let held = try HeldBridge(
        replies: Array(repeating: .failed(EBUSY), count: busyAttempts) + [.unmounted])
    defer { held.cleanup() }
    let backend = held.backend()
    await #expect(throws: POSIXError(.EBUSY)) {
        try await backend.unmountBridge(held.descriptor, at: held.bridge)
    }
    try await backend.unmountBridge(held.descriptor, at: held.bridge)
    #expect(held.unmountCount == busyAttempts + 1)
    #expect(!held.isMounted && !held.directoryExists)
}

/// A stopped read-only disk ejects normally, and another app may still be reading its
/// Disk.img when it stopped: the wait doesn't depend on the connection's state.
@Test(arguments: [DiskConnectionState.reconnecting, .interrupted, .closed, .unknown])
private func aBusyBridgeIsWaitedForWhateverItsConnectionState(_ state: DiskConnectionState)
    async throws
{
    let briefly = try HeldBridge(replies: [.failed(EBUSY), .unmounted], state: state)
    defer { briefly.cleanup() }
    try await briefly.backend().unmountBridge(briefly.descriptor, at: briefly.bridge)
    #expect(briefly.unmountCount == 2 && briefly.slept == [.milliseconds(500)])
    #expect(!briefly.isMounted && !briefly.directoryExists)

    let persistently = try HeldBridge(replies: [], state: state)
    defer { persistently.cleanup() }
    await #expect(throws: POSIXError(.EBUSY)) {
        try await persistently.backend().unmountBridge(
            persistently.descriptor, at: persistently.bridge)
    }
    #expect(persistently.unmountCount == busyAttempts)
    #expect(persistently.isMounted && persistently.directoryExists)
}

/// Any other unmount failure is reported as the umount command reported it, at once.
@Test(arguments: [EIO, EPERM, EAGAIN])
private func anUnmountFailureThatIsNotBusyKeepsTheCommandFailure(_ code: Int32) async throws {
    let held = try HeldBridge(replies: [.failed(code)])
    defer { held.cleanup() }
    do {
        try await held.backend().unmountBridge(held.descriptor, at: held.bridge)
        Issue.record("A failed unmount must not be reported as successful")
    } catch let SystemCommandError.failed(program, status, detail) {
        #expect(program == "umount" && status == 1)
        #expect(
            detail
                == "umount: unmount(\(held.bridge.path)): \(String(cString: strerror(code)))\n")
    }
    #expect(held.unmountCount == 1 && held.slept.isEmpty)
    #expect(held.isMounted && held.directoryExists)
}

@Test func anUnmountThatDoesNotFinishInTimeReportsTheUmountTimeout() async throws {
    let held = try HeldBridge(replies: [.timedOut])
    defer { held.cleanup() }
    await #expect(throws: SystemCommandError.timedOut(program: "umount")) {
        try await held.backend().unmountBridge(held.descriptor, at: held.bridge)
    }
    #expect(held.unmountCount == 1 && held.directoryExists)
}

@Test func cancellingTheEjectionStopsWaitingForABusyBridge() async throws {
    let held = try HeldBridge(replies: [])
    defer { held.cleanup() }
    let base = held.wait()
    let wait = SystemAttachmentBackend.BusyBridgeWait(
        limit: base.limit, interval: base.interval, now: base.now,
        sleep: { _ in try await Task.sleep(for: .seconds(3600)) })
    let backend = held.backend(wait: wait)
    let task = Task { try await backend.unmountBridge(held.descriptor, at: held.bridge) }
    while held.unmountCount == 0 { await Task.yield() }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(held.unmountCount == 1)
    #expect(held.isMounted && held.directoryExists)
}

/// Each retry first observes the bridge again: one unmounted meanwhile is only discarded,
/// and one that no longer answers with this record's identity is never unmounted.
@Test func aBridgeThatChangesWhileBusyIsObservedBeforeTheNextAttempt() async throws {
    let absent = try HeldBridge(replies: [.failed(EBUSY)])
    defer { absent.cleanup() }
    let base = absent.wait()
    let unmountedMeanwhile = SystemAttachmentBackend.BusyBridgeWait(
        limit: base.limit, interval: base.interval, now: base.now,
        sleep: {
            try await base.sleep($0)
            absent.unmountOutsideTheApp()
        })
    try await absent.backend(wait: unmountedMeanwhile).unmountBridge(
        absent.descriptor, at: absent.bridge)
    #expect(absent.unmountCount == 1 && !absent.directoryExists)

    let replaced = try HeldBridge(replies: [.failed(EBUSY)])
    defer { replaced.cleanup() }
    let other = replaced.wait()
    let replacedMeanwhile = SystemAttachmentBackend.BusyBridgeWait(
        limit: other.limit, interval: other.interval, now: other.now,
        sleep: {
            try await other.sleep($0)
            replaced.replaceMount(type: "apfs")
        })
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await replaced.backend(wait: replacedMeanwhile).unmountBridge(
            replaced.descriptor, at: replaced.bridge)
    }
    #expect(replaced.unmountCount == 1 && replaced.directoryExists)
}
