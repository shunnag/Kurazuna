import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Security
import Testing

@testable import ISCSIFSBridge

// REC022: FSKit keeps a loaded but never mounted block resource, and its marker device, open in
// the extension instance. These tests drive the watch with injected time and never sleep.

private final class AbandonTime: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    func expire() { lock.withLock { instant = instant.advanced(by: .seconds(46)) } }
}

/// Each watch sleep waits here until the test releases it; cancellation ends the sleep.
private actor AbandonTicks {
    private var waiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private var order: [UUID] = []
    private(set) var requested: [Duration] = []
    var waiting: Int { order.count }

    func sleep(_ duration: Duration) async throws {
        requested.append(duration)
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                register(id, continuation)
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
    }

    private func register(_ id: UUID, _ continuation: CheckedContinuation<Void, any Error>) {
        if Task.isCancelled {
            continuation.resume(throwing: CancellationError())
        } else {
            waiters[id] = continuation
            order.append(id)
        }
    }

    private func cancel(_ id: UUID) {
        order.removeAll { $0 == id }
        waiters.removeValue(forKey: id)?.resume(throwing: CancellationError())
    }

    func release() {
        guard !order.isEmpty else { return }
        waiters.removeValue(forKey: order.removeFirst())?.resume()
    }
}

private final class AbandonState: @unchecked Sendable {
    private let lock = NSLock()
    private var mounted: Bool? = false
    private var withdrawnValue = false
    private var withdrawChecks = 0
    private var terminations = 0
    var mountState: Bool? {
        get { lock.withLock { mounted } }
        set { lock.withLock { mounted = newValue } }
    }
    var withdrawn: Bool {
        get { lock.withLock { withdrawnValue } }
        set { lock.withLock { withdrawnValue = newValue } }
    }
    func checkWithdrawn() -> Bool {
        lock.withLock {
            withdrawChecks += 1
            return withdrawnValue
        }
    }
    var checks: Int { lock.withLock { withdrawChecks } }
    func terminate() { lock.withLock { terminations += 1 } }
    var terminated: Int { lock.withLock { terminations } }
}

private actor AbandonDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = true
    private(set) var closeCount = 0
    init() throws { capacity = try MemoryDisk().capacity }
    func read(offset: Int64, length: Int) -> Data { Data(repeating: 0, count: length) }
    func write(offset: Int64, data: Data) throws { throw POSIXError(.EROFS) }
    func synchronize() {}
    func close() { closeCount += 1 }
    func connectionState() -> DiskConnectionState { closeCount > 0 ? .closed : .connected }
}

private struct AbandonFixture {
    let time = AbandonTime()
    let ticks = AbandonTicks()
    let state = AbandonState()
    /// This test's own process-wide facts; the shared registry is never consulted.
    let registry = ProcessMountRegistry()
    let disk: AbandonDisk
    let descriptor: ConnectionDescriptor
    let reference: ConnectionResourceReference
    let identity: BlockMountIdentity

    init() throws {
        disk = try AbandonDisk()
        descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: Portal("example.invalid"),
            initiatorName: "iqn.2026-10.test:abandon", targetName: "iqn.2026-10.test:disk",
            lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5]
        ).assigningMountID(UUID())
        reference = try ConnectionResourceReference(descriptor: descriptor)
        identity = try BlockMountIdentity(bsdName: "disk41", mountID: reference.mountID)
    }

    var policy: BlockLoadAbandonment {
        let ticks = ticks
        let state = state
        let identity = identity
        return BlockLoadAbandonment(
            interval: .seconds(1), grace: .seconds(2), sleep: { try await ticks.sleep($0) },
            deviceMountState: { candidate in
                #expect(candidate == identity)
                return state.mountState
            },
            terminate: { state.terminate() })
    }

    func controller(
        opener: ResourceController.Opener? = nil, policy: BlockLoadAbandonment? = nil
    ) -> ResourceController {
        let disk = disk
        let time = time
        return ResourceController(
            opener: opener ?? { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) },
            mountTiming: MountCompletionTiming(
                timeout: .seconds(45), now: { time.now },
                sleepUntil: { _ in try await Task.sleep(for: .seconds(86_400)) },
                isMounted: { _, _ in false }, isBlockMounted: { _ in false }),
            abandonment: policy ?? self.policy, mounts: registry)
    }

    /// Another controller in the same simulated process, without its own watch.
    func neighbour(opener: @escaping ResourceController.Opener) -> ResourceController {
        let time = time
        return ResourceController(
            opener: opener,
            mountTiming: MountCompletionTiming(
                timeout: .seconds(45), now: { time.now },
                sleepUntil: { _ in try await Task.sleep(for: .seconds(86_400)) }),
            mounts: registry)
    }

    func load(_ controller: ResourceController) async throws -> LUNImageVolume {
        let state = state
        let descriptor = descriptor
        return try await controller.load(
            resourceURL: reference.url, readOnly: true, blockMount: identity,
            withdrawn: { state.checkWithdrawn() }, resolve: { descriptor })
    }

    /// Releases the next watch sleep once the watch is waiting for it.
    func tick() async throws {
        try await until { await ticks.waiting > 0 }
        await ticks.release()
    }

    /// Lets every task scheduled so far run, then checks that the watch is waiting again.
    func settle(expectingWait: Bool = true) async throws {
        if expectingWait {
            try await until { await ticks.waiting > 0 }
        }
        for _ in 0..<64 { await Task.yield() }
    }
}

private func until(_ condition: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(5))
    while !(await condition()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

private func activate(_ volume: LUNImageVolume) async throws {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        volume.activateRoot { _, error in
            if let error { continuation.resume(throwing: error) } else { continuation.resume() }
        }
    }
}

@Test func anUnmountedBlockVolumeEndsTheInstanceAfterItsDeadline() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    let volume = try await f.load(controller)
    try await activate(volume)
    try await f.tick()
    try await f.settle()
    #expect(await f.disk.closeCount == 0 && f.state.terminated == 0)
    f.time.expire()
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    // FSKit has the grace period to unload it first.
    try await f.settle()
    #expect(f.state.terminated == 0)
    try await f.tick()
    try await until { f.state.terminated == 1 }
    #expect(await f.ticks.requested == [.seconds(1), .seconds(1), .seconds(2)])
    await #expect(throws: POSIXError(.ENOTCONN)) { try await activate(volume) }
    try await controller.unload(blockDeviceName: "disk41")
    #expect(await f.disk.closeCount == 1)
    #expect(f.state.terminated == 1)
}

@Test func aWithdrawnResourceAbandonsTheLoadedVolumeBeforeItsDeadline() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    let volume = try await f.load(controller)
    try await f.tick()
    try await f.settle()
    #expect(f.state.checks == 1 && f.state.terminated == 0)
    f.state.withdrawn = true
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    // A late activation or mount callback can no longer mount it.
    await #expect(throws: POSIXError(.ENOTCONN)) { try await activate(volume) }
    await #expect(throws: POSIXError(.ENOTCONN)) { try await volume.completeMount() }
    try await f.tick()
    try await until { f.state.terminated == 1 }
    try await controller.unload(blockDeviceName: "disk41")
}

private actor HeldOpener {
    private var started = false
    private var cancelled = false
    private var waiter: CheckedContinuation<Void, Never>?
    var hasStarted: Bool { started }
    var wasCancelled: Bool { cancelled }
    func open() async throws -> LUNImageVolume {
        // Only the first load is held.
        guard !started else { return LUNImageVolume(disk: try MemoryDisk(), identifier: UUID()) }
        started = true
        await withTaskCancellationHandler {
            await withCheckedContinuation { waiter = $0 }
        } onCancel: {
            Task { await self.cancel() }
        }
        try Task.checkCancellation()
        return LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    }
    private func cancel() {
        cancelled = true
        waiter?.resume()
        waiter = nil
    }
}

@Test func aWithdrawnResourceCancelsALoadStillInProgress() async throws {
    let f = try AbandonFixture()
    let opener = HeldOpener()
    let controller = f.controller(opener: { _, _ in try await opener.open() })
    let loading = Task { try await f.load(controller) }
    try await until { await opener.hasStarted }
    try await f.tick()
    try await f.settle()
    #expect(!(await opener.wasCancelled))
    f.state.withdrawn = true
    try await f.tick()
    await #expect(throws: CancellationError.self) { try await loading.value }
    #expect(await opener.wasCancelled)
    // The failed load is FSKit's to end: this instance never ends itself for it.
    #expect(f.state.terminated == 0)
    // The generation is gone: another load is accepted.
    let next = try await controller.load(
        resourceURL: f.reference.url, readOnly: true, blockMount: f.identity
    ) { f.descriptor }
    #expect(next.isMountCompleted == false)
    try await controller.unload(blockDeviceName: "disk41")
}

@Test func aLateOpenerReturnCannotPublishAnAbandonedLoad() async throws {
    let f = try AbandonFixture()
    let release = AbandonTicks()
    let disk = f.disk
    // This opener ignores cancellation and returns a volume after the abandonment.
    let controller = f.controller(opener: { _, _ in
        try? await release.sleep(.zero)
        return LUNImageVolume(disk: disk, identifier: UUID())
    })
    let loading = Task { try await f.load(controller) }
    try await until { await release.waiting > 0 }
    f.state.withdrawn = true
    try await f.tick()
    try await until { await f.ticks.waiting == 0 }
    for _ in 0..<64 { await Task.yield() }
    await release.release()
    await #expect(throws: CancellationError.self) { try await loading.value }
    #expect(await disk.closeCount == 1)
    #expect(f.state.terminated == 0)
}

@Test(arguments: [true, false])
func aMountedOrCompletedVolumeIsNeverAbandoned(_ kernelMount: Bool) async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    let volume = try await f.load(controller)
    try await activate(volume)
    if kernelMount {
        f.state.mountState = true
    } else {
        try await volume.completeMount()
    }
    f.time.expire()
    f.state.withdrawn = true
    try await f.tick()
    // The watch has ended.
    try await f.settle(expectingWait: false)
    #expect(await f.ticks.waiting == 0)
    #expect(await f.disk.closeCount == 0 && f.state.terminated == 0)
    if !kernelMount { #expect(f.state.checks == 0) }
    try await controller.unload(blockDeviceName: "disk41")
    #expect(await f.disk.closeCount == 1)
}

@Test func anUnreadableMountTableNeverAbandons() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    _ = try await f.load(controller)
    f.state.mountState = nil
    f.time.expire()
    f.state.withdrawn = true
    for _ in 0..<3 {
        try await f.tick()
        try await f.settle()
    }
    #expect(await f.disk.closeCount == 0 && f.state.terminated == 0)
    f.state.mountState = false
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    try await f.tick()
    try await until { f.state.terminated == 1 }
    try await controller.unload(blockDeviceName: "disk41")
}

@Test func fskitUnloadDuringTheGraceKeepsTheInstance() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    _ = try await f.load(controller)
    f.time.expire()
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    try await f.settle()
    try await controller.unload(blockDeviceName: "disk41")
    // The unload cancelled the watch's grace period.
    try await until { await f.ticks.waiting == 0 }
    for _ in 0..<64 { await Task.yield() }
    #expect(f.state.terminated == 0)
}

@Test(arguments: [true, nil] as [Bool?])
func aMountAppearingOrUnknownAfterTheGraceKeepsTheInstance(_ state: Bool?) async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    _ = try await f.load(controller)
    f.time.expire()
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    try await f.settle()
    f.state.mountState = state
    try await f.tick()
    try await until { await f.ticks.waiting == 0 }
    for _ in 0..<64 { await Task.yield() }
    #expect(f.state.terminated == 0)
    try await controller.unload(blockDeviceName: "disk41")
}

@Test func aURLResourceIsNeverWatched() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    _ = try await controller.load(f.descriptor, readOnly: true)
    for _ in 0..<64 { await Task.yield() }
    #expect(await f.ticks.requested.isEmpty)
    try await controller.unload(f.descriptor)
}

@Test func anAbandonedVolumeThatCompletedItsMountIsLeftOpen() async throws {
    let disk = try AbandonDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.completeMount()
    #expect(!(await volume.abandonUncompletedMount()))
    #expect(volume.isMountCompleted)
    #expect(await disk.closeCount == 0)
    await volume.shutdown()
    #expect(await disk.closeCount == 1)
}

private actor WithdrawalStore: MountResourceStore {
    let failure: (any Error)?
    let descriptor: ConnectionDescriptor
    init(_ descriptor: ConnectionDescriptor, failure: (any Error)?) {
        self.descriptor = descriptor
        self.failure = failure
    }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        throw POSIXError(.EPERM)
    }
    func resolve(_ reference: ConnectionResourceReference) throws -> ConnectionDescriptor {
        if let failure { throw failure }
        return descriptor
    }
    func remove(_ reference: ConnectionResourceReference) throws { throw POSIXError(.EPERM) }
}

@Test(arguments: [
    ("present", false), ("notFound", true), ("locked", false), ("interaction", false),
    ("posix", false), ("other", false),
])
func onlyADefinitelyMissingMountResourceIsWithdrawn(_ kind: String, _ expected: Bool)
    async throws
{
    let f = try AbandonFixture()
    let failure: (any Error)? =
        switch kind {
        case "notFound": NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))
        case "locked": NSError(domain: NSOSStatusErrorDomain, code: Int(errSecNotAvailable))
        case "interaction":
            NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed))
        case "posix": POSIXError(.ENOENT)
        case "other": ProtocolError.malformed("mount resource data")
        default: nil
        }
    let store = WithdrawalStore(f.descriptor, failure: failure)
    #expect(await ISCSIFileSystem.isWithdrawn(f.reference, from: store) == expected)
}

@Test func aMountCompletedElsewhereInTheProcessKeepsTheInstance() async throws {
    let f = try AbandonFixture()
    let other = try MemoryDisk(readOnly: true)
    let neighbour = f.neighbour { _, _ in LUNImageVolume(disk: other, identifier: UUID()) }
    let mountedDescriptor = try f.descriptor.assigningMountID(UUID())
    let mounted = try await neighbour.load(mountedDescriptor, readOnly: true)
    try await activate(mounted)
    try await mounted.completeMount()
    #expect(f.registry.hasCompletedMount)
    let controller = f.controller()
    _ = try await f.load(controller)
    f.time.expire()
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    try await f.tick()
    try await until { await f.ticks.waiting == 0 }
    for _ in 0..<64 { await Task.yield() }
    // The abandoned volume is closed, but a volume of this process was mounted: it stays.
    #expect(f.state.terminated == 0)
    #expect(await other.connectionState() == .connected)
    try await controller.unload(blockDeviceName: "disk41")
    try await neighbour.unload(mountedDescriptor)
}

@Test func anotherLoadInProgressInTheProcessKeepsTheInstance() async throws {
    let f = try AbandonFixture()
    let held = HeldOpener()
    let neighbour = f.neighbour { _, _ in try await held.open() }
    let loading = Task {
        try await neighbour.load(f.descriptor.assigningMountID(UUID()), readOnly: true)
    }
    try await until { await held.hasStarted }
    #expect(!f.registry.hasCompletedMount)
    let controller = f.controller()
    _ = try await f.load(controller)
    f.time.expire()
    try await f.tick()
    try await until { await f.disk.closeCount == 1 }
    try await f.tick()
    try await until { await f.ticks.waiting == 0 }
    for _ in 0..<64 { await Task.yield() }
    #expect(f.state.terminated == 0)
    loading.cancel()
    await #expect(throws: CancellationError.self) { try await loading.value }
    try await controller.unload(blockDeviceName: "disk41")
}

@Test func theRegistryPermitsEndingOnlyForTheLastGenerationWithoutAMount() {
    let registry = ProcessMountRegistry()
    let first = UUID()
    let second = UUID()
    registry.begin(first)
    #expect(registry.permitsEnding(for: first))
    registry.begin(second)
    #expect(!registry.permitsEnding(for: first) && !registry.permitsEnding(for: second))
    registry.end(second)
    #expect(registry.permitsEnding(for: first))
    registry.recordCompletedMount()
    #expect(!registry.permitsEnding(for: first))
    registry.end(first)
    #expect(registry.hasCompletedMount && !registry.permitsEnding(for: UUID()))
}

@Test func aKernelMountSeenByTheWatchIsRecordedForTheProcess() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    _ = try await f.load(controller)
    f.state.mountState = true
    try await f.tick()
    try await until { f.registry.hasCompletedMount }
    try await controller.unload(blockDeviceName: "disk41")
}

@Test func aSecondLoadIntoAControllerWithAMountedVolumeIsRefused() async throws {
    let f = try AbandonFixture()
    let controller = f.controller()
    let volume = try await f.load(controller)
    try await activate(volume)
    try await volume.completeMount()
    let requested = await f.ticks.requested.count
    let other = try f.descriptor.assigningMountID(UUID())
    let otherIdentity = try BlockMountIdentity(
        bsdName: "disk42", mountID: try #require(other.mountID))
    await #expect(throws: ProtocolError.busy) {
        _ = try await controller.load(
            resourceURL: ConnectionResourceReference(descriptor: other).url, readOnly: true,
            blockMount: otherIdentity, resolve: { other })
    }
    // The refused load reserved nothing: no second watch, and the mounted volume is untouched.
    for _ in 0..<64 { await Task.yield() }
    #expect(await f.ticks.requested.count <= requested + 1)
    #expect(await f.disk.closeCount == 0 && f.state.terminated == 0)
    try await controller.unload(blockDeviceName: "disk41")
}
