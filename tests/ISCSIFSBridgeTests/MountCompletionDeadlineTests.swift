import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIFSBridge

private final class MountTestTime: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    func expire() { lock.withLock { instant = instant.advanced(by: .seconds(46)) } }
}

private actor MountTestTimer {
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var started = false
    func wait() async {
        started = true
        await withCheckedContinuation { waiter = $0 }
    }
    func release() {
        waiter?.resume()
        waiter = nil
    }
}

private final class MountTestFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    var value: Bool { lock.withLock { closed } }
    func finish() { lock.withLock { closed = true } }
}

private actor MountTestDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = true
    let closed = MountTestFlag()
    let closeGate: MountTestTimer?
    private(set) var closeCount = 0
    init(closeGate: MountTestTimer? = nil) throws {
        capacity = try MemoryDisk().capacity
        self.closeGate = closeGate
    }
    func read(offset: Int64, length: Int) -> Data { Data(repeating: 0, count: length) }
    func write(offset: Int64, data: Data) throws { throw POSIXError(.EROFS) }
    func synchronize() {}
    func close() async {
        closeCount += 1
        if let closeGate { await closeGate.wait() }
        closed.finish()
    }
    func connectionState() -> DiskConnectionState { closed.value ? .closed : .connected }
}

private func mountDescriptor() throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:mount-deadline", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5])
}

private func mountController(
    disk: MountTestDisk, clock: MountTestTime, timer: MountTestTimer,
    isMounted: @escaping @Sendable (ConnectionDescriptor) -> Bool = { _ in false }
) -> ResourceController {
    ResourceController(
        opener: { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) },
        mountTiming: MountCompletionTiming(
            timeout: .seconds(45), now: { clock.now }, sleepUntil: { _ in await timer.wait() },
            isMounted: { descriptor, _ in isMounted(descriptor) }))
}

@Test(arguments: [false, true], [false, true])
private func anEncodedResourceRemainsMountedWithoutTheMountCallback(
    _ timerFirst: Bool, _ boundedReference: Bool
)
    async throws
{
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let descriptor = try mountDescriptor().assigningMountID(UUID())
    let canonical = try descriptor.resourceURL.absoluteString
    let encoded = canonical.replacingOccurrences(
        of: "iqn.2026-10.test:", with: "iqn.2026-10.test%3A")
    let resource = FSGenericURLResource(url: try #require(URL(string: encoded)))
    let mountedURL =
        boundedReference
        ? try ConnectionResourceReference(descriptor: descriptor).url : resource.url
    #expect(try ConnectionDescriptor(resourceURL: resource.url) == descriptor)
    #expect(encoded != canonical)
    let observed = MountTestFlag()
    let controller = ResourceController(
        opener: { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) },
        mountTiming: MountCompletionTiming(
            timeout: .seconds(45), now: { clock.now }, sleepUntil: { _ in await timer.wait() },
            isMounted: { candidate, source in
                guard candidate == descriptor, source == mountedURL else {
                    return false
                }
                observed.finish()
                return true
            }))
    let fileSystem = ISCSIFileSystem(controller: controller)
    let volume: LUNImageVolume
    if boundedReference {
        volume = try await controller.load(descriptor, readOnly: true, resourceURL: mountedURL)
    } else {
        volume = try await fileSystem.loadVolume(resource: resource, readOnly: true)
    }
    while !(await timer.started) { await Task.yield() }
    try await activate(volume)
    clock.expire()
    if timerFirst {
        await timer.release()
        let until = ContinuousClock.now.advanced(by: .seconds(3))
        while !observed.value {
            guard ContinuousClock.now < until else { throw ProtocolError.timedOut }
            await Task.yield()
        }
    }
    try await activate(volume)
    await timer.release()
    #expect(observed.value)
    #expect(await disk.closeCount == 0)
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test(arguments: ["target", "readOnly", "mount", "profile", "settings", "unknown", "duplicate"])
private func aDifferentResourceCannotAuthorizeThisMount(_ change: String) async throws {
    let descriptor = try mountDescriptor()
    var components = try #require(
        URLComponents(url: descriptor.resourceURL, resolvingAgainstBaseURL: false))
    if change == "profile" {
        components.path = "/" + UUID().uuidString.lowercased()
    } else {
        var items = try #require(components.queryItems)
        switch change {
        case "target":
            items.removeAll { $0.name == "target" }
            items.append(URLQueryItem(name: "target", value: "iqn.2026-10.test:other"))
        case "readOnly":
            items.removeAll { $0.name == "readOnly" }
            items.append(URLQueryItem(name: "readOnly", value: "0"))
        case "mount": items.append(URLQueryItem(name: "mount", value: UUID().uuidString))
        case "settings":
            items.append(URLQueryItem(name: "settings", value: String(repeating: "00", count: 32)))
        case "unknown": items.append(URLQueryItem(name: "other", value: "1"))
        default: items.append(URLQueryItem(name: "readOnly", value: "1"))
        }
        components.queryItems = items
    }
    let opened = MountTestFlag()
    let controller = ResourceController { _, _ in
        opened.finish()
        return LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    }
    await #expect(throws: POSIXError(.EINVAL)) {
        _ = try await controller.load(
            descriptor, readOnly: true, resourceURL: #require(components.url))
    }
    #expect(!opened.value)
}

@Test(arguments: [false, true])
private func aKernelConfirmedMountSurvivesWithoutTheMountCallback(_ timerFirst: Bool)
    async throws
{
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let descriptor = try mountDescriptor()
    let observed = MountTestFlag()
    let controller = mountController(
        disk: disk, clock: clock, timer: timer,
        isMounted: { candidate in
            guard candidate == descriptor else { return false }
            observed.finish()
            return true
        })
    let volume = try await controller.load(descriptor, readOnly: true)
    while !(await timer.started) { await Task.yield() }
    try await activate(volume)
    clock.expire()
    if timerFirst {
        await timer.release()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !observed.value {
            guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
            await Task.yield()
        }
    }
    try await activate(volume)
    await timer.release()
    #expect(observed.value)
    #expect(await disk.closeCount == 0)
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test private func aKernelMountObservationCannotReviveAnUnloadedVolume() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let descriptor = try mountDescriptor()
    let controller = mountController(
        disk: disk, clock: clock, timer: timer, isMounted: { _ in true })
    let volume = try await controller.load(descriptor, readOnly: true)
    while !(await timer.started) { await Task.yield() }
    try await controller.unload(descriptor)
    clock.expire()
    await timer.release()
    await #expect(throws: POSIXError(.ENOTCONN)) { try await activate(volume) }
    #expect(await disk.closeCount == 1)
}

private func activate(_ volume: LUNImageVolume, requireClosed: MountTestFlag? = nil) async throws {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        volume.activateRoot { root, error in
            if let requireClosed { #expect(requireClosed.value) }
            if let error {
                continuation.resume(throwing: error)
            } else {
                #expect(root != nil)
                continuation.resume()
            }
        }
    }
}

private func waitForClose(_ disk: MountTestDisk) async throws {
    let clock = ContinuousClock()
    let until = clock.now.advanced(by: .seconds(3))
    while !(disk.closed.value), clock.now < until {
        try await clock.sleep(for: .milliseconds(1))
    }
    #expect(disk.closed.value)
}

@Test private func abandonedLoadClosesBeforeAnyActivation() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let controller = mountController(disk: disk, clock: clock, timer: timer)
    let descriptor = try mountDescriptor()
    let volume = try await controller.load(descriptor, readOnly: true)
    while !(await timer.started) { await Task.yield() }
    clock.expire()
    await timer.release()
    try await waitForClose(disk)
    await #expect(throws: ProtocolError.timedOut) { try await activate(volume) }
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test private func activationAloneDoesNotReleaseTheMountDeadline() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let controller = mountController(disk: disk, clock: clock, timer: timer)
    let descriptor = try mountDescriptor()
    let volume = try await controller.load(descriptor, readOnly: true)
    try await activate(volume)
    while !(await timer.started) { await Task.yield() }
    clock.expire()
    await timer.release()
    try await waitForClose(disk)
    await #expect(throws: ProtocolError.timedOut) {
        try await volume.completeMount()
    }
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test private func establishedMountStaysOpenAfterItsCancelledDeadline() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let controller = mountController(disk: disk, clock: clock, timer: timer)
    let descriptor = try mountDescriptor()
    let volume = try await controller.load(descriptor, readOnly: true)
    while !(await timer.started) { await Task.yield() }
    try await activate(volume)
    try await volume.completeMount()
    clock.expire()
    await timer.release()  // The injected sleep deliberately ignores cancellation.
    try await volume.completeMount()
    #expect(await disk.connectionState() == .connected)
    #expect(await disk.closeCount == 0)
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test(arguments: [false, true])
private func lateCallbacksCloseBeforeReplyEvenIfTheTimerWasNotDelivered(mount: Bool) async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let closeGate = MountTestTimer()
    let disk = try MountTestDisk(closeGate: closeGate)
    let controller = mountController(disk: disk, clock: clock, timer: timer)
    let descriptor = try mountDescriptor()
    let volume = try await controller.load(descriptor, readOnly: true)
    if mount { try await activate(volume) }
    while !(await timer.started) { await Task.yield() }
    clock.expire()
    let callback = Task {
        if mount {
            try await volume.completeMount()
        } else {
            try await activate(volume, requireClosed: disk.closed)
        }
    }
    while !(await closeGate.started) { await Task.yield() }
    #expect(!disk.closed.value)
    await closeGate.release()
    await #expect(throws: ProtocolError.timedOut) { try await callback.value }
    #expect(disk.closed.value)
    await timer.release()
    try await controller.unload(descriptor)
    #expect(await disk.closeCount == 1)
}

@Test private func unloadCancelsTheDeadlineAndClosesOnlyOnce() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let controller = mountController(disk: disk, clock: clock, timer: timer)
    let descriptor = try mountDescriptor()
    _ = try await controller.load(descriptor, readOnly: true)
    while !(await timer.started) { await Task.yield() }
    try await controller.unload(descriptor)
    clock.expire()
    await timer.release()
    #expect(disk.closed.value)
    #expect(await disk.closeCount == 1)
}

@Test private func aLateOpenerCannotPublishAnUnusableVolume() async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let controller = ResourceController(
        opener: { _, _ in
            clock.expire()
            return LUNImageVolume(disk: disk, identifier: UUID())
        },
        mountTiming: MountCompletionTiming(
            timeout: .seconds(45), now: { clock.now }, sleepUntil: { _ in await timer.wait() }))
    await #expect(throws: ProtocolError.timedOut) {
        _ = try await controller.load(mountDescriptor(), readOnly: true)
    }
    #expect(disk.closed.value)
    #expect(await disk.closeCount == 1)
}

@Test(arguments: [false, true], [false, true])
private func aBlockResourceDeadlineRequiresItsOwnKernelMount(
    _ kernelConfirmed: Bool, _ timerFirst: Bool
) async throws {
    let clock = MountTestTime()
    let timer = MountTestTimer()
    let disk = try MountTestDisk()
    let descriptor = try mountDescriptor().assigningMountID(UUID())
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    let identity = try BlockMountIdentity(bsdName: "disk41", mountID: reference.mountID)
    let observed = MountTestFlag()
    let controller = ResourceController(
        opener: { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) },
        mountTiming: MountCompletionTiming(
            timeout: .seconds(45), now: { clock.now }, sleepUntil: { _ in await timer.wait() },
            isMounted: { _, _ in
                Issue.record("A URL observation must not keep a block resource alive")
                return true
            },
            isBlockMounted: { candidate in
                #expect(candidate == identity)
                observed.finish()
                return kernelConfirmed
            }))
    let volume = try await controller.load(
        resourceURL: reference.url, readOnly: true, blockMount: identity
    ) { descriptor }
    while !(await timer.started) { await Task.yield() }
    try await activate(volume)
    clock.expire()
    if timerFirst {
        await timer.release()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !observed.value {
            guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
            await Task.yield()
        }
    }
    if kernelConfirmed {
        try await activate(volume)
        #expect(await disk.closeCount == 0)
    } else {
        await #expect(throws: ProtocolError.timedOut) { try await activate(volume) }
        #expect(disk.closed.value)
    }
    await timer.release()
    try await controller.unload(blockDeviceName: "disk41")
    #expect(await disk.closeCount == 1)
}
