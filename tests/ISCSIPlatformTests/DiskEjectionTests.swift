import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private let ejectionImage = URL(fileURLWithPath: "/private/tmp/iscsi-ejection-tests/Disk.img")
private let ejectionDevice = "/dev/disk900000"

private actor EjectionGate {
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

private actor EjectionSteps: DiskEjectionHandle {
    let gate = EjectionGate()
    let pause: String?
    let busy: Bool
    let onUnmount: @Sendable () -> Void
    private var paused = false
    private(set) var events: [String] = []
    init(pause: String? = nil, busy: Bool = false, onUnmount: @escaping @Sendable () -> Void = {}) {
        self.pause = pause
        self.busy = busy
        self.onUnmount = onUnmount
    }
    func record(_ phase: String) async {
        events.append(phase)
        if pause == phase, !paused {
            paused = true
            await gate.wait()  // Models an issued OS request that cannot be cancelled.
        }
    }
    func unmount() async throws {
        await record("unmount")
        onUnmount()
        if busy { throw POSIXError(.EBUSY) }
    }
    func eject() async throws { await record("eject") }
    func validate() async throws { await record("validate") }
}

private func ejection(_ steps: EjectionSteps, timeout: Duration = .seconds(3)) -> DiskEjection {
    DiskEjection(
        timeout: timeout,
        factory: { request in
            #expect(!request.force && request.mediaIdentifiers.isEmpty)
            await steps.record("open")
            return steps
        })
}

@Test private func anExplicitForceEjectRetainsTheConfirmedMediaIdentifiers() async throws {
    let steps = EjectionSteps()
    let identifiers = [ejectionDevice: UInt64(41)]
    let service = DiskEjection(factory: { request in
        #expect(request.force && request.mediaIdentifiers == identifiers)
        await steps.record("open")
        return steps
    })
    try await service.forceEject(
        device: ejectionDevice, image: ejectionImage, unmountDevices: [ejectionDevice],
        mediaIdentifiers: identifiers, validate: steps.validate)
    #expect(await steps.events == ["open", "unmount", "validate", "eject"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test private func aConfirmedNormalEjectRetainsIdentityWithoutForce() async throws {
    let steps = EjectionSteps()
    let identities = [ejectionDevice: UInt64(41)]
    let service = DiskEjection(factory: { request in
        #expect(!request.force && request.mediaIdentifiers == identities)
        return steps
    })
    try await service.ejectConfirmed(
        device: ejectionDevice, image: ejectionImage, unmountDevices: [ejectionDevice],
        mediaIdentifiers: identities, validate: steps.validate)
    #expect(await steps.events == ["unmount", "validate", "eject"])
}

@Test(arguments: [[:], [ejectionDevice: UInt64(0)], ["/dev/disk900001": UInt64(41)]])
private func incompleteNormalMediaIdentityIsRejectedBeforeOpeningAnyDevice(
    _ identifiers: [String: UInt64]
) async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await service.ejectConfirmed(
            device: ejectionDevice, image: ejectionImage, unmountDevices: [ejectionDevice],
            mediaIdentifiers: identifiers, validate: steps.validate)
    }
    #expect(await steps.events.isEmpty)
}

@Test(arguments: [[:], [ejectionDevice: UInt64(0)], ["/dev/disk900001": UInt64(41)]])
private func incompleteForceMediaIdentityIsRejectedBeforeOpeningAnyDevice(
    _ identifiers: [String: UInt64]
) async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await service.forceEject(
            device: ejectionDevice, image: ejectionImage, unmountDevices: [ejectionDevice],
            mediaIdentifiers: identifiers, validate: steps.validate)
    }
    #expect(await steps.events.isEmpty)
}

@Test private func aLateForceUnmountCannotEjectAfterItsDeadline() async throws {
    let steps = EjectionSteps(pause: "unmount")
    let clock = EjectionTime()
    let timer = EjectionGate()
    let service = DiskEjection(
        timeout: .seconds(1), now: { clock.now }, waitUntil: { _ in await timer.wait() },
        factory: { _ in
            await steps.record("open")
            return steps
        })
    let task = Task {
        try await service.forceEject(
            device: ejectionDevice, image: ejectionImage, unmountDevices: [ejectionDevice],
            mediaIdentifiers: [ejectionDevice: 41], validate: steps.validate)
    }
    try await waitForGate(steps)
    let timerDeadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await timer.started) {
        guard ContinuousClock.now < timerDeadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
    clock.advance()
    await timer.release()
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await service.pendingImagePaths() == [ejectionImage.path])
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    await steps.gate.release()
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await service.pendingImagePaths().isEmpty) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
    #expect(await steps.events == ["open", "unmount"])
}

private func waitForGate(_ steps: EjectionSteps) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await steps.gate.started) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

@Test private func normalEjectionUnmountsAndRevalidatesBeforeEjecting() async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    try await service.eject(device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    #expect(await steps.events == ["open", "unmount", "validate", "eject"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test private func busyVolumesAreNotEjectedOrReclassifiedAsOtherFailures() async throws {
    let steps = EjectionSteps(busy: true)
    let service = ejection(steps)
    await #expect(throws: POSIXError(.EBUSY)) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    #expect(await steps.events == ["open", "unmount"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test private func changedOwnershipAfterUnmountStopsEjection() async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await service.eject(device: ejectionDevice, image: ejectionImage) {
            throw AttachmentError.imageIdentityChanged
        }
    }
    #expect(await steps.events == ["open", "unmount"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test(arguments: ["unmount", "validate", "eject"])
private func timedOutEjectionsRemainTrackedAndCannotAdvanceAfterALateCallback(_ phase: String)
    async throws
{
    let steps = EjectionSteps(pause: phase)
    let clock = EjectionTime()
    let service = DiskEjection(
        timeout: .seconds(1), now: { clock.now },
        waitUntil: { deadline in
            while clock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        },
        factory: { request in
            #expect(!request.force && request.mediaIdentifiers.isEmpty)
            await steps.record("open")
            return steps
        })
    let task = Task {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    try await waitForGate(steps)
    clock.advance()
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await service.pendingImagePaths() == [ejectionImage.path])
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage.appendingPathExtension("other"),
            validate: steps.validate)
    }
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await service.eject(
            device: "/dev/disk900001", image: ejectionImage, validate: steps.validate)
    }
    await steps.gate.release()
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await service.pendingImagePaths().isEmpty) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
    let expected = Array(
        ["open", "unmount", "validate", "eject"].prefix(
            phase == "unmount" ? 2 : phase == "validate" ? 3 : 4))
    #expect(await steps.events == expected)
    try await service.eject(device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    #expect(await steps.events == expected + ["open", "unmount", "validate", "eject"])
}

@Test private func callerCancellationWaitsForTheStartedEjection() async throws {
    let steps = EjectionSteps(pause: "unmount")
    let service = ejection(steps)
    let task = Task {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    try await waitForGate(steps)
    task.cancel()
    #expect(await service.pendingImagePaths() == [ejectionImage.path])
    await steps.gate.release()
    try await task.value
    #expect(await steps.events == ["open", "unmount", "validate", "eject"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test private func cancellationBeforeEjectionDoesNotIssueAnOSRequest() async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await steps.events.isEmpty)
}

private final class EjectionTime: @unchecked Sendable {
    private let lock = NSLock()
    private var value = ContinuousClock.now
    var now: ContinuousClock.Instant { lock.withLock { value } }
    func advance() { lock.withLock { value = value.advanced(by: .seconds(2)) } }
}

@Test private func aDelayedTimerCannotStartTheNextOSRequestAfterTheDeadline() async throws {
    let clock = EjectionTime()
    let steps = EjectionSteps(onUnmount: { clock.advance() })
    let service = DiskEjection(
        timeout: .seconds(1), now: { clock.now },
        waitUntil: { _ in try await Task.sleep(for: .seconds(60)) },
        factory: { _ in steps })
    await #expect(throws: ProtocolError.timedOut) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    #expect(await steps.events == ["unmount"])
    #expect(await service.pendingImagePaths().isEmpty)
}

@Test private func partitionNamesCannotRequestWholeDiskEjection() async throws {
    let steps = EjectionSteps()
    let service = ejection(steps)
    await #expect(throws: ProtocolError.invalidState) {
        try await service.eject(
            device: ejectionDevice + "s1", image: ejectionImage, validate: steps.validate)
    }
    #expect(await steps.events.isEmpty)
}

private final class EjectionEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [DiskEjectionDiagnostics.Event] = []
    var values: [DiskEjectionDiagnostics.Event] { lock.withLock { recorded } }
    func append(_ event: DiskEjectionDiagnostics.Event) {
        lock.withLock { recorded.append(event) }
    }
}

@Test private func ejectionDiagnosticsExcludePrivateURLsAndErrorDescriptions() async throws {
    let events = EjectionEvents()
    let steps = EjectionSteps()
    let image = URL(fileURLWithPath: "/private/tmp/private-server-and-password/Disk.img")
    let detail = "private-error-with-iqn-and-credentials"
    let failure = NSError(
        domain: detail, code: 77, userInfo: [NSLocalizedDescriptionKey: image.path + detail])
    let service = DiskEjection(diagnostics: events.append, factory: { _ in steps })
    await #expect(throws: failure) {
        try await service.eject(device: ejectionDevice, image: image) { throw failure }
    }
    let observed = events.values
    #expect(observed.map(\.phase) == [.begin, .finished])
    #expect(Set(observed.map(\.requestID)).count == 1)
    #expect(observed.last?.outcome == .other && observed.last?.errorCode == 0)
    #expect(observed.last?.awaitingReply == true)
    let encoded = String(decoding: try JSONEncoder().encode(observed), as: UTF8.self)
    let output = encoded + observed.map(\.fields).joined(separator: "\n")
    #expect(!output.contains(image.path) && !output.contains(detail))
    #expect(!output.contains(ejectionDevice))
    #expect(await steps.events == ["unmount"])
}

@Test private func ejectionDiagnosticsDistinguishTimeoutFromALateRequestDrain() async throws {
    let events = EjectionEvents()
    let steps = EjectionSteps(pause: "unmount")
    let clock = EjectionTime()
    let timer = EjectionGate()
    let service = DiskEjection(
        timeout: .seconds(1), now: { clock.now }, waitUntil: { _ in await timer.wait() },
        diagnostics: events.append, factory: { _ in steps })
    let task = Task {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    try await waitForGate(steps)
    let timerDeadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await timer.started) {
        guard ContinuousClock.now < timerDeadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
    clock.advance()
    await timer.release()
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(events.values.map(\.phase) == [.begin, .deadline])
    #expect(events.values.last?.outcome == .timedOut)
    #expect(await service.pendingImagePaths() == [ejectionImage.path])
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    #expect(events.values.count == 2)
    await steps.gate.release()
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await service.pendingImagePaths().isEmpty) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
    let observed = events.values
    #expect(observed.map(\.phase) == [.begin, .deadline, .finished])
    #expect(Set(observed.map(\.requestID)).count == 1)
    #expect(observed.last?.awaitingReply == false && observed.last?.outcome == .cancelled)
    #expect(await steps.events == ["unmount"])
}

@Test private func busyEjectionDiagnosticsDoNotRetryOrEscalateToForce() async throws {
    let events = EjectionEvents()
    let steps = EjectionSteps(busy: true)
    let service = DiskEjection(
        diagnostics: events.append,
        factory: { request in
            #expect(!request.force)
            return steps
        })
    await #expect(throws: POSIXError(.EBUSY)) {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    let observed = events.values
    #expect(observed.map(\.phase) == [.begin, .finished])
    #expect(observed.allSatisfy { !$0.force && $0.targetCount == 1 })
    #expect(observed.last?.outcome == .busy && observed.last?.errorCode == Int(EBUSY))
    #expect(await steps.events == ["unmount"])
}

@Test private func refusedEjectionsDoNotProduceAcceptedRequestDiagnostics() async throws {
    let events = EjectionEvents()
    let steps = EjectionSteps()
    let service = DiskEjection(diagnostics: events.append, factory: { _ in steps })
    await #expect(throws: ProtocolError.invalidState) {
        try await service.eject(
            device: ejectionDevice + "s1", image: ejectionImage, validate: steps.validate)
    }
    #expect(events.values.isEmpty)
    #expect(await steps.events.isEmpty)
}

@Test(arguments: [false, true])
private func aPendingEjectionCanBeAwaitedOnlyUntilItEndsOrTheWaitExpires(_ ends: Bool)
    async throws
{
    let steps = EjectionSteps(pause: "unmount")
    let clock = EjectionTime()
    let service = DiskEjection(
        timeout: .seconds(1), now: { clock.now },
        waitUntil: { deadline in
            while clock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        },
        factory: { _ in
            await steps.record("open")
            return steps
        })
    #expect(await service.waitForPendingEjection(of: ejectionImage, timeout: .seconds(1)))
    let task = Task {
        try await service.eject(
            device: ejectionDevice, image: ejectionImage, validate: steps.validate)
    }
    try await waitForGate(steps)
    clock.advance()
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await service.pendingImagePaths() == [ejectionImage.path])
    // Another image has nothing pending.
    #expect(
        await service.waitForPendingEjection(
            of: ejectionImage.appendingPathExtension("other"), timeout: .seconds(1)))
    let waiting = Task {
        await service.waitForPendingEjection(of: ejectionImage, timeout: .seconds(1))
    }
    try await Task.sleep(for: .milliseconds(20))
    if ends {
        // The OS answers the late request; it can't advance past its deadline.
        await steps.gate.release()
        #expect(await waiting.value)
        #expect(await service.pendingImagePaths().isEmpty)
        #expect(await steps.events == ["open", "unmount"])
    } else {
        clock.advance()
        #expect(!(await waiting.value))
        #expect(await service.pendingImagePaths() == [ejectionImage.path])
        await steps.gate.release()
    }
}
