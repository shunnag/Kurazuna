import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private final class PermissionChanges: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func record() { lock.withLock { count += 1 } }
}

@Test func overlappingPermissionWaitsCountElapsedTimeOnceAndRemainBounded() {
    let time = ManualSessionTime()
    let changes = PermissionChanges()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(120)) {
        changes.record()
    }
    let first = UUID()
    let second = UUID()
    wait.update(first, waiting: true)
    time.advance(by: .seconds(26))
    wait.update(first, waiting: true)
    wait.update(second, waiting: true)
    time.advance(by: .seconds(10))
    wait.update(first, waiting: false)
    time.advance(by: .seconds(4))
    wait.update(second, waiting: false)
    #expect(wait.elapsed == .seconds(40))
    #expect(!wait.isWaiting && changes.value == 2)
    time.advance(by: .seconds(200))
    #expect(wait.elapsed == .seconds(40))
    #expect(wait.additionalTime(since: .seconds(40)) == .zero)
    wait.update(first, waiting: true)
    time.advance(by: .seconds(100))
    #expect(wait.elapsed == .seconds(120))
    wait.update(first, waiting: false)
    #expect(wait.elapsed == .seconds(120) && changes.value == 4)
}

@Test func aPermissionChoiceCanExceedTheNetworkBudgetWithoutSendingOrRestartingLogin() async throws
{
    let time = ManualSessionTime()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(120))
    let transport = try PermissionTransport(loginFixtures(normal: true))
    let task = permissionConnection(time: time, wait: wait, transport: transport)
    try await permissionPhase { await transport.connecting && time.pendingCount > 0 }
    let token = UUID()
    wait.update(token, waiting: true)
    time.advance(by: .seconds(26), wakeTimers: true)
    try await permissionPhase { time.hasSleeper(after: .seconds(31)) }
    #expect(await transport.inner.writes.isEmpty)
    #expect(await transport.connectCalls == 1)
    #expect(await !transport.closed)
    wait.update(token, waiting: false)
    await transport.release()
    let connection = try await task.value
    #expect(await transport.connectCalls == 1)
    #expect(await transport.inner.writes.count == 2)
    await connection.session.close()
}

@Test func theOriginalNetworkBudgetStillExpiresAfterPermissionWaitingEnds() async throws {
    let time = ManualSessionTime()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(120))
    let transport = PermissionTransport([])
    let task = permissionConnection(time: time, wait: wait, transport: transport)
    try await permissionPhase { await transport.connecting && time.pendingCount > 0 }
    let token = UUID()
    wait.update(token, waiting: true)
    time.advance(by: .seconds(26), wakeTimers: true)
    try await permissionPhase { time.hasSleeper(after: .seconds(31)) }
    wait.update(token, waiting: false)
    time.advance(by: .seconds(6), wakeTimers: true)
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await transport.closed)
    #expect(await transport.inner.writes.isEmpty)
}

@Test func permissionWaitingCannotExtendAConnectionBeyondItsFiniteAllowance() async throws {
    let time = ManualSessionTime()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(12))
    let transport = PermissionTransport([])
    let task = permissionConnection(time: time, wait: wait, transport: transport)
    try await permissionPhase { await transport.connecting && time.pendingCount > 0 }
    let token = UUID()
    wait.update(token, waiting: true)
    time.advance(by: .seconds(18), wakeTimers: true)
    await #expect(throws: ProtocolError.localNetworkAccessRequired) { try await task.value }
    #expect(await transport.closed)
    #expect(await transport.inner.writes.isEmpty)
    #expect(wait.elapsed == .seconds(12))
    wait.update(token, waiting: false)
}

@Test func cancellingDuringPermissionWaitingClosesWithoutLogin() async throws {
    let time = ManualSessionTime()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(120))
    let transport = PermissionTransport([])
    let task = permissionConnection(time: time, wait: wait, transport: transport)
    try await permissionPhase { await transport.connecting && time.pendingCount > 0 }
    let token = UUID()
    wait.update(token, waiting: true)
    time.advance(by: .seconds(26), wakeTimers: true)
    try await permissionPhase { time.hasSleeper(after: .seconds(31)) }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await transport.closed)
    #expect(await transport.inner.writes.isEmpty)
    wait.update(token, waiting: false)
}

@Test func aNewConnectionCannotReuseTimeFromAnEarlierPermissionWait() async throws {
    let time = ManualSessionTime()
    let wait = LocalNetworkAccessWait(clock: time.source, maximum: .seconds(120))
    let token = UUID()
    wait.update(token, waiting: true)
    time.advance(by: .seconds(26))
    wait.update(token, waiting: false)
    let transport = PermissionTransport([])
    let task = permissionConnection(time: time, wait: wait, transport: transport)
    try await permissionPhase {
        await transport.connecting && time.hasSleeper(after: .seconds(31))
    }
    time.advance(by: .seconds(6), wakeTimers: true)
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await transport.closed)
    #expect(await transport.inner.writes.isEmpty)
}

private func permissionConnection(
    time: ManualSessionTime, wait: LocalNetworkAccessWait, transport: PermissionTransport
) -> Task<SessionConnection, any Error> {
    Task {
        try await SessionConnector.connect(
            portal: Portal("permission.local"), configuration: configuration(normal: true),
            timeout: .seconds(5), clock: time.source, localNetworkAccessWait: wait,
            factory: { _, _ in transport })
    }
}

private actor PermissionTransport: ConnectableByteTransport {
    let inner: ScriptedTransport
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var connecting = false
    private(set) var connectCalls = 0
    private(set) var closed = false

    init(_ responses: [Data]) { inner = ScriptedTransport(responses) }

    func connect() async throws {
        connectCalls += 1
        connecting = true
        if !closed { await withCheckedContinuation { waiter = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
    }

    func release() {
        waiter?.resume()
        waiter = nil
    }
    func send(_ data: Data) async throws { try await inner.send(data) }
    func receive(maximumLength: Int) async throws -> Data {
        try await inner.receive(maximumLength: maximumLength)
    }
    func close() async {
        closed = true
        release()
        await inner.close()
    }
}

private func permissionPhase(_ condition: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(1))
    }
}
