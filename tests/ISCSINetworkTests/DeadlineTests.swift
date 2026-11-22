import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

/// Advances the measured instant independently of timer delivery, including overdue timers.
/// All continuations are removed under the lock and resumed outside it, exactly once.
final class ManualSessionTime: @unchecked Sendable {
    private struct Sleeper {
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, any Error>
    }
    private let lock = NSLock()
    let initial = ContinuousClock.now
    private var instant: ContinuousClock.Instant
    private var sleepers: [UUID: Sleeper] = [:]

    init() { instant = initial }

    var source: SessionClock {
        SessionClock(now: { self.now }, sleep: { try await self.sleep(until: $0) })
    }
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    var pendingCount: Int { lock.withLock { sleepers.count } }

    func hasSleeper(after duration: Duration) -> Bool {
        lock.withLock { sleepers.values.contains { $0.deadline == initial.advanced(by: duration) } }
    }

    func advance(by duration: Duration, wakeTimers: Bool = false) {
        let due: [Sleeper] = lock.withLock {
            instant = instant.advanced(by: duration)
            guard wakeTimers else { return [] }
            let due = sleepers.filter { $0.value.deadline <= instant }
            for id in due.keys { sleepers.removeValue(forKey: id) }
            return Array(due.values)
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    private func sleep(until deadline: ContinuousClock.Instant) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let cancelled = lock.withLock {
                    if Task.isCancelled { return true }
                    sleepers[id] = Sleeper(deadline: deadline, continuation: continuation)
                    return false
                }
                if cancelled { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            let sleeper = self.lock.withLock { self.sleepers.removeValue(forKey: id) }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }
}

private actor DeadlineTransport: ByteTransport {
    enum Mode: String, CaseIterable {
        case login, read, discovery, logout, write, window, heartbeat
    }
    private let mode: Mode
    private let logins: [Data]
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var sender: CheckedContinuation<Void, any Error>?
    private var reply: Data?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private var writeTag: UInt32 = 0
    private var writeBytes = 0
    private(set) var writes: [PDU] = []
    private(set) var isClosed = false
    var hasReply: Bool { reply != nil }
    var hasSender: Bool { sender != nil }

    init(_ mode: Mode) throws {
        self.mode = mode
        var logins = try loginFixtures(normal: mode != .discovery)
        if mode == .window {
            var final = Array(logins[1])
            final.put(UInt32(0), at: 32)
            logins[1] = Data(final)
        }
        self.logins = logins
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 1_048_576)
        let pdus = try decoder.append(data)
        guard pdus.count == 1, decoder.isAtFrameBoundary else {
            throw ProtocolError.malformed("test frame")
        }
        let pdu = pdus[0]
        writes.append(pdu)
        switch pdu.opcode {
        case 0x03:
            let response = logins[Int((pdu.flags >> 2) & 3)]
            if mode == .login { reply = response } else { enqueue(response) }
        case 0x01:
            guard pdu.header.uint32(at: 24) == expectedCommand else {
                throw ProtocolError.malformed("test CmdSN")
            }
            expectedCommand &+= 1
            switch pdu.header[32] {
            case 0x28:
                var header = serverHeader(opcode: 0x25, tag: pdu.taskTag)
                header[1] = 0x81
                reply = try PDU(header: header, data: Data(repeating: 0xA5, count: 512)).encoded()
                status &+= 1
            case 0x2A, 0x8A:
                writeTag = pdu.taskTag
                var header = serverHeader(opcode: 0x31, tag: pdu.taskTag)
                header.put(UInt32(73), at: 20)
                header.put(pdu.header.uint32(at: 20), at: 44)
                enqueue(try PDU(header: header).encoded())
            default:
                enqueue(try PDU(header: serverHeader(opcode: 0x21, tag: pdu.taskTag)).encoded())
                status &+= 1
            }
        case 0x05:
            writeBytes += pdu.data.count
            if writeBytes == pdu.data.count {
                try await withCheckedThrowingContinuation { sender = $0 }
            }
            if pdu.flags & 0x80 != 0 {
                enqueue(try PDU(header: serverHeader(opcode: 0x21, tag: writeTag)).encoded())
                status &+= 1
            }
        case 0x04:
            reply = try PDU(
                header: serverHeader(opcode: 0x24, tag: pdu.taskTag),
                data: TextParameters([.init("TargetName", "iqn.2026-10.test:disk")]).encoded()
            ).encoded()
            status &+= 1
        case 0x06:
            reply = try PDU(header: serverHeader(opcode: 0x26, tag: pdu.taskTag)).encoded()
            status &+= 1
        case 0x00 where pdu.taskTag != UInt32.max:
            // Keep the heartbeat outstanding while a command queues behind its send.
            try await withCheckedThrowingContinuation { sender = $0 }
        case 0x00: break
        default: throw ProtocolError.malformed("unexpected test request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !isClosed { await withCheckedContinuation { reader = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(maximumLength, input.count)
        let data = Data(input.prefix(count))
        input.removeFirst(count)
        return data
    }

    func close() async {
        isClosed = true
        reader?.resume()
        reader = nil
        sender?.resume(throwing: ProtocolError.connectionClosed)
        sender = nil
    }

    func releaseReply() throws {
        guard let reply else { throw ProtocolError.invalidState }
        self.reply = nil
        enqueue(reply)
    }

    func releaseSender() {
        let sender = sender
        self.sender = nil
        sender?.resume()
    }

    func openWindow() throws {
        enqueue(try PDU(header: serverHeader(opcode: 0x20, tag: UInt32.max)).encoded())
    }

    private func serverHeader(opcode: UInt8, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(expectedCommand, at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    private func enqueue(_ data: Data) {
        input.append(data)
        reader?.resume()
        reader = nil
    }
}

private func awaitDeadlinePhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test(arguments: [
    DeadlineTransport.Mode.login, .read, .discovery, .logout,
])
private func lateRepliesCannotWinAgainstAnUndeliveredDeadlineTimer(_ mode: DeadlineTransport.Mode)
    async throws
{
    let time = ManualSessionTime()
    let transport = try DeadlineTransport(mode)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: mode != .discovery),
        clock: time.source)
    if mode != .login { try await session.login() }
    let operation = Task {
        switch mode {
        case .login: try await session.login()
        case .read:
            _ = try await session.execute(
                .read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0))
        case .discovery: _ = try await session.discover()
        case .logout: try await session.logout()
        default: throw ProtocolError.invalidState
        }
    }
    try await awaitDeadlinePhase { await transport.hasReply }
    time.advance(by: .seconds(31))
    try await transport.releaseReply()
    // A login that wrongly accepts the late security reply sends its second request.
    if mode == .login {
        try await awaitDeadlinePhase {
            let closed = await transport.isClosed
            let reply = await transport.hasReply
            return closed || reply
        }
        if await transport.hasReply { try await transport.releaseReply() }
    }
    await #expect(throws: ProtocolError.timedOut) { try await operation.value }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    if mode == .login { #expect(await transport.writes.count == 1) }
    await session.close()
    try await awaitDeadlinePhase { time.pendingCount == 0 }
}

@Test(arguments: [29, 30, 31], [false, true])
private func dataOutAdmissionChecksElapsedTimeBeforeTheTimerRuns(_ elapsed: Int, _ sixteen: Bool)
    async throws
{
    let time = ManualSessionTime()
    let transport = try DeadlineTransport(.write)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    try await session.login()
    let operation = Task {
        let command =
            try sixteen
            ? SCSICommand.write16(lba: 0, blocks: 32, blockSize: 512)
            : SCSICommand.write10(lba: 0, blocks: 32, blockSize: 512)
        return try await session.execute(
            command, lun: LogicalUnit(0),
            output: Data(repeating: 0xA5, count: 16384))
    }
    try await awaitDeadlinePhase { await transport.hasSender }
    time.advance(by: .seconds(elapsed))
    await transport.releaseSender()
    if elapsed >= 30 {
        await #expect(throws: ProtocolError.timedOut) { try await operation.value }
        #expect(await transport.writes.filter { $0.opcode == 5 }.count == 1)
        #expect(await session.state == .failed)
        #expect(await transport.isClosed)
    } else {
        #expect(try await operation.value.data.isEmpty)
        #expect(await transport.writes.filter { $0.opcode == 5 }.count == 2)
        // The completed write's old deadline must not poison the next operation.
        time.advance(by: .seconds(2))
        _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
        #expect(await session.state == .ready)
    }
    await session.close()
    try await awaitDeadlinePhase { time.pendingCount == 0 }
}

@Test private func aLateCommandWindowCannotAdmitAnExpiredCommand() async throws {
    let time = ManualSessionTime()
    let transport = try DeadlineTransport(.window)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    try await session.login()
    let operation = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await awaitDeadlinePhase { time.hasSleeper(after: .seconds(30)) }
    time.advance(by: .seconds(31))
    try await transport.openWindow()
    await #expect(throws: ProtocolError.timedOut) { try await operation.value }
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await session.close()
    try await awaitDeadlinePhase { time.pendingCount == 0 }
}

@Test private func anExpiredHeartbeatCannotBeHiddenByALaterCommandDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try DeadlineTransport(.heartbeat)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    try await session.login()
    try await awaitDeadlinePhase { time.hasSleeper(after: .seconds(10)) }
    time.advance(by: .seconds(10), wakeTimers: true)
    try await awaitDeadlinePhase { await transport.hasSender }
    let operation = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await awaitDeadlinePhase { time.hasSleeper(after: .seconds(40)) }
    time.advance(by: .seconds(6))
    await transport.releaseSender()
    await #expect(throws: ProtocolError.timedOut) { try await operation.value }
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await session.close()
    try await awaitDeadlinePhase { time.pendingCount == 0 }
}

/// The production clock serves deadlines through one shared timer. A reply racing the
/// command's deadline still has exactly one outcome.
@Test(arguments: [29, 30, 31])
private func aReplyRacingItsDeadlineHasOneOutcomeThroughTheSharedTimer(_ elapsed: Int)
    async throws
{
    let time = ManualSessionTime()
    let source = time.source
    let timer = DeadlineTimer(now: { source.now }, sleep: { try await source.sleep(until: $0) })
    let transport = try DeadlineTransport(.read)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        clock: SessionClock(timer: timer))
    try await session.login()
    let operation = Task {
        try await session.execute(
            .read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0))
    }
    // The shared timer sleeps for the idle probe's +10 s; the read's +30 s wait shares it.
    try await awaitDeadlinePhase {
        await transport.hasReply && time.hasSleeper(after: .seconds(10))
    }
    // Only the measured time moves; the deadline timer has not been delivered.
    time.advance(by: .seconds(elapsed))
    try await transport.releaseReply()
    if elapsed < 30 {
        #expect(try await operation.value.data.count == 512)
        // Delivering every timer afterwards cannot fail the completed read.
        time.advance(by: .seconds(2), wakeTimers: true)
        _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
        #expect(await session.state == .ready)
    } else {
        await #expect(throws: ProtocolError.timedOut) { try await operation.value }
        #expect(await session.state == .failed)
        #expect(await transport.isClosed)
    }
    await session.close()
    try await awaitDeadlinePhase {
        timer.pendingCount == 0 && !timer.isArmed && time.pendingCount == 0
    }
}
