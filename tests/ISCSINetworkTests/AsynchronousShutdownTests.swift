import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private actor EventTransport: ByteTransport {
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var blockedSend: CheckedContinuation<Void, any Error>?
    private var command: PDU?
    private var logout: PDU?
    private var ping: PDU?
    private var status: UInt32 = 2
    private var nextCommand: UInt32 = 1
    private var replies: [Data]
    private let holdData: Bool
    private let holdLogout: Bool
    private let holdPing: Bool
    private let allowPriorStatus: Bool
    private var ended = false
    private(set) var writes: [PDU] = []
    private(set) var closed = false
    var dataBlocked: Bool { blockedSend != nil }
    var logoutPending: Bool { logout != nil }
    var pingPending: Bool { ping != nil }

    init(
        holdData: Bool = false, holdLogout: Bool = false, holdPing: Bool = false,
        allowPriorStatus: Bool = false
    ) throws {
        replies = try loginFixtures(normal: true)
        self.holdData = holdData
        self.holdLogout = holdLogout
        self.holdPing = holdPing
        self.allowPriorStatus = allowPriorStatus
    }

    func send(_ bytes: Data) async throws {
        guard !closed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder()
        let pdu = try #require(decoder.append(bytes).first)
        writes.append(pdu)
        switch pdu.opcode {
        case 3: enqueue(replies.removeFirst())
        case 1:
            #expect(pdu.header.uint32(at: 24) == nextCommand)
            nextCommand &+= 1
            command = pdu
            if pdu.header[32] == 0x2A {
                var reply = header(0x31, tag: pdu.taskTag, consuming: false)
                reply.put(UInt32(73), at: 20)
                reply.put(pdu.header.uint32(at: 20), at: 44)
                enqueue(try PDU(header: reply).encoded())
            }
        case 5:
            if holdData { try await withCheckedThrowingContinuation { blockedSend = $0 } }
        case 6:
            #expect(pdu.header[0] == 0x46 && pdu.flags == 0x80)
            #expect(pdu.header.uint32(at: 24) == nextCommand)
            let acknowledged = pdu.header.uint32(at: 28)
            // A concurrent user Logout can already be sent while the server's one
            // Async notification is still in transit to the initiator.
            #expect(acknowledged == status || (allowPriorStatus && acknowledged &+ 1 == status))
            logout = pdu
            if holdLogout { try await withCheckedThrowingContinuation { blockedSend = $0 } }
        case 0:
            if pdu.taskTag != UInt32.max {
                ping = pdu
                if holdPing { try await withCheckedThrowingContinuation { blockedSend = $0 } }
            }
        default: throw ProtocolError.malformed("event fixture request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !closed, !ended { await withCheckedContinuation { reader = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
        if ended, input.isEmpty { return Data() }
        let bytes = Data(input.prefix(maximumLength))
        input.removeFirst(bytes.count)
        return bytes
    }

    func close() {
        closed = true
        reader?.resume()
        reader = nil
        blockedSend?.resume(throwing: ProtocolError.connectionClosed)
        blockedSend = nil
    }

    func releaseData() {
        blockedSend?.resume()
        blockedSend = nil
    }

    func eof() {
        ended = true
        reader?.resume()
        reader = nil
    }

    func targetPing() throws {
        var bytes = header(0x20, tag: UInt32.max, consuming: false)
        bytes.put(UInt32(42), at: 20)
        enqueue(try PDU(header: bytes).encoded())
    }

    func reservedTargetPing() throws {
        var bytes = header(0xE0, tag: UInt32.max, consuming: false)
        bytes[1] = 0xFF
        bytes.put(UInt32(42), at: 20)
        enqueue(try PDU(header: bytes).encoded())
    }

    func event(_ code: UInt8 = 1, grace: UInt16 = 2, cid: UInt16 = 0, corrupt: Bool = false) throws
    {
        var bytes = header(0x32, tag: UInt32.max)
        bytes[36] = code
        bytes.put(cid, at: 38)
        bytes.put(grace, at: 42)
        if corrupt { bytes[1] = 0 }
        let data = code == 0 ? Data([0, 8, 0x72, 6, 0x29, 0, 0, 0, 0, 0]) : Data()
        enqueue(try PDU(header: bytes, data: data).encoded())
    }

    func commandReply() throws {
        let current = try #require(command)
        enqueue(try PDU(header: header(0x21, tag: current.taskTag)).encoded())
    }

    func pingReply() throws {
        let current = try #require(ping)
        enqueue(try PDU(header: header(0x20, tag: current.taskTag), data: current.data).encoded())
    }

    func logoutReply(valid: Bool = true) throws {
        let current = try #require(logout)
        var bytes = header(0x26, tag: current.taskTag)
        bytes[2] = valid ? 0 : 1
        enqueue(try PDU(header: bytes).encoded())
    }

    func prematureLogoutReply() throws {
        enqueue(try PDU(header: header(0x26, tag: 3)).encoded())
    }

    private func header(_ opcode: UInt8, tag: UInt32, consuming: Bool = true) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 48)
        bytes[0] = opcode
        bytes[1] = 0x80
        bytes.put(tag, at: 16)
        bytes.put(UInt32.max, at: 20)
        bytes.put(status, at: 24)
        bytes.put(nextCommand, at: 28)
        bytes.put(UInt32(32), at: 32)
        if consuming { status &+= 1 }
        return bytes
    }

    private func enqueue(_ bytes: Data) {
        input.append(bytes)
        reader?.resume()
        reader = nil
    }
}

private func eventPhase(_ condition: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(1))
    }
}

@Test func slowRequestAdmissionDoesNotExtendTheOverallShutdownBudget() async throws {
    let time = ManualSessionTime()
    let transport = try EventTransport(holdData: true)
    let session = try await eventSession(transport, clock: time.source)
    let write = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 4, blockSize: 512),
            lun: LogicalUnit(0), output: Data(repeating: 7, count: 2048))
    }
    try await eventPhase { await transport.dataBlocked }
    try await transport.event(grace: 2)
    try await eventPhase { await session.state == .closing }
    time.advance(by: .seconds(1))
    await transport.releaseData()
    try await eventPhase { await transport.logoutPending && time.hasSleeper(after: .seconds(5)) }
    let completion = Task { await session.closeGracefully() }
    time.advance(by: .seconds(4), wakeTimers: true)
    #expect(await completion.value == false)
    await #expect(throws: ProtocolError.self) { try await write.value }
    #expect(await transport.closed)
}

private func eventSession(
    _ transport: EventTransport, heartbeat: Duration = .seconds(10),
    clock: SessionClock = .continuous
) async throws -> ISCSISession {
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        heartbeatInterval: heartbeat, clock: clock)
    try await session.login()
    return session
}

@Test func responseWaitingIsSeparateFromIssuanceAndZeroGraceStillIssuesLogoutImmediately()
    async throws
{
    for grace in [UInt16(0), 1] {
        let time = ManualSessionTime()
        let transport = try EventTransport()
        let session = try await eventSession(transport, clock: time.source)
        try await transport.event(grace: grace)
        try await eventPhase {
            await transport.logoutPending && time.hasSleeper(after: .seconds(5))
        }
        let result = Task { await session.closeGracefully() }
        time.advance(by: .seconds(2))
        try await transport.logoutReply()
        #expect(await result.value)
        #expect(await transport.closed)
    }
}

@Test func aLateLogoutCannotBeAdmittedAfterItsRequestedIssuanceDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try EventTransport(holdData: true)
    let session = try await eventSession(transport, clock: time.source)
    let write = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 4, blockSize: 512),
            lun: LogicalUnit(0), output: Data(repeating: 7, count: 2048))
    }
    try await eventPhase { await transport.dataBlocked }
    try await transport.event(grace: 1)
    try await eventPhase { await session.state == .closing }
    time.advance(by: .seconds(1))
    await transport.releaseData()
    await #expect(throws: ProtocolError.self) { try await write.value }
    try await eventPhase { await transport.closed }
    #expect(await transport.writes.filter { $0.opcode == 6 }.isEmpty)
    #expect(await transport.writes.filter { $0.opcode == 5 }.count == 1)
}

@Test func idleServerLogoutAcknowledgesTheEventAndSharesItsExchangeWithCloseCallers() async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    try await transport.event()
    try await eventPhase { await transport.logoutPending }
    #expect(await session.state == .closing)
    var capacityBytes = [UInt8](repeating: 0, count: 8)
    capacityBytes.put(UInt32(7), at: 0)
    capacityBytes.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacityBytes)), readOnly: false)
    #expect(await disk.connectionState() == .interrupted)
    let callers = (0..<3).map { _ in Task { await session.closeGracefully() } }
    await #expect(throws: ProtocolError.targetEvent(1)) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    try await transport.logoutReply()
    for caller in callers { #expect(await caller.value) }
    #expect(await transport.closed)
    #expect(await session.state == .failed)
    #expect(await session.closeGracefully())
    #expect(await transport.writes.map(\.opcode) == [3, 3, 6])
}

@Test func vendorEventsCannotExtendAnOutstandingCommandDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try EventTransport()
    let session = try await eventSession(transport, clock: time.source)
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventPhase {
        await transport.writes.contains { $0.opcode == 1 } && time.hasSleeper(after: .seconds(30))
    }
    try await transport.event(248)
    try await transport.event(255)
    time.advance(by: .seconds(30), wakeTimers: true)
    await #expect(throws: ProtocolError.timedOut) { try await command.value }
    #expect(await transport.closed)
}

@Test func aServerLogoutDuringWriteStopsLaterDataOutAndDoesNotReplayTheCommand() async throws {
    let transport = try EventTransport(holdData: true)
    let session = try await eventSession(transport)
    let task = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 4, blockSize: 512),
            lun: LogicalUnit(0), output: Data(repeating: 7, count: 2048))
    }
    try await eventPhase { await transport.dataBlocked }
    try await transport.event()
    try await eventPhase { await session.state == .closing }
    await transport.releaseData()
    try await eventPhase { await transport.logoutPending }
    // A late status belongs to the retiring command, not to the Logout task.
    try await transport.commandReply()
    try await transport.logoutReply()
    await #expect(throws: ProtocolError.self) { try await task.value }
    try await eventPhase { await transport.closed }
    let writes = await transport.writes
    #expect(writes.filter { $0.opcode == 1 }.count == 1)
    #expect(writes.filter { $0.opcode == 5 }.count == 1)
    #expect(writes.filter { $0.opcode == 6 }.count == 1)
}

@Test func anExistingLogoutIsReusedWhenTheTargetRequestsLogout() async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    let task = Task { try await session.logout() }
    try await eventPhase { await transport.logoutPending }
    try await transport.event()
    try await eventPhase { await session.state == .closing }
    try await transport.logoutReply()
    try await task.value
    #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
    #expect(await session.state == .closed)
}

@Test func vendorEventsAndOtherConnectionDropNoticesPreserveTheActiveSession() async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    try await transport.event(248)
    try await transport.event(2, cid: 7)
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventPhase { await transport.writes.contains { $0.opcode == 1 } }
    try await transport.commandReply()
    _ = try await command.value
    #expect(await session.state == .ready)
    await session.close()
}

@Test(arguments: [UInt8(0), 2, 3, 5])
func destructiveOrUnsupportedEventsStopWithoutResendingWork(_ event: UInt8) async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventPhase { await transport.writes.contains { $0.opcode == 1 } }
    try await transport.event(event)
    await #expect(throws: ProtocolError.self) { try await command.value }
    #expect(await transport.closed)
    #expect(await session.state == .failed)
    #expect(await transport.writes.map(\.opcode) == [3, 3, 1])
}

@Test func serverLogoutReusesAnAlreadySubmittedLogoutWithALateSendCallback() async throws {
    let transport = try EventTransport(holdLogout: true)
    let session = try await eventSession(transport)
    let logout = Task { try await session.logout() }
    try await eventPhase { await transport.logoutPending }
    try await transport.event()
    try await eventPhase { await session.state == .closing }
    try await transport.logoutReply()
    await transport.releaseData()
    try await logout.value
    #expect(await session.state == .closed)
    #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
}

@Test(arguments: [false, true])
func theServerLogoutDeadlineRejectsLateRepliesEvenWhenItsTimerIsDelayed(_ wakeTimer: Bool)
    async throws
{
    let time = ManualSessionTime()
    let transport = try EventTransport()
    let session = try await eventSession(transport, clock: time.source)
    try await transport.event()
    try await eventPhase { await transport.logoutPending && time.hasSleeper(after: .seconds(5)) }
    let completion = Task { await session.closeGracefully() }
    time.advance(by: .seconds(5), wakeTimers: wakeTimer)
    if !wakeTimer { try await transport.logoutReply() }
    #expect(await completion.value == false)
    #expect(await transport.closed)
    #expect(await session.state == .failed)
    try await eventPhase { time.pendingCount == 0 }
}

@Test func repeatedLogoutRequestsCannotExtendTheOriginalDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try EventTransport()
    let session = try await eventSession(transport, clock: time.source)
    try await transport.event(grace: 1)
    try await eventPhase { await transport.logoutPending && time.hasSleeper(after: .seconds(5)) }
    time.advance(by: .milliseconds(500))
    try await transport.event(grace: 10)
    try await transport.targetPing()
    try await eventPhase { await transport.writes.contains { $0.opcode == 0 } }
    time.advance(by: .milliseconds(4500), wakeTimers: true)
    try await eventPhase { await transport.closed }
    #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
}

@Test(arguments: [false, true])
func explicitCloseAndEOFReleaseBothRequestedLogoutAndCommandWaiters(_ eof: Bool) async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventPhase { await transport.writes.contains { $0.opcode == 1 } }
    try await transport.event()
    try await eventPhase { await transport.logoutPending }
    let completion = Task { await session.closeGracefully() }
    if eof { await transport.eof() } else { await session.close() }
    await #expect(throws: ProtocolError.self) { try await command.value }
    #expect(await completion.value == false)
    #expect(await transport.closed)
}

@Test func lateHeartbeatRepliesDoNotCancelTheRequestedLogout() async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport, heartbeat: .milliseconds(5))
    try await eventPhase { await transport.pingPending }
    try await transport.event()
    try await eventPhase { await transport.logoutPending }
    try await transport.pingReply()
    try await transport.logoutReply()
    try await eventPhase { await transport.closed }
    #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
}

@Test func reservedNopBitsCannotInterruptAnOtherwiseValidTargetLogout() async throws {
    let transport = try EventTransport()
    let session = try await eventSession(transport)
    try await transport.event()
    try await eventPhase { await transport.logoutPending }
    try await transport.reservedTargetPing()
    try await eventPhase {
        let closed = await transport.closed
        let writes = await transport.writes
        return closed || writes.contains { $0.opcode == 0 }
    }
    #expect(await transport.closed == false)
    try await transport.logoutReply()
    #expect(await session.closeGracefully())
}

@Test func aLateHeartbeatDuringAReusedLogoutReleasesItsOriginalDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try EventTransport()
    let session = try await eventSession(transport, heartbeat: .milliseconds(5), clock: time.source)
    try await eventPhase { time.hasSleeper(after: .milliseconds(5)) }
    time.advance(by: .milliseconds(5), wakeTimers: true)
    try await eventPhase { await transport.pingPending }
    let quit = Task { try await session.logout() }
    try await eventPhase { await transport.logoutPending }
    try await transport.event()
    try await eventPhase { await session.state == .closing }
    try await transport.pingReply()
    try await eventPhase { time.pendingCount == 2 }
    try await transport.logoutReply()
    try await quit.value
    try await eventPhase { time.pendingCount == 0 }
}

@Test func aTargetRequestRacingWithGracefulCloseStillUsesOneLogoutExchange() async throws {
    for _ in 0..<32 {
        let transport = try EventTransport(allowPriorStatus: true)
        let session = try await eventSession(transport)
        let quit = Task { await session.closeGracefully() }
        try await transport.event()
        try await eventPhase { await transport.logoutPending }
        try await transport.logoutReply()
        #expect(await quit.value)
        #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
    }
}

@Test func aLogoutResponseCannotCompleteARequestStillWaitingToBeSent() async throws {
    let transport = try EventTransport(holdPing: true)
    let session = try await eventSession(transport, heartbeat: .milliseconds(5))
    try await eventPhase { await transport.pingPending }
    let close = Task { await session.closeGracefully() }
    try await eventPhase { await session.queuedSendCount > 0 }
    try await transport.prematureLogoutReply()
    try await eventPhase { await transport.closed }
    #expect(await close.value == false)
    #expect(await transport.writes.filter { $0.opcode == 6 }.isEmpty)
}
