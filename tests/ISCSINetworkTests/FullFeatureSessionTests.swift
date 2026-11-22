import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSINetwork

private actor NegotiatingTransport: ByteTransport {
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var login: [Data]
    private var status: UInt32 = 2
    private var commandSequence: UInt32 = 1
    private var text: PDU?
    private var command: PDU?
    private var heldData: CheckedContinuation<Void, any Error>?
    private let holdFirstData: Bool
    private let holdTextCallback: Bool
    private var heldText: CheckedContinuation<Void, any Error>?
    private(set) var writes: [PDU] = []
    private(set) var closed = false
    var textPending: Bool { text != nil }
    var dataPending: Bool { heldData != nil }
    var textCallbackPending: Bool { heldText != nil }

    init(holdFirstData: Bool = false, holdTextCallback: Bool = false) throws {
        login = try loginFixtures(normal: true)
        self.holdFirstData = holdFirstData
        self.holdTextCallback = holdTextCallback
    }

    func send(_ bytes: Data) async throws {
        guard !closed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder()
        let pdu = try #require(decoder.append(bytes).first)
        writes.append(pdu)
        switch pdu.opcode {
        case 3: enqueue(login.removeFirst())
        case 4:
            #expect(text == nil)
            #expect(pdu.header[0] == 0x44)
            #expect(pdu.header.uint32(at: 24) == commandSequence)
            #expect(pdu.header.uint32(at: 28) == status)
            text = pdu
            if holdTextCallback, writes.filter({ $0.opcode == 4 }).count == 1 {
                try await withCheckedThrowingContinuation { heldText = $0 }
            }
        case 1:
            command = pdu
            #expect(pdu.header.uint32(at: 24) == commandSequence)
            commandSequence &+= 1
            if pdu.header[32] == 0x2A {
                var h = header(0x31, tag: pdu.taskTag, consuming: false)
                h.put(UInt32(44), at: 20)
                h.put(pdu.header.uint32(at: 20), at: 44)
                enqueue(try PDU(header: h).encoded())
            }
        case 5:
            if holdFirstData, writes.filter({ $0.opcode == 5 }).count == 1 {
                try await withCheckedThrowingContinuation { heldData = $0 }
            }
            if pdu.flags & 0x80 != 0 { try commandReply() }
        case 6:
            enqueue(try PDU(header: header(0x26, tag: pdu.taskTag)).encoded())
        case 0: break
        default: throw ProtocolError.malformed("renegotiation fixture")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !closed { await withCheckedContinuation { reader = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
        let bytes = Data(input.prefix(maximumLength))
        input.removeFirst(bytes.count)
        return bytes
    }

    func close() {
        closed = true
        reader?.resume()
        reader = nil
        heldData?.resume(throwing: ProtocolError.connectionClosed)
        heldData = nil
        heldText?.resume(throwing: ProtocolError.connectionClosed)
        heldText = nil
    }

    func releaseData() {
        heldData?.resume()
        heldData = nil
    }

    func releaseText() {
        heldText?.resume()
        heldText = nil
    }

    func targetPing() throws {
        var h = header(0x20, tag: .max, consuming: false)
        h.put(UInt32(42), at: 20)
        enqueue(try PDU(header: h).encoded())
    }

    func event(_ code: UInt8 = 4, grace: UInt16 = 2) throws {
        var h = header(0x32, tag: .max)
        h[36] = code
        h.put(grace, at: 42)
        enqueue(try PDU(header: h).encoded())
    }

    func textReply(_ value: String = "", final: Bool = false, continues: Bool = false) throws {
        let sent = try #require(text)
        text = nil
        var h = header(0x24, tag: sent.taskTag)
        h[1] = final ? 0x80 : (continues ? 0x40 : 0)
        h.put(final ? UInt32.max : UInt32(88), at: 20)
        h[9] = 9
        enqueue(try PDU(header: h, data: Data(value.utf8)).encoded())
    }

    func commandReply() throws {
        let sent = try #require(command)
        enqueue(try PDU(header: header(0x21, tag: sent.taskTag)).encoded())
        command = nil
    }

    func rejectText(reason: UInt8 = 4, corrupt: Bool = false) throws {
        let sent = try #require(text)
        text = nil
        var h = header(0x3F, tag: .max)
        h[2] = reason
        var rejected = sent.header
        if corrupt { rejected[19] ^= 1 }
        enqueue(try PDU(header: h, data: Data(rejected)).encoded())
    }

    private func header(_ opcode: UInt8, tag: UInt32, consuming: Bool = true) -> [UInt8] {
        var h = [UInt8](repeating: 0, count: 48)
        h[0] = opcode
        h[1] = 0x80
        h.put(tag, at: 16)
        h.put(status, at: 24)
        h.put(commandSequence, at: 28)
        h.put(commandSequence &+ 16, at: 32)
        if consuming { status &+= 1 }
        return h
    }

    private func enqueue(_ bytes: Data) {
        input.append(bytes)
        reader?.resume()
        reader = nil
    }
}

private func negotiatingSession(
    _ transport: NegotiatingTransport, clock: SessionClock = .continuous
) async throws -> ISCSISession {
    let session = try ISCSISession(
        transport: transport,
        configuration: configuration(normal: true),
        clock: clock)
    try await session.login()
    return session
}

private func negotiationPhase(_ condition: @escaping @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

@Test func targetRequestedTextNegotiationKeepsTheConnectionReady() async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase {
        let pending = await transport.textPending
        let closed = await transport.closed
        return pending || closed
    }
    #expect(await session.state == .ready)
    let pending = await transport.textPending
    #expect(pending)
    if pending {
        try await transport.textReply("TargetAlias=保存先\0MaxRecvDataSegmentLength=512\0")
        try await negotiationPhase { await transport.textPending }
        try await transport.textReply(final: true)
        try await negotiationPhase { await !session.textNegotiationInProgress }
        try await session.logout()
        #expect(await transport.writes.filter { $0.opcode == 4 }.count == 2)
    }
    await session.close()
}

@Test func aReceiveLimitShrinkingDuringWriteReslicesOnlyUnsentDataWithoutReplaying() async throws {
    let transport = try NegotiatingTransport(holdFirstData: true)
    let session = try await negotiatingSession(transport)
    let writing = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 48, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 7, count: 24_576))
    }
    try await negotiationPhase { await transport.dataPending }
    try await transport.event()
    try await negotiationPhase { await session.textNegotiationInProgress }
    await transport.releaseData()
    try await negotiationPhase { await transport.textPending }
    #expect(await transport.writes.filter { $0.opcode == 5 }.count == 1)
    try await transport.textReply("MaxRecvDataSegmentLength=512\0X-dev.soba.key=Yes\0")
    try await negotiationPhase { await transport.textPending }
    #expect(await transport.writes.filter { $0.opcode == 5 }.count == 1)
    try await transport.textReply(final: true)
    _ = try await writing.value
    let frames = await transport.writes.filter { $0.opcode == 5 }
    #expect(frames.count == 33 && frames.first?.data.count == 8192)
    #expect(frames.dropFirst().allSatisfy { $0.data.count == 512 })
    #expect(frames.map(\.dataSequenceNumber) == Array(0..<UInt32(frames.count)))
    #expect(frames.map(\.bufferOffset) == [0] + (0..<32).map { 8192 + UInt32($0) * 512 })
    #expect(frames.dropLast().allSatisfy { $0.flags & 0x80 == 0 })
    #expect(frames.last?.flags == 0x80)
    #expect(frames.reduce(Data()) { $0 + $1.data } == Data(repeating: 7, count: 24_576))
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
    #expect(await session.state == .ready)
    #expect(await session.closeGracefully())
}

@Test func aCommandQueuedDuringTextUsesTheCommittedLimitAndUnchangedCommandSequence() async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase { await transport.textPending }
    let writing = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 8, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 7, count: 4096))
    }
    try await transport.textReply("MaxRecvDataSegmentLength=512\0")
    try await negotiationPhase { await transport.textPending }
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    try await transport.textReply(final: true)
    _ = try await writing.value
    #expect(
        await transport.writes.filter { $0.opcode == 5 }.map(\.data.count)
            == Array(repeating: 512, count: 8))
    #expect(await session.closeGracefully())
}

@Test(arguments: [false, true])
func repeatedNegotiationRequestsCannotExtendItsFixedDeadline(_ reset: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport, clock: time.source)
    try await transport.event(grace: 1)
    try await negotiationPhase { await transport.textPending }
    time.advance(by: .seconds(29))
    try await transport.event(grace: 100)
    try await transport.textReply("TargetAlias=Archive\0")
    try await negotiationPhase { await transport.textPending }
    if reset {
        try await transport.rejectText()
        try await negotiationPhase { await transport.textPending }
    }
    time.advance(by: .seconds(1))
    try await transport.textReply(final: true)
    try await negotiationPhase { await transport.closed }
    #expect(await session.state == .failed)
    #expect(await transport.writes.filter { $0.opcode == 4 }.count == (reset ? 3 : 2))
    await session.close()
    try await negotiationPhase { time.pendingCount == 0 }
}

@Test func negotiationIssuanceDeadlineIncludesAStalledTransportCallback() async throws {
    let time = ManualSessionTime()
    let transport = try NegotiatingTransport(holdFirstData: true)
    let session = try await negotiatingSession(transport, clock: time.source)
    let writing = Task {
        try await session.execute(
            SCSICommand.write10(lba: 0, blocks: 32, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 7, count: 16_384))
    }
    try await negotiationPhase { await transport.dataPending }
    try await transport.event(grace: 1)
    try await negotiationPhase { await session.textNegotiationInProgress }
    time.advance(by: .seconds(1))
    await transport.releaseData()
    await #expect(throws: ProtocolError.timedOut) { try await writing.value }
    #expect(await transport.writes.filter { $0.opcode == 4 }.isEmpty)
    #expect(await session.state == .failed)
    await session.close()
    try await negotiationPhase { time.pendingCount == 0 }
}

@Test func logoutCanSupersedeTextWithoutTheCancelledWorkerAbortingItsReply() async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase { await transport.textPending }
    #expect(await session.closeGracefully())
    let sent = await transport.writes
    #expect(sent.filter { $0.opcode == 6 }.count == 1)
    let logout = try #require(sent.firstIndex { $0.opcode == 6 })
    #expect(sent.dropFirst(logout + 1).allSatisfy { $0.opcode != 4 })
}

@Test func targetLogoutSupersedesNegotiationAndStillSharesOneOrderlyExchange() async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase { await transport.textPending }
    try await transport.event(1)
    try await negotiationPhase { await session.state != .ready }
    #expect(await session.closeGracefully())
    #expect(await transport.writes.filter { $0.opcode == 6 }.count == 1)
}

@Test func zeroGraceNegotiationIsIssuedImmediatelyAndItsResponseCanFollowLater() async throws {
    let time = ManualSessionTime()
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport, clock: time.source)
    try await transport.event(grace: 0)
    try await negotiationPhase { await transport.textPending }
    time.advance(by: .seconds(2))
    try await transport.textReply(final: true)
    try await negotiationPhase { await !session.textNegotiationInProgress }
    #expect(await session.state == .ready)
    await session.close()
    try await negotiationPhase { time.pendingCount == 0 }
}

@Test func aTextRejectRestartsOnlyTextAndDoesNotApplyAbandonedLimits() async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase { await transport.textPending }
    try await transport.textReply("MaxRecvDataSegmentLength=512\0TargetAlias=Abandoned\0")
    try await negotiationPhase { await transport.textPending }
    try await transport.rejectText()
    try await negotiationPhase { await transport.textPending }
    let text = await transport.writes.filter { $0.opcode == 4 }
    #expect(text.count == 3 && Set(text.map(\.taskTag)).count == 1)
    #expect(text.last?.transferTag == .max && text.last?.data.isEmpty == true)
    try await transport.textReply(
        "MaxRecvDataSegmentLength=1024\0TargetAlias=Accepted\0", final: true)
    _ = try await session.execute(
        SCSICommand.write10(lba: 0, blocks: 4, blockSize: 512), lun: LogicalUnit(0),
        output: Data(repeating: 7, count: 2048))
    #expect(await transport.writes.filter { $0.opcode == 5 }.map(\.data.count) == [1024, 1024])
    #expect(await session.closeGracefully())
}

@Test(arguments: [false, true])
func deprecatedOrMismatchedTextRejectsCannotRestartTheNegotiation(_ corrupt: Bool) async throws {
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport)
    try await transport.event()
    try await negotiationPhase { await transport.textPending }
    try await transport.rejectText(reason: corrupt ? 4 : 0x0B, corrupt: corrupt)
    try await negotiationPhase { await transport.closed }
    #expect(await session.state == .failed)
    #expect(await transport.writes.filter { $0.opcode == 4 }.count == 1)
    await session.close()
}

@Test func aNegotiationRequestAlsoBoundsAnAlreadyQueuedUserLogout() async throws {
    let time = ManualSessionTime()
    let transport = try NegotiatingTransport(holdTextCallback: true)
    let session = try await negotiatingSession(transport, clock: time.source)
    try await transport.event()
    try await negotiationPhase { await transport.textCallbackPending }
    let closing = Task { await session.closeGracefully() }
    try await negotiationPhase { await session.queuedSendCount == 1 }
    try await transport.event(grace: 1)
    try await transport.targetPing()
    try await negotiationPhase { await session.queuedSendCount >= 2 }
    time.advance(by: .seconds(1))
    await transport.releaseText()
    #expect(await closing.value == false)
    #expect(await transport.writes.filter { $0.opcode == 6 }.isEmpty)
    await session.close()
    try await negotiationPhase { time.pendingCount == 0 }
}

/// Counts sleeps a session requests for an instant that has already passed.
private final class PassedDeadlinePolls: Sendable {
    private let count = Mutex(0)
    var value: Int { count.withLock { $0 } }
    func record() { count.withLock { $0 += 1 } }
}

/// The idle probe waits while a target-requested Text exchange is pending. Its loop must sleep
/// for a future instant rather than poll a deadline that has already passed.
@Test(arguments: [false, true])
func aPendingTextNegotiationNeitherSpinsNorProbesTheIdleConnection(_ completes: Bool)
    async throws
{
    let time = ManualSessionTime()
    let source = time.source
    let polls = PassedDeadlinePolls()
    // Like ContinuousClock, a sleep whose deadline has already passed returns at once.
    let clock = SessionClock(
        now: { source.now },
        sleep: { deadline in
            if source.now >= deadline {
                polls.record()
                await Task.yield()
                try Task.checkCancellation()
                return
            }
            try await source.sleep(until: deadline)
        })
    let transport = try NegotiatingTransport()
    let session = try await negotiatingSession(transport, clock: clock)
    try await negotiationPhase { time.hasSleeper(after: .seconds(10)) }
    try await transport.event()
    // Issuing the Text Request moves the watchdog to the fixed +30 s deadline.
    try await negotiationPhase {
        await transport.textPending && time.hasSleeper(after: .seconds(30))
            && !time.hasSleeper(after: .seconds(2))
    }
    time.advance(by: .seconds(10), wakeTimers: true)
    try? await negotiationPhase { time.hasSleeper(after: .seconds(20)) }
    try await Task.sleep(for: .milliseconds(20))
    // The loop sleeps until the next check instead of polling the passed +10 s instant.
    #expect(polls.value == 0)
    try #require(time.hasSleeper(after: .seconds(20)))
    #expect(await transport.writes.filter { $0.opcode == 0 }.isEmpty)
    #expect(await session.state == .ready)
    if completes {
        time.advance(by: .seconds(5))
        try await transport.textReply(final: true)
        try await negotiationPhase { await !session.textNegotiationInProgress }
        // Probing resumes from the completed exchange, not from the earlier check.
        time.advance(by: .seconds(5), wakeTimers: true)
        try await negotiationPhase { time.hasSleeper(after: .seconds(25)) }
        #expect(await transport.writes.filter { $0.opcode == 0 }.isEmpty)
        time.advance(by: .seconds(5), wakeTimers: true)
        try await negotiationPhase {
            await transport.writes.contains { $0.opcode == 0 && $0.taskTag != .max }
        }
        #expect(await session.state == .ready)
    } else {
        time.advance(by: .seconds(19), wakeTimers: true)
        try await negotiationPhase { time.hasSleeper(after: .seconds(39)) }
        #expect(await session.state == .ready)
        // The negotiation's own watchdog still ends the stalled exchange at +30 s.
        time.advance(by: .seconds(1), wakeTimers: true)
        try await negotiationPhase { await transport.closed }
        #expect(await session.state == .failed)
        #expect((await session.terminationReason as? ProtocolError) == .timedOut)
        #expect(await transport.writes.filter { $0.opcode == 0 }.isEmpty)
    }
    #expect(polls.value == 0)
    await session.close()
    try await negotiationPhase { time.pendingCount == 0 }
}
