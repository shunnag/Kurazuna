import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private actor InteractiveTransport: ByteTransport {
    enum EchoFault: String, CaseIterable { case none, dropped, data, tag, transferTag, status }
    private let logins: [Data]
    private let echoFault: EchoFault
    private let holdCommands: Bool
    private let fragmentSize: Int
    private let earlyWriteStatus: Bool
    private let earlyWriteUnderflow: Bool
    private var blockedSender: CheckedContinuation<Void, any Error>?
    private var input = Data()
    private var waiter: CheckedContinuation<Void, Never>?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private var commands: [PDU] = []
    private var outstandingPing: PDU?
    private var readers = 0
    private(set) var maximumReaders = 0
    private(set) var writes: [PDU] = []
    private(set) var isClosed = false

    init(
        echoFault: EchoFault = .none, holdCommands: Bool = false, fragmentSize: Int = 7,
        closedWindow: Bool = false, earlyWriteStatus: Bool = false,
        earlyWriteUnderflow: Bool = false
    ) throws {
        var logins = try loginFixtures(normal: true)
        if closedWindow {
            var final = [UInt8](logins[1])
            final.put(UInt32(0), at: 32)
            logins[1] = Data(final)
        }
        self.logins = logins
        self.echoFault = echoFault
        self.holdCommands = holdCommands
        self.fragmentSize = fragmentSize
        self.earlyWriteStatus = earlyWriteStatus
        self.earlyWriteUnderflow = earlyWriteUnderflow
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 1_048_576)
        let pdus = try decoder.append(data)
        guard pdus.count == 1, decoder.isAtFrameBoundary else {
            throw ProtocolError.malformed("interleaved outgoing frames")
        }
        let pdu = pdus[0]
        writes.append(pdu)
        switch pdu.opcode {
        case 0x03:
            enqueue(logins[Int((pdu.flags >> 2) & 3)])
        case 0x00 where pdu.taskTag != UInt32.max:
            guard pdu.header[0] == 0x40, pdu.header.uint32(at: 24) == expectedCommand else {
                throw ProtocolError.malformed("NOP-Out consumed CmdSN")
            }
            outstandingPing = pdu
            if !holdCommands { try echoPing() }
        case 0x01:
            guard pdu.header.uint32(at: 24) == expectedCommand else {
                throw ProtocolError.malformed("command sequence")
            }
            expectedCommand &+= 1
            commands.append(pdu)
            if earlyWriteStatus || earlyWriteUnderflow,
                pdu.header[32] == 0x8A || pdu.header[32] == 0x2A
            {
                var r2t = try serverHeader(opcode: 0x31, tag: pdu.taskTag, transferTag: 73)
                r2t.put(pdu.header.uint32(at: 20), at: 44)
                enqueue(try PDU(header: r2t).encoded())
            }
            if !holdCommands { try completeCommand() }
        case 0x05 where earlyWriteStatus || earlyWriteUnderflow:
            if earlyWriteUnderflow {
                let command = commands.removeFirst()
                var header = try serverHeader(opcode: 0x21, tag: command.taskTag)
                header[1] = 0x82
                header.put(command.header.uint32(at: 20) - UInt32(pdu.data.count), at: 44)
                enqueue(try PDU(header: header).encoded())
            }
            try await withCheckedThrowingContinuation { blockedSender = $0 }
        case 0x00: break
        default: throw ProtocolError.malformed("unexpected test request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        readers += 1
        maximumReaders = max(maximumReaders, readers)
        defer { readers -= 1 }
        while input.isEmpty, !isClosed { await withCheckedContinuation { waiter = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(input.count, min(maximumLength, fragmentSize))
        let data = Data(input.prefix(count))
        input.removeFirst(count)
        return data
    }

    func close() async {
        isClosed = true
        waiter?.resume()
        waiter = nil
        blockedSender?.resume(throwing: ProtocolError.connectionClosed)
        blockedSender = nil
    }

    func targetPing(
        data: Data = Data(), openWindow: Bool = true, replyRequested: Bool = true
    ) throws {
        var header = try serverHeader(
            opcode: 0x20, tag: UInt32.max, transferTag: replyRequested ? 42 : UInt32.max)
        header.replaceSubrange(8..<16, with: [0, 1, 0x40, 2, 0, 3, 0x40, 4])
        if !openWindow { header.put(UInt32(0), at: 32) }
        enqueue(try PDU(header: header, data: data).encoded())
    }

    func completeCommand() throws {
        guard !commands.isEmpty else { throw ProtocolError.invalidState }
        let command = commands.removeFirst()
        let header = try serverHeader(opcode: 0x21, tag: command.taskTag)
        status &+= 1
        enqueue(try PDU(header: header).encoded())
    }

    func echoPing() throws {
        guard let ping = outstandingPing else { throw ProtocolError.invalidState }
        outstandingPing = nil
        if echoFault == .dropped { return }
        var header = try serverHeader(
            opcode: 0x20, tag: echoFault == .tag ? ping.taskTag &+ 1 : ping.taskTag,
            transferTag: echoFault == .transferTag ? 17 : UInt32.max)
        if echoFault == .status { header.put(status &+ 1, at: 24) }
        status &+= 1
        let data = echoFault == .data ? Data(repeating: 0, count: 3) : ping.data
        enqueue(try PDU(header: header, data: data).encoded())
    }

    private func serverHeader(
        opcode: UInt8, tag: UInt32, transferTag: UInt32 = UInt32.max
    ) throws -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(transferTag, at: 20)
        header.put(status, at: 24)
        header.put(expectedCommand, at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    private func enqueue(_ data: Data) {
        input.append(data)
        waiter?.resume()
        waiter = nil
    }
}

private func eventually(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test func idleTargetPingIsAnsweredWithoutACommandOrStatSNConsumption() async throws {
    let transport = try InteractiveTransport()
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    try await transport.targetPing()
    try await eventually { await transport.writes.contains { $0.opcode == 0 } }
    let writes = await transport.writes
    let echo = try #require(writes.last)
    #expect(echo.taskTag == UInt32.max && echo.transferTag == 42)
    #expect(Array(echo.header[8..<16]) == [0, 1, 0x40, 2, 0, 3, 0x40, 4])
    #expect(echo.header.uint32(at: 24) == 1 && echo.header.uint32(at: 28) == 2)
    #expect(echo.data.isEmpty)
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    #expect(await session.state == .ready)
    #expect(await transport.maximumReaders == 1)
    await session.close()
}

@Test(arguments: [false, true])
func aCommandMayRunWhileAnIdleProbeIsAwaitingItsEcho(commandFirst: Bool) async throws {
    let transport = try InteractiveTransport(holdCommands: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        heartbeatInterval: .milliseconds(40), heartbeatTimeout: .seconds(1))
    try await session.login()
    try await eventually { await transport.writes.contains { $0.opcode == 0 } }
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventually { await transport.writes.contains { $0.opcode == 1 } }
    if commandFirst {
        try await transport.completeCommand()
        try await transport.echoPing()
    } else {
        try await transport.echoPing()
        try await transport.completeCommand()
    }
    #expect(try await command.value.data.isEmpty)
    #expect(await session.state == .ready)
    #expect(await transport.maximumReaders == 1)
    await session.close()
}

@Test(arguments: [
    InteractiveTransport.EchoFault.dropped, .data, .tag, .transferTag, .status,
])
private func missingOrInvalidIdleEchoFailsWithoutReplayingCommands(
    fault: InteractiveTransport.EchoFault
) async throws {
    let transport = try InteractiveTransport(echoFault: fault)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        heartbeatInterval: .milliseconds(20), heartbeatTimeout: .milliseconds(40))
    try await session.login()
    try await eventually { await session.state == .failed }
    await #expect(throws: ProtocolError.invalidState) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    try await eventually { await transport.isClosed }
}

@Test func unsolicitedNOPDataIsRejectedWhileIdle() async throws {
    let transport = try InteractiveTransport()
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    try await transport.targetPing(data: Data([1]))
    try await eventually { await session.state == .failed }
    #expect(await transport.writes.filter { $0.opcode == 0 }.isEmpty)
}

@Test func aClosedCommandWindowStillAllowsTargetPingsAndLaterOpens() async throws {
    let transport = try InteractiveTransport(closedWindow: true)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await transport.targetPing(openWindow: false)
    try await eventually { await transport.writes.contains { $0.opcode == 0 } }
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    try await transport.targetPing()
    #expect(try await command.value.data.isEmpty)
    #expect(await transport.maximumReaders == 1)
    await session.close()
}

@Test func cancellingACommandClosesTheIdleReaderAndUnblocksTheConsumer() async throws {
    let transport = try InteractiveTransport(holdCommands: true)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventually { await transport.writes.contains { $0.opcode == 1 } }
    command.cancel()
    await #expect(throws: CancellationError.self) { try await command.value }
    #expect(await session.state == .failed)
    try await eventually { await transport.isClosed }
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
}

@Test func aFullFeatureCommandDeadlineUnblocksTheResponseMailbox() async throws {
    let time = ManualSessionTime()
    let transport = try InteractiveTransport(holdCommands: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .milliseconds(40), clock: time.source)
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    do {
        try await eventually {
            await transport.writes.contains { $0.opcode == 1 }
                && time.hasSleeper(after: .milliseconds(40))
        }
        time.advance(by: .milliseconds(41), wakeTimers: true)
        try await eventually { await transport.isClosed }
        await #expect(throws: ProtocolError.timedOut) { try await command.value }
    } catch {
        command.cancel()
        _ = try? await command.value
        throw error
    }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
}

@Test func continuingNOPTrafficCannotExtendACommandDeadline() async throws {
    let time = ManualSessionTime()
    let transport = try InteractiveTransport(holdCommands: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .milliseconds(60), clock: time.source)
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    do {
        try await eventually {
            await transport.writes.contains { $0.opcode == 1 }
                && time.hasSleeper(after: .milliseconds(60))
        }
        for expectedReplies in 1...3 {
            time.advance(by: .milliseconds(15))
            try await transport.targetPing()
            try await eventually {
                await transport.writes.filter { $0.opcode == 0 }.count == expectedReplies
            }
        }
        // NOP traffic has reached 45 ms. Only the original 60 ms deadline may win.
        time.advance(by: .milliseconds(16), wakeTimers: true)
        try await eventually { await transport.isClosed }
        await #expect(throws: ProtocolError.timedOut) { try await command.value }
    } catch {
        command.cancel()
        _ = try? await command.value
        throw error
    }
    #expect(await session.state == .failed)
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
}

@Test func anInvalidHeartbeatAlsoUnblocksAnOutstandingCommand() async throws {
    let transport = try InteractiveTransport(echoFault: .data, holdCommands: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        heartbeatInterval: .milliseconds(20), heartbeatTimeout: .seconds(1))
    try await session.login()
    try await eventually { await transport.writes.contains { $0.opcode == 0 } }
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await eventually { await transport.writes.contains { $0.opcode == 1 } }
    try await transport.echoPing()
    await #expect(throws: ProtocolError.malformed("NOP-In echo")) { try await command.value }
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
    #expect(await session.state == .failed)
}

@Test func anR2TDoesNotCountAsSendingAllRequestedWriteData() async throws {
    let transport = try InteractiveTransport(fragmentSize: 65536, earlyWriteStatus: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(1))
    try await session.login()
    await #expect(throws: ProtocolError.malformed("premature write status")) {
        try await session.execute(
            .write16(lba: 0, blocks: 32, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 0xA5, count: 16384))
    }
    #expect(await transport.writes.filter { $0.opcode == 5 }.count <= 1)
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

@Test(arguments: [false, true])
func underflowStatusFailsBeforeADataOutSenderCanResume(_ sixteen: Bool) async throws {
    let transport = try InteractiveTransport(
        holdCommands: true, fragmentSize: 65536, earlyWriteUnderflow: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(1))
    try await session.login()
    let command =
        try sixteen
        ? SCSICommand.write16(lba: 0, blocks: 32, blockSize: 512)
        : SCSICommand.write10(lba: 0, blocks: 32, blockSize: 512)
    await #expect(throws: ProtocolError.malformed("short block transfer")) {
        try await session.execute(
            command, lun: LogicalUnit(0), output: Data(repeating: 0xA5, count: 16384))
    }
    #expect(await transport.writes.filter { $0.opcode == 5 }.count == 1)
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

private final class WeakSession: @unchecked Sendable {
    weak var value: ISCSISession?
    init(_ value: ISCSISession?) { self.value = value }
}

@Test func remoteDiskHealthReflectsTheSessionWithoutSendingAnyIO() async throws {
    let transport = try InteractiveTransport()
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var data = Array(repeating: UInt8(0), count: 8)
    data.put(UInt32(7), at: 0)
    data.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(data)), readOnly: false)
    #expect(await disk.connectionState() == .unknown)
    try await session.login()
    #expect(await disk.connectionState() == .connected)
    try await transport.targetPing(data: Data([1]))
    try await eventually { await session.state == .failed }
    #expect(await disk.connectionState() == .interrupted)
    await disk.close()
    #expect(await disk.connectionState() == .closed)
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
}

@Test func releasingAnIdleSessionDoesNotLeaveASelfRetainingReader() async throws {
    let transport = try InteractiveTransport()
    var session: ISCSISession? = try ISCSISession(
        transport: transport, configuration: configuration(normal: true))
    try await session?.login()
    let released = WeakSession(session)
    session = nil
    try await eventually { released.value == nil }
    try await eventually { await transport.isClosed }
}
