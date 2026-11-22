import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private actor WindowTransport: ByteTransport {
    private let logins: [Data]
    private let singleCredit: Bool
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private(set) var writes: [PDU] = []
    private(set) var isClosed = false

    init(
        singleCredit: Bool = false, initialCommand: UInt32 = 1, initialStatus: UInt32 = 0
    ) throws {
        var logins = try loginFixtures(normal: true)
        for index in logins.indices {
            var bytes = Array(logins[index])
            bytes.put(initialStatus &+ UInt32(index), at: 24)
            bytes.put(initialCommand, at: 28)
            bytes.put(singleCredit ? initialCommand : initialCommand &+ 31, at: 32)
            logins[index] = Data(bytes)
        }
        self.logins = logins
        self.singleCredit = singleCredit
        expectedCommand = initialCommand
        status = initialStatus &+ 2
    }

    func send(_ data: Data) throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 8192)
        let pdus = try decoder.append(data)
        let pdu = try #require(pdus.count == 1 ? pdus.first : nil)
        writes.append(pdu)
        if pdu.opcode == 0x03 {
            #expect(pdu.header.uint32(at: 24) == expectedCommand)
            enqueue(logins[Int((pdu.flags >> 2) & 3)])
        } else if pdu.opcode == 0x01 {
            #expect(pdu.header.uint32(at: 24) == expectedCommand)
            expectedCommand &+= 1
            enqueue(
                try PDU(
                    header: header(
                        opcode: 0x21, tag: pdu.taskTag,
                        expected: expectedCommand,
                        maximum: singleCredit ? expectedCommand &- 1 : expectedCommand &+ 31
                    )
                ).encoded())
            status &+= 1
        } else if pdu.opcode == 0x06 {
            #expect(pdu.header.uint32(at: 24) == expectedCommand)
            enqueue(
                try PDU(
                    header: header(
                        opcode: 0x26, tag: pdu.taskTag, expected: expectedCommand,
                        maximum: expectedCommand &+ 31)
                ).encoded())
            status &+= 1
        } else {
            #expect(pdu.opcode == 0 && pdu.taskTag == UInt32.max)
            // An Immediate request may carry a CmdSN outside the peer's current window.
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !isClosed { await withCheckedContinuation { reader = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(input.count, maximumLength)
        let data = Data(input.prefix(count))
        input.removeFirst(count)
        return data
    }

    func close() {
        isClosed = true
        reader?.resume()
        reader = nil
    }

    func ping(expected: UInt32, maximum: UInt32) throws {
        var header = header(opcode: 0x20, tag: .max, expected: expected, maximum: maximum)
        header.put(UInt32(73), at: 20)
        enqueue(try PDU(header: header).encoded())
    }

    private func header(opcode: UInt8, tag: UInt32, expected: UInt32, maximum: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(expected, at: 28)
        header.put(maximum, at: 32)
        return header
    }

    private func enqueue(_ data: Data) {
        input.append(data)
        reader?.resume()
        reader = nil
    }
}

private func awaitWindowPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test(arguments: ["old-limit", "invalid-pair", "future-invalid-pair"])
func oldOrInvalidCommandWindowsDoNotStallAnEstablishedSession(_ update: String) async throws {
    let transport = try WindowTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .milliseconds(200))
    try await session.login()
    try await transport.ping(
        expected: update == "old-limit" ? 1 : update == "invalid-pair" ? 2 : 50,
        maximum: update == "future-invalid-pair" ? 48 : 0)
    try await awaitWindowPhase {
        let closed = await transport.isClosed
        let echoed = await transport.writes.contains { $0.opcode == 0 }
        return closed || echoed
    }
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    #expect(await session.state == .ready)
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 2)
    await session.close()
}

@Test(arguments: [UInt32(1), UInt32.max])
func aWindowWithNoRemainingCreditWaitsForANewerLimit(_ start: UInt32) async throws {
    let transport = try WindowTransport(singleCredit: true, initialCommand: start)
    let base = try configuration(normal: true)
    let configuration = try LoginConfiguration(
        initiatorName: base.initiatorName, targetName: base.targetName, isid: base.isid,
        initialCommandSequenceNumber: start)
    let session = try ISCSISession(transport: transport, configuration: configuration)
    try await session.login()
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    let pending = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await Task.sleep(for: .milliseconds(10))
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 1)
    try await transport.ping(expected: start &+ 1, maximum: start &+ 1)
    #expect(try await pending.value.data.isEmpty)
    #expect(await transport.writes.filter { $0.opcode == 1 }.count == 2)
    await session.close()
}

@Test func aValidWindowWithAnImpossibleFutureAcknowledgmentStillFails() async throws {
    let transport = try WindowTransport()
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    try await transport.ping(expected: 2, maximum: 32)
    try await awaitWindowPhase { await transport.isClosed }
    #expect(await session.state == .failed)
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
}

@Test(arguments: [UInt32.max - 1, UInt32.max])
func commandAndStatusNumbersWrapOnTheWireWithoutConfusingImmediateRequests(_ start: UInt32)
    async throws
{
    let transport = try WindowTransport(initialCommand: start, initialStatus: UInt32.max - 2)
    let base = try configuration(normal: true)
    let configuration = try LoginConfiguration(
        initiatorName: base.initiatorName, targetName: base.targetName, isid: base.isid,
        initialCommandSequenceNumber: start)
    let session = try ISCSISession(transport: transport, configuration: configuration)
    try await session.login()
    for _ in 0..<3 { _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await transport.ping(expected: start &+ 3, maximum: start &+ 34)
    try await awaitWindowPhase { await transport.writes.contains { $0.opcode == 0 } }
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    try await session.logout()
    let sent = await transport.writes
    let commands = sent.filter { $0.opcode == 1 }
    #expect(commands.map { $0.header.uint32(at: 24) } == (0..<4).map { start &+ UInt32($0) })
    #expect(commands.map { $0.header.uint32(at: 28) } == [UInt32.max, 0, 1, 2])
    let ping = try #require(sent.first { $0.opcode == 0 })
    #expect(ping.header.uint32(at: 24) == start &+ 3)
    #expect(ping.header.uint32(at: 28) == 2)
    let logout = try #require(sent.last)
    #expect(logout.opcode == 6 && logout.header.uint32(at: 24) == start &+ 4)
    #expect(logout.header.uint32(at: 28) == 3)
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
}
