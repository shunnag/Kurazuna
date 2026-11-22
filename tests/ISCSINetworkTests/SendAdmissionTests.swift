import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private enum QueuedOperation: String { case command, discovery, logout }

/// Separates transport admission, peer replies, and completion callbacks without wall-clock races.
private actor AdmissionTransport: ByteTransport {
    private let logins: [Data]
    private let digests: DigestPolicy
    private let holdHeartbeat: Bool
    private let holdCommand: Bool
    private var fullFeature = false
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var sender: CheckedContinuation<Void, any Error>?
    private var heartbeat: PDU?
    private var writeCommand: PDU?
    private var writeBytes = 0
    private var status: UInt32
    private var expectedCommand: UInt32
    private(set) var writes: [PDU] = []
    private(set) var isClosed = false
    var hasHeartbeat: Bool { heartbeat != nil }
    var hasSender: Bool { sender != nil }
    var inputDrained: Bool { input.isEmpty && (reader != nil || isClosed) }

    init(
        discovery: Bool = false, holdHeartbeat: Bool = true, digests: Bool = true,
        statusWrap: Bool = false, initialCommand: UInt32 = 1, holdCommand: Bool = false
    ) throws {
        let firstStatus: UInt32 = statusWrap ? UInt32.max - 2 : 0
        var logins = try loginFixtures(normal: !discovery, digests: digests)
        for index in logins.indices {
            var bytes = Array(logins[index])
            bytes.put(firstStatus &+ UInt32(index), at: 24)
            bytes.put(initialCommand, at: 28)
            bytes.put(initialCommand &+ 31, at: 32)
            logins[index] = Data(bytes)
        }
        self.logins = logins
        self.digests = DigestPolicy(header: digests, data: digests)
        self.holdHeartbeat = holdHeartbeat
        self.holdCommand = holdCommand
        status = firstStatus &+ 2
        expectedCommand = initialCommand
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(
            maximumDataLength: 262_144, digests: fullFeature ? digests : DigestPolicy())
        let pdus = try decoder.append(data)
        let pdu = try #require(pdus.count == 1 && decoder.isAtFrameBoundary ? pdus.first : nil)
        writes.append(pdu)
        switch pdu.opcode {
        case 0x03:
            let stage = Int((pdu.flags >> 2) & 3)
            enqueue(logins[stage])
            if stage == 1 { fullFeature = true }
        case 0x00 where pdu.taskTag != .max:
            heartbeat = pdu
            if holdHeartbeat { try await withCheckedThrowingContinuation { sender = $0 } }
        case 0x00: break
        case 0x01:
            #expect(pdu.header.uint32(at: 24) == expectedCommand)
            expectedCommand &+= 1
            if pdu.header[32] == 0x2A || pdu.header[32] == 0x8A {
                writeCommand = pdu
                var header = replyHeader(opcode: 0x31, tag: pdu.taskTag)
                header.replaceSubrange(8..<16, with: pdu.header[8..<16])
                header.put(UInt32(73), at: 20)
                header.put(pdu.header.uint32(at: 20), at: 44)
                try enqueue(PDU(header: header))
            } else {
                if holdCommand { try await withCheckedThrowingContinuation { sender = $0 } }
                try enqueue(PDU(header: replyHeader(opcode: 0x21, tag: pdu.taskTag)))
                status &+= 1
            }
        case 0x05:
            writeBytes += pdu.data.count
            if writeBytes == pdu.data.count {
                try await withCheckedThrowingContinuation { sender = $0 }
            }
            if pdu.flags & 0x80 != 0 {
                let command = try #require(writeCommand)
                #expect(writeBytes == command.header.uint32(at: 20))
                try enqueue(PDU(header: replyHeader(opcode: 0x21, tag: command.taskTag)))
                status &+= 1
            }
        case 0x04:
            try enqueue(
                PDU(
                    header: replyHeader(opcode: 0x24, tag: pdu.taskTag),
                    data: TextParameters([.init("TargetName", "iqn.2026-10.test:queued")]).encoded()
                ))
            status &+= 1
        case 0x06:
            try enqueue(PDU(header: replyHeader(opcode: 0x26, tag: pdu.taskTag)))
            status &+= 1
        default: throw ProtocolError.malformed("unexpected admission-test request")
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
        sender?.resume(throwing: ProtocolError.connectionClosed)
        sender = nil
    }

    func releaseSender() {
        let sender = sender
        self.sender = nil
        sender?.resume()
    }

    func echoHeartbeat() throws {
        let ping = try #require(heartbeat)
        try enqueue(PDU(header: replyHeader(opcode: 0x20, tag: ping.taskTag), data: ping.data))
        status &+= 1
    }

    func targetPing(futureAcknowledgment: Bool = false) throws {
        var header = replyHeader(opcode: 0x20, tag: .max)
        if futureAcknowledgment {
            header.put(expectedCommand &+ 1, at: 28)
        } else {
            header.put(UInt32(42), at: 20)
        }
        header.replaceSubrange(8..<16, with: [0, 1, 0x40, 2, 0, 3, 0x40, 4])
        try enqueue(PDU(header: header))
    }

    private func replyHeader(opcode: UInt8, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(expectedCommand, at: 28)
        header.put(expectedCommand &+ 31, at: 32)
        return header
    }

    private func enqueue(_ pdu: PDU) { enqueue(pdu.encoded(digests: digests)) }
    private func enqueue(_ data: Data) {
        input.append(data)
        reader?.resume()
        reader = nil
    }
}

private func admissionPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

private func startIdleProbe(
    _ session: ISCSISession, transport: AdmissionTransport, time: ManualSessionTime
) async throws {
    try await session.login()
    try await admissionPhase { time.hasSleeper(after: .seconds(10)) }
    time.advance(by: .seconds(10), wakeTimers: true)
    try await admissionPhase { await transport.hasHeartbeat }
    try await admissionPhase { time.hasSleeper(after: .seconds(15)) }
}

@Test(arguments: [false, true])
private func gracefulCloseCoexistsWithAnAlreadyStartedHeartbeat(_ echoBeforeLogout: Bool)
    async throws
{
    let time = ManualSessionTime()
    let transport = try AdmissionTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await startIdleProbe(session, transport: transport, time: time)
    let closing = Task { await session.closeGracefully() }
    try await admissionPhase { await session.queuedSendCount == 1 }
    if echoBeforeLogout {
        try await transport.echoHeartbeat()
        try await admissionPhase { await transport.inputDrained }
    }
    await transport.releaseSender()
    #expect(await closing.value)
    let requests = await transport.writes
    #expect(requests.map(\.opcode) == [3, 3, 0, 6])
    #expect(requests.last?.header.uint32(at: 28) == (echoBeforeLogout ? 3 : 2))
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await admissionPhase { time.pendingCount == 0 }
}

@Test(arguments: [QueuedOperation.command, .discovery, .logout], [false, true])
private func queuedRequestsAcknowledgeTheLatestStatusAtAdmission(
    _ operation: QueuedOperation, _ wrap: Bool
) async throws {
    let time = ManualSessionTime()
    let transport = try AdmissionTransport(discovery: operation == .discovery, statusWrap: wrap)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: operation != .discovery),
        clock: time.source)
    try await startIdleProbe(session, transport: transport, time: time)
    let work = Task {
        switch operation {
        case .command: _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
        case .discovery: _ = try await session.discover()
        case .logout: try await session.logout()
        }
    }
    try await admissionPhase { await session.queuedSendCount == 1 }
    try await transport.echoHeartbeat()
    try await admissionPhase { await transport.inputDrained }
    await transport.releaseSender()
    try await work.value
    let opcode: UInt8 = operation == .command ? 1 : operation == .discovery ? 4 : 6
    let request = try #require(await transport.writes.first { $0.opcode == opcode })
    #expect(request.header.uint32(at: 24) == 1)
    #expect(request.header.uint32(at: 28) == (wrap ? 0 : 3))
    await session.close()
    try await admissionPhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true], [false, true])
private func dataOutRefreshesStatusBetweenFramesAndPreservesItsPayloadAndReservedFields(
    _ wrap: Bool, _ digests: Bool
) async throws {
    let time = ManualSessionTime()
    let transport = try AdmissionTransport(holdHeartbeat: false, digests: digests, statusWrap: wrap)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    try await startIdleProbe(session, transport: transport, time: time)
    let lun = try LogicalUnit(addressKey: "0001400200034004")
    let data = Data((0..<16384).map { UInt8(truncatingIfNeeded: $0) })
    let work = Task {
        try await session.execute(
            .write16(lba: 0, blocks: 32, blockSize: 512), lun: lun, output: data)
    }
    try await admissionPhase { await transport.hasSender }
    try await transport.echoHeartbeat()
    try await admissionPhase { !time.hasSleeper(after: .seconds(15)) }
    await transport.releaseSender()
    #expect(try await work.value.data.isEmpty)
    let frames = await transport.writes.filter { $0.opcode == 5 }
    #expect(frames.count == 2)
    #expect(frames.map { $0.header.uint32(at: 28) } == (wrap ? [UInt32.max, 0] : [2, 3]))
    #expect(frames.allSatisfy { $0.header.uint32(at: 24) == 0 && $0.transferTag == 73 })
    #expect(frames.allSatisfy { Array($0.header[8..<16]) == lun.wireBytes })
    #expect(frames.map(\.dataSequenceNumber) == [0, 1])
    #expect(frames.map(\.bufferOffset) == [0, 8192])
    #expect(frames.reduce(Data()) { $0 + $1.data } == data)
    await session.close()
    try await admissionPhase { time.pendingCount == 0 }
}

@Test(arguments: [UInt32(1), UInt32.max])
private func aQueuedCommandCannotBeAcknowledgedBeforeAdmission(_ start: UInt32) async throws {
    let time = ManualSessionTime()
    let transport = try AdmissionTransport(initialCommand: start)
    let base = try configuration(normal: true)
    let configuration = try LoginConfiguration(
        initiatorName: base.initiatorName, targetName: base.targetName, isid: base.isid,
        initialCommandSequenceNumber: start)
    let session = try ISCSISession(
        transport: transport, configuration: configuration, clock: time.source)
    try await startIdleProbe(session, transport: transport, time: time)
    let work = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await admissionPhase { await session.queuedSendCount == 1 }
    try await transport.targetPing(futureAcknowledgment: true)
    try await admissionPhase { await transport.inputDrained }
    await transport.releaseSender()
    await #expect(throws: ProtocolError.malformed("command window")) { try await work.value }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    #expect(await transport.writes.filter { $0.opcode == 1 }.isEmpty)
    await session.close()
    try await admissionPhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true])
private func anAdmittedCommandMayBeAcknowledgedBeforeItsSendCallback(_ wrap: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try AdmissionTransport(
        holdHeartbeat: false, statusWrap: wrap, holdCommand: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    try await startIdleProbe(session, transport: transport, time: time)
    let work = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await admissionPhase { await transport.hasSender }
    // The peer received the command, but the local send completion is still held.
    try await transport.echoHeartbeat()
    try await admissionPhase { !time.hasSleeper(after: .seconds(15)) }
    #expect(await session.state == .ready)
    #expect(await transport.isClosed == false)
    await transport.releaseSender()
    #expect(try await work.value.data.isEmpty)
    await session.close()
    try await admissionPhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true], [UInt32(1), UInt32.max])
private func immediatePingsUseTheNextAdmittedCommandNumberInEitherQueueOrder(
    _ commandFirst: Bool, _ start: UInt32
) async throws {
    let time = ManualSessionTime()
    let transport = try AdmissionTransport(initialCommand: start)
    let base = try configuration(normal: true)
    let configuration = try LoginConfiguration(
        initiatorName: base.initiatorName, targetName: base.targetName, isid: base.isid,
        initialCommandSequenceNumber: start)
    let session = try ISCSISession(
        transport: transport, configuration: configuration, clock: time.source)
    try await startIdleProbe(session, transport: transport, time: time)
    let work: Task<SCSIResult, any Error>
    if commandFirst {
        work = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
        try await admissionPhase { await session.queuedSendCount == 1 }
        try await transport.targetPing()
    } else {
        try await transport.targetPing()
        try await admissionPhase { await session.queuedSendCount == 1 }
        work = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    }
    try await admissionPhase { await session.queuedSendCount == 2 }
    await transport.releaseSender()
    #expect(try await work.value.data.isEmpty)
    let ping = try #require(await transport.writes.first { $0.opcode == 0 && $0.taskTag == .max })
    #expect(ping.header.uint32(at: 24) == (commandFirst ? start &+ 1 : start))
    #expect(ping.header.uint32(at: 28) == 2)
    #expect(ping.transferTag == 42 && ping.data.isEmpty)
    #expect(Array(ping.header[8..<16]) == [0, 1, 0x40, 2, 0, 3, 0x40, 4])
    await session.close()
    try await admissionPhase { time.pendingCount == 0 }
}
