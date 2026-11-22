import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

/// Separates request admission, send completion and target responses.
private actor CloseTransport: ByteTransport {
    private let logins: [Data]
    private let digests: DigestPolicy
    private let holdLogoutSend: Bool
    private let replyAfterNOP: Bool
    private var fullFeature = false
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var sender: CheckedContinuation<Void, any Error>?
    private var logout: PDU?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private(set) var writes: [PDU] = []
    private(set) var isClosed = false
    private(set) var dataAccepted = 0
    var hasLogout: Bool { logout != nil }
    var inputEmpty: Bool { input.isEmpty }

    init(digests: Bool = false, holdLogoutSend: Bool = false, replyAfterNOP: Bool = false) throws {
        logins = try loginFixtures(normal: true, digests: digests)
        self.digests = DigestPolicy(header: digests, data: digests)
        self.holdLogoutSend = holdLogoutSend
        self.replyAfterNOP = replyAfterNOP
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(
            maximumDataLength: 262_144, digests: fullFeature ? digests : DigestPolicy())
        let pdus = try decoder.append(data)
        let pdu = try #require(pdus.count == 1 && decoder.isAtFrameBoundary ? pdus.first : nil)
        writes.append(pdu)
        switch pdu.opcode {
        case 3:
            let stage = Int((pdu.flags >> 2) & 3)
            enqueue(logins[stage])
            if stage == 1 { fullFeature = true }
        case 6:
            logout = pdu
            if holdLogoutSend { try await withCheckedThrowingContinuation { sender = $0 } }
        case 1:
            #expect(pdu.header.uint32(at: 24) == expectedCommand)
            expectedCommand &+= 1
            if pdu.header[32] == 0x2A {
                var header = replyHeader(opcode: 0x31, tag: pdu.taskTag)
                header.replaceSubrange(8..<16, with: pdu.header[8..<16])
                header.put(UInt32(73), at: 20)
                header.put(pdu.header.uint32(at: 20), at: 44)
                enqueue(try PDU(header: header).encoded(digests: digests))
            }
        case 5: dataAccepted += pdu.data.count
        case 0:
            if replyAfterNOP, pdu.taskTag == .max, pdu.transferTag == 42 {
                try replyLogout()
            }
        default: throw ProtocolError.malformed("unexpected close-test request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !isClosed { await withCheckedContinuation { reader = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(input.count, maximumLength)
        let bytes = Data(input.prefix(count))
        input.removeFirst(count)
        return bytes
    }

    func replyLogout(
        code: UInt8 = 0, wrongTag: Bool = false, flags: UInt8 = 0x80, data: Data = Data()
    ) throws {
        let request = try #require(logout)
        var header = replyHeader(opcode: 0x26, tag: request.taskTag &+ (wrongTag ? 1 : 0))
        header[2] = code
        header[1] = flags
        status &+= 1
        enqueue(try PDU(header: header, data: data).encoded(digests: digests))
    }

    func targetPing() throws {
        var header = replyHeader(opcode: 0x20, tag: .max)
        header.put(UInt32(42), at: 20)
        enqueue(try PDU(header: header).encoded(digests: digests))
    }

    func releaseSender() {
        let sender = sender
        self.sender = nil
        sender?.resume()
    }

    func close() {
        isClosed = true
        reader?.resume()
        reader = nil
        sender?.resume(throwing: ProtocolError.connectionClosed)
        sender = nil
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

    private func enqueue(_ bytes: Data) {
        input.append(bytes)
        reader?.resume()
        reader = nil
    }
}

private func closePhase(_ predicate: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(2))
    }
}

private func closeDisk(_ session: ISCSISession) throws -> RemoteDisk {
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(127), at: 0)
    capacity.put(UInt32(512), at: 4)
    return RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false)
}

@Test(arguments: [false, true])
private func idleDiskCloseSharesOneLogoutAndRejectsNewIO(_ digests: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport(digests: digests)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let first = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout }
    let disk = try closeDisk(session)
    let second = Task { await disk.close() }
    await #expect(throws: ProtocolError.busy) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    try await transport.replyLogout()
    #expect(await first.value)
    await second.value
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    let frames = await transport.writes
    #expect(frames.map(\.opcode) == [3, 3, 6])
    let logout = try #require(frames.last)
    #expect(logout.header[0] == 0x46 && logout.flags == 0x80 && logout.data.isEmpty)
    #expect(logout.header.uint32(at: 24) == 1 && logout.header.uint32(at: 28) == 2)
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true], [1, 30])
private func closeUsesFiveSecondsOrAShorterCommandLimit(_ holdSend: Bool, _ commandSeconds: Int)
    async throws
{
    let time = ManualSessionTime()
    let transport = try CloseTransport(holdLogoutSend: holdSend)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(commandSeconds), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    let limit = min(commandSeconds, 5)
    try await closePhase { await transport.hasLogout && time.hasSleeper(after: .seconds(limit)) }
    time.advance(by: .milliseconds(limit * 1000 - 1), wakeTimers: true)
    #expect(await transport.isClosed == false)
    time.advance(by: .milliseconds(1), wakeTimers: true)
    #expect(await closing.value == false)
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    #expect(await transport.writes.map(\.opcode) == [3, 3, 6])
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: [4999, 5000, 5001], [false, true])
private func lateLogoutRepliesAndSendCallbacksCannotPublishSuccessfulClose(
    _ milliseconds: Int, _ holdSend: Bool
) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport(holdLogoutSend: holdSend)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout && time.hasSleeper(after: .seconds(5)) }
    let responseAt = holdSend ? 4999 : milliseconds
    time.advance(by: .milliseconds(responseAt))
    try await transport.replyLogout()
    if holdSend {
        try await closePhase { await transport.inputEmpty }
        time.advance(by: .milliseconds(milliseconds - responseAt))
        await transport.releaseSender()
    }
    #expect(await closing.value == (milliseconds < 5000))
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true])
private func busyDiskCloseAbortsReadOrUncertainWriteWithoutLogout(_ write: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let disk = try closeDisk(session)
    let work = Task {
        if write {
            try await disk.write(offset: 0, data: Data(repeating: 0xA5, count: 4096))
        } else {
            _ = try await disk.read(offset: 0, length: 512)
        }
    }
    try await closePhase {
        if write { return await transport.dataAccepted == 4096 }
        return await transport.writes.contains { $0.opcode == 1 }
    }
    await disk.close()
    await #expect(throws: ProtocolError.self) { try await work.value }
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    let frames = await transport.writes
    #expect(frames.filter { $0.opcode == 6 }.isEmpty)
    #expect(frames.filter { $0.opcode == 1 }.count == 1)
    #expect(frames.filter { $0.opcode == 5 }.count == (write ? 1 : 0))
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true])
private func failedOrCancelledSessionsCloseWithoutLogout(_ cancelled: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    if cancelled {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await session.closeGracefully()
        }
        #expect(await task.value == false)
    } else {
        await transport.close()
        try await closePhase { await session.state == .failed }
        #expect(await session.closeGracefully() == false)
    }
    #expect(await transport.writes.map(\.opcode) == [3, 3])
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

@Test private func explicitAbortInterruptsASharedGracefulClose() async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport(holdLogoutSend: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let first = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout }
    let second = Task { await session.closeGracefully() }
    await session.close()
    #expect(await first.value == false)
    #expect(await second.value == false)
    #expect(await transport.writes.map(\.opcode) == [3, 3, 6])
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

@Test private func aQueuedTargetNOPReplyRemainsValidWhileLogoutIsPending() async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport(digests: true, holdLogoutSend: true, replyAfterNOP: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout }
    try await transport.targetPing()
    try await closePhase { await session.queuedSendCount == 1 }
    await transport.releaseSender()
    try await closePhase { await transport.writes.contains { $0.opcode == 0 } }
    #expect(await closing.value)
    let frames = await transport.writes
    #expect(frames.map(\.opcode) == [3, 3, 6, 0])
    #expect(frames.last?.taskTag == UInt32.max && frames.last?.transferTag == 42)
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

@Test private func shutdownDoesNotStartNewHeartbeatRequests() async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        heartbeatInterval: .seconds(1), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout && time.hasSleeper(after: .seconds(5)) }
    for second in 1...4 {
        time.advance(by: .seconds(1), wakeTimers: true)
        try await closePhase { time.hasSleeper(after: .seconds(second + 1)) }
        #expect(await transport.writes.map(\.opcode) == [3, 3, 6])
    }
    time.advance(by: .seconds(1), wakeTimers: true)
    #expect(await closing.value == false)
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: [false, true])
private func rejectedOrMismatchedLogoutIsNotReportedAsOrderly(_ wrongTag: Bool) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout }
    try await transport.replyLogout(code: wrongTag ? 0 : 1, wrongTag: wrongTag)
    #expect(await closing.value == false)
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

@Test(arguments: ["missing-final", "data", "reserved"])
private func logoutReplyShapeChecksFixedFieldsAndIgnoresReservedFlags(_ form: String) async throws {
    let time = ManualSessionTime()
    let transport = try CloseTransport(digests: true)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true), clock: time.source)
    defer { Task { await session.close() } }
    try await session.login()
    let closing = Task { await session.closeGracefully() }
    try await closePhase { await transport.hasLogout }
    try await transport.replyLogout(
        flags: form == "missing-final" ? 0 : form == "reserved" ? 0xFF : 0x80,
        data: form == "data" ? Data([1]) : Data())
    #expect(await closing.value == (form == "reserved"))
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    try await closePhase { time.pendingCount == 0 }
}

/// close() and a graceful close tear the session down once. The heartbeat task and any
/// receive the close interrupted end afterwards; they must not close the transport again
/// after the session has reported closed (a late cleanup was seen as a second close).
/// Without the guard in fail() this fails almost every run; with it no second close exists.
@Test(arguments: [false, true])
private func aClosedSessionIsNotTornDownAgainByItsBackgroundTasks(_ graceful: Bool) async throws {
    let (session, target) = try await reservedSession(IntentFixture())
    if graceful {
        #expect(await session.closeGracefully())
    } else {
        await session.close()
    }
    #expect(await session.state == .closed)
    #expect(await target.closeCalls == 1)
    for _ in 0..<1_000 { await Task.yield() }
    try await Task.sleep(for: .milliseconds(50))
    #expect(await target.closeCalls == 1)
}
