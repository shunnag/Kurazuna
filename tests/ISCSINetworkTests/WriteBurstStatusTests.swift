import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private struct WriteBurstCase: Sendable {
    let digests: Bool
    let sixteen: Bool
    let burstLength: Int
}

private let writeBurstCases = [false, true].flatMap { digests in
    [false, true].flatMap { sixteen in
        [8192, 16384].map {
            WriteBurstCase(digests: digests, sixteen: sixteen, burstLength: $0)
        }
    }
}

/// The target requests one partial burst, then reports a device failure after its F PDU.
/// Transport completion stays pending so response admission is tested independently.
private actor WriteBurstTransport: ByteTransport {
    enum Failure: Sendable { case device, beforeFinal, senseLength, residual }
    private let logins: [Data]
    private let digests: DigestPolicy
    private let burstLength: Int
    private let failure: Failure
    private var fullFeature = false
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var sender: CheckedContinuation<Void, any Error>?
    private var command: PDU?
    private var status: UInt32 = 2
    private(set) var sent: [PDU] = []
    private(set) var closed = false
    private(set) var failureSent = false
    var hasPendingSender: Bool { sender != nil }

    static let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])

    init(digests: Bool, burstLength: Int, failure: Failure = .device) throws {
        logins = try loginFixtures(normal: true, digests: digests)
        self.digests = DigestPolicy(header: digests, data: digests)
        self.burstLength = burstLength
        self.failure = failure
    }

    func send(_ bytes: Data) async throws {
        guard !closed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(
            maximumDataLength: 262_144, digests: fullFeature ? digests : DigestPolicy())
        let pdus = try decoder.append(bytes)
        let pdu = try #require(pdus.count == 1 && decoder.isAtFrameBoundary ? pdus.first : nil)
        sent.append(pdu)
        switch pdu.opcode {
        case 0x03:
            let stage = Int((pdu.flags >> 2) & 3)
            enqueue(logins[stage])
            if stage == 1 { fullFeature = true }
        case 0x01:
            #expect(command == nil)
            #expect(pdu.header.uint32(at: 20) == 32768)
            command = pdu
            var header = responseHeader(opcode: 0x31, tag: pdu.taskTag)
            header.replaceSubrange(8..<16, with: pdu.header[8..<16])
            header.put(UInt32(73), at: 20)
            header.put(UInt32(burstLength), at: 44)
            enqueue(try PDU(header: header).encoded(digests: digests))
        case 0x05:
            if !failureSent, pdu.flags & 0x80 != 0 || failure == .beforeFinal {
                let command = try #require(command)
                var header = responseHeader(opcode: 0x21, tag: command.taskTag)
                header[1] = failure == .residual ? 0x86 : 0x82
                header[3] = 2
                header.put(UInt32(32768 - burstLength), at: 44)
                var payload = [UInt8](repeating: 0, count: 2)
                payload.put(UInt16(failure == .senseLength ? 16 : 8), at: 0)
                payload.append(contentsOf: Self.sense)
                failureSent = true
                enqueue(try PDU(header: header, data: Data(payload)).encoded(digests: digests))
                status &+= 1
                try await withCheckedThrowingContinuation { sender = $0 }
            }
        case 0x06:
            enqueue(
                try PDU(header: responseHeader(opcode: 0x26, tag: pdu.taskTag)).encoded(
                    digests: digests))
            status &+= 1
        default: throw ProtocolError.malformed("unexpected burst-test request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !closed { await withCheckedContinuation { reader = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
        let length = min(maximumLength, input.count)
        let bytes = Data(input.prefix(length))
        input.removeFirst(length)
        return bytes
    }

    func releaseSender() {
        let sender = sender
        self.sender = nil
        sender?.resume()
    }

    func close() {
        closed = true
        reader?.resume()
        reader = nil
        sender?.resume(throwing: ProtocolError.connectionClosed)
        sender = nil
    }

    private func responseHeader(opcode: UInt8, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(UInt32(2), at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    private func enqueue(_ bytes: Data) {
        input.append(bytes)
        reader?.resume()
        reader = nil
    }
}

private func burstPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let end = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < end else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

@Test(arguments: writeBurstCases)
private func deviceFailureAfterFinalPartialBurstKeepsItsStatus(_ test: WriteBurstCase) async throws
{
    let transport = try WriteBurstTransport(digests: test.digests, burstLength: test.burstLength)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(5))
    try await session.login()
    let cdb =
        try test.sixteen
        ? SCSICommand.write16(lba: 0, blocks: 64, blockSize: 512)
        : SCSICommand.write10(lba: 0, blocks: 64, blockSize: 512)
    let task = Task {
        try await session.execute(
            cdb, lun: LogicalUnit(0), output: Data(repeating: 0x6D, count: 32768))
    }
    try await burstPhase { await transport.failureSent }
    // A command sent after the target's status is a protocol error in this fixture.
    // Give the receiver a deterministic terminal point before releasing the callback.
    try await burstPhase {
        let state = await session.state
        let sequence = await session.expectedStatusSequenceNumber
        return state == .failed || sequence == 3
    }
    await transport.releaseSender()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: WriteBurstTransport.sense)) {
        try await task.value
    }
    #expect(await session.state == .ready)
    let data = await transport.sent.filter { $0.opcode == 5 }
    #expect(data.count == test.burstLength / 8192)
    #expect(data.reduce(0) { $0 + $1.data.count } == test.burstLength)
    #expect(data.last?.flags == 0x80)
    #expect(await transport.sent.filter { $0.opcode == 1 }.count == 1)
    await session.close()
}

@Test(arguments: [false, true])
private func deviceFailureBeforeTheRequestedBurstFinalStillStopsData(_ digests: Bool) async throws {
    let transport = try WriteBurstTransport(
        digests: digests, burstLength: 16384, failure: .beforeFinal)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(5))
    try await session.login()
    await #expect(throws: ProtocolError.malformed("write status during Data-Out")) {
        try await session.execute(
            .write16(lba: 0, blocks: 64, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 0x6D, count: 32768))
    }
    #expect(await transport.sent.filter { $0.opcode == 5 }.count == 1)
    #expect(await session.state == .failed)
    #expect(await transport.closed)
}

@Test(arguments: [false, true], [WriteBurstTransport.Failure.senseLength, .residual])
private func aFinalPartialBurstDoesNotMakeMalformedErrorsRecoverable(
    _ digests: Bool, _ failure: WriteBurstTransport.Failure
) async throws {
    let transport = try WriteBurstTransport(digests: digests, burstLength: 8192, failure: failure)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(5))
    try await session.login()
    let task = Task {
        try await session.execute(
            .write10(lba: 0, blocks: 64, blockSize: 512), lun: LogicalUnit(0),
            output: Data(repeating: 0x6D, count: 32768))
    }
    try await burstPhase { await session.expectedStatusSequenceNumber == 3 }
    await transport.releaseSender()
    let expected = ProtocolError.malformed(
        failure == .senseLength ? "SCSI sense length" : "SCSI residual count")
    await #expect(throws: expected) { try await task.value }
    #expect(await transport.sent.filter { $0.opcode == 5 }.count == 1)
    #expect(await session.state == .failed)
    #expect(await transport.closed)
}

@Test(arguments: [false, true])
private func aPartialBurstDeviceFailureRetiresTheDiskWithoutReplayingIO(_ digests: Bool)
    async throws
{
    let transport = try WriteBurstTransport(digests: digests, burstLength: 8192)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: true),
        commandTimeout: .seconds(5))
    try await session.login()
    var capacityBytes = Array(repeating: UInt8(0), count: 8)
    capacityBytes.put(UInt32(63), at: 0)
    capacityBytes.put(UInt32(512), at: 4)
    let capacity = try DiskCapacity(readCapacity10: Data(capacityBytes))
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0), capacity: capacity, readOnly: false)
    let task = Task { try await disk.write(offset: 0, data: Data(repeating: 0x6D, count: 32768)) }
    try await burstPhase { await session.expectedStatusSequenceNumber == 3 }
    await transport.releaseSender()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: WriteBurstTransport.sense)) {
        try await task.value
    }
    #expect(await session.state == .ready)
    #expect(await disk.connectionState() == .interrupted)
    let count = await transport.sent.count
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.read(offset: 0, length: 512)
    }
    await #expect(throws: ProtocolError.invalidState) { try await disk.synchronize() }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 0, data: Data(repeating: 0x6E, count: 512))
    }
    #expect(await transport.sent.count == count)
    await disk.close()
    #expect(await session.state == .closed)
    #expect(await transport.closed)
    #expect(await transport.sent.filter { $0.opcode == 6 }.count == 1)
}
