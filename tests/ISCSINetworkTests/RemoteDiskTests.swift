import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

@Test func diskRejectsInvalidRangesBeforeSendingAnything() async throws {
    let transport = ScriptedTransport([])
    let session = try ISCSISession(
        transport: transport,
        configuration: LoginConfiguration(initiatorName: "iqn.2026-10.test:initiator"))
    var bytes = Array(repeating: UInt8(0), count: 32)
    bytes.put(UInt64(127), at: 0)
    bytes.put(UInt32(512), at: 8)
    let capacity = try DiskCapacity(readCapacity16: Data(bytes))
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0), capacity: capacity, readOnly: false)
    for offset: Int64 in [-1, 65_536, Int64.max] {
        await #expect(throws: POSIXError(.EINVAL)) {
            try await disk.read(offset: offset, length: 1)
        }
    }
    await #expect(throws: POSIXError(.EINVAL)) { try await disk.read(offset: 0, length: -1) }
    await #expect(throws: POSIXError(.EINVAL)) { try await disk.read(offset: 65_535, length: 2) }
    #expect(try await disk.read(offset: 65_536, length: 0).isEmpty)
    let readOnly = RemoteDisk(
        session: session, lun: try LogicalUnit(0), capacity: capacity, readOnly: true)
    await #expect(throws: POSIXError(.EROFS)) {
        try await readOnly.write(offset: 0, data: Data([1]))
    }
    #expect(await transport.writes.isEmpty)
}

@Test func cancelledGateWaiterDoesNotConsumePermit() async throws {
    let gate = AsyncGate()
    try await gate.acquire()
    let waiter = Task { try await gate.acquire() }
    waiter.cancel()
    await #expect(throws: CancellationError.self) { try await waiter.value }
    await gate.release()
    try await gate.acquire()
    await gate.release()
}

@Test(arguments: [UInt32(512), 4096])
func aSmallTargetLimitPreservesUnalignedReadContentsAcrossCommands(_ size: UInt32) async throws {
    var responses = try loginFixtures(normal: true)
    let portions = [
        Data(repeating: 0xA5, count: Int(size) * 2),
        Data(repeating: 0xB6, count: Int(size) * 2),
        Data(repeating: 0xC7, count: Int(size)),
    ]
    for (index, bytes) in portions.enumerated() {
        let number = UInt32(index + 2)
        responses.append(
            try fixture(
                opcode: 0x25, flags: 0x81, tag: number, stat: number, exp: number,
                data: bytes))
    }
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var bytes = Array(repeating: UInt8(0), count: 8)
    bytes.put(UInt32(7), at: 0)
    bytes.put(size, at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(bytes)),
        readOnly: true, maximumTransferBlocks: 2)
    try await session.login()
    let all = portions.reduce(into: Data()) { $0.append($1) }
    let start = Int(size) - 3
    let length = Int(size) * 3 + 6
    #expect(
        try await disk.read(offset: Int64(start), length: length)
            == Data(all[start..<(start + length)]))
    let sent = await transport.writes.map { [UInt8]($0) }.filter { $0[0] & 0x3F == 1 }
    #expect(sent.map { $0.uint16(at: 39) } == [2, 2, 1])
    #expect(sent.map { $0.uint32(at: 34) } == [0, 2, 4])
    #expect(sent.allSatisfy { $0[32] == 0x28 })
    await session.close()
}

@Test func capacity10DiskUsesRead10AndWholeLUNSync10() async throws {
    var responses = try loginFixtures(normal: true)
    responses.append(
        try fixture(
            opcode: 0x25, flags: 0x81, tag: 2, stat: 2, exp: 2,
            data: Data(repeating: 0xA5, count: 512)))
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 4, stat: 4, exp: 3))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var bytes = Array(repeating: UInt8(0), count: 8)
    bytes.put(UInt32(7), at: 0)
    bytes.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(bytes)), readOnly: false)
    try await session.login()
    #expect(try await disk.read(offset: 0, length: 512) == Data(repeating: 0xA5, count: 512))
    // A read leaves nothing to flush; give the flush something, as after a write.
    markUnsynchronizedWrite(disk)
    try await disk.synchronize()
    let sent = await transport.writes.map { Array(Array($0)[32..<48]) }
    #expect(sent[2].first == 0x28)
    let expectedFlush: [UInt8] = [0x35] + Array(repeating: 0, count: 15)
    #expect(sent[3] == expectedFlush)
    await disk.close()
}

@Test func highAndCrossBoundaryDiskIOPreservesTheFullLBAAndUsesWholeLUNSync10() async throws {
    let lun = try LogicalUnit(256)
    let boundary = UInt64(UInt32.max)
    var responses = try loginFixtures(normal: true)
    responses.append(
        try fixture(
            opcode: 0x25, flags: 0x81, tag: 2, stat: 2, exp: 2,
            data: Data(repeating: 0xAA, count: 512) + Data(repeating: 0xBB, count: 512)))
    var r2t = Array(repeating: UInt8(0), count: 48)
    r2t[0] = 0x31
    r2t[1] = 0x80
    r2t.replaceSubrange(8..<16, with: lun.wireBytes)
    r2t.put(UInt32(3), at: 16)
    r2t.put(UInt32(73), at: 20)
    r2t.put(UInt32(3), at: 24)
    r2t.put(UInt32(3), at: 28)
    r2t.put(UInt32(32), at: 32)
    r2t.put(UInt32(512), at: 44)
    responses.append(try PDU(header: r2t).encoded())
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 4, stat: 4, exp: 4))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 5, stat: 5, exp: 4))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var bytes = Array(repeating: UInt8(0), count: 32)
    bytes.put(boundary + 127, at: 0)
    bytes.put(UInt32(512), at: 8)
    let disk = RemoteDisk(
        session: session, lun: lun, capacity: try DiskCapacity(readCapacity16: Data(bytes)),
        readOnly: false)
    try await session.login()
    #expect(
        try await disk.read(offset: Int64(boundary * 512), length: 1024)
            == Data(repeating: 0xAA, count: 512) + Data(repeating: 0xBB, count: 512))
    try await disk.write(
        offset: Int64((boundary + 1) * 512), data: Data(repeating: 0xCC, count: 512))
    try await disk.synchronize()
    let sent = await transport.writes.map { Array($0) }
    #expect(sent.count == 6)
    #expect(sent[2][32] == 0x88 && sent[2].uint64(at: 34) == boundary)
    #expect(sent[2].uint32(at: 42) == 2)
    #expect(sent[3][32] == 0x8A && sent[3].uint64(at: 34) == boundary + 1)
    #expect(sent[3].uint32(at: 42) == 1)
    #expect(
        sent[4][0] & 0x3F == 5 && Data(sent[4].suffix(512)) == Data(repeating: 0xCC, count: 512))
    let expectedFlush: [UInt8] = [0x35] + Array(repeating: 0, count: 15)
    #expect(Array(sent[5][32..<48]) == expectedFlush)
    await disk.close()
}

@Test(arguments: [false, true])
func rejectedWritesAndInvalidSyncFieldsDoNotTryAnotherCommandFormat(_ flush: Bool) async throws {
    var responses = try loginFixtures(normal: true)
    let sense = Data([0x72, 5, flush ? 0x24 : 0x20, 0, 0, 0, 0, 0])
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x21
    header[1] = 0x80
    header[3] = 2
    header.put(UInt32(2), at: 16)
    header.put(UInt32(2), at: 24)
    header.put(UInt32(2), at: 28)
    header.put(UInt32(32), at: 32)
    responses.append(try PDU(header: header, data: Data([0, 8]) + sense).encoded())
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var bytes = Array(repeating: UInt8(0), count: 8)
    bytes.put(UInt32(7), at: 0)
    bytes.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(bytes)), readOnly: false)
    try await session.login()
    if flush { markUnsynchronizedWrite(disk) }
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        if flush {
            try await disk.synchronize()
        } else {
            try await disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        }
    }
    let sent = await transport.writes.map { Array($0) }
    #expect(sent.count == 3)
    #expect(sent[2][32] == (flush ? 0x35 : 0x2A))
    #expect(await session.state == .ready)
    await disk.close()
}
