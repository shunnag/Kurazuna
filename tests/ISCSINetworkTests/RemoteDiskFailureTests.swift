import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func failedDiskCommand(status: UInt8, sense: Data) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x21
    header[1] = 0x80
    header[3] = status
    header.put(UInt32(2), at: 16)
    header.put(UInt32(2), at: 24)
    header.put(UInt32(2), at: 28)
    header.put(UInt32(32), at: 32)
    let data = sense.isEmpty ? Data() : Data([0, UInt8(sense.count)]) + sense
    return try PDU(header: header, data: data).encoded()
}

private func smallFailureTestDisk(session: ISCSISession) throws -> RemoteDisk {
    var bytes = Array(repeating: UInt8(0), count: 8)
    bytes.put(UInt32(7), at: 0)
    bytes.put(UInt32(512), at: 4)
    return try RemoteDisk(
        session: session, lun: LogicalUnit(0),
        capacity: DiskCapacity(readCapacity10: Data(bytes)), readOnly: false)
}

// BUSY reports an unexecuted command and is retried first; RemoteDiskRetryTests covers it.
@Test(arguments: [false, true], [UInt8(2), 0x18])
func rejectedMutationInterruptsTheDiskBeforeFurtherIO(_ flush: Bool, _ status: UInt8)
    async throws
{
    let sense = status == 2 ? Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0]) : Data()
    var responses = try loginFixtures(normal: true)
    responses.append(try failedDiskCommand(status: status, sense: sense))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try smallFailureTestDisk(session: session)
    try await session.login()
    if flush { markUnsynchronizedWrite(disk) }
    await #expect(throws: ProtocolError.scsiFailure(status: status, sense: sense)) {
        if flush {
            try await disk.synchronize()
        } else {
            try await disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        }
    }
    // Keep the protocol session usable for Logout without treating this disk as healthy.
    #expect(await session.state == .ready)
    let state = await disk.connectionState()
    #expect(state == .interrupted)
    guard state == .interrupted else {
        await disk.close()
        return
    }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.read(offset: 0, length: 512)
    }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 0, data: Data(repeating: 0xCC, count: 512))
    }
    await #expect(throws: ProtocolError.invalidState) { try await disk.synchronize() }
    #expect(await disk.connectionState() == .interrupted)
    #expect(await transport.writes.count == 3)
    await disk.close()
    #expect(await session.state == .closed)
    #expect(await disk.connectionState() == .closed)
    let sent = await transport.writes.map { Array($0) }
    #expect(sent.count == 4 && sent.last?[0] == 0x46)
}

@Test func currentReadFailureDoesNotRetireAnOtherwiseUsableDisk() async throws {
    let sense = Data([0x72, 3, 0x11, 0, 0, 0, 0, 0])
    var responses = try loginFixtures(normal: true)
    responses.append(try failedDiskCommand(status: 2, sense: sense))
    responses.append(
        try fixture(
            opcode: 0x25, flags: 0x81, tag: 3, stat: 3, exp: 3,
            data: Data(repeating: 0xA5, count: 512)))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 4, stat: 4, exp: 3))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try smallFailureTestDisk(session: session)
    try await session.login()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(await disk.connectionState() == .connected)
    #expect(try await disk.read(offset: 0, length: 512) == Data(repeating: 0xA5, count: 512))
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func cancelledMutationAdmissionDoesNotRetireTheDisk() async throws {
    var responses = try loginFixtures(normal: true)
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 2, stat: 2, exp: 2))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try smallFailureTestDisk(session: session)
    try await session.login()
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await disk.write(offset: 0, data: Data([0xA5]))
    }
    await #expect(throws: CancellationError.self) { try await cancelled.value }
    #expect(await disk.connectionState() == .connected)
    #expect(await transport.writes.count == 2)
    // Nothing was sent, so nothing needs flushing; a later write's flush still runs.
    #expect(disk.coverage.isClean)
    markUnsynchronizedWrite(disk)
    try await disk.synchronize()
    await disk.close()
    #expect(await session.state == .closed)
}
