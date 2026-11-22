import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func deviceErrorReply(flags: UInt8, residual: UInt32) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x21
    header[1] = flags
    header[3] = 2
    header.put(UInt32(2), at: 16)
    header.put(UInt32(2), at: 24)
    header.put(UInt32(2), at: 28)
    header.put(UInt32(32), at: 32)
    header.put(residual, at: 44)
    return try PDU(header: header, data: Data([0, 8, 0x72, 6, 0x29, 0, 0, 0, 0, 0])).encoded()
}

@Test(arguments: ["both", "zero-underflow", "large-underflow", "zero-overflow"])
func malformedDeviceErrorsFailTheSessionBeforeAFollowUpCommand(_ fault: String) async throws {
    let flags: UInt8 = fault == "both" ? 0x86 : fault == "zero-overflow" ? 0x84 : 0x82
    let count: UInt32 = fault == "both" ? 1 : fault == "large-underflow" ? 97 : 0
    var replies = try loginFixtures(normal: true)
    replies.append(try deviceErrorReply(flags: flags, residual: count))
    replies.append(try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    let transport = ScriptedTransport(replies)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    await #expect(throws: ProtocolError.malformed("SCSI residual count")) {
        try await session.execute(.inquiry(), lun: LogicalUnit(0))
    }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await #expect(throws: ProtocolError.invalidState) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.count == 1)
    await session.close()
}

@Test(arguments: [false, true])
func aValidDeviceErrorWithResidualKeepsTheConnectionUsable(_ underflow: Bool) async throws {
    var replies = try loginFixtures(normal: true)
    replies.append(
        try deviceErrorReply(flags: underflow ? 0x82 : 0x80, residual: underflow ? 96 : .max))
    replies.append(try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    let transport = ScriptedTransport(replies)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    await #expect(
        throws: ProtocolError.scsiFailure(status: 2, sense: Data([0x72, 6, 0x29, 0, 0, 0, 0, 0]))
    ) { try await session.execute(.inquiry(), lun: LogicalUnit(0)) }
    #expect(await session.state == .ready)
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.count == 2)
    await session.close()
}
