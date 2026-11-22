import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func transferReply(
    opcode: UInt8, flags: UInt8, tag: UInt32, stat: UInt32,
    residual: UInt32 = 0, status: UInt8 = 0, data: Data = Data()
) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = opcode
    header[1] = flags
    header[3] = status
    header.put(tag, at: 16)
    header.put(stat, at: 24)
    header.put(tag, at: 28)
    header.put(UInt32(32), at: 32)
    header.put(residual, at: 44)
    if opcode == 0x31 { header.put(UInt32(73), at: 20) }
    return try PDU(header: header, data: data).encoded()
}

@Test(arguments: ["read", "read-modify-write", "write"])
func shortBlockIOFailsTheConnectionBeforeAnotherOperationCanBeSent(_ operation: String)
    async throws
{
    var responses = try loginFixtures(normal: true)
    if operation == "write" {
        responses.append(
            try transferReply(opcode: 0x31, flags: 0x80, tag: 2, stat: 2, residual: 256))
        responses.append(
            try transferReply(opcode: 0x21, flags: 0x82, tag: 2, stat: 2, residual: 256))
    } else {
        responses.append(
            try transferReply(
                opcode: 0x25, flags: 0x83, tag: 2, stat: 2, residual: 256,
                data: Data(repeating: 0xA5, count: 256)))
    }
    // These valid replies make an accidental follow-up complete instead of timing out.
    responses.append(
        try transferReply(
            opcode: 0x25, flags: 0x81, tag: 3, stat: 3,
            data: Data(repeating: 0xA5, count: 512)))
    responses.append(
        try transferReply(
            opcode: 0x21, flags: 0x80, tag: 4, stat: 4, status: 2,
            data: Data([0, 8, 0x72, 5, 0x20, 0, 0, 0, 0, 0])))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(7), at: 0)
    capacity.put(UInt32(512), at: 4)
    let diagnostics = IODiagnostics.Recorder(layer: .remoteDisk)
    // Retain payload evidence so the write outcome below remains observable.
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        diagnostics: diagnostics, reservedAccess: nil, retainedMutationBytes: 4_194_304)
    try await session.login()
    await #expect(throws: ProtocolError.self) {
        switch operation {
        case "read": _ = try await disk.read(offset: 0, length: 512)
        case "read-modify-write": try await disk.write(offset: 1, data: Data([0xCC]))
        default: try await disk.write(offset: 0, data: Data(repeating: 0xCC, count: 512))
        }
    }
    #expect(diagnostics.retainedMutationCauseID == nil)
    let evidence = disk.mutationEvidence
    if operation == "write" {
        #expect(evidence.intents.first?.outcome == .indeterminate)
        #expect(!evidence.outcomesCertain)
        #expect(evidence.incident == nil)
    } else {
        #expect(evidence.intents.isEmpty)
    }
    #expect(await session.state == .failed)
    #expect(await disk.connectionState() == .interrupted)
    #expect(await transport.isClosed)
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.read(offset: 0, length: 512)
    }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 0, data: Data(repeating: 0xCC, count: 512))
    }
    let sent = await transport.writes.map { Array($0) }
    #expect(sent.filter { $0[0] & 0x3F == 1 }.count == 1)
    #expect(sent.filter { $0[0] & 0x3F == 5 }.count == (operation == "write" ? 1 : 0))
    await disk.close()
}
