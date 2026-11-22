import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func cacheFailure(
    tag: UInt32, sense: Data, status: UInt8 = 2
) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x21
    header[1] = 0x80
    header[3] = status
    header.put(tag, at: 16)
    header.put(tag, at: 24)
    header.put(tag, at: 28)
    header.put(UInt32(32), at: 32)
    let data = sense.isEmpty ? Data() : Data([0, UInt8(sense.count)]) + sense
    return try PDU(header: header, data: data).encoded()
}

private func cacheTestDisk(session: ISCSISession, readOnly: Bool = false) throws -> RemoteDisk {
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(127), at: 0)
    capacity.put(UInt32(512), at: 4)
    return try RemoteDisk(
        session: session, lun: LogicalUnit(0),
        capacity: DiskCapacity(readCapacity10: Data(capacity)),
        readOnly: readOnly)
}

private func opcodeSense(fixed: Bool, deferred: Bool = false) -> Data {
    if fixed {
        var bytes = Array(repeating: UInt8(0), count: 18)
        bytes[0] = deferred ? 0x71 : 0x70
        bytes[2] = 5
        bytes[7] = 10
        bytes[12] = 0x20
        return Data(bytes)
    }
    return Data([deferred ? 0x73 : 0x72, 5, 0x20, 0, 0, 0, 0, 0])
}

@Test(arguments: [false, true])
func unsupportedSync10UsesSync16AndRemembersItForThisDisk(_ fixed: Bool) async throws {
    var responses = try loginFixtures(normal: true)
    responses.append(try cacheFailure(tag: 2, sense: opcodeSense(fixed: fixed)))
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    responses.append(try fixture(opcode: 0x21, flags: 0x80, tag: 4, stat: 4, exp: 4))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 5, stat: 5, exp: 4))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try cacheTestDisk(session: session)
    try await session.login()
    do {
        markUnsynchronizedWrite(disk)
        try await disk.synchronize()
        let afterFallback = disk.mutationEvidence
        #expect(afterFallback.generation == 1)
        #expect(afterFallback.precedingBarrier?.attempts.map(\.opcode) == [0x35, 0x91])
        markUnsynchronizedWrite(disk)
        try await disk.synchronize()
        #expect(disk.mutationEvidence.generation == 2)
        #expect(disk.mutationEvidence.precedingBarrier?.attempts.map(\.opcode) == [0x91])
        #expect(await disk.connectionState() == .connected)
        let commands = await transport.writes.map { Array($0) }.filter { $0[0] & 0x3F == 1 }
        #expect(commands.map { $0[32] } == [0x35, 0x91, 0x91])
        #expect(commands.allSatisfy { Array($0[33..<48]) == Array(repeating: 0, count: 15) })
    } catch {
        await disk.close()
        throw error
    }
    await disk.close()
    #expect(await session.state == .closed)
}

private struct CacheRejection: Sendable {
    let status: UInt8
    let sense: Data
}

// A current unit attention, BUSY and TASK SET FULL report an unexecuted command and are
// retried before they retire the disk; RemoteDiskRetryTests covers them.
@Test(arguments: [
    CacheRejection(status: 2, sense: Data([0x72, 5, 0x24, 0, 0, 0, 0, 0])),
    CacheRejection(status: 2, sense: Data([0x72, 5, 0x20, 1, 0, 0, 0, 0])),
    CacheRejection(status: 2, sense: Data([0x72, 3, 0x20, 0, 0, 0, 0, 0])),
    CacheRejection(status: 2, sense: Data([0x72, 5, 0x20])),
    CacheRejection(status: 2, sense: opcodeSense(fixed: false, deferred: true)),
    CacheRejection(status: 2, sense: opcodeSense(fixed: true, deferred: true)),
    CacheRejection(status: 0x18, sense: Data()),
])
private func otherSyncFailuresRemainVisibleAndRetireTheDisk(_ rejection: CacheRejection)
    async throws
{
    var responses = try loginFixtures(normal: true)
    responses.append(try cacheFailure(tag: 2, sense: rejection.sense, status: rejection.status))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try cacheTestDisk(session: session)
    try await session.login()
    markUnsynchronizedWrite(disk)
    await #expect(
        throws: ProtocolError.scsiFailure(status: rejection.status, sense: rejection.sense)
    ) {
        try await disk.synchronize()
    }
    #expect(await disk.connectionState() == .interrupted)
    await #expect(throws: ProtocolError.invalidState) { try await disk.synchronize() }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.read(offset: 0, length: 512)
    }
    let commands = await transport.writes.map { Array($0) }.filter { $0[0] & 0x3F == 1 }
    #expect(commands.map { $0[32] } == [0x35])
    await disk.close()
}

@Test(arguments: [
    CacheRejection(status: 2, sense: opcodeSense(fixed: false)),
    CacheRejection(status: 2, sense: Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])),
    CacheRejection(status: 2, sense: opcodeSense(fixed: true, deferred: true)),
])
private func failedSync16IsNotRepeatedOrHidden(_ rejection: CacheRejection) async throws {
    var responses = try loginFixtures(normal: true)
    responses.append(try cacheFailure(tag: 2, sense: opcodeSense(fixed: false)))
    responses.append(try cacheFailure(tag: 3, sense: rejection.sense, status: rejection.status))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 4, stat: 4, exp: 3))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try cacheTestDisk(session: session)
    try await session.login()
    markUnsynchronizedWrite(disk)
    await #expect(
        throws: ProtocolError.scsiFailure(status: rejection.status, sense: rejection.sense)
    ) {
        try await disk.synchronize()
    }
    #expect(await disk.connectionState() == .interrupted)
    await #expect(throws: ProtocolError.invalidState) { try await disk.synchronize() }
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    }
    let commands = await transport.writes.map { Array($0) }.filter { $0[0] & 0x3F == 1 }
    #expect(commands.map { $0[32] } == [0x35, 0x91])
    await disk.close()
}

@Test func readOnlyDisksNeverProbeASynchronizationFormat() async throws {
    var responses = try loginFixtures(normal: true)
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 2, stat: 2, exp: 1))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try cacheTestDisk(session: session, readOnly: true)
    try await session.login()
    try await disk.synchronize()
    #expect(await transport.writes.count == 2)
    await disk.close()
}
