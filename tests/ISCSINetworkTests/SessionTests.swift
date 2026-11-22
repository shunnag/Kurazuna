import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

@Test func disconnectedSessionRejectsCommands() async throws {
    let session = try ISCSISession(
        transport: ScriptedTransport([]),
        configuration: LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk"))
    await #expect(throws: ProtocolError.invalidState) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
}

actor ScriptedTransport: ByteTransport {
    private var responses: [Data]
    private var gates: [(offset: Int, writes: Int)]
    private var position = 0
    private let initiallyEmpty: Bool
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var writes: [Data] = []
    private(set) var isClosed = false

    init(_ responses: [Data], gates: [(offset: Int, writes: Int)]? = nil) {
        self.responses = responses
        initiallyEmpty = responses.isEmpty
        var offset = 0
        self.gates =
            gates
            ?? responses.enumerated().map { index, response in
                defer { offset += response.count }
                return (offset, index + 1)
            }
    }
    func send(_ data: Data) async throws {
        writes.append(data)
        waiter?.resume()
        waiter = nil
    }
    func receive(maximumLength: Int) async throws -> Data {
        while !isClosed, !initiallyEmpty {
            if let gate = gates.first, gate.offset == position {
                if gate.writes <= writes.count {
                    gates.removeFirst()
                } else {
                    await withCheckedContinuation { waiter = $0 }
                    continue
                }
            }
            if !responses.isEmpty { break }
            await withCheckedContinuation { waiter = $0 }
        }
        guard !isClosed, !responses.isEmpty else { throw ProtocolError.connectionClosed }
        let limit = min(maximumLength, (gates.first?.offset ?? Int.max) - position)
        let result = Data(responses[0].prefix(limit))
        position += result.count
        responses[0].removeFirst(result.count)
        if responses[0].isEmpty { responses.removeFirst() }
        return result
    }
    func close() async {
        isClosed = true
        waiter?.resume()
        waiter = nil
    }
}

private let isid: [UInt8] = [0x80, 1, 2, 3, 4, 5]

func fixture(
    opcode: UInt8, flags: UInt8, tag: UInt32, stat: UInt32,
    exp: UInt32 = 1, data: Data = Data(), digests: DigestPolicy = DigestPolicy()
) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = opcode
    header[1] = flags
    header.replaceSubrange(8..<14, with: isid)
    header.put(UInt16(1), at: 14)
    header.put(tag, at: 16)
    header.put(stat, at: 24)
    header.put(exp, at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data).encoded(digests: digests)
}

func loginFixtures(normal: Bool = false, digests: Bool = false) throws -> [Data] {
    var securityEntries: [TextParameters.Entry] = [.init("AuthMethod", "None")]
    if normal { securityEntries.append(.init("TargetPortalGroupTag", "1")) }
    let security = try fixture(
        opcode: 0x23, flags: 0x81, tag: 1, stat: 0,
        data: TextParameters(securityEntries).encoded())
    var entries: [TextParameters.Entry] = [
        .init("HeaderDigest", digests ? "CRC32C" : "None"),
        .init("DataDigest", digests ? "CRC32C" : "None"),
        .init("MaxRecvDataSegmentLength", "8192"),
    ]
    if normal {
        entries += [
            .init("MaxConnections", "1"), .init("InitialR2T", "Yes"),
            .init("ImmediateData", "No"), .init("MaxBurstLength", "262144"),
            .init("FirstBurstLength", "65536"), .init("MaxOutstandingR2T", "1"),
            .init("DataPDUInOrder", "Yes"), .init("DataSequenceInOrder", "Yes"),
            .init("ErrorRecoveryLevel", "0"), .init("DefaultTime2Wait", "2"),
            .init("DefaultTime2Retain", "0"),
        ]
    }
    return [
        security,
        try fixture(
            opcode: 0x23, flags: 0x87, tag: 1, stat: 1,
            data: TextParameters(entries).encoded()),
    ]
}

func configuration(normal: Bool = false) throws -> LoginConfiguration {
    try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:initiator",
        targetName: normal ? "iqn.2026-10.test:disk" : nil, isid: isid)
}

@Test func discoveryLoginContinuationAndLogout() async throws {
    var data = try loginFixtures()
    let text = try TextParameters([
        .init("TargetName", "iqn.2026-10.test:a"), .init("TargetAddress", "127.0.0.1:3260,1"),
        .init("TargetName", "iqn.2026-10.test:b"), .init("TargetAddress", "[::1]:3260,1"),
    ]).encoded()
    var first = Array(repeating: UInt8(0), count: 48)
    first[0] = 0x24
    first[1] = 0x40
    first.put(UInt32(2), at: 16)
    first.put(UInt32(42), at: 20)
    first.put(UInt32(2), at: 24)
    first.put(UInt32(1), at: 28)
    first.put(UInt32(32), at: 32)
    data.append(try PDU(header: first, data: Data(text.prefix(13))).encoded())
    first[1] = 0x80
    first.put(UInt32.max, at: 20)
    first.put(UInt32(3), at: 24)
    data.append(try PDU(header: first, data: Data(text.dropFirst(13))).encoded())
    data.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 4))
    let transport = ScriptedTransport(data)
    let session = try ISCSISession(transport: transport, configuration: configuration())
    try await session.login()
    let targets = try await session.discover()
    #expect(targets.map(\.name) == ["iqn.2026-10.test:a", "iqn.2026-10.test:b"])
    #expect(targets[1].addresses == ["[::1]:3260,1"])
    try await session.logout()
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    let writes = await transport.writes
    #expect(writes.count == 5)
    #expect([UInt8](writes[3]).uint32(at: 20) == 42)
}

@Test func coalescedLoginAndDigestedRead() async throws {
    let policy = DigestPolicy(header: true, data: true)
    let login = try loginFixtures(normal: true, digests: true)
    var wire = login.reduce(Data(), +)
    var capacity = Array(repeating: UInt8(0), count: 32)
    capacity.put(UInt64(1023), at: 0)
    capacity.put(UInt32(512), at: 8)
    wire.append(
        try fixture(
            opcode: 0x25, flags: 0x81, tag: 2, stat: 2, exp: 2,
            data: Data(capacity), digests: policy))
    let transport = ScriptedTransport(
        [wire], gates: [(0, 1), (login[0].count, 2), (login[0].count + login[1].count, 3)])
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    let result = try await session.execute(.readCapacity16(), lun: LogicalUnit(0))
    #expect(try DiskCapacity(readCapacity16: result.data).byteCount == 524_288)
    #expect(await session.state == .ready)
    await session.close()
}

@Test func wrongTaskClosesSession() async throws {
    var data = try loginFixtures(normal: true)
    data.append(try fixture(opcode: 0x21, flags: 0x80, tag: 99, stat: 2, exp: 2))
    let transport = ScriptedTransport(data)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    try await session.login()
    await #expect(throws: ProtocolError.self) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

@Test func failedLoginNeverBecomesReady() async throws {
    let transport = ScriptedTransport([])
    let session = try ISCSISession(transport: transport, configuration: configuration())
    await #expect(throws: ProtocolError.connectionClosed) { try await session.login() }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

private actor SilentTransport: ByteTransport {
    private(set) var isClosed = false
    func send(_ data: Data) async throws {}
    func receive(maximumLength: Int) async throws -> Data {
        try await Task.sleep(for: .seconds(60))
        throw ProtocolError.connectionClosed
    }
    func close() async { isClosed = true }
}

@Test func wholeExchangeDeadlineClosesTransport() async throws {
    let transport = SilentTransport()
    let session = try ISCSISession(
        transport: transport, configuration: configuration(), commandTimeout: .milliseconds(20))
    await #expect(throws: ProtocolError.timedOut) { try await session.login() }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

/// A successful Logout Response can be the last bytes before the peer's TCP FIN.
private actor LogoutEOFTransport: ByteTransport {
    private let inner: ScriptedTransport
    private var remaining: Int
    private(set) var eofReads = 0
    private(set) var isClosed = false

    init(normal: Bool) throws {
        let responses =
            try loginFixtures(normal: normal) + [
                fixture(opcode: 0x26, flags: 0x80, tag: 2, stat: 2)
            ]
        inner = ScriptedTransport(responses)
        remaining = responses.reduce(0) { $0 + $1.count }
    }

    func send(_ data: Data) async throws { try await inner.send(data) }

    func receive(maximumLength: Int) async throws -> Data {
        guard remaining > 0 else {
            eofReads += 1
            throw ProtocolError.connectionClosed
        }
        let data = try await inner.receive(maximumLength: maximumLength)
        remaining -= data.count
        return data
    }

    func close() async {
        isClosed = true
        await inner.close()
    }
}

@Test(arguments: [false, true])
func aSuccessfulLogoutStopsReceivingBeforeThePeersEOF(_ normal: Bool) async throws {
    let transport = try LogoutEOFTransport(normal: normal)
    let session = try ISCSISession(
        transport: transport, configuration: configuration(normal: normal))
    try await session.login()
    try await session.logout()
    #expect(await session.state == .closed)
    #expect(await transport.isClosed)
    #expect(await transport.eofReads == 0)
}
