import Foundation
import Testing

@testable import ISCSICore

private let testISID: [UInt8] = [0x80, 1, 2, 3, 4, 5]

private func loginResponse(
    flags: UInt8, sequence: UInt32, entries: [TextParameters.Entry] = [], data: Data? = nil,
    expectedCommand: UInt32 = 1, maximumCommand: UInt32? = nil
) throws -> PDU {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x23
    header[1] = flags
    header.replaceSubrange(8..<14, with: testISID)
    header.put(UInt16(1), at: 14)
    header.put(UInt32(1), at: 16)
    header.put(sequence, at: 24)
    header.put(expectedCommand, at: 28)
    header.put(maximumCommand ?? expectedCommand &+ 31, at: 32)
    return try PDU(header: header, data: data ?? TextParameters(entries).encoded())
}

@Test func discoveryLoginAndDigestSelection() throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", isid: testISID))
    let first = try machine.start()
    #expect(first.header[0] == 0x43)
    #expect(first.flags == 0x81)
    let operationalResponse = try machine.accept(
        loginResponse(flags: 0x81, sequence: 50, entries: [.init("AuthMethod", "None")]))
    let operational = try #require(operationalResponse)
    #expect(operational.flags == 0x87)
    #expect(try TextParameters(data: operational.data).uniqueValue(for: "InitialR2T") == nil)
    let final = try machine.accept(
        loginResponse(
            flags: 0x87, sequence: 51,
            entries: [
                .init("HeaderDigest", "CRC32C"), .init("DataDigest", "None"),
                .init("MaxRecvDataSegmentLength", "512"),
            ]))
    #expect(final == nil)
    #expect(machine.isComplete)
    #expect(machine.parameters.digests == DigestPolicy(header: true, data: false))
    #expect(machine.parameters.expectedStatusSequenceNumber == 52)
}

@Test func loginContinuationMaySplitAKey() throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", isid: testISID))
    _ = try machine.start()
    let acknowledgment = try machine.accept(
        loginResponse(flags: 0x40, sequence: 0, data: Data("AuthMeth".utf8)))
    #expect(acknowledgment?.flags == 0x81)
    let next = try machine.accept(
        loginResponse(flags: 0x81, sequence: 1, data: Data("od=None\0".utf8)))
    #expect(next?.flags == 0x87)
}

@Test func chapCannotDowngradeToNone() throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator",
            credentials: CHAPCredentials(username: "name", password: "twelve-bytes-or-more"),
            isid: testISID))
    let first = try machine.start()
    #expect(first.flags == 0)
    #expect(throws: ProtocolError.self) {
        try machine.accept(
            loginResponse(flags: 0x81, sequence: 0, entries: [.init("AuthMethod", "None")]))
    }
    #expect(throws: ProtocolError.invalidState) {
        try machine.accept(loginResponse(flags: 0x81, sequence: 1))
    }
}

@Test func chapSecurityExchange() throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator",
            credentials: CHAPCredentials(
                username: "name", password: "correct horse battery staple"), isid: testISID))
    _ = try machine.start()
    let algorithmResponse = try machine.accept(
        loginResponse(flags: 0, sequence: 0, entries: [.init("AuthMethod", "CHAP")]))
    let algorithm = try #require(algorithmResponse)
    #expect(try TextParameters(data: algorithm.data).uniqueValue(for: "CHAP_A") == "5")
    let answerResponse = try machine.accept(
        loginResponse(
            flags: 0, sequence: 1,
            entries: [
                .init("CHAP_A", "5"), .init("CHAP_I", "7"),
                .init("CHAP_C", "0x000102030405060708090a0b0c0d0e0f"),
            ]))
    let answer = try #require(answerResponse)
    #expect(answer.flags == 0x81)
    #expect(
        try TextParameters(data: answer.data).uniqueValue(for: "CHAP_R")
            == "0x4743b2bd34fa732295d209c4eb4dfc7b")
    #expect(try machine.accept(loginResponse(flags: 0x81, sequence: 2))?.flags == 0x87)
}

@Test func missingDigestAnswerAndOutOfOrderStatusRejected() throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", isid: testISID))
    _ = try machine.start()
    _ = try machine.accept(
        loginResponse(flags: 0x81, sequence: 0, entries: [.init("AuthMethod", "None")]))
    #expect(throws: ProtocolError.self) {
        try machine.accept(
            loginResponse(flags: 0x87, sequence: 1, entries: [.init("HeaderDigest", "None")]))
    }
    var other = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", isid: testISID))
    _ = try other.start()
    _ = try other.accept(
        loginResponse(flags: 0x81, sequence: UInt32.max, entries: [.init("AuthMethod", "None")]))
    #expect(throws: ProtocolError.self) {
        try other.accept(loginResponse(flags: 0x87, sequence: 1))
    }
}

@Test(arguments: [UInt32(0), UInt32.max - 1, UInt32.max], [false, true])
func loginUsesItsChosenCommandNumberAcrossAStatusWrap(_ start: UInt32, _ closed: Bool) throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", isid: testISID,
            initialCommandSequenceNumber: start))
    let maximum = closed ? start &- 1 : start &+ 31
    #expect(try machine.start().header.uint32(at: 24) == start)
    let response = try machine.accept(
        loginResponse(
            flags: 0x81, sequence: .max, entries: [.init("AuthMethod", "None")],
            expectedCommand: start, maximumCommand: maximum))
    let operational = try #require(response)
    #expect(operational.header.uint32(at: 24) == start)
    #expect(operational.header.uint32(at: 28) == 0)
    #expect(
        try machine.accept(
            loginResponse(
                flags: 0x87, sequence: 0,
                entries: [.init("HeaderDigest", "None"), .init("DataDigest", "None")],
                expectedCommand: start, maximumCommand: maximum)) == nil)
    #expect(machine.isComplete)
    #expect(machine.parameters.commandSequenceNumber == start)
    #expect(machine.parameters.expectedCommandSequenceNumber == start)
    #expect(machine.parameters.maximumCommandSequenceNumber == maximum)
    #expect(machine.parameters.expectedStatusSequenceNumber == 1)
}

@Test(arguments: [UInt32(0), UInt32.max - 1, UInt32.max])
func aLoginResponseCannotChangeTheChosenCommandNumberOrAdvertiseAnInvalidWindow(_ start: UInt32)
    throws
{
    for (expected, maximum) in [(start &+ 1, start &+ 32), (start, start &- 2)] {
        var machine = LoginMachine(
            configuration: try LoginConfiguration(
                initiatorName: "iqn.2026-10.test:initiator", isid: testISID,
                initialCommandSequenceNumber: start))
        _ = try machine.start()
        #expect(throws: ProtocolError.malformed("initial command window")) {
            try machine.accept(
                loginResponse(
                    flags: 0x81, sequence: 0, entries: [.init("AuthMethod", "None")],
                    expectedCommand: expected, maximumCommand: maximum))
        }
        #expect(!machine.isComplete)
    }
}
