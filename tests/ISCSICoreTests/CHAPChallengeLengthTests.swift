import Foundation
import Testing

@testable import ISCSICore

private func encodedChallenge(_ length: Int, base64: Bool) -> String {
    let bytes = Data((0..<length).map { UInt8(truncatingIfNeeded: $0) })
    return base64
        ? "0b" + bytes.base64EncodedString()
        : "0x" + bytes.map { String(format: "%02x", $0) }.joined()
}

// Independent Python hashlib vectors, including the leading zero challenge octet.
@Test(arguments: [1, 15, 16, 32, 1024], [false, true])
func chapChallengeLengthUsesDecodedOctets(_ length: Int, _ base64: Bool) throws {
    let expected = [
        1: "e730f2beb4a5a8cf6ef8552e2b802b42",
        15: "a31d048785a95ad10eec26685bae6f06",
        16: "085eb3bac66ae1a2853ecc51569a2b6d",
        32: "ab7addaffd54bbe1ef56649896b45785",
        1024: "65b78f74cdac501d15571684c992b732",
    ]
    #expect(
        try CHAP.response(
            identifier: 7, secret: "Alpha0123456789Az",
            challenge: encodedChallenge(length, base64: base64)) == "0x" + expected[length]!)
}

@Test(arguments: [0, 1025], [false, true])
func chapChallengeRejectsEmptyAndOversizedDecodedValues(_ length: Int, _ base64: Bool) {
    #expect(throws: ProtocolError.malformed("CHAP challenge length")) {
        try CHAP.response(
            identifier: 7, secret: "Alpha0123456789Az",
            challenge: encodedChallenge(length, base64: base64))
    }
}

private let boundaryISID: [UInt8] = [0x80, 9, 8, 7, 6, 5]

private func boundaryReply(_ flags: UInt8, _ sequence: UInt32, data: Data) throws -> PDU {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x23
    header[1] = flags
    header.replaceSubrange(8..<14, with: boundaryISID)
    header.put(UInt16(flags == 0x87 ? 7 : 0), at: 14)
    header.put(UInt32(1), at: 16)
    header.put(sequence, at: 24)
    header.put(UInt32(1), at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data)
}

private func boundaryMachine(normal: Bool) throws -> LoginMachine {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:chap-boundary",
            targetName: normal ? "iqn.2026-10.test:disk" : nil,
            credentials: CHAPCredentials(username: "Mac", password: "Alpha0123456789Az"),
            isid: boundaryISID))
    _ = try machine.start()
    var entries: [TextParameters.Entry] = [.init("AuthMethod", "CHAP")]
    if normal { entries.append(.init("TargetPortalGroupTag", "1")) }
    _ = try machine.accept(boundaryReply(0, 0, data: TextParameters(entries).encoded()))
    return machine
}

@Test(arguments: [1, 1024], [0, 1, 2, 3])
func chapIncomingBoundaryCompletesDiscoveryAndNormalLogin(
    _ length: Int, _ variant: Int
) throws {
    let base64 = variant & 1 != 0
    let normal = variant & 2 != 0
    var machine = try boundaryMachine(normal: normal)
    let challenge = try TextParameters([
        .init("CHAP_A", "5"), .init("CHAP_I", "7"),
        .init("CHAP_C", encodedChallenge(length, base64: base64)),
    ]).encoded()
    // Split inside the binary value; the completed logical value determines the length.
    let split = min(challenge.count - 1, 45)
    _ = try machine.accept(boundaryReply(0x40, 1, data: Data(challenge.prefix(split))))
    let answer = try #require(
        try machine.accept(boundaryReply(0, 2, data: Data(challenge.dropFirst(split)))))
    let text = try TextParameters(data: answer.data)
    #expect(try text.uniqueValue(for: "CHAP_N") == "Mac")
    #expect(
        try text.uniqueValue(for: "CHAP_R")
            == "0x"
            + (length == 1
                ? "e730f2beb4a5a8cf6ef8552e2b802b42" : "65b78f74cdac501d15571684c992b732"))
    let offer = try #require(try machine.accept(boundaryReply(0x81, 3, data: Data())))
    let selected = try TextParameters(data: offer.data).entries.map {
        ["HeaderDigest", "DataDigest"].contains($0.key) ? TextParameters.Entry($0.key, "None") : $0
    }
    #expect(
        try machine.accept(boundaryReply(0x87, 4, data: TextParameters(selected).encoded())) == nil)
    #expect(machine.isComplete)
}

@Test(arguments: [0, 1025], [false, true])
func chapIncomingInvalidLengthPermanentlyFailsLogin(_ length: Int, _ base64: Bool) throws {
    var machine = try boundaryMachine(normal: true)
    let challenge = try TextParameters([
        .init("CHAP_A", "5"), .init("CHAP_I", "7"),
        .init("CHAP_C", encodedChallenge(length, base64: base64)),
    ]).encoded()
    #expect(throws: ProtocolError.malformed("CHAP challenge length")) {
        try machine.accept(boundaryReply(0, 1, data: challenge))
    }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) {
        try machine.accept(boundaryReply(0x81, 2, data: Data()))
    }
}
