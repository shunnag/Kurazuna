import CryptoKit
import Foundation
import Testing

@testable import ISCSICore

private let mutualISID: [UInt8] = [0x80, 5, 4, 3, 2, 1]
private let initiatorSecret = "initiator disposable secret"
private let targetSecret = "target disposable secret"

private func mutualResponse(
    _ flags: UInt8, _ sequence: UInt32, _ entries: [TextParameters.Entry] = [], data: Data? = nil
) throws -> PDU {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x23
    header[1] = flags
    header.replaceSubrange(8..<14, with: mutualISID)
    header.put(UInt16(1), at: 14)
    header.put(UInt32(1), at: 16)
    header.put(sequence, at: 24)
    header.put(UInt32(1), at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data ?? TextParameters(entries).encoded())
}

private func mutualExchange(peerLength: Int = 16) throws -> (LoginMachine, UInt8, String) {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
            credentials: CHAPCredentials(
                username: "Mac", password: initiatorSecret,
                targetUsername: "Server", targetPassword: targetSecret), isid: mutualISID))
    _ = try machine.start()
    _ = try machine.accept(
        mutualResponse(0, 0, [.init("AuthMethod", "CHAP"), .init("TargetPortalGroupTag", "1")]))
    let next = try machine.accept(
        mutualResponse(
            0, 1,
            [
                .init("CHAP_A", "5"), .init("CHAP_I", "7"),
                .init(
                    "CHAP_C",
                    "0x"
                        + (0..<peerLength).map {
                            String(format: "%02x", UInt8(truncatingIfNeeded: $0))
                        }
                        .joined()),
            ]))
    let answer = try #require(next)
    let text = try TextParameters(data: answer.data)
    let identifier = try #require(try text.uniqueValue(for: "CHAP_I").flatMap(UInt8.init))
    let challenge = try #require(try text.uniqueValue(for: "CHAP_C"))
    #expect(answer.flags == 0x81)
    #expect(try CHAP.decodeBinary(challenge).count == 32)
    #expect(try text.uniqueValue(for: "CHAP_N") == "Mac")
    return (machine, identifier, challenge)
}

private func proof(_ identifier: UInt8, _ challenge: String, secret: String = targetSecret) throws
    -> Data
{
    var input = Data([identifier])
    input.append(contentsOf: secret.utf8)
    input.append(try CHAP.decodeBinary(challenge))
    return Data(Insecure.MD5.hash(data: input))
}

@Test(arguments: [false, true])
func targetProofIsBoundToItsIdentifierAndChallenge(_ changedIdentifier: Bool) throws {
    let challenge = "0x" + String(repeating: "00", count: 32)
    let previous = try proof(7, challenge)
    let text = "0x" + previous.map { String(format: "%02x", $0) }.joined()
    let credentials = try CHAPCredentials(
        username: "Mac", password: initiatorSecret,
        targetUsername: "Server", targetPassword: targetSecret)
    #expect(throws: ProtocolError.authenticationFailed) {
        try credentials.verifyTarget(
            username: "Server", response: text,
            identifier: changedIdentifier ? 8 : 7,
            challenge: changedIdentifier ? challenge : "0x" + String(repeating: "01", count: 32))
    }
}

@Test(arguments: [1, 16, 1024], [0, 1, 2, 3])
func mutualCHAPAcceptsTargetProofBeforeTheSecurityTransition(
    _ peerLength: Int, _ variant: Int
) throws {
    let split = variant & 1 != 0
    let base64 = variant & 2 != 0
    var (machine, identifier, challenge) = try mutualExchange(peerLength: peerLength)
    let bytes = try proof(identifier, challenge)
    let value =
        base64
        ? "0b" + bytes.base64EncodedString()
        : "0X" + bytes.map { String(format: "%02X", $0) }.joined()
    let data = try TextParameters([.init("CHAP_N", "Server"), .init("CHAP_R", value)]).encoded()
    var sequence: UInt32 = 2
    if split {
        _ = try machine.accept(mutualResponse(0x40, sequence, data: Data(data.prefix(11))))
        sequence += 1
        _ = try machine.accept(mutualResponse(0, sequence, data: Data(data.dropFirst(11))))
        sequence += 1
    }
    let next = try machine.accept(mutualResponse(0x81, sequence, data: split ? Data() : data))
    let offer = try #require(next)
    sequence += 1
    let selected = try TextParameters(data: offer.data).entries.map {
        ["HeaderDigest", "DataDigest"].contains($0.key) ? TextParameters.Entry($0.key, "None") : $0
    }
    #expect(try machine.accept(mutualResponse(0x87, sequence, selected)) == nil)
    #expect(machine.isComplete)
}

@Test(arguments: [1, 16])
func mutualCHAPRejectsMissingTargetProof(_ peerLength: Int) throws {
    var (machine, _, _) = try mutualExchange(peerLength: peerLength)
    #expect(throws: ProtocolError.authenticationFailed) {
        try machine.accept(mutualResponse(0x81, 2))
    }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) { try machine.accept(mutualResponse(0x81, 3)) }
}

@Test(arguments: ["name", "digest", "own-secret", "length", "encoding", "half"], [1, 16])
func mutualCHAPRejectsInvalidTargetProof(_ fault: String, _ peerLength: Int) throws {
    var (machine, identifier, challenge) = try mutualExchange(peerLength: peerLength)
    var bytes = try proof(
        identifier, challenge, secret: fault == "own-secret" ? initiatorSecret : targetSecret)
    if fault == "digest" { bytes[0] ^= 1 }
    if fault == "length" { bytes.removeLast() }
    let value =
        fault == "encoding" ? "0xzz" : "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    var entries: [TextParameters.Entry] = [.init("CHAP_N", fault == "name" ? "Other" : "Server")]
    if fault != "half" { entries.append(.init("CHAP_R", value)) }
    #expect(throws: ProtocolError.authenticationFailed) {
        try machine.accept(mutualResponse(0x81, 2, entries))
    }
    #expect(!machine.isComplete)
}

@Test(arguments: ["missing-name", "missing-secret", "same-secret", "short", "control"])
func mutualCHAPRequiresCompleteDistinctCredentials(_ fault: String) {
    #expect(throws: ProtocolError.self) {
        try CHAPCredentials(
            username: "Mac", password: initiatorSecret,
            targetUsername: fault == "missing-name" ? nil : fault == "control" ? "\n" : "Server",
            targetPassword: fault == "missing-secret"
                ? nil
                : fault == "same-secret"
                    ? initiatorSecret : fault == "short" ? "short" : targetSecret)
    }
}
