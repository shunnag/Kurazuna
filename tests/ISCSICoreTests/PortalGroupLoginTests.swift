import Foundation
import Testing

@testable import ISCSICore

private let groupISID: [UInt8] = [0x80, 1, 3, 5, 7, 9]

private func groupResponse(_ flags: UInt8, _ sequence: UInt32, _ data: Data) throws -> PDU {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header[1] = flags
    header.replaceSubrange(8..<14, with: groupISID)
    header.put(UInt16(1), at: 14)
    header.put(UInt32(1), at: 16)
    header.put(sequence, at: 24)
    header.put(UInt32(1), at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data)
}

private func groupMachine(_ authentication: String, normal: Bool = true) throws -> LoginMachine {
    let credentials: CHAPCredentials? =
        authentication == "None"
        ? nil
        : try CHAPCredentials(
            username: "Mac", password: "disposable initiator secret",
            targetUsername: authentication == "Mutual" ? "Server" : nil,
            targetPassword: authentication == "Mutual" ? "disposable target secret" : nil)
    return LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.dev.soba:group-test",
            targetName: normal ? "iqn.2026-10.test:disk" : nil,
            credentials: credentials, isid: groupISID))
}

@Test(arguments: ["None", "CHAP", "Mutual"])
func normalLoginRejectsMissingGroupInFirstLogicalResponse(_ authentication: String) throws {
    var machine = try groupMachine(authentication)
    _ = try machine.start()
    let text = try TextParameters([
        .init("AuthMethod", authentication == "None" ? "None" : "CHAP"),
        .init("TargetAlias", "Storage"),
    ]).encoded()
    #expect(throws: ProtocolError.malformed("target portal group")) {
        try machine.accept(groupResponse(authentication == "None" ? 0x81 : 0, 0, text))
    }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) {
        try machine.accept(groupResponse(0, 1, Data("TargetPortalGroupTag=1\0".utf8)))
    }
}

@Test(arguments: ["None", "CHAP", "Mutual"], ["0", "65535", "0x01", "0bAAE="])
func normalLoginAcceptsDeclaredGroupIncludingZero(_ authentication: String, _ value: String)
    throws
{
    var machine = try groupMachine(authentication)
    _ = try machine.start()
    let text = try TextParameters([
        .init("AuthMethod", authentication == "None" ? "None" : "CHAP"),
        .init("TargetPortalGroupTag", value),
    ]).encoded()
    let next = try #require(
        try machine.accept(groupResponse(authentication == "None" ? 0x81 : 0, 0, text)))
    #expect(
        machine.parameters.targetPortalGroupTag == (value == "65535" ? 65535 : value == "0" ? 0 : 1)
    )
    #expect(try TextParameters(data: next.data).uniqueValue(for: "TargetPortalGroupTag") == nil)
    #expect(next.flags == (authentication == "None" ? 0x87 : 0))
}

@Test(arguments: [false, true])
func firstResponseContinuationIsCheckedAfterReassembly(_ declared: Bool) throws {
    var machine = try groupMachine("None")
    _ = try machine.start()
    let text = Data(
        ("AuthMethod=None\0" + (declared ? "TargetPortalGroupTag=0\0" : "TargetAlias=Storage\0"))
            .utf8)
    let split = text.count - 2
    let acknowledgment = try #require(
        try machine.accept(groupResponse(0x40, 0, text.prefix(split))))
    #expect(acknowledgment.flags == 0x81 && acknowledgment.data.isEmpty)
    if declared {
        let next = try #require(try machine.accept(groupResponse(0x81, 1, text.suffix(2))))
        #expect(next.flags == 0x87 && machine.parameters.targetPortalGroupTag == 0)
    } else {
        #expect(throws: ProtocolError.malformed("target portal group")) {
            try machine.accept(groupResponse(0x81, 1, text.suffix(2)))
        }
    }
}

@Test(arguments: ["None", "CHAP", "Mutual"])
func unnamedDiscoveryDoesNotRequirePortalGroup(_ authentication: String) throws {
    var machine = try groupMachine(authentication, normal: false)
    _ = try machine.start()
    let next = try machine.accept(
        groupResponse(
            authentication == "None" ? 0x81 : 0, 0,
            TextParameters([.init("AuthMethod", authentication == "None" ? "None" : "CHAP")])
                .encoded()))
    #expect(next != nil && machine.parameters.targetPortalGroupTag == nil)
}
