import Foundation
import Testing

@testable import ISCSICore

private let redirectISID: [UInt8] = [0x80, 1, 2, 3, 4, 5]

private func redirectReply(
    status: UInt8 = 1, detail: UInt8 = 1, entries: [TextParameters.Entry], tag: UInt32 = 1
) throws -> PDU {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header[1] = 0xFF
    header[3] = 0xFF
    header.replaceSubrange(8..<14, with: redirectISID)
    header.put(tag, at: 16)
    header.put(UInt32.max, at: 28)
    header[36] = status
    header[37] = detail
    return try PDU(header: header, data: TextParameters(entries).encoded())
}

@Test(arguments: [
    ("nas.local", "nas.local", UInt16(3260), nil as UInt16?),
    ("127.0.0.1:3261", "127.0.0.1", UInt16(3261), nil),
    ("[::1]:0xCBC,0x02", "::1", UInt16(3260), UInt16(2)),
    ("[2001:db8::1]:0bDLw=", "2001:db8::1", UInt16(3260), nil),
])
func targetAddressParsesBinaryPortsAndOptionalGroup(_ input: (String, String, UInt16, UInt16?))
    throws
{
    let value = try TargetAddress(input.0)
    let expected = try Portal(host: input.1, port: input.2)
    #expect(value.portal == expected)
    #expect(value.portalGroupTag == input.3)
}

@Test(arguments: [
    "", "host:0", "host:65536", "host:+3260", "host:0xZZ", "host:0b", "host:0bAQID", "host,",
    "host,1,2", "user@host", "host/path", "::1", "[::1", "[::1]suffix",
])
func targetAddressRejectsMalformedEndpoints(_ input: String) {
    #expect(throws: ProtocolError.self) { try TargetAddress(input) }
}

@Test(arguments: [UInt8(1), UInt8(2)])
func loginReturnsTypedRedirectWithoutUsingSuccessOnlyFields(_ detail: UInt8) throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:redirect", targetName: "iqn.2026-10.test:disk",
            isid: redirectISID))
    _ = try machine.start()
    let expected = try LoginRedirect(
        kind: #require(LoginRedirect.Kind(rawValue: detail)),
        addresses: [Portal("nas.local"), Portal("[::1]:3261")])
    #expect(throws: ProtocolError.loginRedirect(expected)) {
        try machine.accept(
            redirectReply(
                detail: detail,
                entries: [
                    .init("TargetAddress", "nas.local"), .init("TargetAddress", "[::1]:3261"),
                    .init("AuthMethod", "None"),
                ]))
    }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) {
        try machine.accept(redirectReply(entries: [.init("TargetAddress", "other.local")]))
    }
}

@Test(
    arguments: [[], [.init("AuthMethod", "None")], [.init("TargetAddress", "host,1")]]
        as [[TextParameters.Entry]])
func redirectRequiresAddressesWithoutPortalGroup(_ entries: [TextParameters.Entry]) throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:redirect", isid: redirectISID))
    _ = try machine.start()
    #expect(throws: ProtocolError.self) { try machine.accept(redirectReply(entries: entries)) }
}

@Test func redirectListAndResponseIdentityAreBounded() throws {
    let configuration = try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:redirect", isid: redirectISID)
    var oversized = LoginMachine(configuration: configuration)
    _ = try oversized.start()
    #expect(throws: ProtocolError.limitExceeded("login redirect addresses")) {
        try oversized.accept(
            redirectReply(entries: Array(repeating: .init("TargetAddress", "host"), count: 17)))
    }
    var wrongTag = LoginMachine(configuration: configuration)
    _ = try wrongTag.start()
    #expect(throws: ProtocolError.malformed("login response identity")) {
        try wrongTag.accept(redirectReply(entries: [.init("TargetAddress", "host")], tag: 2))
    }
}

@Test(arguments: [(UInt8(1), UInt8(3)), (UInt8(2), UInt8(1)), (UInt8(3), UInt8(1))])
func otherLoginFailuresDoNotBecomeRedirects(_ status: (UInt8, UInt8)) throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:redirect", isid: redirectISID))
    _ = try machine.start()
    #expect(throws: ProtocolError.loginRejected(statusClass: status.0, detail: status.1)) {
        try machine.accept(
            redirectReply(
                status: status.0, detail: status.1,
                entries: [.init("TargetAddress", "host")]))
    }
}

/// Linux LIO (`iscsit_tx_login_rsp`) zeroes the whole header of a login rejection except the
/// opcode, the status and the initiator task tag: its ISID is all zero. Captured from LIO on
/// Linux 6.12 for an unknown target name (0301), a missing ACL (0202) and missing CHAP
/// credentials (0201); see scripts/test-lio-recovery.py R4-staged and R4-auth.
private func lioRejection(status: UInt8, detail: UInt8, isid: [UInt8] = [0, 0, 0, 0, 0, 0])
    throws -> PDU
{
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header.replaceSubrange(8..<14, with: isid)
    header.put(UInt32(1), at: 16)
    header[36] = status
    header[37] = detail
    return try PDU(header: header, data: Data())
}

@Test(arguments: [(UInt8(3), UInt8(1)), (2, 1), (2, 2), (2, 3), (3, 0)])
func aRejectionWithoutTheISIDEchoIsStillARejection(_ status: (UInt8, UInt8)) throws {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:redirect", targetName: "iqn.2026-10.test:disk",
            isid: redirectISID))
    _ = try machine.start()
    #expect(throws: ProtocolError.loginRejected(statusClass: status.0, detail: status.1)) {
        try machine.accept(lioRejection(status: status.0, detail: status.1))
    }
}

@Test func aRejectionNamingAnotherSessionOrTaskIsMalformed() throws {
    let configuration = try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:redirect", targetName: "iqn.2026-10.test:disk",
        isid: redirectISID)
    var otherSession = LoginMachine(configuration: configuration)
    _ = try otherSession.start()
    #expect(throws: ProtocolError.malformed("login response identity")) {
        try otherSession.accept(lioRejection(status: 3, detail: 1, isid: [0x80, 9, 9, 9, 9, 9]))
    }
    var otherTask = LoginMachine(configuration: configuration)
    _ = try otherTask.start()
    var header = try lioRejection(status: 3, detail: 1).header
    header.put(UInt32(2), at: 16)
    #expect(throws: ProtocolError.malformed("login response identity")) {
        try otherTask.accept(PDU(header: header, data: Data()))
    }
}
