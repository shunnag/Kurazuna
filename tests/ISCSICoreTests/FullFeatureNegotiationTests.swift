import Foundation
import Testing

@testable import ISCSICore

private func textReply(
    _ text: String = "", flags: UInt8 = 0, transfer: UInt32 = 91, tag: UInt32 = 17,
    lun: [UInt8] = [0, 2, 0, 0, 0, 0, 0, 0]
) throws -> PDU {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x24
    header[1] = flags
    header.replaceSubrange(8..<16, with: lun)
    header.put(tag, at: 16)
    header.put(transfer, at: 20)
    return try PDU(header: header, data: Data(text.utf8))
}

@Test func fullFeatureDeclarationsCommitOnlyAfterTheFinalExchange() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    let start = try machine.start()
    #expect(start.header[0] == 0x44 && start.flags == 0x80 && start.data.isEmpty)
    #expect(start.taskTag == 17 && start.transferTag == UInt32.max)
    let proposalReply = try machine.accept(
        textReply("MaxRecvDataSegmentLength=512\0TargetAlias=保存先\0"))
    let next = try #require(proposalReply)
    #expect(!machine.isComplete && next.data.isEmpty)
    #expect(next.transferTag == 91 && Array(next.header[8..<16]) == [0, 2, 0, 0, 0, 0, 0, 0])
    #expect(try machine.accept(textReply(flags: 0x80, transfer: .max)) == nil)
    #expect(machine.isComplete && machine.changes.targetReceiveSegmentLength == 512)
    #expect(machine.changes.targetAlias == "保存先")
}

@Test func fullFeatureUnknownAndObsoleteKeysReceiveExplicitAnswers() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    let proposalReply = try machine.accept(
        textReply("X-dev.soba.unknown=Yes\0IFMarker=Yes\0OFMarkInt=1~100\0"))
    let next = try #require(proposalReply)
    #expect(
        try TextParameters(data: next.data).entries == [
            .init("X-dev.soba.unknown", "NotUnderstood"), .init("IFMarker", "Reject"),
            .init("OFMarkInt", "Reject"),
        ])
    #expect(try machine.accept(textReply(flags: 0x80, transfer: .max)) == nil)
}

@Test func targetTextCanSplitInsideAUTF8ValueAndChangeItsContinuationHandle() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    let bytes = Data("TargetAlias=保存先\0".utf8)
    var first = try textReply(flags: 0x7F)
    first = try PDU(header: first.header, data: Data(bytes.prefix(13)))
    #expect(try machine.accept(first)?.data.isEmpty == true)
    let last = try textReply(flags: 0xBF, transfer: .max)
    #expect(try machine.accept(PDU(header: last.header, data: Data(bytes.dropFirst(13)))) == nil)
    #expect(machine.changes.targetAlias == "保存先")
}

@Test func largeTextAnswersAreFragmentedAndEachContinuationIsAcknowledged() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 512)
    _ = try machine.start()
    let text = (0..<40).map { "X-dev.soba.test\($0)=Yes\0" }.joined()
    let proposalReply = try machine.accept(textReply(text))
    var request = try #require(proposalReply)
    var bytes = Data()
    while true {
        #expect(request.data.count <= 512 && request.taskTag == 17 && request.transferTag == 91)
        bytes.append(request.data)
        if request.flags == 0x80 { break }
        #expect(request.flags == 0x40)
        let next = try machine.accept(textReply())
        request = try #require(next)
    }
    #expect(try TextParameters(data: bytes).entries.count == 40)
    #expect(try machine.accept(textReply(flags: 0x80, transfer: .max)) == nil)
}

@Test(arguments: [
    "HeaderDigest=None\0", "InitialR2T=No\0", "AuthMethod=None\0", "CHAP_N=changed\0",
    "TargetName=iqn.2026-10.test:other\0", "InitiatorAlias=other\0",
    "MaxRecvDataSegmentLength=511\0", "MaxRecvDataSegmentLength=Reject\0",
    "TargetAlias=one\0TargetAlias=two\0", "X-dev.soba.key=NotUnderstood\0",
])
func invalidFullFeatureProposalsCannotChangeTheConnection(_ text: String) throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    #expect(throws: (any Error).self) { try machine.accept(textReply(text)) }
    #expect(!machine.isComplete)
}

@Test(arguments: [0xC0, 0x80, 0x00])
func invalidTextFinalFlagsAndTransferTagsAreRejected(_ flags: UInt8) throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    let tag: UInt32 = flags == 0 ? .max : 91
    #expect(throws: (any Error).self) { try machine.accept(textReply(flags: flags, transfer: tag)) }
}

@Test func aFinalTextResponseCannotProposeAKeyThatNeedsAnAnswer() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    #expect(throws: (any Error).self) {
        try machine.accept(textReply("X-dev.soba.key=Yes\0", flags: 0x80, transfer: .max))
    }
    #expect(!machine.isComplete)
}

@Test func textNegotiationAllowsSixExchangesButHasAFixedResourceLimit() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    for _ in 0..<255 { #expect(try machine.accept(textReply()) != nil) }
    #expect(throws: ProtocolError.limitExceeded("Text negotiation exchanges")) {
        try machine.accept(textReply())
    }
}

@Test func resettingATextSequenceDiscardsAllAbandonedDeclarations() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    _ = try machine.accept(textReply("MaxRecvDataSegmentLength=512\0TargetAlias=Abandoned\0"))
    let restarted = try machine.reset()
    #expect(restarted.taskTag == 17 && restarted.transferTag == .max && restarted.data.isEmpty)
    #expect(machine.changes.targetAlias == nil && machine.changes.targetReceiveSegmentLength == nil)
    #expect(
        try machine.accept(
            textReply(
                "MaxRecvDataSegmentLength=1024\0TargetAlias=Accepted\0", flags: 0x80, transfer: .max
            )) == nil)
    #expect(machine.isComplete && machine.changes.targetReceiveSegmentLength == 1024)
    #expect(machine.changes.targetAlias == "Accepted")
}

@Test func resettingTextNeverResetsItsExchangeBudget() throws {
    var machine = try FullFeatureNegotiation(taskTag: 17, maximumSegmentLength: 8192)
    _ = try machine.start()
    for _ in 0..<255 { _ = try machine.reset() }
    #expect(throws: ProtocolError.limitExceeded("Text negotiation exchanges")) {
        try machine.reset()
    }
}
