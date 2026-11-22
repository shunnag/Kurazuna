import Foundation
import Testing

@testable import ISCSICore

private let negotiationISID: [UInt8] = [0x80, 6, 7, 8, 9, 10]

private func response(
    _ flags: UInt8, _ sequence: UInt32,
    _ entries: [TextParameters.Entry] = [], data: Data? = nil
) throws -> PDU {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x23
    header[1] = flags
    header.replaceSubrange(8..<14, with: negotiationISID)
    header.put(UInt16(1), at: 14)
    header.put(UInt32(1), at: 16)
    header.put(sequence, at: 24)
    header.put(UInt32(1), at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data ?? TextParameters(entries).encoded())
}

private func begin(normal: Bool = true, metadata: [TextParameters.Entry] = []) throws -> (
    LoginMachine, [TextParameters.Entry]
) {
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator",
            targetName: normal ? "iqn.2026-10.test:disk" : nil,
            isid: negotiationISID))
    _ = try machine.start()
    let group: [TextParameters.Entry] =
        normal && !metadata.contains(where: { $0.key == "TargetPortalGroupTag" })
        ? [.init("TargetPortalGroupTag", "1")] : []
    let requestValue = try machine.accept(
        response(0x81, 0, [.init("AuthMethod", "None")] + group + metadata))
    let request = try #require(requestValue)
    let entries = try TextParameters(data: request.data).entries.map {
        ["HeaderDigest", "DataDigest"].contains($0.key)
            ? TextParameters.Entry($0.key, "CRC32C") : $0
    }
    return (machine, entries)
}

private func replacing(_ entries: [TextParameters.Entry], _ key: String, _ value: String)
    -> [TextParameters.Entry]
{
    entries.map { $0.key == key ? .init(key, value) : $0 }
}

@Test func loginKeyLimitSpansSeparateTextSequences() throws {
    var negotiation = LoginNegotiation(normal: false, receiveLength: 8192)
    var parameters = SessionParameters()
    for offset in stride(from: 0, to: TextParameters.maximumEntryCount, by: 256) {
        let entries = (offset..<(offset + 256)).map { TextParameters.Entry("Future\($0)", "1") }
        let replies = try negotiation.accept(entries, security: false, parameters: &parameters)
        #expect(replies.count == 256)
    }
    #expect(throws: ProtocolError.limitExceeded("login negotiation keys")) {
        try negotiation.accept([.init("OneTooMany", "1")], security: false, parameters: &parameters)
    }
}

@Test func loginEntryLimitAlsoAppliesToContinuedOperationalText() throws {
    var (machine, _) = try begin()
    let bytes = Data(String(repeating: "a=\0", count: TextParameters.maximumEntryCount + 1).utf8)
    var sequence: UInt32 = 1
    for offset in stride(from: 0, to: bytes.count, by: 8192) {
        let final = offset + 8192 >= bytes.count
        let fragment = Data(bytes.dropFirst(offset).prefix(8192))
        if final {
            #expect(throws: ProtocolError.limitExceeded("text entries")) {
                try machine.accept(response(0x04, sequence, data: fragment))
            }
        } else {
            #expect(
                try machine.accept(response(0x44, sequence, data: fragment))?.data.isEmpty == true)
        }
        sequence += 1
    }
    #expect(!machine.isComplete)
}

@Test(arguments: 0..<16)
func determinedBooleanAnswersMayBeOmitted(mask: Int) throws {
    let optional = ["InitialR2T", "ImmediateData", "DataPDUInOrder", "DataSequenceInOrder"]
    let omitted = Set(
        optional.enumerated().compactMap { mask & (1 << $0.offset) != 0 ? $0.element : nil })
    var (machine, entries) = try begin()
    entries.removeAll { omitted.contains($0.key) }
    #expect(try machine.accept(response(0x87, 1, entries)) == nil)
    #expect(
        machine.isComplete && machine.parameters.digests == DigestPolicy(header: true, data: true))
}

@Test(arguments: [
    "HeaderDigest", "DataDigest", "MaxConnections", "MaxBurstLength", "FirstBurstLength",
    "MaxOutstandingR2T", "ErrorRecoveryLevel", "DefaultTime2Wait", "DefaultTime2Retain",
])
func otherNegotiationAnswersRemainRequired(key: String) throws {
    var (machine, entries) = try begin()
    entries.removeAll { $0.key == key }
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x87, 1, entries)) }
    #expect(!machine.isComplete)
}

@Test func irrelevantFirstBurstAllowsSmallerSolicitedBursts() throws {
    var (machine, entries) = try begin()
    entries = replacing(entries, "FirstBurstLength", "Irrelevant")
    entries = replacing(entries, "MaxBurstLength", "1024")
    #expect(try machine.accept(response(0x87, 1, entries)) == nil)
    #expect(machine.isComplete && machine.parameters.maximumBurstLength == 1024)
}

@Test func targetProposalsGetAnswersAndDeclarationsAreNotEchoed() throws {
    var (machine, entries) = try begin(metadata: [
        .init("TargetAlias", "Archive"), .init("TargetPortalGroupTag", "0b//8="),
    ])
    entries += [
        .init("X-com.example.feature", "Enabled"), .init("IFMarker", "Yes"),
        .init("OFMarker", "No"),
        .init("IFMarkInt", "2048~4096"), .init("OFMarkInt", "4096~8192"),
        .init("TaskReporting", "FastAbort,ResponseFence,RFC3720"), .init("iSCSIProtocolLevel", "2"),
        .init("X#NodeArchitecture", "Disposable target/1.0"),
        .init("TargetAddress", "nas.local:0xCBC,1"), .init("TargetAddress", "[::1]:0bDLw=,0x02"),
    ]
    let acknowledgmentValue = try machine.accept(response(0x04, 1, entries))
    let acknowledgment = try #require(acknowledgmentValue)
    #expect(acknowledgment.flags == 0x87)
    #expect(
        try TextParameters(data: acknowledgment.data).entries == [
            .init("X-com.example.feature", "NotUnderstood"), .init("IFMarker", "Reject"),
            .init("OFMarker", "Reject"),
            .init("IFMarkInt", "Reject"), .init("OFMarkInt", "Reject"),
            .init("TaskReporting", "RFC3720"),
            .init("iSCSIProtocolLevel", "0"),
        ])
    #expect(try machine.accept(response(0x87, 2)) == nil)
    #expect(machine.parameters.targetAlias == "Archive")
    #expect(machine.parameters.targetPortalGroupTag == 65_535)
}

@Test func discoveryProposalsUseSessionRulesAndKeepIndependentReceiveLimits() throws {
    var (machine, entries) = try begin(normal: false)
    entries = replacing(entries, "MaxRecvDataSegmentLength", "0x200")
    entries += [
        .init("InitialR2T", "No"), .init("ImmediateData", "Yes"), .init("MaxConnections", "8"),
        .init("FirstBurstLength", "65536"), .init("TaskReporting", "RFC3720,ResponseFence"),
        .init("iSCSIProtocolLevel", "2"), .init("DefaultTime2Wait", "20"),
        .init("DefaultTime2Retain", "20"), .init("ErrorRecoveryLevel", "2"),
    ]
    let acknowledgmentValue = try machine.accept(response(0x04, 1, entries))
    let acknowledgment = try #require(acknowledgmentValue)
    let answers = try TextParameters(data: acknowledgment.data)
    #expect(try answers.uniqueValue(for: "InitialR2T") == "Irrelevant")
    #expect(try answers.uniqueValue(for: "MaxConnections") == "Irrelevant")
    #expect(try answers.uniqueValue(for: "iSCSIProtocolLevel") == "Irrelevant")
    #expect(try answers.uniqueValue(for: "DefaultTime2Wait") == "20")
    #expect(try answers.uniqueValue(for: "DefaultTime2Retain") == "0")
    #expect(try answers.uniqueValue(for: "ErrorRecoveryLevel") == "0")
    #expect(try answers.uniqueValue(for: "MaxRecvDataSegmentLength") == nil)
    #expect(machine.parameters.targetReceiveSegmentLength == 512)
    #expect(try machine.accept(response(0x87, 2)) == nil)
}

@Test(arguments: [
    "HeaderDigest", "DataDigest", "MaxConnections", "InitialR2T", "MaxBurstLength",
    "FirstBurstLength",
    "MaxOutstandingR2T", "DataPDUInOrder", "DataSequenceInOrder", "ErrorRecoveryLevel",
    "DefaultTime2Wait",
])
func rejectedProposalUsesAnAcceptableDefault(key: String) throws {
    var (machine, entries) = try begin()
    entries = replacing(entries, key, "Reject")
    #expect(try machine.accept(response(0x87, 1, entries)) == nil)
    if key == "HeaderDigest" { #expect(machine.parameters.digests.header == false) }
    if key == "DataDigest" { #expect(machine.parameters.digests.data == false) }
}

@Test(arguments: ["ImmediateData", "DefaultTime2Retain"])
func rejectedProposalCannotEnableAnUnacceptableDefault(key: String) throws {
    var (machine, entries) = try begin()
    entries = replacing(entries, key, "Reject")
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x87, 1, entries)) }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) { try machine.accept(response(0x87, 2)) }
}

@Test(arguments: [
    "HeaderDigest=Irrelevant", "HeaderDigest=NotUnderstood", "HeaderDigest=CRC32C,None",
    "DefaultTime2Wait=1", "DefaultTime2Retain=20", "MaxConnections=2", "MaxBurstLength=262145",
    "FirstBurstLength=65537", "InitialR2T=No", "ImmediateData=Yes",
    "DataPDUInOrder=No", "DataSequenceInOrder=No",
    "MaxRecvDataSegmentLength=0bAgA=",
])
func invalidSelectionsAndResultFunctionsAreRejected(pair: String) throws {
    let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
    var (machine, entries) = try begin()
    entries = replacing(entries, String(parts[0]), String(parts[1]))
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x87, 1, entries)) }
}

@Test(arguments: [
    "X-com.example.feature=1", "IFMarker=Yes", "TaskReporting=RFC3720,ResponseFence",
    "iSCSIProtocolLevel=2",
])
func finalResponseCannotIntroduceKeysNeedingAnswers(pair: String) throws {
    let parts = pair.split(separator: "=", maxSplits: 1)
    var (machine, entries) = try begin()
    entries.append(.init(String(parts[0]), String(parts[1])))
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x87, 1, entries)) }
}

@Test(arguments: [
    "MaxRecvDataSegmentLength", "HeaderDigest", "X-com.example.feature", "TargetAlias",
])
func loginKeysCannotBeRenegotiatedAcrossResponses(key: String) throws {
    var (machine, entries) = try begin()
    let entry = entries.first(where: { $0.key == key }) ?? .init(key, "Example")
    if !entries.contains(where: { $0.key == key }) { entries.append(entry) }
    _ = try machine.accept(response(0x04, 1, entries))
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x04, 2, [entry])) }
}

@Test func continuedOperationalReplyKeepsTransitRequestAndParsesOnlyCompleteText() throws {
    var (machine, entries) = try begin()
    entries = replacing(entries, "FirstBurstLength", "Irrelevant")
    let bytes = try TextParameters(entries).encoded()
    let split = 17
    let acknowledgmentValue = try machine.accept(response(0x44, 1, data: Data(bytes.prefix(split))))
    let acknowledgment = try #require(acknowledgmentValue)
    #expect(acknowledgment.flags == 0x87 && acknowledgment.data.isEmpty)
    #expect(try machine.accept(response(0x87, 2, data: Data(bytes.dropFirst(split)))) == nil)
    #expect(machine.isComplete)
}

@Test func standardNumericKeysAllowHexadecimalButNotSignsOrOverflow() throws {
    var (machine, entries) = try begin()
    entries = entries.map {
        guard let number = Int($0.value) else { return $0 }
        return .init($0.key, "0X" + String(number, radix: 16))
    }
    #expect(try machine.accept(response(0x87, 1, entries)) == nil)
    for value in ["", "+512", "-512", " 512", "0x", "0x10000000000000000", "18446744073709551616"] {
        var (invalid, values) = try begin()
        values = replacing(values, "MaxRecvDataSegmentLength", value)
        #expect(throws: ProtocolError.self) { try invalid.accept(response(0x87, 1, values)) }
    }
}

@Test func relevantNumericFirstBurstCannotExceedMaximumBurst() throws {
    var (machine, entries) = try begin()
    entries = replacing(entries, "MaxBurstLength", "1024")
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x87, 1, entries)) }
}

@Test func oversizedNegotiationAnswersUseBoundedLoginContinuationPDUs() throws {
    var (machine, entries) = try begin()
    entries += (0..<600).map { .init("FutureKey\($0)", "1") }
    let data = try TextParameters(entries).encoded()
    // The target's valid short values can still require an answer exceeding the login limit.
    let split = min(8192, data.count - 1)
    _ = try machine.accept(response(0x44, 1, data: Data(data.prefix(split))))
    let first = try machine.accept(response(0x04, 2, data: Data(data.dropFirst(split))))
    var next = try #require(first)
    var answer = Data()
    var sequence: UInt32 = 3
    while true {
        #expect(next.data.count <= 8192)
        answer.append(next.data)
        if next.flags & 0x40 == 0 { break }
        #expect(next.flags == 0x44)
        let following = try machine.accept(response(0x04, sequence))
        next = try #require(following)
        sequence &+= 1
    }
    #expect(next.flags == 0x87)
    #expect(
        try TextParameters(data: answer).entries
            == (0..<600).map { .init("FutureKey\($0)", "NotUnderstood") })
    #expect(try machine.accept(response(0x87, sequence)) == nil)
    #expect(machine.isComplete)
}

private func unknownKeys(answerByteCount: Int) -> [TextParameters.Entry] {
    let count = answerByteCount < 10000 ? 128 : 256
    return (0..<count).map { index in
        let length = 49 + (index == count - 1 ? answerByteCount - count * 64 : 0)
        return .init(
            String(format: "Future%04d", index).padding(
                toLength: length, withPad: "x", startingAt: 0), "1")
    }
}

@Test(arguments: [8191, 8192, 8193, 16384, 16385])
func loginRequestFragmentBoundariesRetainEveryByteAndUpdateStatusAcknowledgments(_ count: Int)
    throws
{
    var (machine, entries) = try begin()
    let extra = unknownKeys(answerByteCount: count)
    entries += extra
    let first = try machine.accept(response(0x04, 1, entries))
    var frame = try #require(first)
    var sequence: UInt32 = 2
    var bytes = Data()
    var lengths: [Int] = []
    while true {
        bytes.append(frame.data)
        lengths.append(frame.data.count)
        #expect(frame.header[8..<14].elementsEqual(negotiationISID))
        #expect(frame.taskTag == 1 && frame.header.uint32(at: 24) == 1)
        #expect(frame.header.uint32(at: 28) == sequence)
        guard frame.flags & 0x40 != 0 else { break }
        #expect(frame.flags == 0x44 && frame.data.count == 8192)
        let following = try machine.accept(response(0x04, sequence))
        sequence &+= 1
        frame = try #require(following)
    }
    #expect(frame.flags == 0x87)
    #expect(bytes.count == count)
    let expected = try TextParameters(extra.map { .init($0.key, "NotUnderstood") }).encoded()
    #expect(bytes == expected)
    #expect(lengths.count == (count + 8191) / 8192)
    #expect(!lengths.contains(0))
    #expect(try machine.accept(response(0x87, sequence)) == nil)
}

@Test(arguments: ["data", "transit", "stage", "tag", "sequence", "reject"])
func malformedLoginContinuationAcknowledgmentsStopTheExchange(_ fault: String) throws {
    var (machine, entries) = try begin()
    entries += unknownKeys(answerByteCount: 8193)
    let first = try machine.accept(response(0x04, 1, entries))
    #expect(first?.flags == 0x44)
    var ack = try response(0x04, 2)
    switch fault {
    case "data": ack = try response(0x04, 2, [.init("TargetAlias", "Unexpected")])
    case "transit": ack = try response(0x87, 2)
    case "stage": ack = try response(0, 2)
    case "sequence": ack = try response(0x04, 3)
    default:
        var header = ack.header
        if fault == "tag" { header.put(UInt32(2), at: 16) } else { header[36] = 2 }
        ack = try PDU(header: header)
    }
    #expect(throws: ProtocolError.self) { try machine.accept(ack) }
    #expect(!machine.isComplete)
    #expect(throws: ProtocolError.invalidState) { try machine.accept(response(0x04, 2)) }
}

@Test func emptyContinuationAcknowledgmentsDoNotConsumePendingRequestText() throws {
    var (machine, entries) = try begin()
    let extra = unknownKeys(answerByteCount: 8193)
    entries += extra
    let first = try machine.accept(response(0x04, 1, entries))
    var bytes = try #require(first).data
    for sequence: UInt32 in [2, 3] {
        let next = try machine.accept(response(0x44, sequence))
        #expect(next?.flags == 0x44 && next?.data.isEmpty == true)
    }
    let final = try machine.accept(response(0x04, 4))
    let last = try #require(final)
    #expect(last.flags == 0x87 && last.data == Data([0]))
    bytes.append(last.data)
    let expected = try TextParameters(extra.map { .init($0.key, "NotUnderstood") }).encoded()
    #expect(bytes == expected)
    #expect(try machine.accept(response(0x87, 5)) == nil)
}

@Test func endlessContinuationAcknowledgmentsRemainBounded() throws {
    var (machine, entries) = try begin()
    entries += unknownKeys(answerByteCount: 8193)
    _ = try machine.accept(response(0x04, 1, entries))
    var stopped = false
    for sequence in UInt32(2)..<40 {
        do { _ = try machine.accept(response(0x44, sequence)) } catch {
            #expect(error as? ProtocolError == .limitExceeded("login exchanges"))
            stopped = true
            break
        }
    }
    #expect(stopped && !machine.isComplete)
}

@Test(arguments: [false, true])
func fragmentedSecurityAnswersPreserveCHAPProgressAndTransitIntent(_ chap: Bool) throws {
    let credentials =
        chap ? try CHAPCredentials(username: "User", password: "correct horse battery staple") : nil
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
            credentials: credentials, isid: negotiationISID))
    _ = try machine.start()
    let extra = unknownKeys(answerByteCount: 8193)
    let first = try machine.accept(
        response(
            0, 0,
            [.init("AuthMethod", chap ? "CHAP" : "None"), .init("TargetPortalGroupTag", "1")]
                + extra))
    var frame = try #require(first)
    var sequence: UInt32 = 1
    var bytes = Data()
    while true {
        bytes.append(frame.data)
        if frame.flags & 0x40 == 0 { break }
        #expect(frame.flags == 0x40)
        let next = try machine.accept(response(0, sequence))
        sequence &+= 1
        frame = try #require(next)
    }
    #expect(frame.flags == (chap ? 0 : 0x81))
    let expected =
        extra.map { TextParameters.Entry($0.key, "NotUnderstood") }
        + (chap ? [.init("CHAP_A", "5")] : [])
    #expect(try TextParameters(data: bytes).entries == expected)
    if chap {
        let answer = try machine.accept(
            response(
                0, sequence,
                [
                    .init("CHAP_A", "5"), .init("CHAP_I", "7"),
                    .init("CHAP_C", "0x000102030405060708090a0b0c0d0e0f"),
                ]))
        #expect(answer?.flags == 0x81)
        sequence &+= 1
    }
    let operational = try machine.accept(response(0x81, sequence))
    sequence &+= 1
    let offer = try #require(operational)
    let selected = try TextParameters(data: offer.data).entries.map {
        ["HeaderDigest", "DataDigest"].contains($0.key)
            ? TextParameters.Entry($0.key, "CRC32C") : $0
    }
    #expect(try machine.accept(response(0x87, sequence, selected)) == nil)
    #expect(machine.isComplete)
}

@Test func chapHexadecimalNumbersAndUnrequestedTransitions() throws {
    let configuration = try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:initiator",
        credentials: CHAPCredentials(username: "User", password: "correct horse battery staple"),
        isid: negotiationISID)
    var machine = LoginMachine(configuration: configuration)
    _ = try machine.start()
    _ = try machine.accept(response(0, 0, [.init("AuthMethod", "CHAP")]))
    let answerValue = try machine.accept(
        response(
            0, 1,
            [
                .init("CHAP_A", "0x05"), .init("CHAP_I", "0X07"),
                .init("CHAP_C", "0x000102030405060708090a0b0c0d0e0f"),
            ]))
    let answer = try #require(answerValue)
    #expect(
        try TextParameters(data: answer.data).uniqueValue(for: "CHAP_R")
            == "0x4743b2bd34fa732295d209c4eb4dfc7b")
    var invalid = LoginMachine(configuration: configuration)
    _ = try invalid.start()
    #expect(throws: ProtocolError.self) {
        try invalid.accept(response(0x81, 0, [.init("AuthMethod", "CHAP")]))
    }
}

@Test(arguments: [
    "AuthMethod=None", "CHAP_A=5", "TargetName=iqn.2026-10.test:disk", "IFMarkInt=4096~2048",
    "TaskReporting=RFC3720",
])
func wrongStageKeysAndMalformedTargetProposalsAreRejected(pair: String) throws {
    var (machine, entries) = try begin()
    let parts = pair.split(separator: "=", maxSplits: 1)
    entries.append(.init(String(parts[0]), String(parts[1])))
    #expect(throws: ProtocolError.self) { try machine.accept(response(0x04, 1, entries)) }
}
