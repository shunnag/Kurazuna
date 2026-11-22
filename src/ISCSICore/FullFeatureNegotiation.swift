import Foundation

/// One atomic RFC 7143 §6.4 Text sequence. Sequence numbers are supplied at transport admission.
/// Only changes permitted outside login are staged here; authentication and digests stay fixed.
public struct FullFeatureNegotiation: Sendable {
    public struct Changes: Sendable, Equatable {
        public fileprivate(set) var targetReceiveSegmentLength: Int?
        public fileprivate(set) var targetAlias: String?
    }

    public private(set) var changes = Changes()
    public private(set) var isComplete = false
    private let tag: UInt32
    private let maximumSegmentLength: Int
    private var transferTag = UInt32.max
    private var lun = [UInt8](repeating: 0, count: 8)
    private var awaitingResponse = false
    private var requestContinues = false
    private var started = false
    private var exchanges = 0
    private var totalBytes = 0
    private var addressCount = 0
    private var seen: Set<String> = []
    private var incoming = Data()
    private var outgoing = Data()
    private var outgoingOffset = 0

    public init(taskTag: UInt32, maximumSegmentLength: Int) throws {
        guard taskTag != UInt32.max, (512...PDU.maximumDataLength).contains(maximumSegmentLength)
        else { throw ProtocolError.malformed("Text negotiation configuration") }
        self.tag = taskTag
        self.maximumSegmentLength = maximumSegmentLength
    }

    public mutating func start() throws -> PDU {
        guard !started else { throw ProtocolError.invalidState }
        started = true
        return try request()
    }

    /// A Reject resets a Text sequence (§6.4); discard staged changes without
    /// resetting its resource budget. The connection owner validates the rejected header.
    public mutating func reset() throws -> PDU {
        guard started, awaitingResponse, !isComplete else { throw ProtocolError.invalidState }
        awaitingResponse = false
        transferTag = .max
        lun = [UInt8](repeating: 0, count: 8)
        changes = Changes()
        incoming.removeAll()
        outgoing.removeAll()
        outgoingOffset = 0
        seen.removeAll()
        addressCount = 0
        return try request()
    }

    /// nil means the final response was validated; callers may now apply Changes atomically.
    public mutating func accept(_ response: PDU) throws -> PDU? {
        guard awaitingResponse, !isComplete else { throw ProtocolError.invalidState }
        guard response.opcode == 0x24, response.taskTag == tag,
            response.flags & 0xC0 != 0xC0
        else { throw ProtocolError.malformed("Text negotiation response") }
        let final = response.flags & 0x80 != 0
        let continues = response.flags & 0x40 != 0
        guard final ? response.transferTag == UInt32.max : response.transferTag != UInt32.max
        else { throw ProtocolError.malformed("Text negotiation transfer tag") }
        guard !requestContinues || (!final && !continues && response.data.isEmpty) else {
            throw ProtocolError.malformed("Text continuation acknowledgement")
        }
        awaitingResponse = false
        if !final {
            transferTag = response.transferTag
            lun = Array(response.header[8..<16])
        }
        if requestContinues { return try request() }
        totalBytes += response.data.count
        guard totalBytes <= 1_048_576 else {
            throw ProtocolError.limitExceeded("Text negotiation data")
        }
        incoming.append(response.data)
        if continues { return try request() }  // An incomplete peer text requires an empty request.
        let replies = try accept(try TextParameters(data: incoming).entries)
        incoming.removeAll(keepingCapacity: true)
        outgoing = try TextParameters(replies).encoded()
        outgoingOffset = 0
        if final {
            guard outgoing.isEmpty else {
                throw ProtocolError.malformed("final Text response requires an answer")
            }
            isComplete = true
            return nil
        }
        return try request()
    }

    private mutating func request() throws -> PDU {
        guard !awaitingResponse, !isComplete else { throw ProtocolError.invalidState }
        guard exchanges < 256 else {
            throw ProtocolError.limitExceeded("Text negotiation exchanges")
        }
        exchanges += 1
        let count = min(maximumSegmentLength, outgoing.count - outgoingOffset)
        let data = Data(outgoing[outgoingOffset..<(outgoingOffset + count)])
        outgoingOffset += count
        requestContinues = outgoingOffset < outgoing.count
        var header = [UInt8](repeating: 0, count: 48)
        header[0] = 0x44
        header[1] = requestContinues ? 0x40 : 0x80
        header.replaceSubrange(8..<16, with: lun)
        header.put(tag, at: 16)
        header.put(transferTag, at: 20)
        awaitingResponse = true
        return try PDU(header: header, data: data)
    }

    private mutating func accept(_ entries: [TextParameters.Entry]) throws -> [TextParameters.Entry]
    {
        var replies: [TextParameters.Entry] = []
        for entry in entries {
            guard entry.key == "TargetAddress" || seen.insert(entry.key).inserted else {
                throw ProtocolError.malformed("repeated Text key \(entry.key)")
            }
            guard seen.count <= 512 else {
                throw ProtocolError.limitExceeded("Text negotiation keys")
            }
            guard !["Reject", "Irrelevant", "NotUnderstood"].contains(entry.value) else {
                throw ProtocolError.malformed("reserved Text value")
            }
            switch entry.key {
            case "MaxRecvDataSegmentLength":
                changes.targetReceiveSegmentLength = try LoginNegotiation.numeric(
                    entry, range: 512...PDU.maximumDataLength)
            case "TargetAlias":
                guard entry.value.utf8.count <= 255 else {
                    throw ProtocolError.limitExceeded(entry.key)
                }
                changes.targetAlias = entry.value
            case "TargetAddress":
                addressCount += 1
                guard addressCount <= 16 else {
                    throw ProtocolError.limitExceeded("Text target addresses")
                }
                _ = try TargetAddress(entry.value)
            case "IFMarker", "OFMarker":
                guard ["Yes", "No"].contains(entry.value) else {
                    throw ProtocolError.malformed(entry.key)
                }
                replies.append(.init(entry.key, "Reject"))
            case "IFMarkInt", "OFMarkInt":
                let bounds = entry.value.split(separator: "~", omittingEmptySubsequences: false)
                guard bounds.count == 2 else { throw ProtocolError.malformed(entry.key) }
                let lower = try LoginNegotiation.numeric(
                    .init(entry.key, String(bounds[0])), range: 1...65_535)
                let upper = try LoginNegotiation.numeric(
                    .init(entry.key, String(bounds[1])), range: 1...65_535)
                guard lower <= upper else { throw ProtocolError.malformed(entry.key) }
                replies.append(.init(entry.key, "Reject"))
            default:
                guard !Self.loginOrInitiatorOnly.contains(entry.key),
                    !entry.key.hasPrefix("CHAP_"), !entry.key.hasPrefix("SRP_"),
                    !entry.key.hasPrefix("KRB_")
                else { throw ProtocolError.malformed("key outside login or wrong sender") }
                replies.append(.init(entry.key, "NotUnderstood"))
            }
        }
        return replies
    }

    private static let loginOrInitiatorOnly: Set<String> = [
        "HeaderDigest", "DataDigest", "MaxConnections", "TargetName", "InitiatorName",
        "InitiatorAlias", "TargetPortalGroupTag", "InitialR2T", "ImmediateData", "MaxBurstLength",
        "FirstBurstLength", "DefaultTime2Wait", "DefaultTime2Retain", "MaxOutstandingR2T",
        "DataPDUInOrder", "DataSequenceInOrder", "ErrorRecoveryLevel", "SessionType",
        "SendTargets", "AuthMethod", "TaskReporting", "iSCSIProtocolLevel", "X#NodeArchitecture",
    ]
}
