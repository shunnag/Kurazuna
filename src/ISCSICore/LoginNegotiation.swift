import Foundation

/// Text-key negotiation independent of PDU framing and CHAP. No target key is silently echoed.
struct LoginNegotiation: Sendable {
    let normal: Bool
    let receiveLength: Int
    private var seen: Set<String> = []
    private var answered: Set<String> = []
    private var firstBurstLength: Int?

    var offers: [TextParameters.Entry] {
        let connection: [TextParameters.Entry] = [
            .init("HeaderDigest", "CRC32C,None"), .init("DataDigest", "CRC32C,None"),
            .init("MaxRecvDataSegmentLength", String(receiveLength)),
        ]
        guard normal else { return connection }
        return connection + [
            .init("MaxConnections", "1"), .init("InitialR2T", "Yes"),
            .init("ImmediateData", "No"), .init("MaxBurstLength", "262144"),
            .init("FirstBurstLength", "65536"), .init("MaxOutstandingR2T", "1"),
            .init("DataPDUInOrder", "Yes"), .init("DataSequenceInOrder", "Yes"),
            .init("ErrorRecoveryLevel", "0"), .init("DefaultTime2Wait", "2"),
            .init("DefaultTime2Retain", "0"),
        ]
    }

    init(normal: Bool, receiveLength: Int) {
        self.normal = normal
        self.receiveLength = receiveLength
    }

    mutating func accept(
        _ entries: [TextParameters.Entry], security: Bool,
        parameters: inout SessionParameters
    ) throws -> [TextParameters.Entry] {
        var replies: [TextParameters.Entry] = []
        let offered = security ? Set<String>() : Set(offers.map(\.key))
        for entry in entries {
            guard entry.key == "TargetAddress" || seen.insert(entry.key).inserted else {
                throw ProtocolError.malformed("repeated login key \(entry.key)")
            }
            guard seen.count <= TextParameters.maximumEntryCount else {
                throw ProtocolError.limitExceeded("login negotiation keys")
            }
            switch entry.key {
            case "TargetAlias":
                guard entry.value.utf8.count <= 255 else {
                    throw ProtocolError.limitExceeded(entry.key)
                }
                try rejectReserved(entry)
                parameters.targetAlias = entry.value
                continue
            case "TargetPortalGroupTag":
                parameters.targetPortalGroupTag = UInt16(try Self.binary16(entry))
                continue
            case "TargetAddress":
                try Self.validateAddress(entry.value)
                continue
            case "InitiatorName", "TargetName", "InitiatorAlias", "SessionType", "SendTargets",
                "AuthMethod":
                throw ProtocolError.malformed("unexpected login key \(entry.key)")
            default:
                guard !entry.key.hasPrefix("CHAP_") else {
                    throw ProtocolError.malformed("authentication key in operational negotiation")
                }
            }
            let known = Self.operationalKeys.contains(entry.key)
            guard !security || !known else {
                throw ProtocolError.malformed("operational key in security stage")
            }
            if offered.contains(entry.key) {
                answered.insert(entry.key)
                if entry.value == "NotUnderstood" {
                    throw ProtocolError.malformed("unrecognized standard login key")
                }
                if entry.value == "Irrelevant" {
                    guard entry.key == "FirstBurstLength", normal else {
                        throw ProtocolError.malformed("relevant login key marked Irrelevant")
                    }
                    continue
                }
                if entry.value == "Reject" {
                    // A rejected proposal retains the default. Do not accept defaults that would
                    // enable immediate data or retain failed sessions against our explicit policy.
                    guard let value = Self.acceptableDefaults[entry.key] else {
                        throw ProtocolError.unsupported(entry.key)
                    }
                    try apply(.init(entry.key, value), parameters: &parameters)
                } else {
                    try apply(entry, parameters: &parameters)
                }
                continue
            }
            try rejectReserved(entry)
            if !normal, Self.discoveryIrrelevant.contains(entry.key) {
                replies.append(.init(entry.key, "Irrelevant"))
                continue
            }
            switch entry.key {
            case "MaxRecvDataSegmentLength":
                // Declarative; never echo our receive limit.
                try apply(entry, parameters: &parameters)
            case "DefaultTime2Wait":
                // RFC 7143 §13.15: the result is the maximum of both values.
                let wait = max(2, try Self.numeric(entry, range: 0...3600))
                parameters.defaultTime2Wait = wait
                replies.append(.init(entry.key, String(wait)))
            case "DefaultTime2Retain":
                _ = try Self.numeric(entry, range: 0...3600)
                replies.append(.init(entry.key, "0"))
            case "ErrorRecoveryLevel":
                _ = try Self.numeric(entry, range: 0...2)
                replies.append(.init(entry.key, "0"))
            case "IFMarker", "OFMarker":
                guard ["Yes", "No"].contains(entry.value) else {
                    throw ProtocolError.malformed(entry.key)
                }
                replies.append(.init(entry.key, "Reject"))
            case "IFMarkInt", "OFMarkInt":
                // Obsoleted range keys: RFC 7143 §13.25 requires Reject, not NotUnderstood.
                let bounds = entry.value.split(separator: "~", omittingEmptySubsequences: false)
                guard bounds.count == 2 else { throw ProtocolError.malformed(entry.key) }
                let lower = try Self.numeric(.init(entry.key, String(bounds[0])), range: 1...65_535)
                let upper = try Self.numeric(.init(entry.key, String(bounds[1])), range: 1...65_535)
                guard lower <= upper else { throw ProtocolError.malformed(entry.key) }
                replies.append(.init(entry.key, "Reject"))
            case "TaskReporting":
                let values = entry.value.split(separator: ",", omittingEmptySubsequences: false)
                guard values.allSatisfy({ !$0.isEmpty }), values.contains("RFC3720"),
                    values.contains("ResponseFence"),
                    Set(values).count == values.count
                else { throw ProtocolError.malformed(entry.key) }
                replies.append(.init(entry.key, "RFC3720"))
            case "iSCSIProtocolLevel":
                _ = try Self.numeric(entry, range: 0...31)
                // Level 0 makes no compliance claim and does not enable SAM-5 extensions.
                replies.append(.init(entry.key, "0"))
            case "X#NodeArchitecture":
                guard entry.value.utf8.count <= 255 else {
                    throw ProtocolError.limitExceeded(entry.key)
                }
            default:
                guard !known else {
                    throw ProtocolError.malformed("unexpected login key \(entry.key)")
                }
                guard normal || !entry.key.hasPrefix("X-") else {
                    throw ProtocolError.malformed("private key in discovery login")
                }
                replies.append(.init(entry.key, "NotUnderstood"))
            }
        }
        return replies
    }

    func finish(parameters: SessionParameters) throws {
        // RFC 7143 §6.2: OR/Yes and AND/No already determine the result, so
        // the peer may omit its answer. This is not a fallback to defaults.
        let required = Set(
            offers.filter {
                $0.key != "MaxRecvDataSegmentLength"
                    && Self.determinedBooleans[$0.key] != $0.value
            }.map(\.key))
        guard required.isSubset(of: answered) else {
            throw ProtocolError.malformed("incomplete operational negotiation")
        }
        if let firstBurstLength, firstBurstLength > parameters.maximumBurstLength {
            throw ProtocolError.malformed("FirstBurstLength exceeds MaxBurstLength")
        }
    }

    private mutating func apply(_ entry: TextParameters.Entry, parameters: inout SessionParameters)
        throws
    {
        switch entry.key {
        case "HeaderDigest", "DataDigest":
            guard ["CRC32C", "None"].contains(entry.value) else {
                throw ProtocolError.unsupported(entry.key)
            }
            if entry.key == "HeaderDigest" {
                parameters.digests.header = entry.value == "CRC32C"
            } else {
                parameters.digests.data = entry.value == "CRC32C"
            }
        case "MaxRecvDataSegmentLength":
            parameters.targetReceiveSegmentLength = try Self.numeric(entry, range: 512...0xFF_FFFF)
        case "MaxBurstLength":
            parameters.maximumBurstLength = try Self.numeric(entry, range: 512...262_144)
        case "FirstBurstLength": firstBurstLength = try Self.numeric(entry, range: 512...65_536)
        case "MaxConnections", "MaxOutstandingR2T":
            guard try Self.numeric(entry, range: 1...65_535) == 1 else {
                throw ProtocolError.unsupported(entry.key)
            }
        case "InitialR2T", "DataPDUInOrder", "DataSequenceInOrder":
            guard entry.value == "Yes" else { throw ProtocolError.unsupported(entry.key) }
        case "ImmediateData":
            guard entry.value == "No" else { throw ProtocolError.unsupported(entry.key) }
        case "ErrorRecoveryLevel":
            guard try Self.numeric(entry, range: 0...2) == 0 else {
                throw ProtocolError.unsupported(entry.key)
            }
        case "DefaultTime2Wait":
            let wait = try Self.numeric(entry, range: 0...3600)
            guard wait >= 2 else { throw ProtocolError.malformed(entry.key) }
            parameters.defaultTime2Wait = wait
        case "DefaultTime2Retain":
            guard try Self.numeric(entry, range: 0...3600) == 0 else {
                throw ProtocolError.malformed(entry.key)
            }
        default: throw ProtocolError.malformed("unexpected negotiation answer")
        }
    }

    static func numeric(_ entry: TextParameters.Entry, range: ClosedRange<Int>) throws -> Int {
        let hexadecimal = entry.value.hasPrefix("0x") || entry.value.hasPrefix("0X")
        let digits = hexadecimal ? String(entry.value.dropFirst(2)) : entry.value
        guard !digits.isEmpty,
            digits.utf8.allSatisfy({ byte in
                (48...57).contains(byte)
                    || (hexadecimal && ((65...70).contains(byte) || (97...102).contains(byte)))
            }), let value = UInt64(digits, radix: hexadecimal ? 16 : 10),
            value <= UInt64(range.upperBound), value >= UInt64(range.lowerBound)
        else {
            throw ProtocolError.malformed(entry.key)
        }
        return Int(value)
    }

    private static func binary16(_ entry: TextParameters.Entry) throws -> Int {
        if entry.value.hasPrefix("0b") || entry.value.hasPrefix("0B") {
            guard let data = Data(base64Encoded: String(entry.value.dropFirst(2))),
                !data.isEmpty, data.count <= 2
            else { throw ProtocolError.malformed(entry.key) }
            return data.reduce(0) { ($0 << 8) | Int($1) }
        }
        return try numeric(entry, range: 0...65_535)
    }

    private static func validateAddress(_ value: String) throws {
        _ = try TargetAddress(value)
    }

    private func rejectReserved(_ entry: TextParameters.Entry) throws {
        guard !["Reject", "Irrelevant", "NotUnderstood"].contains(entry.value) else {
            throw ProtocolError.malformed("unsolicited reserved login answer")
        }
    }

    private static let discoveryIrrelevant: Set<String> = [
        "MaxConnections", "InitialR2T", "ImmediateData", "MaxBurstLength", "FirstBurstLength",
        "MaxOutstandingR2T", "DataPDUInOrder", "DataSequenceInOrder", "TaskReporting",
        "iSCSIProtocolLevel",
    ]
    private static let operationalKeys = discoveryIrrelevant.union([
        "HeaderDigest", "DataDigest", "MaxRecvDataSegmentLength", "DefaultTime2Wait",
        "DefaultTime2Retain",
        "ErrorRecoveryLevel", "IFMarker", "OFMarker", "IFMarkInt", "OFMarkInt",
        "X#NodeArchitecture",
    ])
    private static let acceptableDefaults: [String: String] = [
        "HeaderDigest": "None", "DataDigest": "None", "MaxConnections": "1", "InitialR2T": "Yes",
        "MaxBurstLength": "262144", "FirstBurstLength": "65536", "MaxOutstandingR2T": "1",
        "DataPDUInOrder": "Yes", "DataSequenceInOrder": "Yes", "ErrorRecoveryLevel": "0",
        "DefaultTime2Wait": "2",
    ]
    private static let determinedBooleans: [String: String] = [
        "InitialR2T": "Yes", "ImmediateData": "No",
        "DataPDUInOrder": "Yes", "DataSequenceInOrder": "Yes",
    ]
}
