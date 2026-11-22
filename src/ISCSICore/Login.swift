import Foundation

public struct LoginConfiguration: Sendable {
    public let initiatorName: String
    public let targetName: String?
    public let credentials: CHAPCredentials?
    public let isid: [UInt8]
    /// The leading login selects the session's initial CmdSN. All UInt32 values are valid.
    public let initialCommandSequenceNumber: UInt32
    public let receiveSegmentLength = 262_144

    public init(
        initiatorName: String, targetName: String? = nil, credentials: CHAPCredentials? = nil,
        isid: [UInt8]? = nil, initialCommandSequenceNumber: UInt32 = 1
    ) throws {
        for name in [initiatorName, targetName].compactMap({ $0 }) {
            guard name.utf8.count <= 223,
                ["iqn.", "eui.", "naa."].contains(where: name.hasPrefix),
                name.utf8.allSatisfy({ (33...126).contains($0) && $0 != 61 && $0 != 44 })
            else { throw ProtocolError.malformed("iSCSI name") }
        }
        let identifier = isid ?? ([0x80] + (0..<5).map { _ in UInt8.random(in: .min ... .max) })
        guard identifier.count == 6, identifier[0] & 0xC0 == 0x80 else {
            throw ProtocolError.malformed("random-format ISID")
        }
        self.initiatorName = initiatorName
        self.targetName = targetName
        self.credentials = credentials
        self.isid = identifier
        self.initialCommandSequenceNumber = initialCommandSequenceNumber
    }
}

public struct SessionParameters: Sendable, Equatable {
    public var digests = DigestPolicy()
    public var targetReceiveSegmentLength = 8192
    public var maximumBurstLength = 262_144
    public var targetSessionHandle: UInt16 = 0
    public var expectedStatusSequenceNumber: UInt32 = 0
    public var commandSequenceNumber: UInt32 = 1
    public var expectedCommandSequenceNumber: UInt32 = 1
    public var maximumCommandSequenceNumber: UInt32 = 1
    public var targetAlias: String?
    public var targetPortalGroupTag: UInt16?
    /// Negotiated minimum wait, in seconds, before logging in again after a lost connection.
    public var defaultTime2Wait = 2

    /// Apply each peer boundary monotonically. RFC 7143 requires ignoring both fields
    /// when their pair describes a negative command window.
    public mutating func updateCommandWindow(expected: UInt32, maximum: UInt32) throws {
        guard maximum == expected &- 1 || maximum &- expected < 0x8000_0000 else { return }
        guard
            expected == commandSequenceNumber
                || SerialNumber.precedes(expected, commandSequenceNumber)
        else { throw ProtocolError.malformed("command window") }
        if SerialNumber.precedes(expectedCommandSequenceNumber, expected) {
            expectedCommandSequenceNumber = expected
        }
        if SerialNumber.precedes(maximumCommandSequenceNumber, maximum) {
            maximumCommandSequenceNumber = maximum
        }
    }
}

/// Pure login state machine. Login PDUs never carry digests, even on the final response.
public struct LoginMachine: Sendable {
    private enum Stage: UInt8, Sendable {
        case security = 0
        case operational = 1
        case full = 3
    }
    private let configuration: LoginConfiguration
    private var stage = Stage.security
    private var started = false
    private var failed = false
    private var exchanges = 0
    private var chapOffered = false
    private var chapAnswered = false
    private var targetChallenge: (identifier: UInt8, text: String)?
    private var targetAuthenticated = false
    private var authenticationSelected = false
    private var negotiation: LoginNegotiation
    private var securityKeys: Set<String> = []
    private var requestedTransit = false
    private var continuedText = Data()
    private var pendingRequestText: Data?
    private var pendingRequestOffset = 0
    private var pendingRequestTransit = false
    private var sentContinuation = false
    public private(set) var parameters = SessionParameters()
    public var isComplete: Bool { !failed && stage == .full }

    public init(configuration: LoginConfiguration) {
        self.configuration = configuration
        parameters.commandSequenceNumber = configuration.initialCommandSequenceNumber
        parameters.expectedCommandSequenceNumber = configuration.initialCommandSequenceNumber
        parameters.maximumCommandSequenceNumber = configuration.initialCommandSequenceNumber &- 1
        negotiation = LoginNegotiation(
            normal: configuration.targetName != nil,
            receiveLength: configuration.receiveSegmentLength)
    }

    public mutating func start() throws -> PDU {
        guard !started, !failed else { throw ProtocolError.invalidState }
        started = true
        var entries: [TextParameters.Entry] = [
            .init("InitiatorName", configuration.initiatorName),
            .init("SessionType", configuration.targetName == nil ? "Discovery" : "Normal"),
            .init("AuthMethod", configuration.credentials == nil ? "None" : "CHAP"),
        ]
        if let name = configuration.targetName { entries.append(.init("TargetName", name)) }
        return try request(entries, transit: configuration.credentials == nil)
    }

    public mutating func accept(_ response: PDU) throws -> PDU? {
        guard started, !failed, stage != .full else { throw ProtocolError.invalidState }
        do { return try process(response) } catch {
            failed = true
            throw error
        }
    }

    private mutating func process(_ response: PDU) throws -> PDU? {
        exchanges += 1
        guard exchanges <= 32 else { throw ProtocolError.limitExceeded("login exchanges") }
        let isid = Array(response.header[8..<14])
        // Linux LIO answers an initiator or target error (status class 2 or 3) with a header
        // zeroed except for its opcode, status and task tag. Such a rejection is still one.
        let zeroedRejection = response.header[36] >= 2 && isid.allSatisfy { $0 == 0 }
        guard response.opcode == 0x23, response.taskTag == 1,
            isid == configuration.isid || zeroedRejection
        else { throw ProtocolError.malformed("login response identity") }
        if response.header[36] == 1,
            let kind = LoginRedirect.Kind(rawValue: response.header[37])
        {
            throw ProtocolError.loginRedirect(try LoginRedirect(kind: kind, text: response.data))
        }
        guard response.header[36] == 0 else {
            throw ProtocolError.loginRejected(
                statusClass: response.header[36], detail: response.header[37])
        }
        guard response.header[3] == 0 else { throw ProtocolError.malformed("active iSCSI version") }
        guard response.expectedCommandSequenceNumber == configuration.initialCommandSequenceNumber,
            response.maximumCommandSequenceNumber == configuration.initialCommandSequenceNumber &- 1
                || response.maximumCommandSequenceNumber
                    &- configuration.initialCommandSequenceNumber
                    < 0x8000_0000
        else { throw ProtocolError.malformed("initial command window") }
        let transit = response.flags & 0x80 != 0
        let more = response.flags & 0x40 != 0
        guard (response.flags >> 2) & 3 == stage.rawValue, !(transit && more),
            transit || response.flags & 3 == 0, !transit || requestedTransit
        else { throw ProtocolError.malformed("login stage flags") }
        if exchanges > 1, response.statusSequenceNumber != parameters.expectedStatusSequenceNumber {
            throw ProtocolError.malformed("login StatSN")
        }
        parameters.expectedStatusSequenceNumber = response.statusSequenceNumber &+ 1
        parameters.commandSequenceNumber = response.expectedCommandSequenceNumber
        parameters.expectedCommandSequenceNumber = response.expectedCommandSequenceNumber
        parameters.maximumCommandSequenceNumber = response.maximumCommandSequenceNumber
        if sentContinuation {
            // A peer must not negotiate on an incomplete logical request. Empty C=1
            // acknowledgments are polled without advancing our remaining text.
            guard response.data.isEmpty else {
                throw ProtocolError.malformed("login continuation acknowledgment")
            }
            if more { return try makeRequest(Data(), continues: true, transit: false) }
            return try nextRequestFragment()
        }
        guard continuedText.count + response.data.count <= 1_048_576 else {
            throw ProtocolError.limitExceeded("continued login text")
        }
        continuedText.append(response.data)
        if more { return try request([], transit: requestedTransit) }
        let text = try TextParameters(data: continuedText)
        continuedText.removeAll()
        if configuration.targetName != nil, parameters.targetPortalGroupTag == nil,
            try text.uniqueValue(for: "TargetPortalGroupTag") == nil
        {
            throw ProtocolError.malformed("target portal group")
        }

        if stage == .security {
            let authentication = text.entries.filter {
                $0.key == "AuthMethod" || $0.key.hasPrefix("CHAP_")
            }
            for entry in authentication {
                let targetKey =
                    ["CHAP_N", "CHAP_R"].contains(entry.key)
                    && configuration.credentials?.targetUsername != nil && chapAnswered
                    && !targetAuthenticated
                guard
                    ["AuthMethod", "CHAP_A", "CHAP_I", "CHAP_C"].contains(entry.key) || targetKey,
                    securityKeys.insert(entry.key).inserted
                else {
                    throw ProtocolError.malformed("unexpected authentication key")
                }
            }
            let replies = try negotiation.accept(
                text.entries.filter {
                    $0.key != "AuthMethod" && !$0.key.hasPrefix("CHAP_")
                }, security: true, parameters: &parameters)
            guard !transit || replies.isEmpty else {
                throw ProtocolError.malformed("security transition with unanswered target key")
            }
            let method = try text.uniqueValue(for: "AuthMethod")
            if method != nil { authenticationSelected = true }
            if let credentials = configuration.credentials {
                guard method == nil || method == "CHAP" else {
                    throw ProtocolError.unsupported("authentication method")
                }
                if !chapOffered {
                    guard method == "CHAP", !transit, authentication.count == 1 else {
                        throw ProtocolError.malformed("CHAP selection")
                    }
                    chapOffered = true
                    return try request(replies + [.init("CHAP_A", "5")], transit: false)
                }
                if !chapAnswered {
                    guard !transit, let algorithm = try text.uniqueValue(for: "CHAP_A"),
                        try LoginNegotiation.numeric(.init("CHAP_A", algorithm), range: 5...5) == 5,
                        let identifierText = try text.uniqueValue(for: "CHAP_I"),
                        let challenge = try text.uniqueValue(for: "CHAP_C")
                    else { throw ProtocolError.malformed("CHAP challenge") }
                    let identifier = UInt8(
                        try LoginNegotiation.numeric(
                            .init("CHAP_I", identifierText), range: 0...255))
                    chapAnswered = true
                    var answer =
                        replies + [
                            .init("CHAP_N", credentials.username),
                            .init(
                                "CHAP_R",
                                try credentials.response(
                                    identifier: identifier, challenge: challenge)),
                        ]
                    if credentials.targetUsername != nil {
                        let peerChallenge = try CHAP.decodeBinary(challenge)
                        var bytes: [UInt8]
                        repeat {
                            bytes = (0..<32).map { _ in UInt8.random(in: .min ... .max) }
                        } while Data(bytes) == peerChallenge
                        let identifier = UInt8.random(in: .min ... .max)
                        let text = "0x" + bytes.map { String(format: "%02x", $0) }.joined()
                        targetChallenge = (identifier, text)
                        answer += [.init("CHAP_I", String(identifier)), .init("CHAP_C", text)]
                    }
                    return try request(answer, transit: true)
                }
                if credentials.targetUsername != nil, !targetAuthenticated {
                    guard let targetChallenge,
                        let name = try text.uniqueValue(for: "CHAP_N"),
                        let answer = try text.uniqueValue(for: "CHAP_R")
                    else { throw ProtocolError.authenticationFailed }
                    try credentials.verifyTarget(
                        username: name, response: answer, identifier: targetChallenge.identifier,
                        challenge: targetChallenge.text)
                    targetAuthenticated = true
                    self.targetChallenge = nil
                }
            } else {
                guard authentication.allSatisfy({ $0.key == "AuthMethod" }),
                    method == nil || method == "None"
                else {
                    throw ProtocolError.unsupported("authentication required")
                }
            }
            if transit {
                guard authenticationSelected,
                    response.flags & 3 == Stage.operational.rawValue
                else {
                    throw ProtocolError.malformed("security transition")
                }
                stage = .operational
                return try request(negotiation.offers, transit: true)
            }
            return try request(replies, transit: true)
        }

        let replies = try negotiation.accept(text.entries, security: false, parameters: &parameters)
        if transit {
            guard response.flags & 3 == Stage.full.rawValue, replies.isEmpty else {
                throw ProtocolError.malformed("operational transition")
            }
            try negotiation.finish(parameters: parameters)
            parameters.targetSessionHandle = response.header.uint16(at: 14)
            guard configuration.targetName == nil || parameters.targetSessionHandle != 0 else {
                throw ProtocolError.malformed("normal session TSIH")
            }
            stage = .full
            return nil
        }
        return try request(replies, transit: true)
    }

    private mutating func request(_ entries: [TextParameters.Entry], transit: Bool) throws -> PDU {
        guard pendingRequestText == nil else { throw ProtocolError.invalidState }
        let data = try TextParameters(entries).encoded()
        guard data.count <= 1_048_576 else {
            throw ProtocolError.limitExceeded("login request text")
        }
        pendingRequestText = data
        pendingRequestOffset = 0
        pendingRequestTransit = transit
        return try nextRequestFragment()
    }

    private mutating func nextRequestFragment() throws -> PDU {
        guard let data = pendingRequestText else { throw ProtocolError.invalidState }
        let end = min(pendingRequestOffset + 8192, data.count)
        let fragment = data.subdata(in: pendingRequestOffset..<end)
        let more = end < data.count
        pendingRequestOffset = end
        if !more {
            pendingRequestText = nil
            pendingRequestOffset = 0
        }
        return try makeRequest(fragment, continues: more, transit: pendingRequestTransit && !more)
    }

    private mutating func makeRequest(_ data: Data, continues: Bool, transit: Bool) throws -> PDU {
        var header = Array(repeating: UInt8(0), count: PDU.headerLength)
        header[0] = 0x43
        header[1] = stage.rawValue << 2
        if continues { header[1] |= 0x40 }
        if transit { header[1] |= 0x80 | (stage == .security ? 1 : 3) }
        header.replaceSubrange(8..<14, with: configuration.isid)
        header.put(UInt32(1), at: 16)
        header.put(parameters.commandSequenceNumber, at: 24)
        header.put(parameters.expectedStatusSequenceNumber, at: 28)
        let pdu = try PDU(header: header, data: data)
        requestedTransit = transit
        sentContinuation = continues
        return pdu
    }
}
