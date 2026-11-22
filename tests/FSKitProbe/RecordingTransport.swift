import Foundation
import ISCSICore

@testable import ISCSINetwork

/// Records what the probe's own connections send and receive, for an external target whose wire
/// the harness cannot observe (scripts/test-external-target.py). It keeps TCP connect outcomes,
/// login and text keys (never the values of CHAP_C or CHAP_R), each SCSI CDB with its status and
/// sense, and the negotiated digests. Payloads are not kept. The FSKit extension's own sessions
/// are not recorded: they run in another process.
final class WireRecorder: @unchecked Sendable {
    private final class Connection {
        let id: Int
        let label: String
        let portal: String
        let openedNS = RecoveryProbe.now()
        var phase: String
        var connect: [String: Any] = [:]
        var closedNS: UInt64?
        var buffers: [Bool: [UInt8]] = [true: [], false: []]
        var fullFeature = false
        var headerDigest = false
        var dataDigest = false
        var stopped: String?
        var login: [[String: Any]] = []
        var text: [[String: Any]] = []
        var pendingText: [Bool: [UInt8]] = [true: [], false: []]
        var offered: [String: String] = [:]
        var answered: [String: String] = [:]
        var commands: [[String: Any]] = []
        var tags: [UInt32: Int] = [:]
        var events: [[String: Any]] = []
        var nops = 0

        init(id: Int, label: String, portal: String, phase: String) {
            self.id = id
            self.label = label
            self.portal = portal
            self.phase = phase
        }
    }

    private let lock = NSLock()
    private var connections: [Connection] = []
    private var phase = "login"

    /// Labels the commands of later connections and of every open one (for example
    /// "app-inspection", "extension-open", "extra").
    func setPhase(_ value: String) {
        lock.withLock {
            phase = value
            for connection in connections where connection.closedNS == nil {
                connection.phase = value
            }
        }
    }

    func open(label: String, portal: Portal) -> Int {
        lock.withLock {
            let id = connections.count + 1
            connections.append(
                Connection(id: id, label: label, portal: portal.description, phase: phase))
            return id
        }
    }

    func connected(_ id: Int, began: UInt64, error: (any Error)?) {
        lock.withLock {
            guard let connection = connections.first(where: { $0.id == id }) else { return }
            connection.connect = [
                "ok": error == nil,
                "elapsedMS": RecoveryProbe.milliseconds(began, RecoveryProbe.now()),
                "error": error.map { RecoveryProbe.errorText($0) as Any } ?? NSNull(),
            ]
        }
    }

    func closed(_ id: Int) {
        lock.withLock { connections.first { $0.id == id }?.closedNS = RecoveryProbe.now() }
    }

    func observe(_ id: Int, toTarget: Bool, bytes: Data) {
        lock.withLock {
            guard let connection = connections.first(where: { $0.id == id }),
                connection.stopped == nil
            else { return }
            connection.buffers[toTarget, default: []].append(contentsOf: bytes)
            while connection.stopped == nil {
                var buffer = connection.buffers[toTarget] ?? []
                guard buffer.count >= 48 else { break }
                let additional = Int(buffer[4]) * 4
                let length = Int(buffer[5]) << 16 | Int(buffer[6]) << 8 | Int(buffer[7])
                let headerDigest = connection.fullFeature && connection.headerDigest ? 4 : 0
                let dataDigest =
                    connection.fullFeature && connection.dataDigest && length > 0 ? 4 : 0
                let padded = (length + 3) & ~3
                let total = 48 + headerDigest + additional + padded + dataDigest
                guard total <= 16 * 1_048_576 + 1024 else {
                    connection.stopped = "frame too large to be an iSCSI PDU"
                    break
                }
                guard buffer.count >= total else { break }
                let header = Array(buffer[0..<48])
                let start = 48 + headerDigest + additional
                let data = Array(buffer[start..<(start + length)])
                buffer.removeFirst(total)
                connection.buffers[toTarget] = buffer
                handle(connection, header: header, data: data, toTarget: toTarget)
            }
        }
    }

    // MARK: PDU interpretation

    private static func keys(_ data: [UInt8]) -> [(String, String)] {
        data.split(separator: 0, omittingEmptySubsequences: true).compactMap { item in
            let text = String(decoding: item, as: UTF8.self)
            guard let equals = text.firstIndex(of: "=") else { return (text, "") }
            return (String(text[..<equals]), String(text[text.index(after: equals)...]))
        }
    }

    /// Challenges and responses are authentication material; only their length is kept.
    private static func redacted(_ pairs: [(String, String)]) -> [[String]] {
        pairs.prefix(128).map { key, value in
            ["CHAP_C", "CHAP_R"].contains(key)
                ? [key, "<\(value.utf8.count) characters, not recorded>"]
                : [key, String(value.prefix(512))]
        }
    }

    private func handle(_ connection: Connection, header: [UInt8], data: [UInt8], toTarget: Bool) {
        let opcode = header[0] & 0x3F
        let flags = header[1]
        let tag =
            UInt32(header[16]) << 24 | UInt32(header[17]) << 16 | UInt32(header[18]) << 8
            | UInt32(header[19])
        switch (toTarget, opcode) {
        case (true, 0x03), (false, 0x23):
            var pending = connection.pendingText[toTarget] ?? []
            pending.append(contentsOf: data)
            let continues = flags & 0x40 != 0
            connection.pendingText[toTarget] = continues ? pending : []
            let pairs = continues ? [] : Self.keys(pending)
            var row: [String: Any] = [
                "from": toTarget ? "initiator" : "target",
                "currentStage": Int((flags >> 2) & 3), "nextStage": Int(flags & 3),
                "transit": flags & 0x80 != 0, "continues": continues,
                "keys": Self.redacted(pairs),
            ]
            if !toTarget {
                row["statusClass"] = Int(header[36])
                row["statusDetail"] = Int(header[37])
                row["tsih"] = Int(header[14]) << 8 | Int(header[15])
            }
            if connection.login.count < 64 { connection.login.append(row) }
            for (key, value) in pairs where (flags >> 2) & 3 == 1 || key == "AuthMethod" {
                if toTarget {
                    connection.offered[key] = value
                } else {
                    connection.answered[key] = value
                }
            }
            if !toTarget {
                for (key, value) in pairs {
                    if key == "HeaderDigest" { connection.headerDigest = value == "CRC32C" }
                    if key == "DataDigest" { connection.dataDigest = value == "CRC32C" }
                }
                if flags & 0x80 != 0, flags & 3 == 3, header[36] == 0 {
                    connection.fullFeature = true
                }
            }
        case (true, 0x04), (false, 0x24):
            var pending = connection.pendingText[toTarget] ?? []
            pending.append(contentsOf: data)
            let continues = flags & 0x40 != 0
            connection.pendingText[toTarget] = continues ? pending : []
            if !continues, connection.text.count < 64 {
                connection.text.append([
                    "from": toTarget ? "initiator" : "target", "final": flags & 0x80 != 0,
                    "keys": Self.redacted(Self.keys(pending)),
                ])
            }
        case (true, 0x01):
            let cdb = Array(header[32..<48])
            let lun = Int(header[8] & 0x3F) << 8 | Int(header[9])
            var row: [String: Any] = [
                "phase": connection.phase, "lun": lun, "cdb": Self.hex(Self.trimmed(cdb)),
                "name": Self.name(cdb),
                "expectedTransfer": Int(header[20]) << 24 | Int(header[21]) << 16
                    | Int(header[22]) << 8 | Int(header[23]),
                "read": flags & 0x40 != 0, "write": flags & 0x20 != 0,
                "sentNS": RecoveryProbe.now(),
            ]
            row["dataInBytes"] = 0
            if connection.commands.count < 512 {
                connection.tags[tag] = connection.commands.count
                connection.commands.append(row)
            }
        case (false, 0x25):
            if let index = connection.tags[tag] {
                connection.commands[index]["dataInBytes"] =
                    (connection.commands[index]["dataInBytes"] as? Int ?? 0) + data.count
                if flags & 0x01 != 0 {
                    connection.commands[index]["status"] = Int(header[3])
                    connection.tags[tag] = nil
                }
            }
        case (false, 0x21):
            if let index = connection.tags[tag] {
                connection.commands[index]["response"] = Int(header[2])
                connection.commands[index]["status"] = Int(header[3])
                if data.count >= 2 {
                    let length = Int(data[0]) << 8 | Int(data[1])
                    let sense = Array(data.dropFirst(2).prefix(length))
                    if let decoded = Self.sense(sense) {
                        connection.commands[index]["sense"] = decoded
                    }
                }
                connection.tags[tag] = nil
            }
        case (true, 0x00), (false, 0x20):
            connection.nops += 1
        case (true, 0x06):
            event(connection, ["event": "logout-request", "reason": Int(flags & 0x7F)])
        case (false, 0x26):
            event(connection, ["event": "logout-response", "response": Int(header[2])])
        case (false, 0x3F):
            event(connection, ["event": "reject", "reason": Int(header[2])])
        case (false, 0x32):
            event(connection, ["event": "async-message", "code": Int(header[36])])
        default:
            break
        }
    }

    private func event(_ connection: Connection, _ value: [String: Any]) {
        guard connection.events.count < 64 else { return }
        var row = value
        row["ns"] = RecoveryProbe.now()
        connection.events.append(row)
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// The CDB length its group code defines (SPC-4 4.2.5.1).
    private static func trimmed(_ cdb: [UInt8]) -> [UInt8] {
        switch cdb[0] >> 5 {
        case 0: Array(cdb.prefix(6))
        case 1, 2: Array(cdb.prefix(10))
        case 5: Array(cdb.prefix(12))
        default: cdb
        }
    }

    static func name(_ cdb: [UInt8]) -> String {
        switch cdb[0] {
        case 0x00: return "TEST UNIT READY"
        case 0x12:
            return cdb[1] & 1 == 1
                ? String(format: "INQUIRY VPD 0x%02X", Int(cdb[2])) : "INQUIRY"
        case 0x1A: return "MODE SENSE(6)"
        case 0x5A: return "MODE SENSE(10)"
        case 0x25: return "READ CAPACITY(10)"
        case 0x9E: return cdb[1] & 0x1F == 0x10 ? "READ CAPACITY(16)" : "SERVICE ACTION IN(16)"
        case 0xA0: return "REPORT LUNS"
        case 0x28: return "READ(10)"
        case 0x88: return "READ(16)"
        case 0x2A: return "WRITE(10)"
        case 0x8A: return "WRITE(16)"
        case 0x35: return "SYNCHRONIZE CACHE(10)"
        case 0x91: return "SYNCHRONIZE CACHE(16)"
        case 0x42: return "UNMAP"
        case 0x5E: return "PERSISTENT RESERVE IN"
        case 0x5F: return "PERSISTENT RESERVE OUT"
        default: return String(format: "opcode 0x%02X", Int(cdb[0]))
        }
    }

    static func sense(_ bytes: [UInt8]) -> [String: Int]? {
        guard let first = bytes.first else { return nil }
        let format = first & 0x7F
        if format == 0x70 || format == 0x71, bytes.count >= 14 {
            return ["key": Int(bytes[2] & 0x0F), "asc": Int(bytes[12]), "ascq": Int(bytes[13])]
        }
        if format == 0x72 || format == 0x73, bytes.count >= 4 {
            return ["key": Int(bytes[1] & 0x0F), "asc": Int(bytes[2]), "ascq": Int(bytes[3])]
        }
        return nil
    }

    // MARK: Report

    /// The keys the initiator offered in the operational stage and what the target answered.
    private static func negotiation(_ connection: Connection) -> [String: Any] {
        var keys: [String: Any] = [:]
        for key in Set(connection.offered.keys).union(connection.answered.keys) {
            keys[key] = [
                "offered": connection.offered[key].map { $0 as Any } ?? NSNull(),
                "answered": connection.answered[key].map { $0 as Any } ?? NSNull(),
            ]
        }
        return keys
    }

    var report: [[String: Any]] {
        lock.withLock {
            connections.map { connection in
                [
                    "id": connection.id, "label": connection.label, "portal": connection.portal,
                    "connect": connection.connect, "openedNS": connection.openedNS,
                    "closedNS": connection.closedNS.map { $0 as Any } ?? NSNull(),
                    "login": connection.login, "text": connection.text,
                    "negotiated": Self.negotiation(connection),
                    "digests": [
                        "header": connection.headerDigest ? "CRC32C" : "None",
                        "data": connection.dataDigest ? "CRC32C" : "None",
                    ],
                    "fullFeature": connection.fullFeature, "commands": connection.commands,
                    "events": connection.events, "nops": connection.nops,
                    "recordingStopped": connection.stopped.map { $0 as Any } ?? NSNull(),
                ]
            }
        }
    }
}

/// A TCP connection whose bytes the recorder sees, in the order the session submits and
/// receives them. Recording happens at submission, so a send that then fails is still listed.
final class RecordingTransport: ConnectableByteTransport, SendAdmissionTransport, Sendable {
    private let inner: TCPTransport
    private let recorder: WireRecorder
    private let id: Int

    init(
        portal: Portal, timeout: TimeInterval, label: String, recorder: WireRecorder,
        localNetworkAccessWait: LocalNetworkAccessWait?
    ) throws {
        inner = try TCPTransport(
            portal: portal, timeout: timeout, waitForConnectivity: false,
            localNetworkAccessWait: localNetworkAccessWait)
        self.recorder = recorder
        id = recorder.open(label: label, portal: portal)
    }

    func connect() async throws {
        let began = RecoveryProbe.now()
        do {
            try await inner.connect()
            recorder.connected(id, began: began, error: nil)
        } catch {
            recorder.connected(id, began: began, error: error)
            throw error
        }
    }

    func send(_ data: Data) async throws {
        recorder.observe(id, toTarget: true, bytes: data)
        try await inner.send(data)
    }

    func send(
        _ data: Data, whileAdmitted: @escaping @Sendable (_ submit: () -> Void) throws -> Void
    ) async throws {
        recorder.observe(id, toTarget: true, bytes: data)
        try await inner.send(data, whileAdmitted: whileAdmitted)
    }

    func receive(maximumLength: Int) async throws -> Data {
        let data = try await inner.receive(maximumLength: maximumLength)
        recorder.observe(id, toTarget: false, bytes: data)
        return data
    }

    func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data {
        let data = try await inner.receive(
            maximumLength: maximumLength, waitingForActivity: waitingForActivity)
        recorder.observe(id, toTarget: false, bytes: data)
        return data
    }

    func close() async {
        await inner.close()
        recorder.closed(id)
    }
}
