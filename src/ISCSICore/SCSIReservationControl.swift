import Foundation

/// Deliberately excludes CLEAR, PREEMPT, IGNORE EXISTING KEY and registration replacement.
public enum SCSIReservationAction: UInt8, Sendable {
    case register = 0
    case reserve = 1
    case release = 2
}

public struct SCSIReservationControl: Sendable, Equatable {
    public let command: SCSICommand
    public let parameters: Data

    public init(action: SCSIReservationAction, key: UInt64, newKey: UInt64 = 0) throws {
        if action == .register {
            guard (key == 0) != (newKey == 0) else { throw ProtocolError.invalidState }
        } else {
            guard key != 0, newKey == 0 else { throw ProtocolError.invalidState }
        }
        command = .reservationControl(action)
        var bytes = Array(repeating: UInt8(0), count: 24)
        bytes.put(key, at: 0)
        bytes.put(newKey, at: 8)
        // APTPL, ALL_TG_PT and SPEC_I_PT stay zero: only this live initiator/target nexus.
        parameters = Data(bytes)
    }
}

/// An actual initiator-port TransportID. Node-only format cannot identify an I_T nexus.
public struct ISCSIReservationPort: Sendable, Equatable {
    public let initiatorName: String
    public let isid: [UInt8]

    public init(data: Data) throws {
        let bytes = Array(data)
        guard bytes.count >= 24, bytes[0] == 0x45, bytes[1] == 0,
            Int(bytes.uint16(at: 2)) == bytes.count - 4, (bytes.count - 4) % 4 == 0,
            bytes.count <= 256,
            let end = bytes[4...].firstIndex(of: 0), bytes[end...].allSatisfy({ $0 == 0 }),
            let text = String(bytes: bytes[4..<end], encoding: .ascii),
            let separator = text.range(of: ",i,0x"),
            text.range(of: ",i,0x", range: separator.upperBound..<text.endIndex) == nil
        else { throw ProtocolError.malformed("iSCSI reservation port") }
        let name = String(text[..<separator.lowerBound])
        let hex = String(text[separator.upperBound...])
        guard !name.isEmpty, name.utf8.count <= 223, !name.contains(","),
            hex.utf8.count == 12,
            hex.utf8.allSatisfy({
                (48...57).contains($0) || (97...102).contains($0) || (65...70).contains($0)
            })
        else { throw ProtocolError.malformed("iSCSI reservation initiator port") }
        initiatorName = name
        isid = Array(try CHAP.decodeBinary("0x" + hex))
    }
}
