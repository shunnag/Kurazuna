import Foundation

public enum SCSIReservationType: UInt8, Sendable, CaseIterable {
    case writeExclusive = 1
    case exclusiveAccess = 3
    case writeExclusiveRegistrants = 5
    case exclusiveAccessRegistrants = 6
    case writeExclusiveAllRegistrants = 7
    case exclusiveAccessAllRegistrants = 8
}

public enum SCSIReservationQuery: UInt8, Sendable {
    case keys = 0
    case reservation = 1
    case capabilities = 2
    case fullStatus = 3
}

public struct SCSIReservationKeys: Sendable, Equatable {
    public let generation: UInt32
    /// Duplicates identify distinct registrations and must not be removed.
    public let keys: [UInt64]

    public init(data: Data) throws {
        let bytes = try reservationBytes(data)
        let length = Int(bytes.uint32(at: 4))
        guard length % 8 == 0 else { throw ProtocolError.malformed("reservation key list") }
        generation = bytes.uint32(at: 0)
        keys = stride(from: 8, to: 8 + length, by: 8).map { bytes.uint64(at: $0) }
        guard !keys.contains(0) else { throw ProtocolError.malformed("zero reservation key") }
    }
}

public struct SCSIReservation: Sendable, Equatable {
    public struct Holder: Sendable, Equatable {
        public let key: UInt64
        public let type: SCSIReservationType
    }
    public let generation: UInt32
    public let holder: Holder?

    public init(data: Data) throws {
        let bytes = try reservationBytes(data)
        generation = bytes.uint32(at: 0)
        let length = bytes.uint32(at: 4)
        guard length == 0 || length == 16 else {
            throw ProtocolError.malformed("reservation descriptor length")
        }
        if length == 0 {
            holder = nil
            return
        }
        guard bytes[21] >> 4 == 0,
            let type = SCSIReservationType(rawValue: bytes[21] & 15)
        else { throw ProtocolError.unsupported("reservation scope or type") }
        let key = bytes.uint64(at: 8)
        let allRegistrants =
            type == .writeExclusiveAllRegistrants || type == .exclusiveAccessAllRegistrants
        guard allRegistrants ? key == 0 : key != 0 else {
            throw ProtocolError.malformed("reservation holder key")
        }
        holder = Holder(key: key, type: type)
    }
}

public struct SCSIReservationCapabilities: Sendable, Equatable {
    public let persistThroughPowerLossCapable: Bool
    public let persistThroughPowerLossActive: Bool
    public let allTargetPortsCapable: Bool
    /// nil means the target did not validate its type mask, not that all types are supported.
    public let supportedTypes: Set<SCSIReservationType>?

    public init(data: Data) throws {
        guard data.count >= 8, data.count <= Int(UInt16.max) else {
            throw ProtocolError.malformed("reservation capabilities")
        }
        let bytes = Array(data.prefix(8))
        guard bytes.uint16(at: 0) == 8 else {
            throw ProtocolError.malformed("reservation capabilities length")
        }
        persistThroughPowerLossCapable = bytes[2] & 1 != 0
        persistThroughPowerLossActive = bytes[3] & 1 != 0
        allTargetPortsCapable = bytes[2] & 4 != 0
        if bytes[3] & 0x80 != 0 {
            let positions: [(SCSIReservationType, Int, UInt8)] = [
                (.writeExclusive, 4, 2), (.exclusiveAccess, 4, 8),
                (.writeExclusiveRegistrants, 4, 0x20), (.exclusiveAccessRegistrants, 4, 0x40),
                (.writeExclusiveAllRegistrants, 4, 0x80), (.exclusiveAccessAllRegistrants, 5, 1),
            ]
            supportedTypes = Set(positions.compactMap { bytes[$0.1] & $0.2 != 0 ? $0.0 : nil })
        } else {
            supportedTypes = nil
        }
    }
}

public struct SCSIReservationFullStatus: Sendable, Equatable {
    public struct Registration: Sendable, Equatable {
        public let key: UInt64
        public let isHolder: Bool
        public let allTargetPorts: Bool
        public let type: SCSIReservationType?
        public let relativeTargetPort: UInt16?
        /// Remains protocol data. It is never accepted as a lease or rendered as untrusted text.
        public let transportID: Data
    }
    public let generation: UInt32
    public let registrations: [Registration]

    public init(data: Data) throws {
        let bytes = try reservationBytes(data)
        generation = bytes.uint32(at: 0)
        let end = 8 + Int(bytes.uint32(at: 4))
        var cursor = 8
        var rows: [Registration] = []
        while cursor < end {
            guard end - cursor >= 24 else {
                throw ProtocolError.malformed("reservation full status descriptor")
            }
            let additional = Int(bytes.uint32(at: cursor + 20))
            guard additional >= 24, additional <= end - cursor - 24 else {
                throw ProtocolError.malformed("reservation transport identifier length")
            }
            let key = bytes.uint64(at: cursor)
            guard key != 0 else { throw ProtocolError.malformed("zero reservation registration") }
            let holder = bytes[cursor + 12] & 1 != 0
            let allPorts = bytes[cursor + 12] & 2 != 0
            let type: SCSIReservationType?
            if holder {
                guard bytes[cursor + 13] >> 4 == 0,
                    let known = SCSIReservationType(rawValue: bytes[cursor + 13] & 15)
                else { throw ProtocolError.unsupported("reservation full status type") }
                type = known
            } else {
                type = nil  // Scope/type have no defined meaning for non-holders.
            }
            rows.append(
                Registration(
                    key: key, isHolder: holder, allTargetPorts: allPorts,
                    type: type, relativeTargetPort: allPorts ? nil : bytes.uint16(at: cursor + 18),
                    transportID: Data(bytes[(cursor + 24)..<(cursor + 24 + additional)])))
            cursor += 24 + additional
        }
        registrations = rows
    }
}

/// Bounds the declared body before allocating or indexing any descriptor.
private func reservationBytes(_ data: Data) throws -> [UInt8] {
    guard (8...Int(UInt16.max)).contains(data.count) else {
        throw ProtocolError.malformed("reservation response length")
    }
    let header = Array(data.prefix(8))
    let additional = header.uint32(at: 4)
    guard additional <= UInt16.max - 8 else {
        throw ProtocolError.limitExceeded("reservation response")
    }
    let end = 8 + Int(additional)
    guard end <= data.count else { throw ProtocolError.malformed("truncated reservation response") }
    return Array(data.prefix(end))
}
