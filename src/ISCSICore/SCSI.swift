import Foundation

public struct LogicalUnit: Sendable, Equatable, Hashable, Codable {
    /// SAM's eight-byte address is opaque to iSCSI. Never normalize a reported address.
    public let wireBytes: [UInt8]

    public init(_ number: UInt16) throws {
        guard number <= 0x3FFF else { throw ProtocolError.unsupported("LUN addressing method") }
        wireBytes =
            [number > 255 ? (0x40 | UInt8(number >> 8)) : 0, UInt8(truncatingIfNeeded: number)]
            + Array(repeating: 0, count: 6)
    }

    public init(wireBytes: [UInt8]) throws {
        guard wireBytes.count == 8 else { throw ProtocolError.malformed("LUN address length") }
        self.wireBytes = wireBytes
    }

    public init(addressKey: String) throws {
        guard addressKey.utf8.count == 16 else {
            throw ProtocolError.malformed("LUN address length")
        }
        try self.init(wireBytes: Array(CHAP.decodeBinary("0x" + addressKey)))
    }

    public var addressKey: String { wireBytes.map { String(format: "%02x", $0) }.joined() }

    /// Keep identifiers from the initial numeric API stable for its canonical addresses.
    public var stableIdentifier: String {
        if wireBytes.dropFirst(2).allSatisfy({ $0 == 0 }) {
            if wireBytes[0] == 0 { return String(wireBytes[1]) }
            if wireBytes[0] & 0xC0 == 0x40 {
                let number = UInt16(wireBytes[0] & 0x3F) << 8 | UInt16(wireBytes[1])
                if number > 255 { return String(number) }
            }
        }
        return "0x" + addressKey
    }

    public var displayIdentifier: String { stableIdentifier }
    private enum CodingKeys: String, CodingKey { case address, number }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let address = try container.decodeIfPresent(String.self, forKey: .address) {
            guard !container.contains(.number) else {
                throw ProtocolError.malformed("ambiguous LUN encoding")
            }
            try self.init(addressKey: address)
        } else {
            try self.init(container.decode(UInt16.self, forKey: .number))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(addressKey, forKey: .address)
    }
}

public struct SCSICommand: Sendable, Equatable {
    public enum Direction: Sendable { case none, read, write }
    public let cdb: [UInt8]
    public let direction: Direction
    public let transferLength: UInt32
    public let requiresExactTransfer: Bool

    private init(
        cdb: [UInt8], direction: Direction, transferLength: UInt32 = 0,
        requiresExactTransfer: Bool = false
    ) {
        self.cdb = cdb
        self.direction = direction
        self.transferLength = transferLength
        self.requiresExactTransfer = requiresExactTransfer
    }

    public static func testUnitReady() -> Self {
        Self(cdb: Array(repeating: 0, count: 16), direction: .none)
    }

    public static func inquiry(allocationLength: UInt8 = 96) -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x12
        cdb[4] = allocationLength
        return Self(cdb: cdb, direction: .read, transferLength: UInt32(allocationLength))
    }

    public static func blockLimits() -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x12
        cdb[1] = 1  // EVPD
        cdb[2] = 0xB0
        cdb.put(UInt16(64), at: 3)
        return Self(cdb: cdb, direction: .read, transferLength: 64)
    }

    public static func deviceIdentification(allocationLength: UInt16 = .max) throws -> Self {
        guard allocationLength >= 4 else {
            throw ProtocolError.limitExceeded("device identification allocation")
        }
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x12
        cdb[1] = 1
        cdb[2] = 0x83
        cdb.put(allocationLength, at: 3)
        return Self(cdb: cdb, direction: .read, transferLength: UInt32(allocationLength))
    }

    public static func persistentReservation(
        _ query: SCSIReservationQuery, allocationLength: UInt16 = .max
    ) throws -> Self {
        guard allocationLength >= 8 else {
            throw ProtocolError.limitExceeded("persistent reservation allocation")
        }
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x5E
        cdb[1] = query.rawValue
        cdb.put(allocationLength, at: 7)
        return Self(cdb: cdb, direction: .read, transferLength: UInt32(allocationLength))
    }

    public static func modeSense10(headerOnly: Bool = false) -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x5A
        cdb[1] = 8  // DBD: the write-protection bit is in the header.
        cdb[2] = headerOnly ? 0 : 0x3F
        cdb.put(UInt16(8), at: 7)
        return Self(cdb: cdb, direction: .read, transferLength: 8)
    }

    static func reservationControl(_ action: SCSIReservationAction) -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x5F
        cdb[1] = action.rawValue
        cdb[2] = action == .register ? 0 : SCSIReservationType.writeExclusive.rawValue
        cdb.put(UInt32(24), at: 5)
        return Self(cdb: cdb, direction: .write, transferLength: 24, requiresExactTransfer: true)
    }

    public static func modeSense6(headerOnly: Bool = false) -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x1A
        cdb[1] = 8
        cdb[2] = headerOnly ? 0 : 0x3F
        cdb[4] = 4
        return Self(cdb: cdb, direction: .read, transferLength: 4)
    }

    public static func readCapacity16() -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x9E
        cdb[1] = 0x10
        cdb.put(UInt32(32), at: 10)
        return Self(cdb: cdb, direction: .read, transferLength: 32)
    }

    public static func readCapacity10() -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x25
        return Self(cdb: cdb, direction: .read, transferLength: 8)
    }

    public static func reportLUNs(allocationLength: UInt32 = 4096) throws -> Self {
        guard (16...1_048_576).contains(allocationLength) else {
            throw ProtocolError.limitExceeded("REPORT LUNS allocation")
        }
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0xA0
        cdb.put(allocationLength, at: 6)
        return Self(cdb: cdb, direction: .read, transferLength: allocationLength)
    }

    public static func read(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        if fitsIn10(lba: lba, blocks: blocks) {
            return try read10(lba: lba, blocks: blocks, blockSize: blockSize)
        }
        return try read16(lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func write(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        if fitsIn10(lba: lba, blocks: blocks) {
            return try write10(lba: lba, blocks: blocks, blockSize: blockSize)
        }
        return try write16(lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func read10(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        try blockCommand10(
            opcode: 0x28, direction: .read, lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func write10(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        try blockCommand10(
            opcode: 0x2A, direction: .write, lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func read16(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        try blockCommand(
            opcode: 0x88, direction: .read, lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func write16(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws -> Self {
        try blockCommand(
            opcode: 0x8A, direction: .write, lba: lba, blocks: blocks, blockSize: blockSize)
    }

    public static func synchronizeCache10() -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x35
        // LBA=0, count=0 covers the whole LUN, including media larger than 32-bit LBA.
        // IMMED remains clear: only the completed flush may be reported as success.
        return Self(cdb: cdb, direction: .none)
    }

    public static func synchronizeCache16() -> Self {
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = 0x91
        // IMMED remains clear. Success means the target completed the flush.
        return Self(cdb: cdb, direction: .none)
    }

    private static func blockCommand(
        opcode: UInt8, direction: Direction, lba: UInt64, blocks: UInt32, blockSize: UInt32
    ) throws -> Self {
        let length = try transferLength(lba: lba, blocks: blocks, blockSize: blockSize)
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = opcode
        cdb.put(lba, at: 2)
        cdb.put(blocks, at: 10)
        return Self(
            cdb: cdb, direction: direction, transferLength: length, requiresExactTransfer: true)
    }

    private static func blockCommand10(
        opcode: UInt8, direction: Direction, lba: UInt64, blocks: UInt32, blockSize: UInt32
    ) throws -> Self {
        let length = try transferLength(lba: lba, blocks: blocks, blockSize: blockSize)
        guard fitsIn10(lba: lba, blocks: blocks) else {
            throw ProtocolError.limitExceeded("10-byte block transfer")
        }
        // The iSCSI BHS always has 16 bytes for the CDB. Unused bytes stay zero.
        var cdb = Array(repeating: UInt8(0), count: 16)
        cdb[0] = opcode
        cdb.put(UInt32(lba), at: 2)
        cdb.put(UInt16(blocks), at: 7)
        return Self(
            cdb: cdb, direction: direction, transferLength: length, requiresExactTransfer: true)
    }

    private static func fitsIn10(lba: UInt64, blocks: UInt32) -> Bool {
        guard blocks > 0, blocks <= UInt16.max, lba <= UInt32.max else { return false }
        return UInt64(blocks) - 1 <= UInt64(UInt32.max) - lba
    }

    private static func transferLength(lba: UInt64, blocks: UInt32, blockSize: UInt32) throws
        -> UInt32
    {
        let (length, overflow) = blocks.multipliedReportingOverflow(by: blockSize)
        guard !overflow, length > 0, length <= 1_048_576,
            !lba.addingReportingOverflow(UInt64(blocks) - 1).overflow
        else { throw ProtocolError.limitExceeded("block transfer") }
        return length
    }
}

public struct DiskCapacity: Sendable, Equatable {
    public let blockCount: UInt64
    public let blockSize: UInt32
    public let byteCount: UInt64

    public init(readCapacity16 data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 32 else { throw ProtocolError.malformed("READ CAPACITY(16)") }
        try self.init(lastBlock: bytes.uint64(at: 0), size: bytes.uint32(at: 8))
    }

    public init(readCapacity10 data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8 else { throw ProtocolError.malformed("READ CAPACITY(10)") }
        let lastBlock = bytes.uint32(at: 0)
        guard lastBlock != UInt32.max else {
            throw ProtocolError.unsupported("capacity requires READ CAPACITY(16)")
        }
        try self.init(lastBlock: UInt64(lastBlock), size: bytes.uint32(at: 4))
    }

    private init(lastBlock: UInt64, size: UInt32) throws {
        guard lastBlock != UInt64.max, size >= 512, size <= 65_536, size.nonzeroBitCount == 1 else {
            throw ProtocolError.unsupported("disk geometry")
        }
        let count = lastBlock + 1
        let (total, overflow) = count.multipliedReportingOverflow(by: UInt64(size))
        guard !overflow, total <= UInt64(Int64.max) else {
            throw ProtocolError.limitExceeded("disk capacity")
        }
        self.blockCount = count
        self.blockSize = size
        self.byteCount = total
    }
}

public struct SCSISense: Sendable, Equatable {
    /// A deferred error describes an earlier command, even if its key resembles a
    /// retryable condition or an unsupported opcode on the command receiving it.
    public let isDeferred: Bool
    public let key: UInt8
    public let additionalSenseCode: UInt8
    public let qualifier: UInt8

    public init(data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, bytes.count >= 8 + Int(bytes[7]) else {
            throw ProtocolError.malformed("truncated SCSI sense")
        }
        switch bytes[0] & 0x7F {
        case 0x70, 0x71:
            guard bytes.count >= 14, bytes[7] >= 6 else {
                throw ProtocolError.malformed("fixed SCSI sense")
            }
            key = bytes[2] & 0x0F
            additionalSenseCode = bytes[12]
            qualifier = bytes[13]
            isDeferred = bytes[0] & 0x7F == 0x71
        case 0x72, 0x73:
            key = bytes[1] & 0x0F
            additionalSenseCode = bytes[2]
            qualifier = bytes[3]
            isDeferred = bytes[0] & 0x7F == 0x73
        default: throw ProtocolError.malformed("SCSI sense response code")
        }
    }

    public var isUnitAttention: Bool { key == 6 }
    public var isUnsupportedCommand: Bool {
        key == 5 && qualifier == 0 && (additionalSenseCode == 0x20 || additionalSenseCode == 0x24)
    }
}

public enum LUNList {
    public static func decode(_ data: Data) throws -> [LogicalUnit] {
        let bytes = [UInt8](data)
        guard bytes.count >= 8 else { throw ProtocolError.malformed("REPORT LUNS header") }
        let length = Int(bytes.uint32(at: 0))
        guard length % 8 == 0, length <= 65_528, length <= bytes.count - 8 else {
            throw ProtocolError.malformed("REPORT LUNS length")
        }
        var result: [LogicalUnit] = []
        for offset in stride(from: 8, to: 8 + length, by: 8) {
            let lun = try LogicalUnit(wireBytes: Array(bytes[offset..<(offset + 8)]))
            guard !result.contains(lun) else { throw ProtocolError.malformed("duplicate LUN") }
            result.append(lun)
        }
        return result
    }
}
