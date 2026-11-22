import Foundation

/// An entirely allocated UDSP view. Headers are generated locally; every payload
/// byte has one fixed position in the LUN. No allocation table is changed at runtime.
public struct SparseImageLayout: Sendable, Equatable {
    public static let headerByteCount: UInt64 = 4096
    public static let maximumRequestLength = 16 * 1_048_576
    public let capacity: UInt64
    public let bandSize: UInt64
    public let headerCount: UInt64
    public let imageByteCount: UInt64
    private let bandCount: UInt64

    public enum Segment: Sendable, Equatable {
        case header(index: UInt64, offset: Int, length: Int)
        case payload(offset: UInt64, length: Int)
        case padding(length: Int)

        public var length: Int {
            switch self {
            case .header(_, _, let length), .payload(_, let length), .padding(let length): length
            }
        }
    }

    public init(capacity: UInt64, bandSize requestedBandSize: UInt64? = nil) throws {
        guard capacity >= 512, capacity % 512 == 0, capacity <= UInt64(Int64.max) else {
            throw ProtocolError.malformed("sparse image capacity")
        }
        var bandSize = requestedBandSize ?? 64 * 1_048_576
        if requestedBandSize == nil {
            while (capacity - 1) / bandSize + 1 > UInt64(UInt32.max) { bandSize *= 2 }
            // Keep at least one zero sector in the last allocated physical band.
            // Otherwise an opaque UDIF trailer at LUN EOF is also the container's
            // EOF and can be mistaken for an outer encoding before UDSP is opened.
            while capacity % bandSize == 0 { bandSize += 512 }
        }
        guard bandSize >= 4096, bandSize % 512 == 0,
            bandSize / 512 <= UInt64(UInt32.max)
        else { throw ProtocolError.malformed("sparse image band size") }
        let bands = (capacity - 1) / bandSize + 1
        guard bands <= UInt64(UInt32.max) else {
            throw ProtocolError.limitExceeded("sparse image bands")
        }
        let headers = bands <= 1008 ? 1 : 1 + (bands - 1008 + 1009) / 1010
        // Capacity is at most Int64.max; the final band and small header overhead
        // cannot overflow UInt64, but the exposed file must still fit POSIX off_t.
        let bytes = bands * bandSize + headers * Self.headerByteCount
        guard bytes <= UInt64(Int64.max) else {
            throw ProtocolError.limitExceeded("sparse image file size")
        }
        self.capacity = capacity
        self.bandSize = bandSize
        self.bandCount = bands
        self.headerCount = headers
        self.imageByteCount = bytes
    }

    public init(firstHeader: Data, imageByteCount: UInt64) throws {
        guard firstHeader.count == Int(Self.headerByteCount) else {
            throw ProtocolError.malformed("sparse image header size")
        }
        let bytes = [UInt8](firstHeader)
        let sectors = bytes.uint64(at: 28)
        guard sectors <= UInt64(Int64.max) / 512 else {
            throw ProtocolError.limitExceeded("sparse image capacity")
        }
        try self.init(capacity: sectors * 512, bandSize: UInt64(bytes.uint32(at: 8)) * 512)
        guard self.imageByteCount == imageByteCount, try header(at: 0) == firstHeader else {
            throw ProtocolError.malformed("sparse image fixed mapping")
        }
    }

    private func firstBand(in header: UInt64) -> UInt64 {
        header == 0 ? 0 : 1008 + (header - 1) * 1010
    }

    public func headerOffset(at index: UInt64) throws -> UInt64 {
        guard index < headerCount else {
            throw ProtocolError.malformed("sparse image header index")
        }
        return firstBand(in: index) * bandSize + index * Self.headerByteCount
    }

    public func header(at index: UInt64) throws -> Data {
        guard index < headerCount else {
            throw ProtocolError.malformed("sparse image header index")
        }
        var bytes = [UInt8](repeating: 0, count: Int(Self.headerByteCount))
        bytes.replaceSubrange(0..<4, with: [0x73, 0x70, 0x72, 0x73])
        let next = index + 1 < headerCount ? try headerOffset(at: index + 1) : 0
        let tableOffset: Int
        let slots: UInt64
        if index == 0 {
            bytes.put(UInt32(3), at: 4)
            bytes.put(UInt32(bandSize / 512), at: 8)
            bytes.put(UInt32(1), at: 12)
            bytes.put(UInt32(truncatingIfNeeded: capacity / 512), at: 16)
            bytes.put(next, at: 20)
            bytes.put(capacity / 512, at: 28)
            tableOffset = 64
            slots = 1008
        } else {
            bytes.put(UInt32(index - 1), at: 4)
            bytes.put(UInt32(1), at: 8)
            bytes.put(next, at: 12)
            tableOffset = 56
            slots = 1010
        }
        let first = firstBand(in: index)
        for slot in 0..<min(slots, bandCount - first) {
            bytes.put(UInt32(first + slot + 1), at: tableOffset + Int(slot) * 4)
        }
        return Data(bytes)
    }

    public func physicalOffset(forLUNOffset offset: UInt64) throws -> UInt64 {
        guard offset < capacity else { throw ProtocolError.malformed("sparse image LUN offset") }
        let band = offset / bandSize
        let header = band < 1008 ? 0 : 1 + (band - 1008) / 1010
        return offset + (header + 1) * Self.headerByteCount
    }

    public func segments(at offset: UInt64, length: Int) throws -> [Segment] {
        guard (0...Self.maximumRequestLength).contains(length), offset <= imageByteCount,
            UInt64(length) <= imageByteCount - offset
        else { throw ProtocolError.malformed("sparse image I/O range") }
        let firstGroupEnd = Self.headerByteCount + 1008 * bandSize
        let groupLength = Self.headerByteCount + 1010 * bandSize
        var position = offset
        var remaining = length
        var result: [Segment] = []
        while remaining > 0 {
            let group = position < firstGroupEnd ? 0 : 1 + (position - firstGroupEnd) / groupLength
            let start = try headerOffset(at: group)
            let relative = position - start
            let count: Int
            if relative < Self.headerByteCount {
                count = min(remaining, Int(Self.headerByteCount - relative))
                result.append(.header(index: group, offset: Int(relative), length: count))
            } else {
                let logical = position - (group + 1) * Self.headerByteCount
                if logical >= capacity {
                    count = remaining
                    result.append(.padding(length: count))
                } else {
                    let end =
                        group + 1 < headerCount ? try headerOffset(at: group + 1) : imageByteCount
                    count = Int(min(UInt64(remaining), min(capacity - logical, end - position)))
                    result.append(.payload(offset: logical, length: count))
                }
            }
            position += UInt64(count)
            remaining -= count
        }
        return result
    }
}
