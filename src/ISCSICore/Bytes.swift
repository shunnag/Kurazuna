import Foundation

extension Array where Element == UInt8 {
    public func uint16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }

    public func uint32(at offset: Int) -> UInt32 {
        (0..<4).reduce(0) { ($0 << 8) | UInt32(self[offset + $1]) }
    }

    public func uint64(at offset: Int) -> UInt64 {
        (0..<8).reduce(0) { ($0 << 8) | UInt64(self[offset + $1]) }
    }

    public mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        for index in 0..<MemoryLayout<T>.size {
            self[offset + index] = UInt8(
                truncatingIfNeeded: value >> ((MemoryLayout<T>.size - index - 1) * 8))
        }
    }
}

/// RFC 1982 serial arithmetic. Exactly half the sequence space is deliberately unordered.
public enum SerialNumber {
    public static func precedes(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
        let distance = rhs &- lhs
        return distance > 0 && distance < 0x8000_0000
    }

    public static func isWithin(_ value: UInt32, first: UInt32, last: UInt32) -> Bool {
        let width = last &- first
        return width < 0x8000_0000 && value &- first <= width
    }
}
