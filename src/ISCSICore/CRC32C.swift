import Foundation

public enum CRC32C {
    private static let table: [UInt32] = (0..<256).map { value in
        (0..<8).reduce(UInt32(value)) { crc, _ in
            (crc >> 1) ^ ((crc & 1) == 1 ? 0x82F6_3B78 : 0)
        }
    }

    public static func checksum(_ bytes: some Sequence<UInt8>) -> UInt32 {
        ~bytes.reduce(UInt32.max) { crc, byte in
            (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 0xFF)]
        }
    }

    /// iSCSI transmits the CRC's least significant byte first.
    public static func wireBytes(_ bytes: some Sequence<UInt8>) -> [UInt8] {
        let crc = checksum(bytes)
        return (0..<4).map { UInt8(truncatingIfNeeded: crc >> ($0 * 8)) }
    }
}
