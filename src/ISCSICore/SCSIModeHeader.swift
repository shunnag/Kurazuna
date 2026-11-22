import Foundation

/// The common mode header's device-specific WP bit for direct-access block devices.
public struct SCSIModeHeader: Sendable, Equatable {
    public let isWriteProtected: Bool

    public init(modeSense10 data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, bytes.uint16(at: 0) >= 6,
            bytes.uint16(at: 6) <= bytes.uint16(at: 0) - 6
        else {
            throw ProtocolError.malformed("MODE SENSE(10) header")
        }
        // Only a header was allocated. A longer reported list is valid truncation.
        isWriteProtected = bytes[3] & 0x80 != 0
    }

    public init(modeSense6 data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 4, bytes[0] >= 3, bytes[3] <= bytes[0] - 3 else {
            throw ProtocolError.malformed("MODE SENSE(6) header")
        }
        isWriteProtected = bytes[2] & 0x80 != 0
    }
}
