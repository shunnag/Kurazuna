import Foundation

/// The READ/WRITE limit reported by the Block Limits VPD page (SBC-4, 6.6.4).
/// Zero means that this page does not report a limit, rather than zero blocks per I/O.
public struct SCSIBlockLimits: Sendable, Equatable {
    public let maximumTransferBlocks: UInt32

    /// Decode the prefix requested by SCSICommand.blockLimits(). A future longer page
    /// may be truncated to our allocation, while every field we consume must be present.
    public init(data: Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 12, bytes[0] == 0, bytes[1] == 0xB0 else {
            throw ProtocolError.malformed("Block Limits VPD header")
        }
        let reported = 4 + Int(bytes.uint16(at: 2))
        guard reported >= 12, bytes.count >= min(reported, 64) else {
            throw ProtocolError.malformed("truncated Block Limits VPD page")
        }
        maximumTransferBlocks = bytes.uint32(at: 8)
    }
}
