import Foundation

/// Choose the sector units of an existing partition map without changing bytes.
/// A legacy 512-byte GPT may live on a target with larger SCSI blocks. Otherwise
/// the target's immutable geometry is the default, including for blank media.
public enum DiskImageGeometry {
    public static let prefixByteCount = 131_072

    public static func blockSize(
        prefix: Data, byteCount: UInt64, sourceBlockSize: UInt32? = nil
    ) throws -> UInt32 {
        guard prefix.count <= prefixByteCount, byteCount >= 512,
            byteCount <= UInt64(Int64.max), byteCount % 512 == 0
        else { throw ProtocolError.malformed("image geometry") }
        if let sourceBlockSize {
            try validateBlockSize(sourceBlockSize)
            guard byteCount % UInt64(sourceBlockSize) == 0 else {
                throw ProtocolError.malformed("source geometry capacity")
            }
        }
        let bytes = [UInt8](prefix)
        let matches = (9...16).map { UInt32(1) << $0 }.filter {
            validPrimaryHeader(bytes, byteCount: byteCount, blockSize: $0)
        }
        guard matches.count <= 1 else {
            throw ProtocolError.malformed("ambiguous partition geometry")
        }
        return matches.first ?? sourceBlockSize ?? 512
    }

    public static func sourceBlockSize(from attribute: Data) throws -> UInt32 {
        guard attribute.count == 4 else { throw ProtocolError.malformed("source block size") }
        let value = [UInt8](attribute).uint32(at: 0)
        try validateBlockSize(value)
        return value
    }

    private static func validateBlockSize(_ size: UInt32) throws {
        guard (512...65_536).contains(size), size.nonzeroBitCount == 1 else {
            throw ProtocolError.unsupported("source block size")
        }
    }

    private static func validPrimaryHeader(
        _ bytes: [UInt8], byteCount: UInt64, blockSize: UInt32
    ) -> Bool {
        let block = UInt64(blockSize)
        let at = Int(blockSize)
        guard byteCount % block == 0, byteCount / block >= 3, bytes.count >= at + 92,
            Array(bytes[at..<(at + 8)]) == Array("EFI PART".utf8),
            bytes.little32(at + 8) == 0x0001_0000,
            bytes.little32(at + 20) == 0, bytes.little64(at + 24) == 1
        else { return false }
        let size = Int(bytes.little32(at + 12))
        guard (92...at).contains(size), bytes.count >= at + size else { return false }
        let backup = bytes.little64(at + 32)
        let first = bytes.little64(at + 40)
        let last = bytes.little64(at + 48)
        let table = bytes.little64(at + 72)
        let entries = UInt64(bytes.little32(at + 80))
        let entrySize = UInt64(bytes.little32(at + 84))
        guard entries > 0, entrySize >= 128, entrySize.nonzeroBitCount == 1,
            table >= 2, first >= table, last >= first, backup > last,
            backup < byteCount / block
        else { return false }
        let tableBlocks = (entries * entrySize - 1) / block + 1
        guard tableBlocks <= first - table else { return false }
        var header = Array(bytes[at..<(at + size)])
        header.replaceSubrange(16..<20, with: [0, 0, 0, 0])
        return crc32(header) == bytes.little32(at + 16)
    }

    private static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc >> 1) ^ (crc & 1 == 0 ? 0 : 0xEDB8_8320)
            }
        }
        return ~crc
    }
}

extension [UInt8] {
    fileprivate func little32(_ offset: Int) -> UInt32 {
        (0..<4).reduce(0) { $0 | UInt32(self[offset + $1]) << ($1 * 8) }
    }
    fileprivate func little64(_ offset: Int) -> UInt64 {
        (0..<8).reduce(0) { $0 | UInt64(self[offset + $1]) << ($1 * 8) }
    }
}
