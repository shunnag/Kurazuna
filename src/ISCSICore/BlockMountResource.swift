import CryptoKit
import Foundation

/// A local marker carries only a reference to immutable, user-scoped connection metadata.
/// Its digest detects damaged bytes; resolving and validating the reference authorizes a load.
public struct BlockMountResource: Sendable, Equatable {
    public static let mediaByteCount: UInt64 = 1_048_576
    public static let headerByteCount = 8192
    public static let logicalBlockSize: UInt64 = 512
    private static let referenceByteCount = 121
    private static let magic: Data = {
        let prefix = Data("soba.dev/iscsi/mount-resource/1".utf8)
        return prefix + Data(repeating: 0, count: 32 - prefix.count)
    }()

    public let reference: ConnectionResourceReference

    public init(reference: ConnectionResourceReference) {
        self.reference = reference
    }

    public init(header: Data) throws {
        guard header.count == Self.headerByteCount else {
            throw ProtocolError.malformed("block mount header length")
        }
        // Normalize collection indices, including a header supplied as a Data slice.
        let bytes = Array(header)
        guard Data(bytes[0..<32]) == Self.magic else {
            throw ProtocolError.malformed("block mount header version")
        }
        let length = bytes[32..<36].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length == Self.referenceByteCount else {
            throw ProtocolError.malformed("block mount reference length")
        }
        let end = 68 + Int(length)
        let payload = Data(bytes[68..<end])
        guard Data(SHA256.hash(data: payload)) == Data(bytes[36..<68]),
            bytes[end...].allSatisfy({ $0 == 0 }),
            let text = String(data: payload, encoding: .utf8), let url = URL(string: text)
        else { throw ProtocolError.malformed("block mount header integrity") }
        reference = try ConnectionResourceReference(url: url)
    }

    public func encodedHeader() throws -> Data {
        let payload = Data(reference.url.absoluteString.utf8)
        guard payload.count == Self.referenceByteCount,
            try ConnectionResourceReference(url: reference.url) == reference
        else { throw ProtocolError.malformed("block mount reference") }
        let count = UInt32(payload.count)
        var result = Self.magic
        result.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: count >> $0) })
        result.append(Data(SHA256.hash(data: payload)))
        result.append(payload)
        result.append(Data(repeating: 0, count: Self.headerByteCount - result.count))
        return result
    }
}
