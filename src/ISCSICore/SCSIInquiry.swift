import Foundation

public struct SCSIInquiry: Sendable, Equatable {
    public let peripheralQualifier: UInt8
    public let peripheralDeviceType: UInt8
    public let removable: Bool
    public let version: UInt8
    public let responseDataFormat: UInt8
    public let vendor: String
    public let product: String
    public let revision: String

    public init(data: Data) throws {
        // Only consume the standard header and identification fields. Optional descriptors
        // may exceed our allocation, and a short, self-consistent response has no such fields.
        let bytes = Array(data.prefix(36))
        guard bytes.count >= 5 else { throw ProtocolError.malformed("INQUIRY header") }
        let reportedLength = 5 + Int(bytes[4])
        guard bytes.count >= min(reportedLength, 36) else {
            throw ProtocolError.malformed("truncated INQUIRY identification")
        }
        let available = min(reportedLength, bytes.count)
        peripheralQualifier = bytes[0] >> 5
        peripheralDeviceType = bytes[0] & 0x1F
        removable = bytes[1] & 0x80 != 0
        version = bytes[2]
        responseDataFormat = bytes[3] & 0x0F
        vendor = available >= 16 ? Self.text(bytes[8..<16]) : ""
        product = available >= 32 ? Self.text(bytes[16..<32]) : ""
        revision = available >= 36 ? Self.text(bytes[32..<36]) : ""
    }

    public var displayName: String {
        [vendor, product].filter { !$0.isEmpty }.joined(separator: " ")
    }

    private static func text(_ bytes: ArraySlice<UInt8>) -> String {
        // Identification is display-only. Never pass controls or non-ASCII bytes to a UI or
        // terminal, and never use these untrusted strings as a disk or credential identity.
        String(bytes: bytes.map { (0x20...0x7E).contains($0) ? $0 : 0x3F }, encoding: .ascii)!
            .trimmingCharacters(in: .whitespaces)
    }
}
