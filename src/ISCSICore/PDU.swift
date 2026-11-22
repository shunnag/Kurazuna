import Foundation

public struct DigestPolicy: Sendable, Equatable {
    public var header: Bool
    public var data: Bool

    public init(header: Bool = false, data: Bool = false) {
        self.header = header
        self.data = data
    }
}

public struct PDU: Sendable, Equatable {
    public static let headerLength = 48
    public static let maximumDataLength = 0xFF_FFFF
    public private(set) var header: [UInt8]
    public let data: Data

    public init(header: [UInt8], data: Data = Data()) throws {
        guard header.count == Self.headerLength else {
            throw ProtocolError.malformed("basic header length")
        }
        guard header[4] == 0 else { throw ProtocolError.unsupported("additional headers") }
        guard data.count <= Self.maximumDataLength else {
            throw ProtocolError.limitExceeded("data segment")
        }
        self.header = header
        self.header[5] = UInt8(truncatingIfNeeded: data.count >> 16)
        self.header[6] = UInt8(truncatingIfNeeded: data.count >> 8)
        self.header[7] = UInt8(truncatingIfNeeded: data.count)
        self.data = data
    }

    public var opcode: UInt8 { header[0] & 0x3F }
    public var flags: UInt8 { header[1] }
    public var taskTag: UInt32 { header.uint32(at: 16) }
    public var statusSequenceNumber: UInt32 { header.uint32(at: 24) }
    public var expectedCommandSequenceNumber: UInt32 { header.uint32(at: 28) }
    public var maximumCommandSequenceNumber: UInt32 { header.uint32(at: 32) }
    public var dataSequenceNumber: UInt32 { header.uint32(at: 36) }
    public var bufferOffset: UInt32 { header.uint32(at: 40) }
    public var residualCount: UInt32 { header.uint32(at: 44) }
    public var transferTag: UInt32 { header.uint32(at: 20) }

    public func encoded(digests: DigestPolicy = DigestPolicy()) -> Data {
        var result = Data(header)
        if digests.header { result.append(contentsOf: CRC32C.wireBytes(header)) }
        if !data.isEmpty {
            var padded = data
            padded.append(contentsOf: repeatElement(0, count: (4 - data.count % 4) % 4))
            result.append(padded)
            if digests.data { result.append(contentsOf: CRC32C.wireBytes(padded)) }
        }
        return result
    }
}

/// Incremental framing with a hard allocation bound, including when many frames arrive together.
/// Any framing error poisons the decoder: the connection must be discarded at ERL 0.
public struct PDUDecoder: Sendable {
    public let maximumDataLength: Int
    public let digests: DigestPolicy
    private var buffer = Data()
    private var frameLength = PDU.headerLength
    private var hasHeader = false
    private var failed = false

    public init(maximumDataLength: Int = 262_144, digests: DigestPolicy = DigestPolicy()) throws {
        guard (512...PDU.maximumDataLength).contains(maximumDataLength) else {
            throw ProtocolError.limitExceeded("receive segment length")
        }
        self.maximumDataLength = maximumDataLength
        self.digests = digests
    }

    public mutating func append(_ incoming: Data) throws -> [PDU] {
        guard !failed else { throw ProtocolError.invalidState }
        do {
            var result: [PDU] = []
            var cursor = incoming.startIndex
            while cursor < incoming.endIndex {
                let count = min(frameLength - buffer.count, incoming.endIndex - cursor)
                buffer.append(incoming[cursor..<(cursor + count)])
                cursor += count
                if buffer.count == PDU.headerLength && !hasHeader {
                    let header = [UInt8](buffer)
                    guard header[4] == 0 else {
                        throw ProtocolError.unsupported("additional headers")
                    }
                    let length = Int(header[5]) << 16 | Int(header[6]) << 8 | Int(header[7])
                    guard length <= maximumDataLength else {
                        throw ProtocolError.limitExceeded("received data segment")
                    }
                    frameLength =
                        PDU.headerLength + (digests.header ? 4 : 0)
                        + ((length + 3) & ~3) + (digests.data && length > 0 ? 4 : 0)
                    hasHeader = true
                }
                if hasHeader && buffer.count == frameLength {
                    result.append(try decode())
                    buffer.removeAll(keepingCapacity: true)
                    frameLength = PDU.headerLength
                    hasHeader = false
                }
            }
            return result
        } catch {
            failed = true
            buffer.removeAll()
            throw error
        }
    }

    public var isAtFrameBoundary: Bool { !failed && buffer.isEmpty }

    /// Lets a transport avoid reading across the final, undigested login frame.
    public var bytesNeeded: Int { frameLength - buffer.count }

    private func decode() throws -> PDU {
        let bytes = [UInt8](buffer)
        let length = Int(bytes[5]) << 16 | Int(bytes[6]) << 8 | Int(bytes[7])
        let start = PDU.headerLength + (digests.header ? 4 : 0)
        if digests.header && Array(bytes[48..<52]) != CRC32C.wireBytes(bytes[0..<48]) {
            throw ProtocolError.digestMismatch
        }
        let paddedEnd = start + ((length + 3) & ~3)
        if digests.data && length > 0
            && Array(bytes[paddedEnd..<(paddedEnd + 4)])
                != CRC32C.wireBytes(bytes[start..<paddedEnd])
        {
            throw ProtocolError.digestMismatch
        }
        return try PDU(header: Array(bytes[0..<48]), data: Data(bytes[start..<(start + length)]))
    }
}
