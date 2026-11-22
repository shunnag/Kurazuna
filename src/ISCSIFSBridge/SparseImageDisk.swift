import Foundation
import ISCSICore

/// A fixed UDSP container over one LUN. Used by LUNImageVolume's operation gate,
/// so a metadata check, split payload and subsequent flush keep their I/O order.
final class SparseImageDisk: ImageDisk {
    let layout: SparseImageLayout
    let capacity: DiskCapacity
    private let disk: any ImageDisk
    var isReadOnly: Bool { disk.isReadOnly }

    /// Logical headroom in the private presentation namespace, not free space
    /// inside the LUN. Every in-place payload write is already backed. DiskImages
    /// conservatively discounts four bands from its backing filesystem's budget.
    var rewriteReserveBlocks: UInt64 {
        let blockSize = UInt64(capacity.blockSize)
        let alignedBand = ((layout.bandSize + 4095) / 4096) * 4096
        let requested = (layout.capacity + 4 * alignedBand) / blockSize
        return min(requested, UInt64.max / blockSize - capacity.blockCount)
    }

    init(_ disk: any ImageDisk, bandSize: UInt64? = nil) throws {
        self.disk = disk
        layout = try SparseImageLayout(capacity: disk.capacity.byteCount, bandSize: bandSize)
        var response = [UInt8](repeating: 0, count: 32)
        response.put(layout.imageByteCount / 512 - 1, at: 0)
        response.put(UInt32(512), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(response))
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        guard offset >= 0 else { throw POSIXError(.EINVAL) }
        let segments = try layout.segments(at: UInt64(offset), length: length)
        try await requireConnected()
        var result = Data()
        result.reserveCapacity(length)
        for segment in segments {
            try Task.checkCancellation()
            switch segment {
            case .header(let index, let offset, let length):
                result.append(try layout.header(at: index).subdata(in: offset..<(offset + length)))
            case .payload(let offset, let length):
                let bytes = try await disk.read(offset: Int64(offset), length: length)
                guard bytes.count == length else {
                    throw ProtocolError.malformed("short sparse image payload")
                }
                result.append(bytes)
            case .padding(let length): result.append(Data(repeating: 0, count: length))
            }
        }
        return result
    }

    func write(offset: Int64, data: Data) async throws {
        guard !isReadOnly else { throw POSIXError(.EROFS) }
        guard offset >= 0 else { throw POSIXError(.EINVAL) }
        let segments = try layout.segments(at: UInt64(offset), length: data.count)
        try await requireConnected()
        try validateWrite(offset: offset, data: data)
        var position = 0
        for segment in segments {
            try Task.checkCancellation()
            if case .payload(let offset, let length) = segment {
                let start = data.startIndex + position
                try await disk.write(
                    offset: Int64(offset), data: Data(data[start..<(start + length)]))
            }
            position += segment.length
        }
    }

    func validateWrite(offset: Int64, data: Data) throws {
        guard offset >= 0 else { throw POSIXError(.EINVAL) }
        guard UInt64(offset) <= layout.imageByteCount,
            UInt64(data.count) <= layout.imageByteCount - UInt64(offset)
        else { throw POSIXError(.ENOSPC) }
        var cursor = 0
        while cursor < data.count {
            try Task.checkCancellation()
            let length = min(SparseImageLayout.maximumRequestLength, data.count - cursor)
            let segments = try layout.segments(at: UInt64(offset) + UInt64(cursor), length: length)
            var position = cursor
            for segment in segments {
                let start = data.startIndex + position
                switch segment {
                case .header(let index, let offset, let length):
                    let expected = try layout.header(at: index).subdata(
                        in: offset..<(offset + length))
                    guard Data(data[start..<(start + length)]) == expected else {
                        throw POSIXError(.EPERM)
                    }
                case .padding(let length):
                    guard data[start..<(start + length)].allSatisfy({ $0 == 0 }) else {
                        throw POSIXError(.EPERM)
                    }
                case .payload: break
                }
                position += segment.length
            }
            cursor += length
        }
    }

    private func requireConnected() async throws {
        try Task.checkCancellation()
        // A reconnecting disk blocks its I/O instead of failing it.
        switch await disk.connectionState() {
        case .connected, .reconnecting: break
        case .unknown, .interrupted, .closed: throw POSIXError(.EIO)
        }
    }

    func synchronize() async throws { try await disk.synchronize() }
    func close() async { await disk.close() }
    func connectionState() async -> DiskConnectionState { await disk.connectionState() }
    func connectionEpoch() async -> UInt64 { await disk.connectionEpoch() }
    func repeatingWithinOneEpoch<Value: Sendable>(_ pass: @Sendable () async throws -> Value)
        async throws -> Value
    {
        try await disk.repeatingWithinOneEpoch(pass)
    }
    func abandonConnectionRecovery() async { await disk.abandonConnectionRecovery() }
}
