import CryptoKit
import Foundation
import Testing

@testable import ISCSICore

@Test func defaultSparseImageBandsKeepOpaqueFootersAwayFromContainerEOF() throws {
    for capacity: UInt64 in [64 * 1_048_576, 128 * 1_048_576, 8_796_160_819_200] {
        let layout = try SparseImageLayout(capacity: capacity)
        #expect(capacity % layout.bandSize != 0)
        #expect(
            try layout.segments(at: layout.imageByteCount - 512, length: 512) == [
                .padding(length: 512)
            ])
    }
    let aligned = try SparseImageLayout(capacity: 128 * 1_048_576)
    #expect(aligned.bandSize == 64 * 1_048_576 + 512)
    #expect(aligned.imageByteCount == 134_222_848)
}

@Test func sparseImageHeadersMatchNativeFullyAllocatedTables() throws {
    // hdiutil-created UDSP, 12 MiB / 4 KiB bands, written through /dev/rdisk.
    // The first two allocation tables are full, and both point to the next table.
    let layout = try SparseImageLayout(capacity: 12 * 1_048_576, bandSize: 4096)
    #expect(layout.headerCount == 4)
    #expect(layout.imageByteCount == 12_599_296)
    let hashes = [
        "fba3eb1310898e0a65e3f97a470a24e874974efb703f6447193caa1b82877738",
        "e35989e78286e1524a4a8caf9cc01974738c20b2021761c34602d1d31e869d4c",
    ]
    for (index, expected) in hashes.enumerated() {
        let hash = SHA256.hash(data: try layout.header(at: UInt64(index)))
            .map { String(format: "%02x", $0) }.joined()
        #expect(hash == expected)
    }
}

@Test func sparseImageSeparatesPayloadFromEveryChainedHeader() throws {
    let layout = try SparseImageLayout(capacity: 12 * 1_048_576, bandSize: 4096)
    for index in 1..<layout.headerCount {
        let header = try layout.headerOffset(at: index)
        let logical = index == 1 ? UInt64(1008 * 4096) : (1008 + (index - 1) * 1010) * 4096
        #expect(
            try layout.segments(at: header - 512, length: 512 + 4096 + 512) == [
                .payload(offset: logical - 512, length: 512),
                .header(index: index, offset: 0, length: 4096),
                .payload(offset: logical, length: 512),
            ])
        #expect(try layout.physicalOffset(forLUNOffset: logical) == header + 4096)
    }
    var position: UInt64 = 0
    var payloadBytes: UInt64 = 0
    while position < layout.imageByteCount {
        let count = Int(min(1_048_573, layout.imageByteCount - position))
        let segments = try layout.segments(at: position, length: count)
        #expect(segments.map(\.length).reduce(0, +) == count)
        for segment in segments {
            if case .payload(let offset, let length) = segment {
                #expect(offset == payloadBytes)
                payloadBytes += UInt64(length)
            }
        }
        position += UInt64(count)
    }
    #expect(payloadBytes == layout.capacity)
}

@Test func sparseImagePreservesPartialTailAndCapacitiesAboveTwoTiB() throws {
    let partial = try SparseImageLayout(capacity: 64 * 1_048_576 + 1536)
    let tail = try partial.physicalOffset(forLUNOffset: partial.capacity - 512)
    #expect(
        try partial.segments(at: tail, length: 1024) == [
            .payload(offset: partial.capacity - 512, length: 512), .padding(length: 512),
        ])
    // Verified with a 3 TiB + 1,536 B native device, 49 headers and boundary writes.
    let large = try SparseImageLayout(capacity: 3 * 1_099_511_627_776 + 1536)
    #expect(large.headerCount == 49)
    #expect(large.imageByteCount == 3_298_602_192_896)
    #expect(try large.physicalOffset(forLUNOffset: 67_645_734_912) == 67_645_743_104)
    #expect([UInt8](try large.header(at: 0)).uint64(at: 28) == 6_442_450_947)
    #expect(
        try SparseImageLayout(
            firstHeader: large.header(at: 0), imageByteCount: large.imageByteCount) == large)
}

@Test func sparseImageRejectsMalformedGeometryAndMappingChanges() throws {
    for capacity: UInt64 in [0, 511, 513, .max, UInt64(Int64.max) - 511] {
        #expect(throws: ProtocolError.self) { try SparseImageLayout(capacity: capacity) }
    }
    for band: UInt64 in [0, 512, 8193, .max, 1 << 41] {
        #expect(throws: ProtocolError.self) {
            try SparseImageLayout(capacity: 4096, bandSize: band)
        }
    }
    let layout = try SparseImageLayout(capacity: 4096)
    for offset in [0, 4, 12, 16, 20, 28, 64, 68, 4095] {
        var header = try layout.header(at: 0)
        header[offset] ^= 1
        #expect(throws: ProtocolError.self) {
            try SparseImageLayout(firstHeader: header, imageByteCount: layout.imageByteCount)
        }
    }
    #expect(throws: ProtocolError.self) { try layout.segments(at: .max, length: 1) }
    #expect(throws: ProtocolError.self) { try layout.segments(at: 0, length: -1) }
    #expect(throws: ProtocolError.self) { try layout.segments(at: 0, length: Int.max) }
    #expect(throws: ProtocolError.self) { try layout.header(at: layout.headerCount) }
    #expect(throws: ProtocolError.self) { try layout.physicalOffset(forLUNOffset: layout.capacity) }
    #expect(try layout.segments(at: layout.imageByteCount, length: 0).isEmpty)
}
