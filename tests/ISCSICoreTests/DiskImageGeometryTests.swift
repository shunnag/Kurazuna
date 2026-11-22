import Foundation
import Testing
import zlib

@testable import ISCSICore

// Primary headers from hdiutil/diskutil-generated private images, before any test mutation.
private func nativeHeader(_ block: Int) throws -> Data {
    let hex =
        block == 512
        ? "4546492050415254000001005c000000cc83534a000000000100000000000000ffff0300000000002200000000000000deff030000000000887c56edab608f4397423bfc8465abf802000000000000008000000080000000bcec5d1c"
        : "4546492050415254000001005c000000daa5c213000000000100000000000000ffff0100000000000600000000000000faff010000000000cfdb1dadb1b6294ebb9e8535580ea40f02000000000000008000000080000000df8018d0"
    return Data(try CHAP.decodeBinary("0x" + hex))
}

private func nativePrefix(_ block: Int) throws -> Data {
    var prefix = Data(repeating: 0, count: DiskImageGeometry.prefixByteCount)
    let header = try nativeHeader(block)
    prefix.replaceSubrange(block..<(block + header.count), with: header)
    return prefix
}

private func little(_ value: UInt64, width: Int) -> Data {
    Data((0..<width).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
}

// Independent system zlib, not the implementation's CRC, produces valid checksums
// for semantically invalid headers so each field check is exercised separately.
private func rechecksum(_ prefix: inout Data, block: Int) {
    prefix.replaceSubrange((block + 16)..<(block + 20), with: Data(repeating: 0, count: 4))
    let header = prefix.subdata(in: block..<(block + 92))
    let crc = header.withUnsafeBytes {
        crc32(0, $0.bindMemory(to: UInt8.self).baseAddress, uInt(header.count))
    }
    prefix.replaceSubrange((block + 16)..<(block + 20), with: little(UInt64(crc), width: 4))
}

@Test func validatedGPTUnitsTakePrecedenceOverDifferentTargetSectors() throws {
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: nativePrefix(512), byteCount: 128 * 1_048_576, sourceBlockSize: 4096) == 512)
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: nativePrefix(4096), byteCount: 512 * 1_048_576, sourceBlockSize: 512) == 4096)
    // Enlarging the LUN does not invalidate the old header's sector units.
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: nativePrefix(512), byteCount: 3 * 1_099_511_627_776, sourceBlockSize: 4096)
            == 512)
}

@Test func blankOrUnknownContentsUseTheActualTargetGeometry() throws {
    for prefix in [Data(), Data(repeating: 0, count: 8192), Data(repeating: 0xA7, count: 8192)] {
        #expect(try DiskImageGeometry.blockSize(prefix: prefix, byteCount: 512 * 1_048_576) == 512)
        #expect(
            try DiskImageGeometry.blockSize(
                prefix: prefix, byteCount: 512 * 1_048_576, sourceBlockSize: 4096) == 4096)
    }
}

@Test func checksummedButInvalidGPTFieldsCannotOverrideTargetGeometry() throws {
    let mutations: [(Int, UInt64, Int)] = [
        (20, 1, 4), (24, 2, 8), (32, .max, 8), (40, 0, 8), (48, 5, 8),
        (72, 100_000, 8), (80, 0, 4), (84, 127, 4), (80, UInt64(UInt32.max), 4),
    ]
    for (offset, value, width) in mutations {
        var prefix = try nativePrefix(4096)
        prefix.replaceSubrange(
            (4096 + offset)..<(4096 + offset + width), with: little(value, width: width))
        rechecksum(&prefix, block: 4096)
        #expect(
            try DiskImageGeometry.blockSize(
                prefix: prefix, byteCount: 512 * 1_048_576, sourceBlockSize: 512) == 512)
    }
    var corrupt = try nativePrefix(4096)
    corrupt[4096 + 16] ^= 1
    #expect(
        try DiskImageGeometry.blockSize(
            prefix: corrupt, byteCount: 512 * 1_048_576, sourceBlockSize: 512) == 512)
}

@Test func ambiguousPartitionUnitsAreRejectedInsteadOfGuessing() throws {
    var prefix = try nativePrefix(4096)
    let other = try nativeHeader(512)
    prefix.replaceSubrange(512..<(512 + other.count), with: other)
    #expect(throws: ProtocolError.malformed("ambiguous partition geometry")) {
        try DiskImageGeometry.blockSize(
            prefix: prefix, byteCount: 512 * 1_048_576, sourceBlockSize: 4096)
    }
}

@Test func sourceGeometryAttributeAndInputBoundsAreValidated() throws {
    for block: UInt32 in [512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536] {
        var bytes = [UInt8](repeating: 0, count: 4)
        bytes.put(block, at: 0)
        #expect(try DiskImageGeometry.sourceBlockSize(from: Data(bytes)) == block)
    }
    for bytes in [
        Data(), Data([0, 0, 16]), Data([0, 0, 16, 0, 0]), Data([0, 0, 2, 1]), Data([0, 0, 0, 0]),
    ] {
        #expect(throws: ProtocolError.self) { try DiskImageGeometry.sourceBlockSize(from: bytes) }
    }
    for size: UInt64 in [0, 511, 513, .max] {
        #expect(throws: ProtocolError.self) {
            try DiskImageGeometry.blockSize(prefix: Data(), byteCount: size)
        }
    }
    #expect(throws: ProtocolError.self) {
        try DiskImageGeometry.blockSize(
            prefix: Data(repeating: 0, count: DiskImageGeometry.prefixByteCount + 1),
            byteCount: 1_048_576)
    }
    #expect(throws: ProtocolError.self) {
        try DiskImageGeometry.blockSize(prefix: Data(), byteCount: 512, sourceBlockSize: 4096)
    }
}
