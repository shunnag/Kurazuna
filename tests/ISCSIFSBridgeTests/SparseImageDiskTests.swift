import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

@Test(arguments: [false, true])
func sparseImageLogicalRewriteReservationCannotGrowOrAllocateLUNData(_ readOnly: Bool) async throws
{
    let source = try MemoryDisk(readOnly: readOnly)
    let rawVolume = LUNImageVolume(disk: source, identifier: UUID())
    let raw = rawVolume.volumeStatistics
    #expect(raw.freeBlocks >= source.capacity.blockCount)
    #expect(raw.freeBlocks == raw.availableBlocks)
    #expect(raw.usedBlocks + raw.freeBlocks == raw.totalBlocks)
    #expect(rawVolume.maximumFileSize == source.capacity.byteCount)
    await #expect(throws: POSIXError(readOnly ? .EROFS : .ENOSPC)) {
        try await rawVolume.write(
            contents: Data([1]), to: rawVolume.imageItem, at: Int64(source.capacity.byteCount))
    }
    let image = try SparseImageDisk(source)
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    let space = volume.volumeStatistics
    #expect(space.usedBlocks + space.freeBlocks == space.totalBlocks)
    #expect(space.availableBlocks == space.freeBlocks)
    #expect(space.freeBlocks >= (image.layout.capacity + 4 * image.layout.bandSize) / 512)
    #expect(space.freeFiles == 0 && space.totalFiles == 2)
    #expect(volume.maximumFileSize == image.layout.imageByteCount)
    await #expect(throws: POSIXError(readOnly ? .EROFS : .ENOSPC)) {
        try await volume.write(
            contents: Data([1]), to: volume.imageItem, at: Int64(image.capacity.byteCount))
    }
    #expect(try await source.read(offset: 0, length: 4096) == Data(repeating: 0, count: 4096))
}

@Test func sparseImageViewKeepsMetadataLocalAndFlushesTheLUN() async throws {
    let source = try MemoryDisk()
    let image = try SparseImageDisk(source)
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    let header = try image.layout.header(at: 0)
    #expect(try await image.read(offset: 0, length: 4096) == header)
    #expect(try await volume.write(contents: header, to: volume.imageItem, at: 0) == 4096)
    #expect(try await source.read(offset: 0, length: 4096) == Data(repeating: 0, count: 4096))
    #expect(await source.flushes == 1)
    let contents = Data([1, 2, 3])
    #expect(try await volume.write(contents: contents, to: volume.imageItem, at: 4096 + 17) == 3)
    #expect(try await source.read(offset: 17, length: 3) == contents)
    #expect(await source.flushes == 2)
    await image.close()
    // Generated headers and padding must also stop after the remote session closes.
    await #expect(throws: POSIXError(.EIO)) { try await image.read(offset: 0, length: 512) }
    await #expect(throws: POSIXError(.EIO)) { try await image.read(offset: 8192, length: 512) }
}

@Test func sparseImageRejectsBadMetadataBeforeWritingAnyPayload() async throws {
    let source = try MemoryDisk()
    let image = try SparseImageDisk(source)
    var combined = try image.layout.header(at: 0)
    combined[4095] ^= 1
    combined.append(Data(repeating: 0xA7, count: 512))
    await #expect(throws: POSIXError(.EPERM)) { try await image.write(offset: 0, data: combined) }
    #expect(try await source.read(offset: 0, length: 512) == Data(repeating: 0, count: 512))
    let tail = Data(repeating: 0xA7, count: 1024)
    await #expect(throws: POSIXError(.EPERM)) {
        try await image.write(offset: 4096 + 4096 - 512, data: tail)
    }
    #expect(try await source.read(offset: 3584, length: 512) == Data(repeating: 0, count: 512))
    try await image.write(offset: 8192, data: Data(repeating: 0, count: 512))
    let readonly = try SparseImageDisk(MemoryDisk(readOnly: true))
    await #expect(throws: POSIXError(.EROFS)) {
        try await readonly.write(offset: 0, data: header(readonly))
    }
}

private func header(_ disk: SparseImageDisk) throws -> Data { try disk.layout.header(at: 0) }

@Test func sparseImageAcceptsSlicedBuffersWithoutShiftingPayloadOrMetadata() async throws {
    let source = try MemoryDisk()
    let image = try SparseImageDisk(source)
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    let bytes = Data([0xDE, 0xAD]) + (try image.layout.header(at: 0)) + Data([0x51, 0x52])
    let slice = bytes[2..<bytes.endIndex]
    #expect(slice.startIndex == 2)
    #expect(try await volume.write(contents: slice, to: volume.imageItem, at: 0) == 4098)
    #expect(try await source.read(offset: 0, length: 2) == Data([0x51, 0x52]))
    #expect(await source.flushes == 1)
}

private actor SparseRecordingDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = false
    private(set) var writes = 0
    init() throws {
        var response = [UInt8](repeating: 0, count: 32)
        response.put(UInt64(12 * 1_048_576 / 512 - 1), at: 0)
        response.put(UInt32(512), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(response))
    }
    func read(offset: Int64, length: Int) async throws -> Data { Data(repeating: 0, count: length) }
    func write(offset: Int64, data: Data) async throws { writes += 1 }
    func synchronize() async throws {}
    func close() async {}
    func connectionState() async -> DiskConnectionState { .connected }
}

@Test func sparseImageValidatesLaterHeadersBeforeTheFirstChunkOfALargeWrite() async throws {
    let source = try SparseRecordingDisk()
    let image = try SparseImageDisk(source, bandSize: 4096)
    let volume = LUNImageVolume(disk: image, identifier: UUID())
    let next = try image.layout.headerOffset(at: 1)
    var bytes = Data(repeating: 0xA7, count: Int(next))
    let headerStart = Int(next) - 4096
    bytes.replaceSubrange(headerStart..<(headerStart + 4096), with: try image.layout.header(at: 1))
    bytes[bytes.count - 1] ^= 1
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.write(contents: bytes, to: volume.imageItem, at: 4096)
    }
    #expect(await source.writes == 0)
}
