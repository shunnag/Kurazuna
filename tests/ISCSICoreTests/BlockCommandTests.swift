import Foundation
import Testing

@testable import ISCSICore

@Test func tenByteBlockCommandsHaveExactWireFieldsAndZeroPadding() throws {
    let read = try SCSICommand.read10(lba: 0x1234_5678, blocks: 0x1234, blockSize: 1)
    let write = try SCSICommand.write10(lba: 0x1234_5678, blocks: 0x1234, blockSize: 1)
    let expectedRead: [UInt8] = [
        0x28, 0, 0x12, 0x34, 0x56, 0x78, 0, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0,
    ]
    #expect(read.cdb == expectedRead && read.transferLength == 0x1234 && read.direction == .read)
    #expect(write.cdb == [0x2A] + expectedRead.dropFirst())
    #expect(write.transferLength == 0x1234 && write.direction == .write)
    let sync = SCSICommand.synchronizeCache10()
    let expectedSync: [UInt8] = [0x35] + Array(repeating: 0, count: 15)
    #expect(sync.cdb == expectedSync && sync.transferLength == 0 && sync.direction == .none)
}

private struct BlockRange: Sendable {
    let lba: UInt64
    let blocks: UInt32
    let blockSize: UInt32
    let readOpcode: UInt8
}

@Test(arguments: [
    BlockRange(lba: 0, blocks: 2048, blockSize: 512, readOpcode: 0x28),
    BlockRange(lba: UInt64(UInt32.max), blocks: 1, blockSize: 4096, readOpcode: 0x28),
    BlockRange(lba: UInt64(UInt32.max), blocks: 2, blockSize: 512, readOpcode: 0x88),
    BlockRange(lba: UInt64(UInt32.max) + 1, blocks: 1, blockSize: 512, readOpcode: 0x88),
    BlockRange(lba: 0, blocks: 65_535, blockSize: 1, readOpcode: 0x28),
    BlockRange(lba: 0, blocks: 65_536, blockSize: 1, readOpcode: 0x88),
    BlockRange(lba: UInt64.max, blocks: 1, blockSize: 512, readOpcode: 0x88),
])
private func blockFormatIsSelectedBeforeTransferWithoutTruncatingTheRange(_ range: BlockRange)
    throws
{
    let read = try SCSICommand.read(
        lba: range.lba, blocks: range.blocks, blockSize: range.blockSize)
    let write = try SCSICommand.write(
        lba: range.lba, blocks: range.blocks, blockSize: range.blockSize)
    #expect(read.cdb[0] == range.readOpcode && write.cdb[0] == range.readOpcode + 2)
    #expect(read.transferLength == range.blocks * range.blockSize)
    #expect(write.transferLength == read.transferLength)
    if range.readOpcode == 0x28 {
        #expect(read.cdb.uint32(at: 2) == range.lba && read.cdb.uint16(at: 7) == range.blocks)
        #expect(write.cdb.uint32(at: 2) == range.lba && write.cdb.uint16(at: 7) == range.blocks)
    } else {
        #expect(read.cdb.uint64(at: 2) == range.lba && read.cdb.uint32(at: 10) == range.blocks)
        #expect(write.cdb.uint64(at: 2) == range.lba && write.cdb.uint32(at: 10) == range.blocks)
    }
}

@Test func blockCommandsRejectZeroOverflowAndUnrepresentableTenByteRanges() throws {
    for (lba, blocks, size): (UInt64, UInt32, UInt32) in [
        (0, 0, 512), (0, 1, 0), (UInt64.max, 2, 512),
        (0, UInt32.max, 4096), (0, 2049, 512),
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSICommand.read(lba: lba, blocks: blocks, blockSize: size)
        }
        #expect(throws: ProtocolError.self) {
            try SCSICommand.write(lba: lba, blocks: blocks, blockSize: size)
        }
    }
    for (lba, blocks): (UInt64, UInt32) in [
        (UInt64(UInt32.max), 2), (UInt64(UInt32.max) + 1, 1), (0, 65_536),
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSICommand.read10(lba: lba, blocks: blocks, blockSize: 1)
        }
        #expect(throws: ProtocolError.self) {
            try SCSICommand.write10(lba: lba, blocks: blocks, blockSize: 1)
        }
    }
}
