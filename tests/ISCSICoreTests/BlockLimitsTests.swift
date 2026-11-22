import Foundation
import Testing

@testable import ISCSICore

private func blockLimitsPage(limit: UInt32, reportedLength: UInt16 = 60) -> Data {
    var bytes = Array(repeating: UInt8(0), count: 64)
    bytes[1] = 0xB0
    bytes.put(reportedLength, at: 2)
    bytes.put(limit, at: 8)
    return Data(bytes)
}

@Test(arguments: [UInt32(0), 1, 3, .max])
func blockLimitsPreserveUnreportedSmallAndLargeBlockCounts(_ limit: UInt32) throws {
    #expect(try SCSIBlockLimits(data: blockLimitsPage(limit: limit)).maximumTransferBlocks == limit)
    // A longer future page may fill our allocation without transferring its optional tail.
    #expect(
        try SCSIBlockLimits(data: blockLimitsPage(limit: limit, reportedLength: 256))
            .maximumTransferBlocks == limit)
}

@Test func invalidBlockLimitsNeverSupplyAUsableTransferLimit() throws {
    let valid = blockLimitsPage(limit: 3)
    for count in [0, 3, 11, 12, 63] {
        #expect(throws: ProtocolError.self) { try SCSIBlockLimits(data: valid.prefix(count)) }
    }
    for (offset, value): (Int, UInt8) in [(0, 1), (0, 0x20), (1, 0xB1), (3, 7)] {
        var bad = valid
        bad[offset] = value
        #expect(throws: ProtocolError.self) { try SCSIBlockLimits(data: bad) }
    }
}
