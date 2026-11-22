import Foundation
import ISCSICore
import Testing

@Test(arguments: [false, true])
func modeQueriesRequestCurrentValuesWithoutBlockDescriptors(_ headerOnly: Bool) {
    let ten = SCSICommand.modeSense10(headerOnly: headerOnly)
    let six = SCSICommand.modeSense6(headerOnly: headerOnly)
    #expect(ten.cdb == [0x5A, 8, headerOnly ? 0 : 0x3F, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0])
    #expect(six.cdb == [0x1A, 8, headerOnly ? 0 : 0x3F, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    #expect(ten.direction == .read && ten.transferLength == 8 && !ten.requiresExactTransfer)
    #expect(six.direction == .read && six.transferLength == 4 && !six.requiresExactTransfer)
}

@Test(arguments: [UInt8(0), 0x10, 0x80, 0x90], [false, true])
func protectionIsIndependentOfFUAAndAcceptsAnAllocatedHeader(_ flags: UInt8, _ long: Bool) throws {
    let ten = Data([long ? 1 : 0, long ? 0 : 6, 0, flags, 0, 0, 0, 0])
    let six = Data([long ? 255 : 3, 0, flags, 0])
    #expect(try SCSIModeHeader(modeSense10: ten).isWriteProtected == (flags & 0x80 != 0))
    #expect(try SCSIModeHeader(modeSense6: six).isWriteProtected == (flags & 0x80 != 0))
}

@Test(arguments: [0, 1, 2, 3, 4, 5, 6, 7])
func modeHeaderRejectsEveryTruncatedTenByteHeader(_ count: Int) {
    let data = Data([0, 6, 0, 0x80, 0, 0, 0, 0].prefix(count))
    #expect(throws: ProtocolError.self) { try SCSIModeHeader(modeSense10: data) }
}

@Test(arguments: [0, 1, 2, 3])
func modeHeaderRejectsEveryTruncatedSixByteHeader(_ count: Int) {
    let data = Data([3, 0, 0x80, 0].prefix(count))
    #expect(throws: ProtocolError.self) { try SCSIModeHeader(modeSense6: data) }
}

@Test func modeHeaderRejectsAReportedListShorterThanItsHeader() {
    #expect(throws: ProtocolError.self) {
        try SCSIModeHeader(modeSense10: Data([0, 5, 0, 0x80, 0, 0, 0, 0]))
    }
    #expect(throws: ProtocolError.self) {
        try SCSIModeHeader(modeSense6: Data([2, 0, 0x80, 0]))
    }
    #expect(throws: ProtocolError.self) {
        try SCSIModeHeader(modeSense10: Data([0, 6, 0, 0x80, 0, 0, 0, 8]))
    }
    #expect(throws: ProtocolError.self) {
        try SCSIModeHeader(modeSense6: Data([3, 0, 0x80, 8]))
    }
}
