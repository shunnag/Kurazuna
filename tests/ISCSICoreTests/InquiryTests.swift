import Foundation
import Testing

@testable import ISCSICore

@Test func inquiryDecodesStandardFieldsWithoutDependingOnOptionalDescriptors() throws {
    var bytes = Array(repeating: UInt8(0), count: 96)
    bytes[1] = 0x80
    bytes[2] = 6
    bytes[3] = 0x12
    bytes[4] = 91
    bytes.replaceSubrange(8..<16, with: "SobaDev ".utf8)
    bytes.replaceSubrange(16..<32, with: "Memory Disk     ".utf8)
    bytes.replaceSubrange(32..<36, with: "1.0 ".utf8)
    let inquiry = try SCSIInquiry(data: Data(bytes))
    #expect(inquiry.peripheralQualifier == 0 && inquiry.peripheralDeviceType == 0)
    #expect(inquiry.removable && inquiry.version == 6 && inquiry.responseDataFormat == 2)
    #expect(inquiry.vendor == "SobaDev" && inquiry.product == "Memory Disk")
    #expect(inquiry.revision == "1.0" && inquiry.displayName == "SobaDev Memory Disk")
    #expect(try SCSIInquiry(data: Data(bytes.prefix(36))) == inquiry)
}

@Test(arguments: [UInt8(0), 1, 5, 0x0E, 0x14, 0x20, 0x7F, 0xFF])
func inquiryPreservesPeripheralTypeAndQualifier(_ device: UInt8) throws {
    let inquiry = try SCSIInquiry(data: Data([device, 0, 6, 2, 0]))
    #expect(inquiry.peripheralQualifier == device >> 5)
    #expect(inquiry.peripheralDeviceType == device & 0x1F)
    #expect(inquiry.displayName.isEmpty && inquiry.revision.isEmpty)
}

@Test func inquiryNeverReadsBeyondReportedIdentificationLength() throws {
    var bytes = Array(repeating: UInt8(0x41), count: 36)
    bytes[0] = 0
    bytes[3] = 2
    bytes[4] = 11
    let inquiry = try SCSIInquiry(data: Data(bytes))
    #expect(inquiry.vendor == "AAAAAAAA")
    #expect(inquiry.product.isEmpty && inquiry.revision.isEmpty)
    bytes[4] = 0
    #expect(try SCSIInquiry(data: Data(bytes)).displayName.isEmpty)
    bytes[4] = 255
    #expect(try SCSIInquiry(data: Data(bytes)).revision == "AAAA")
}

@Test func truncatedInquiryAndDisplayControlsAreHandledWithoutPaddingOrInjection() throws {
    for length in [0, 4, 5, 15, 35] {
        var bytes = Array(repeating: UInt8(0), count: length)
        if length >= 5 { bytes[4] = 31 }
        #expect(throws: ProtocolError.self) { try SCSIInquiry(data: Data(bytes)) }
    }
    var bytes = Array(repeating: UInt8(0x20), count: 36)
    bytes[0] = 0
    bytes[3] = 2
    bytes[4] = 31
    bytes.replaceSubrange(8..<16, with: [0x53, 0x4F, 0, 0x42, 0x41, 0x1B, 0xFF, 0x7F])
    bytes.replaceSubrange(32..<36, with: [0x0A, 0x2E, 0x31, 0x20])
    let inquiry = try SCSIInquiry(data: Data(bytes))
    #expect(inquiry.vendor == "SO?BA???" && inquiry.product.isEmpty)
    #expect(inquiry.revision == "?.1" && inquiry.displayName == "SO?BA???")
}
