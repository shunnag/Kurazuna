import Foundation
import Testing

@testable import ISCSICore

private func message(_ event: UInt8, data: Data = Data()) throws -> PDU {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x32
    header[1] = 0x80
    header.put(UInt32.max, at: 16)
    header[36] = event
    header[37] = 249
    header.put(UInt16(7), at: 38)
    header.put(UInt16(11), at: 40)
    header.put(UInt16.max, at: 42)
    header.replaceSubrange(8..<16, with: [0xC1, 1, 2, 3, 4, 5, 6, 7])
    return try PDU(header: header, data: data)
}

@Test(arguments: [UInt8(1), 2, 3, 4, 5, 248, 255])
func asynchronousFieldsAndOpaqueVendorDataAreDecoded(_ event: UInt8) throws {
    let value = try AsynchronousMessage(message(event, data: Data([0, 0, 255, 1, 2])))
    #expect(value.event == event && value.vendorCode == 249)
    #expect(value.parameter1 == 7 && value.parameter2 == 11 && value.parameter3 == 65535)
    #expect(value.lun.wireBytes == [0xC1, 1, 2, 3, 4, 5, 6, 7])
    #expect(value.sense.isEmpty)
}

@Test(arguments: [0, 1, 2])
func asynchronousHeaderIdentityAndFlagsAreRequired(_ fault: Int) throws {
    let original = try message(1)
    var header = original.header
    if fault == 0 { header[0] = 0x33 }
    if fault == 1 { header[1] = 0 }
    if fault == 2 { header.put(UInt32(7), at: 16) }
    #expect(throws: ProtocolError.malformed("asynchronous message header")) {
        try AsynchronousMessage(PDU(header: header))
    }
}

@Test func asynchronousSenseLengthAndSCSISenseAreValidated() throws {
    let sense = Data([0x72, 6, 0x29, 0, 0, 0, 0, 0])
    let decoded = try AsynchronousMessage(message(0, data: Data([0, 8]) + sense + Data([42])))
    #expect(decoded.sense == sense)
    let offsetData = (Data([42, 43]) + Data([0, 8]) + sense).dropFirst(2)
    #expect(try AsynchronousMessage(message(0, data: offsetData)).sense == sense)
    for data in [Data(), Data([0]), Data([0, 9]) + sense, Data([0, 1, 0])] {
        #expect(throws: ProtocolError.self) { try AsynchronousMessage(message(0, data: data)) }
    }
    #expect(try AsynchronousMessage(message(1, data: Data([0, 8]) + sense)).sense == sense)
}

@Test func asynchronousReservedBitsAndFieldsAreIgnored() throws {
    var header = try message(1).header
    header[0] = 0xF2
    header[1] = 0xFF
    header[2] = 123
    header[3] = 45
    header.put(UInt32.max, at: 20)
    header.put(UInt32.max, at: 44)
    let value = try AsynchronousMessage(PDU(header: header))
    #expect(value.event == 1 && value.parameter3 == 65535)
}
