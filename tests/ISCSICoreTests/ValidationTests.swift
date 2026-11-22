import Foundation
import Testing

@testable import ISCSICore

@Test(arguments: ["nas.local", "192.0.2.1:3261", "[2001:db8::1]:3260", "[::1]"])
func portalRoundTrip(_ address: String) throws {
    let portal = try Portal(address)
    #expect(try Portal(portal.description) == portal)
    #expect(try JSONDecoder().decode(Portal.self, from: JSONEncoder().encode(portal)) == portal)
}

@Test(arguments: [
    "", "nas:", "nas:0", "nas:65536", "nas:-1", "nas:bad", "a b", "https://nas", "[::1", "::1",
    "user@nas", "nas\u{1}", "nas?x",
])
func invalidPortals(_ address: String) {
    #expect(throws: ProtocolError.self) { try Portal(address) }
}

@Test func persistedValuesCannotBypassValidation() {
    #expect(throws: ProtocolError.self) {
        try JSONDecoder().decode(Portal.self, from: Data(#"{"host":"","port":3260}"#.utf8))
    }
    #expect(throws: ProtocolError.self) {
        try JSONDecoder().decode(LogicalUnit.self, from: Data(#"{"number":65535}"#.utf8))
    }
}

@Test func textPreservesDiscoveryOrderAndEquals() throws {
    let text = try TextParameters([
        .init("TargetName", "iqn.2026-10.test:a"), .init("TargetAddress", "host:3260,1"),
        .init("TargetName", "iqn.2026-10.test:b"), .init("TargetAlias", "a=b"),
    ])
    #expect(try TextParameters(data: text.encoded()) == text)
    #expect(throws: ProtocolError.self) { try text.uniqueValue(for: "TargetName") }
    #expect(try text.uniqueValue(for: "TargetAlias") == "a=b")
    #expect(try TextParameters(data: Data()).entries.isEmpty)
}

@Test(arguments: [
    Data("Key=Value".utf8), Data([0xFF, 61, 0]), Data("NoEquals\0".utf8), Data("=empty\0".utf8),
    Data([0]),
])
func invalidText(_ data: Data) {
    #expect(throws: ProtocolError.self) { try TextParameters(data: data) }
}

@Test(arguments: [TextParameters.maximumEntryCount - 1, TextParameters.maximumEntryCount])
func textEntryBoundaryPreservesRepeatedKeysAndSlicedData(_ count: Int) throws {
    let bytes = Data(("prefix" + String(repeating: "a=\0", count: count)).utf8).dropFirst(6)
    let text = try TextParameters(data: bytes)
    #expect(text.entries.count == count)
    #expect(text.entries.allSatisfy { $0 == .init("a", "") })
    #expect(text.encoded() == bytes)
}

@Test(arguments: [TextParameters.maximumEntryCount + 1, 1_048_576 / 3])
func shortTextEntriesCannotAmplifyTheByteLimit(_ count: Int) {
    let bytes = Data(String(repeating: "a=\0", count: count).utf8)
    #expect(bytes.count <= 1_048_576)
    #expect(throws: ProtocolError.limitExceeded("text entries")) {
        try TextParameters(data: bytes)
    }
}

@Test func constructedTextHasTheSameEntryLimit() {
    #expect(throws: ProtocolError.limitExceeded("text entries")) {
        try TextParameters(
            Array(repeating: .init("a", ""), count: TextParameters.maximumEntryCount + 1))
    }
}

@Test func chapIndependentMD5Vector() throws {
    // Expected value calculated independently using Python hashlib.md5.
    let response = try CHAP.response(
        identifier: 7, secret: "correct horse battery staple",
        challenge: "0x000102030405060708090a0b0c0d0e0f")
    #expect(response == "0x4743b2bd34fa732295d209c4eb4dfc7b")
    #expect(try CHAP.decodeBinary("0bAAECAwQFBgcICQoLDA0ODw==") == Data(0..<16))
}

@Test(arguments: ["0x0", "0xgg", "0b%%%", "xyz"])
func invalidChapBinary(_ value: String) {
    #expect(throws: ProtocolError.self) { try CHAP.decodeBinary(value) }
}

@Test func serialArithmeticAcrossWrap() {
    #expect(SerialNumber.precedes(UInt32.max, 0))
    #expect(!SerialNumber.precedes(0, UInt32.max))
    #expect(!SerialNumber.precedes(0, 0x8000_0000))
    #expect(SerialNumber.isWithin(0, first: UInt32.max - 1, last: 2))
    #expect(!SerialNumber.isWithin(4, first: 5, last: 4))
}

@Test func capacityBoundsAndCommandOverflow() throws {
    var data = Array(repeating: UInt8(0), count: 32)
    data.put(UInt64(2047), at: 0)
    data.put(UInt32(4096), at: 8)
    let capacity = try DiskCapacity(readCapacity16: Data(data))
    #expect(capacity.byteCount == 8_388_608)
    data.put(UInt64.max, at: 0)
    #expect(throws: ProtocolError.self) { try DiskCapacity(readCapacity16: Data(data)) }
    #expect(throws: ProtocolError.self) {
        try SCSICommand.read16(lba: UInt64.max, blocks: 2, blockSize: 512)
    }
    #expect(throws: ProtocolError.self) {
        try SCSICommand.write16(lba: 0, blocks: 0, blockSize: 512)
    }
    #expect(throws: ProtocolError.self) {
        try SCSICommand.read16(lba: 0, blocks: UInt32.max, blockSize: 4096)
    }
    #expect(try LogicalUnit(256).wireBytes == [0x41, 0, 0, 0, 0, 0, 0, 0])
}
