import Foundation
import Testing

@testable import ISCSICore

@Test func crc32cKnownVector() {
    #expect(CRC32C.checksum("123456789".utf8) == 0xE306_9283)
    #expect(CRC32C.wireBytes("123456789".utf8) == [0x83, 0x92, 0x06, 0xE3])
}

@Test(arguments: [0, 1, 2, 3, 4, 511, 8192])
func frameRoundTripAtEverySplit(length: Int) throws {
    let pdu = try PDU(
        header: Array(repeating: 0, count: 48), data: Data(repeating: 0xA5, count: length))
    let digests = DigestPolicy(header: true, data: true)
    let wire = pdu.encoded(digests: digests)
    // Every split for short frames; all boundary neighborhoods for long frames.
    let splits =
        length < 10
        ? Array(0...wire.count) : [0, 1, 47, 48, 49, 51, 52, wire.count - 1, wire.count]
    for split in splits {
        var decoder = try PDUDecoder(digests: digests)
        let first = try decoder.append(Data(wire.prefix(split)))
        let second = try decoder.append(Data(wire.dropFirst(split)))
        #expect(first + second == [pdu])
        #expect(decoder.isAtFrameBoundary)
    }
}

@Test func coalescedFramesDoNotExceedBufferBound() throws {
    let pdu = try PDU(header: Array(repeating: 0, count: 48), data: Data(repeating: 7, count: 512))
    var input = Data()
    for _ in 0..<100 { input.append(pdu.encoded()) }
    var decoder = try PDUDecoder(maximumDataLength: 512)
    #expect(try decoder.append(input) == Array(repeating: pdu, count: 100))
}

@Test func corruptDigestPoisonsDecoder() throws {
    let pdu = try PDU(header: Array(repeating: 0, count: 48), data: Data([1, 2, 3]))
    var data = pdu.encoded(digests: DigestPolicy(header: true, data: true))
    data[54] ^= 1
    var decoder = try PDUDecoder(digests: DigestPolicy(header: true, data: true))
    #expect(throws: ProtocolError.digestMismatch) { try decoder.append(data) }
    #expect(throws: ProtocolError.invalidState) { try decoder.append(Data()) }
}

@Test func oversizedHeaderRejectedBeforePayload() throws {
    var data = Data(repeating: 0, count: 48)
    data[5] = 0xFF
    var decoder = try PDUDecoder()
    #expect(throws: ProtocolError.limitExceeded("received data segment")) {
        try decoder.append(data)
    }
}

@Test func nonzeroDataIndices() throws {
    let pdu = try PDU(header: Array(repeating: 0, count: 48), data: Data([1, 2, 3]))
    var data = Data([9, 9])
    data.append(pdu.encoded())
    data.removeFirst(2)
    var decoder = try PDUDecoder()
    #expect(try decoder.append(data) == [pdu])
}
