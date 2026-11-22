import CryptoKit
import Foundation
import Testing

@testable import ISCSICore

private let markerReferenceText =
    "iscsi-fskit://mount/00000000-0000-4000-8000-000000000001/" + String(repeating: "a", count: 64)

@Test func blockMarkersUseAnIndependentFixedFormatVector() throws {
    let reference = try ConnectionResourceReference(url: #require(URL(string: markerReferenceText)))
    let marker = BlockMountResource(reference: reference)
    let header = try marker.encodedHeader()
    #expect(header.count == 8192)
    #expect(header.prefix(32) == Data("soba.dev/iscsi/mount-resource/1\0".utf8))
    #expect(Array(header[32..<36]) == [0, 0, 0, 121])
    #expect(
        SHA256.hash(data: header).map { String(format: "%02x", $0) }.joined()
            == "6b34cdd633fb79e13cd960d2501ee8cafc904b98e6b77667170e216d1c662867")
    #expect(try BlockMountResource(header: header) == marker)
    let prefixed = Data([1, 2, 3]) + header
    #expect(try BlockMountResource(header: prefixed.dropFirst(3)) == marker)
}

@Test(arguments: ["magic", "version", "digest", "payload", "padding", "length", "short", "long"])
func damagedBlockMarkersCannotResolveAConnection(_ change: String) throws {
    let reference = try ConnectionResourceReference(url: #require(URL(string: markerReferenceText)))
    var bytes = try BlockMountResource(reference: reference).encodedHeader()
    switch change {
    case "magic": bytes[0] ^= 1
    case "version": bytes[30] = 0x32
    case "digest": bytes[36] ^= 1
    case "payload": bytes[68] ^= 1
    case "padding": bytes[8191] = 1
    case "length": bytes.replaceSubrange(32..<36, with: [255, 255, 255, 255])
    case "short": bytes.removeLast()
    default: bytes.append(0)
    }
    #expect(throws: ProtocolError.self) { try BlockMountResource(header: bytes) }
}

@Test(arguments: ["host", "query", "legacy", "utf8"])
func aCorrectDigestCannotAuthorizeAnInvalidReference(_ change: String) throws {
    let payload: Data
    switch change {
    case "host":
        payload = Data(
            markerReferenceText.replacingOccurrences(of: "://mount/", with: "://other/").utf8)
    case "query": payload = Data((markerReferenceText + "?other=1").utf8)
    case "legacy": payload = Data("iscsi-fskit://nas.local:3260/legacy?readOnly=0".utf8)
    default: payload = Data(repeating: 0xFF, count: 121)
    }
    var bytes = Data("soba.dev/iscsi/mount-resource/1\0".utf8)
    let length = UInt32(payload.count)
    bytes.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: length >> $0) })
    bytes.append(Data(SHA256.hash(data: payload)))
    bytes.append(payload)
    bytes.append(Data(repeating: 0, count: 8192 - bytes.count))
    #expect(throws: ProtocolError.self) { try BlockMountResource(header: bytes) }
}
