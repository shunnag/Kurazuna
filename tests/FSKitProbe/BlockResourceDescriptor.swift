import CryptoKit
import FSKit
import Foundation
import ISCSICore

/// A test-only metadata format. It authorizes only nonce-scoped loopback fixtures.
enum BlockResourceDescriptor {
    static let imageBytes = 1_048_576
    static let headerBytes = 8192
    private static let magic: Data = {
        let prefix = Data("soba.dev/iscsi/block-control/1".utf8)
        return prefix + Data(repeating: 0, count: 32 - prefix.count)
    }()

    static func validate(_ value: ConnectionDescriptor) throws {
        guard value.portal.host == "127.0.0.1", value.portal.port > 1024,
            value.targetName == "iqn.2026-10.test:fskit-" + value.profileID.uuidString.lowercased(),
            value.mountID != nil, value.chapUsername == nil, value.targetCHAPUsername == nil,
            value.credentialID == nil, value.settingsBinding == nil, value.portalGroupTag == nil,
            value.imagePresentation == .raw, value.lun.addressKey == "0000000000000000"
        else { throw ProtocolError.malformed("block control descriptor scope") }
    }

    static func pack(_ url: String) throws -> Data {
        let payload = Data(url.utf8)
        guard magic.count == 32, (1...4096).contains(payload.count) else {
            throw ProtocolError.invalidState
        }
        let count = UInt32(payload.count)
        var result = magic
        result.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: count >> $0) })
        result.append(Data(SHA256.hash(data: payload)))
        result.append(payload)
        result.append(Data(repeating: 0, count: headerBytes - result.count))
        return result
    }

    static func encode(_ value: ConnectionDescriptor) throws -> Data {
        try validate(value)
        return try pack(value.resourceURL.absoluteString)
    }

    static func decode(_ data: Data) throws -> ConnectionDescriptor {
        guard data.count == headerBytes, data.prefix(32) == magic else {
            throw ProtocolError.malformed("block control header")
        }
        let count = data[32..<36].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1...4096).contains(count) else { throw ProtocolError.invalidState }
        let end = 68 + Int(count)
        let payload = data[68..<end]
        guard Data(SHA256.hash(data: payload)) == data[36..<68],
            data[end...].allSatisfy({ $0 == 0 }),
            let text = String(data: payload, encoding: .utf8), let url = URL(string: text)
        else { throw ProtocolError.malformed("block control integrity") }
        let value = try ConnectionDescriptor(resourceURL: url)
        try validate(value)
        return value
    }

    static func read(_ resource: FSBlockDeviceResource) throws -> ConnectionDescriptor {
        guard resource.blockSize == 512, resource.blockCount == UInt64(imageBytes / 512),
            [UInt64(512), 4096].contains(resource.physicalBlockSize)
        else { throw ProtocolError.malformed("block control resource geometry") }
        var data = Data(count: headerBytes)
        let count = try data.withUnsafeMutableBytes { buffer in
            try resource.read(into: buffer, startingAt: 0, length: headerBytes)
        }
        guard count == headerBytes else {
            throw ProtocolError.malformed("block control short read")
        }
        return try decode(data)
    }

    static func check(root: URL, nonce: UUID) throws {
        func value(host: String = "127.0.0.1", mounted: Bool = true) throws -> ConnectionDescriptor
        {
            try ConnectionDescriptor(
                profileID: nonce, portal: Portal(host: host, port: 3260),
                initiatorName: "iqn.2026-10.test:fskit-probe-" + nonce.uuidString.lowercased(),
                targetName: "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased(),
                lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5],
                mountID: mounted ? UUID() : nil)
        }
        let original = try value()
        let encoded = try encode(original)
        guard try decode(encoded) == original else { throw ProtocolError.invalidState }
        var badMagic = encoded
        badMagic[0] ^= 1
        var badDigest = encoded
        badDigest[36] ^= 1
        var badLength = encoded
        badLength[32] = 1
        var badPadding = encoded
        badPadding[headerBytes - 1] = 1
        let cases = [
            badMagic, badDigest, badLength, badPadding, Data(encoded.dropLast()),
            try pack(value(host: "192.0.2.1").resourceURL.absoluteString),
            try pack(value(mounted: false).resourceURL.absoluteString),
        ]
        for data in cases {
            var rejected = false
            do { _ = try decode(data) } catch { rejected = true }
            guard rejected else { throw ProtocolError.invalidState }
        }
        try encoded.write(
            to: root.appendingPathComponent("BlockHeader.bin"), options: .withoutOverwriting)
        let report: [String: Any] = [
            "validRoundTrip": true, "rejectedHeaders": cases.count,
            "headerBytes": headerBytes, "resourceURL": try original.resourceURL.absoluteString,
        ]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(to: root.appendingPathComponent("BlockCodec.json"), options: .withoutOverwriting)
        print("PASS: block control codec round trip and \(cases.count) malformed/scope refusals")
    }
}
