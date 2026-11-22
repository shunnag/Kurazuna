import Foundation
import Testing

@testable import ISCSICore

private func routeDescriptor(binding: Data? = nil) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(uuidString: "00000000-0000-4000-8000-000000000069")!,
        portal: Portal("source.local"), initiatorName: "iqn.2026-10.test:initiator",
        targetName: "iqn.2026-10.test:disk", lun: LogicalUnit(0), readOnly: true,
        isid: [0x80, 1, 2, 3, 4, 5], settingsBinding: binding)
}

@Test func mountSettingsBindingRoundTripsWithoutChangingLegacyResourceIdentities() throws {
    let legacy = try routeDescriptor()
    let expected =
        "iscsi-fskit://source.local:3260/00000000-0000-4000-8000-000000000069?initiator=iqn.2026-10.test:initiator&target=iqn.2026-10.test:disk&lun=0x0000000000000000&readOnly=1&isid=800102030405"
    #expect(try legacy.resourceURL.absoluteString == expected)
    #expect(try ConnectionDescriptor(resourceURL: URL(string: expected)!) == legacy)
    let value = try routeDescriptor(binding: Data(0..<32)).assigningMountID(UUID())
    #expect(try value.resourceIdentity != legacy.resourceIdentity)
    #expect(try ConnectionDescriptor(resourceURL: value.resourceURL) == value)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(value))
            == value)
    #expect(try value.assigningMountID(UUID()).settingsBinding == value.settingsBinding)
    for length in [0, 31, 33] {
        #expect(throws: ProtocolError.self) {
            try routeDescriptor(binding: Data(repeating: 0, count: length))
        }
    }
    for text in [
        "", String(repeating: "0", count: 63), String(repeating: "0", count: 65),
        String(repeating: "F", count: 64), String(repeating: "g", count: 64),
    ] {
        #expect(throws: ProtocolError.self) {
            try ConnectionDescriptor(resourceURL: URL(string: expected + "&settings=" + text)!)
        }
    }
}

@Test func aMountedRouteIsBoundToTheExactResourceAndSuccessfulWirePath() throws {
    let descriptor = try routeDescriptor(binding: Data(repeating: 7, count: 32)).assigningMountID(
        UUID())
    let middle = try Portal("middle.local")
    let final = try Portal("final.local")
    let hint = try PermanentPortalRedirect(source: descriptor.portal, destinations: [middle])
    let report = try ConnectionRouteReport(
        resourceIdentity: descriptor.resourceIdentity, connectedPortal: final,
        contactedPortals: [descriptor.portal, middle, final], permanentRedirects: [hint],
        creationOrder: 1)
    #expect(try ConnectionRouteReport(data: report.encoded(), descriptor: descriptor) == report)
    #expect(throws: ProtocolError.self) {
        try report.validate(for: descriptor.assigningMountID(UUID()))
    }
    #expect(throws: ProtocolError.self) {
        try ConnectionRouteReport(data: Data(repeating: 0, count: 65_537), descriptor: descriptor)
    }
    var object = try #require(
        JSONSerialization.jsonObject(with: report.encoded()) as? [String: Any])
    for version in [0, 2] {
        object["version"] = version
        #expect(throws: ProtocolError.self) {
            try ConnectionRouteReport(
                data: JSONSerialization.data(withJSONObject: object), descriptor: descriptor)
        }
    }
    #expect(throws: ProtocolError.self) {
        try ConnectionRouteReport(
            resourceIdentity: descriptor.resourceIdentity, connectedPortal: final,
            contactedPortals: [middle, final], permanentRedirects: [], creationOrder: 1
        ).validate(for: descriptor)
    }
}

@Test func malformedMountedRoutePathsCannotBecomeSettingsHints() throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let identity = Data(repeating: 0, count: 32)
    func report(
        _ path: [Portal], _ hints: [PermanentPortalRedirect] = [], order: UInt64 = 1,
        id: Data? = nil
    ) throws -> ConnectionRouteReport {
        try ConnectionRouteReport(
            resourceIdentity: id ?? identity, connectedPortal: b,
            contactedPortals: path, permanentRedirects: hints, creationOrder: order)
    }
    for path in [[], [a], [a, b, a, b], [a, try Portal("A.LOCAL"), b], [a, b, c]] {
        #expect(throws: ProtocolError.self) { try report(path) }
    }
    for hints in [
        [try PermanentPortalRedirect(source: a, destinations: [c])],
        [try PermanentPortalRedirect(source: b, destinations: [c])],
        [try PermanentPortalRedirect(source: c, destinations: [b])],
        Array(repeating: try PermanentPortalRedirect(source: a, destinations: [b]), count: 2),
    ] {
        #expect(throws: ProtocolError.self) { try report([a, b], hints) }
    }
    #expect(throws: ProtocolError.self) { try report([a, b], order: 0) }
    #expect(throws: ProtocolError.self) { try report([a, b], id: Data([0])) }
}
