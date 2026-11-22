import Foundation
import Testing

@testable import ISCSICore

@Test func aSelectedPortalGroupSurvivesMountIdentityAndPersistence() throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("[::1]:3271"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], portalGroupTag: 65535)
    #expect(try ConnectionDescriptor(resourceURL: descriptor.resourceURL) == descriptor)
    let mounted = try descriptor.assigningMountID(UUID())
    #expect(mounted.portalGroupTag == 65535)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(mounted))
            == mounted)
    let originalURL = try descriptor.resourceURL.absoluteString
    for value in ["-1", "65536", "01", "0x1", ""] {
        let malformed = originalURL.replacingOccurrences(
            of: "portalGroup=65535", with: "portalGroup=" + value)
        #expect(throws: ProtocolError.self) {
            try ConnectionDescriptor(resourceURL: #require(URL(string: malformed)))
        }
    }
}

@Test func mutualCHAPIdentitySurvivesResourceAndPersistenceWithoutDowngrade() throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(1), readOnly: true, chapUsername: "Mac", isid: [0x80, 1, 2, 3, 4, 5],
        credentialID: UUID(), targetCHAPUsername: "Server")
    #expect(try ConnectionDescriptor(resourceURL: descriptor.resourceURL) == descriptor)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(descriptor))
            == descriptor)
    #expect(try descriptor.assigningMountID(UUID()).targetCHAPUsername == "Server")
    var components = try #require(
        URLComponents(url: descriptor.resourceURL, resolvingAgainstBaseURL: false))
    components.queryItems?.removeAll { $0.name == "chap" || $0.name == "credential" }
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: components.url!) }
    components.queryItems?.append(.init(name: "chap", value: "Mac"))
    components.queryItems?.append(.init(name: "targetCHAP", value: "Other"))
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: components.url!) }
}

@Test func imagePresentationSurvivesPersistenceAndCannotBeSilentlyIgnored() throws {
    func value(_ presentation: LUNImagePresentation) throws -> ConnectionDescriptor {
        try ConnectionDescriptor(
            profileID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            portal: Portal("nas.local"), initiatorName: "iqn.2026-10.test:initiator",
            targetName: "iqn.2026-10.test:disk", lun: LogicalUnit(0), readOnly: false,
            isid: [0x80, 1, 2, 3, 4, 5], imagePresentation: presentation)
    }
    let raw = try value(.raw)
    let image = try value(.udsp)
    #expect(try !raw.resourceURL.absoluteString.contains("image="))
    #expect(try image.resourceURL.absoluteString.contains("image=udsp"))
    #expect(try raw.resourceIdentity != image.resourceIdentity)
    #expect(try image.assigningMountID(UUID()).imagePresentation == .udsp)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(image))
            == image)
    for name in ["sparsebundle", "unknown", "", "raw"] {
        var c = try #require(URLComponents(url: raw.resourceURL, resolvingAgainstBaseURL: false))
        c.queryItems?.append(URLQueryItem(name: "image", value: name))
        #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: c.url!) }
    }
}

@Test func connectionStateCodecRejectsUnknownVersionsAndTruncation() throws {
    for state in DiskConnectionState.allCases {
        #expect(try DiskConnectionState(encoded: state.encoded) == state)
    }
    for bytes in [Data(), Data([1]), Data([1, 1, 0]), Data([2, 1]), Data([1, 255])] {
        #expect(throws: ProtocolError.self) { try DiskConnectionState(encoded: bytes) }
    }
    let data = Data([0, 1, 2, 0])
    #expect(try DiskConnectionState(encoded: data[1..<3]) == .interrupted)
}

@Test(arguments: ["4001000000000000", "0001400200034004", "c101000000000000"])
func reportedLUNAddressSurvivesEveryRepresentation(_ hex: String) throws {
    let lun = try LogicalUnit(addressKey: hex)
    var report = [UInt8](repeating: 0, count: 8)
    report.put(UInt32(8), at: 0)
    report.append(contentsOf: lun.wireBytes)
    #expect(try LUNList.decode(Data(report)) == [lun])
    #expect(try JSONDecoder().decode(LogicalUnit.self, from: JSONEncoder().encode(lun)) == lun)
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk", lun: lun,
        readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let decoded = try ConnectionDescriptor(resourceURL: descriptor.resourceURL)
    #expect(decoded == descriptor)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(descriptor))
            == descriptor)
    let transfer = try CommandTransfer(
        command: .read16(lba: 0, blocks: 1, blockSize: 512), lun: decoded.lun, taskTag: 8)
    let request = try transfer.request(commandSequenceNumber: 1, expectedStatusSequenceNumber: 0)
    #expect(Array(request.header[8..<16]) == lun.wireBytes)
}

@Test func flatAndPeripheralAddressesDoNotCollapse() throws {
    let flat = try LogicalUnit(addressKey: "4001000000000000")
    let peripheral = try LogicalUnit(1)
    #expect(flat != peripheral)
    #expect(flat.stableIdentifier != peripheral.stableIdentifier)
    #expect(peripheral.stableIdentifier == "1")
    #expect(try LogicalUnit(256).stableIdentifier == "256")
    #expect(throws: ProtocolError.self) { try LogicalUnit(addressKey: "0001") }
    #expect(throws: ProtocolError.self) { try LogicalUnit(wireBytes: [0, 1]) }
}

@Test func legacyNumericResourceURLsRemainReadable() throws {
    let value = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(257), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
    var c = try #require(URLComponents(url: value.resourceURL, resolvingAgainstBaseURL: false))
    c.queryItems = c.queryItems?.map {
        $0.name == "lun" ? URLQueryItem(name: "lun", value: "257") : $0
    }
    #expect(try ConnectionDescriptor(resourceURL: c.url!).lun == value.lun)
}

@Test func credentialReferenceSurvivesMountAssignmentAndPersistence() throws {
    let id = UUID()
    let value = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"), initiatorName: "iqn.2026-10.test:initiator",
        targetName: "iqn.2026-10.test:disk", lun: LogicalUnit(0), readOnly: false,
        chapUsername: "User", isid: [0x80, 1, 2, 3, 4, 5], credentialID: id)
    let mounted = try value.assigningMountID(UUID())
    #expect(mounted.credentialID == id)
    #expect(try ConnectionDescriptor(resourceURL: mounted.resourceURL) == mounted)
    #expect(
        try JSONDecoder().decode(ConnectionDescriptor.self, from: JSONEncoder().encode(mounted))
            == mounted)
    let invalid = try #require(
        URL(string: value.resourceURL.absoluteString + "&credential=" + id.uuidString))
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: invalid) }
    var components = try #require(
        URLComponents(url: value.resourceURL, resolvingAgainstBaseURL: false))
    components.queryItems?.removeAll { $0.name == "chap" }
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: components.url!) }
    components.queryItems = components.queryItems?.filter { $0.name != "credential" }
    components.queryItems?.append(URLQueryItem(name: "credential", value: "invalid"))
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: components.url!) }
}

@Test(arguments: ["nas.local:3260", "[2001:db8::1]:3261", "[::1]:3260"])
func resourceURLRoundTrip(_ portal: String) throws {
    let value = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal(portal),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk?x&y%20",
        lun: LogicalUnit(257), readOnly: true, chapUsername: "user + & 名前",
        isid: [0x80, 1, 2, 3, 4, 5])
    #expect(try ConnectionDescriptor(resourceURL: value.resourceURL) == value)
}

@Test(arguments: ["&password=secret", "&readOnly=0", "&isid=800102030405", "&unknown=1"])
func resourceURLRejectsAdditionalOrDuplicateParameters(_ suffix: String) throws {
    let value = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
    let url = try #require(URL(string: value.resourceURL.absoluteString + suffix))
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: url) }
}

@Test func resourceURLRejectsCredentialsAndMissingFields() throws {
    let value = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
    var c = try #require(URLComponents(url: value.resourceURL, resolvingAgainstBaseURL: false))
    c.password = "do-not-accept"
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: c.url!) }
    c.password = nil
    c.queryItems?.removeAll(where: { $0.name == "readOnly" })
    #expect(throws: ProtocolError.self) { try ConnectionDescriptor(resourceURL: c.url!) }
}

@Test func senseAndLogicalUnitDecodingBoundaries() throws {
    let fixed = Data([0x70, 0, 6, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x29, 0])
    #expect(try SCSISense(data: fixed).isUnitAttention)
    #expect(try SCSISense(data: Data([0x72, 5, 0x20, 0, 0, 0, 0, 0])).isUnsupportedCommand)
    #expect(throws: ProtocolError.self) { try SCSISense(data: fixed.dropLast()) }
    var report = Array(repeating: UInt8(0), count: 24)
    report.put(UInt32(16), at: 0)
    report[16] = 0x41
    #expect(try LUNList.decode(Data(report)).map(\.displayIdentifier) == ["0", "256"])
    report[16] = 0
    #expect(throws: ProtocolError.self) { try LUNList.decode(Data(report)) }
    report[16] = 0xC1
    #expect(try LUNList.decode(Data(report)).last?.wireBytes == [0xC1, 0, 0, 0, 0, 0, 0, 0])
    report.put(UInt32(17), at: 0)
    #expect(throws: ProtocolError.self) { try LUNList.decode(Data(report)) }
}
