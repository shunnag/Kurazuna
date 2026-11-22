import Foundation
import Testing

@testable import ISCSICore

@Test func boundedResourceReferencesPreserveLongConnectionMetadataAndLegacyPersistence() throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("[2001:db8::1234]:65535"),
        initiatorName: "iqn.2026-10.test:" + String(repeating: "a", count: 206),
        targetName: "iqn.2026-10.test:" + String(repeating: "b", count: 206),
        lun: LogicalUnit(addressKey: "0001400200034004"), readOnly: true,
        chapUsername: String(repeating: "?", count: 223), isid: [0x80, 1, 2, 3, 4, 5],
        mountID: UUID(), credentialID: UUID(), imagePresentation: .udsp,
        targetCHAPUsername: String(repeating: "&", count: 223), portalGroupTag: 65535,
        settingsBinding: Data(repeating: 0xCD, count: 32))
    #expect(descriptor.initiatorName.utf8.count == 223)
    #expect(try descriptor.resourceURL.absoluteString.utf8.count > 1023)
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    #expect(reference.url.absoluteString.utf8.count == 121)
    #expect(try ConnectionResourceReference(url: reference.url) == reference)
    #expect(descriptor.acceptsResourceURL(reference.url))
    #expect(try descriptor.acceptsResourceURL(descriptor.resourceURL))
    let data = try JSONEncoder().encode(descriptor)
    #expect(try JSONDecoder().decode(ConnectionDescriptor.self, from: data) == descriptor)
    #expect(!String(decoding: data, as: UTF8.self).contains("mount/"))

    var components = try #require(
        URLComponents(url: descriptor.resourceURL, resolvingAgainstBaseURL: false))
    for name in [
        "initiator", "target", "lun", "readOnly", "isid", "chap", "targetCHAP", "portalGroup",
        "credential", "mount", "image", "settings",
    ] {
        let original = components
        components.queryItems?.removeAll { $0.name == name }
        let replacements = [
            "initiator": "iqn.2026-10.test:other", "target": "iqn.2026-10.test:other",
            "lun": "0", "readOnly": "0", "isid": "800102030406",
            "chap": "other", "targetCHAP": "other", "portalGroup": "1",
            "credential": UUID().uuidString.lowercased(), "mount": UUID().uuidString.lowercased(),
            "image": "raw", "settings": String(repeating: "00", count: 32),
        ]
        // Removing UDSP means raw; all other variants remain independently valid.
        if name != "image" {
            components.queryItems?.append(.init(name: name, value: replacements[name]!))
        }
        let changed = try ConnectionDescriptor(resourceURL: #require(components.url))
        #expect(!changed.acceptsResourceURL(reference.url))
        components = original
    }
    components.host = "[2001:db8::4321]"
    #expect(
        try !ConnectionDescriptor(resourceURL: #require(components.url)).acceptsResourceURL(
            reference.url))
    components.host = "[2001:db8::1234]"
    components.path = "/" + UUID().uuidString.lowercased()
    #expect(
        try !ConnectionDescriptor(resourceURL: #require(components.url)).acceptsResourceURL(
            reference.url))
}

@Test func resourceReferencesRejectAliasesAndIncompleteBindings() throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
    #expect(throws: ProtocolError.self) { try ConnectionResourceReference(descriptor: descriptor) }
    let mounted = try descriptor.assigningMountID(UUID())
    let text = try ConnectionResourceReference(descriptor: mounted).url.absoluteString
    for invalid in [
        text.uppercased(), text + "?x=1", text + "#fragment", text + "/", String(text.dropLast()),
        text.replacingOccurrences(of: "://mount/", with: "://user@mount/"),
        text.replacingOccurrences(of: "://mount/", with: "://mount:3260/"),
        text.replacingOccurrences(of: "://mount/", with: "://other/"),
        text.replacingOccurrences(of: "://mount/", with: "://mount//"),
        text.replacingOccurrences(of: "/", with: "%2F"),
    ] {
        if let url = URL(string: invalid) {
            #expect(throws: ProtocolError.self) { try ConnectionResourceReference(url: url) }
            #expect(!mounted.acceptsResourceURL(url))
        }
    }
}
