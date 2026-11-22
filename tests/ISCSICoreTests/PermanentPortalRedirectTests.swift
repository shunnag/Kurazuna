import Foundation
import Testing

@testable import ISCSICore

@Test func permanentPortalHintsNormalizeAliasesAndExcludeTheirOwnSource() throws {
    let source = try Portal("NAS.local")
    let first = try Portal("Storage.local:3271")
    let redirect = try PermanentPortalRedirect(
        source: source, destinations: [Portal("nas.LOCAL"), first, Portal("storage.LOCAL:3271")])
    #expect(redirect.destinations == [first])
    #expect(
        try JSONDecoder().decode(PermanentPortalRedirect.self, from: JSONEncoder().encode(redirect))
            == redirect)
    #expect(throws: ProtocolError.malformed("permanent redirect loop")) {
        try PermanentPortalRedirect(source: source, destinations: [Portal("nas.local")])
    }
}

@Test func permanentPortalHintsRetainZoneIdentifierCaseAndOnlyPreferAdvertisedEndpoints() throws {
    let source = try Portal("source.local")
    let a = try Portal("[fe80::1%EN0]")
    let b = try Portal("[fe80::1%en0]")
    let redirect = try PermanentPortalRedirect(source: source, destinations: [a, b])
    #expect(try redirect.preferring(b).destinations == [b, a])
    #expect(throws: ProtocolError.invalidState) {
        try redirect.preferring(Portal("unadvertised.local"))
    }
}

@Test(arguments: [0, 17])
func permanentPortalHintAddressListsAreBounded(_ count: Int) throws {
    #expect(throws: ProtocolError.limitExceeded("permanent redirect addresses")) {
        try PermanentPortalRedirect(
            source: Portal("source.local"),
            destinations: (0..<count).map {
                try Portal("storage\($0).local")
            })
    }
}
