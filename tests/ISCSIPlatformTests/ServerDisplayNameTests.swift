import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

// These ranges are an independent expectation, not the implementation's property predicates.
@Test(arguments: Array(0x00...0x1F) + Array(0x7F...0x9F))
private func serverLabelsExposeAcceptedControlsWithoutChangingName(_ value: Int) throws {
    let scalar = try #require(Unicode.Scalar(value))
    let name = "A" + String(scalar) + "B"
    if [0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x85].contains(value) {
        // Existing newline/NUL rejection remains part of the persisted format.
        #expect(throws: ProtocolError.self) {
            try ServerProfile(name: name, portal: Portal("example.invalid"))
        }
    } else {
        let server = try ServerProfile(name: name, portal: Portal("example.invalid"))
        #expect(server.displayName == String(format: "A[U+%04X]B", value))
        #expect(Array(server.name.unicodeScalars) == Array(name.unicodeScalars))
    }
}

@Test(arguments: [0x061C, 0x200E, 0x200F] + Array(0x202A...0x202E) + Array(0x2066...0x2069))
private func serverLabelsExposeEachBidirectionalControl(_ value: Int) throws {
    let name = "A" + String(try #require(Unicode.Scalar(value))) + "B"
    let server = try ServerProfile(name: name, portal: Portal("example.invalid"))
    #expect(server.displayName == String(format: "A[U+%04X]B", value))
    #expect(Array(server.name.unicodeScalars) == Array(name.unicodeScalars))
}

@Test(arguments: [
    "書庫 2026", "e\u{0301}", "מחשב 123", "مخزن 123", "نامه\u{200C}ای",
    "👩🏽‍💻", "👨‍👩‍👧‍👦", "🏳️‍🌈", "क्\u{200D}ष", "क्\u{200C}ष", "☀\u{FE0F}",
    "A\u{061B}B", "A\u{061D}B", "A\u{200B}B", "A\u{2010}B", "A\u{2029}B",
    "A\u{2065}B", "A\u{206A}B", "A\u{00A0}B", "A~B",
])
private func serverLabelPreservesOtherScalarsExactly(_ name: String) throws {
    if name.contains("\u{2029}") {
        #expect(throws: ProtocolError.self) {
            try ServerProfile(name: name, portal: Portal("example.invalid"))
        }
    } else {
        let server = try ServerProfile(name: name, portal: Portal("example.invalid"))
        #expect(Array(server.displayName.unicodeScalars) == Array(name.unicodeScalars))
    }
}

@Test private func storedControlNamesRoundTripWithIdentityAndCredentialsIntact() throws {
    let server = try ServerProfile(
        name: "A\u{001B}\u{0009}\u{202E}B", portal: Portal("example.invalid"),
        chapUsername: "test-user", credentialID: UUID())
    let original = try ProfileDocument(identity: .makeNew(), servers: [server])
    let decoded = try JSONDecoder().decode(
        ProfileDocument.self, from: JSONEncoder().encode(original))
    let copy = try #require(decoded.servers.first)
    #expect(Array(copy.name.unicodeScalars) == Array(server.name.unicodeScalars))
    #expect(copy.displayName == "A[U+001B][U+0009][U+202E]B")
    #expect(copy.id == server.id && copy.credentialContext == server.credentialContext)
    #expect(decoded.identity == original.identity)
    let secondCopy = try JSONDecoder().decode(
        ServerProfile.self, from: JSONEncoder().encode(copy))
    #expect(Array(secondCopy.name.unicodeScalars) == Array(server.name.unicodeScalars))
}

@Test private func maximumLengthControlNameKeepsItsStoredLength() throws {
    let name = String(repeating: "\u{202E}", count: 80)
    let server = try ServerProfile(name: name, portal: Portal("example.invalid"))
    #expect(server.name.count == 80)
    #expect(server.displayName == String(repeating: "[U+202E]", count: 80))
    #expect(throws: ProtocolError.self) {
        try ServerProfile(name: name + "\u{202E}", portal: Portal("example.invalid"))
    }
}
