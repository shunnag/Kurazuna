import Foundation
import Testing

@testable import ISCSICore

private func identityDescriptor(
    _ kind: UInt8, _ payload: [UInt8], code: UInt8 = 1,
    association: UInt8 = 0
) -> [UInt8] {
    [code, association << 4 | kind, 0, UInt8(payload.count)] + payload
}

private func identityPage(_ descriptors: [[UInt8]]) -> Data {
    let body = descriptors.flatMap { $0 }
    return Data([0, 0x83, UInt8(body.count >> 8), UInt8(body.count & 255)] + body)
}

private func paddedName(_ name: String, extra: Int = 0) -> [UInt8] {
    let content = Array(name.utf8) + [0]
    return content + Array(repeating: 0, count: (4 - content.count % 4) % 4 + extra)
}

@Test func identityUsesLUNNamesAndIgnoresPortsDevicesAndUnknownDescriptors() throws {
    let lun = identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 15))
    let ports = [
        identityDescriptor(3, [0x50] + Array(repeating: 0x45, count: 7), association: 1),
        identityDescriptor(3, [0x50] + Array(repeating: 0x67, count: 7), association: 2),
        identityDescriptor(0, [1, 2, 3]), identityDescriptor(15, [], association: 3),
    ]
    let a = try SCSILogicalUnitIdentity(data: identityPage([lun]))
    let b = try SCSILogicalUnitIdentity(data: identityPage(ports + [lun, lun]))
    #expect(a == b)
    #expect(a.designators.count == 1)
    #expect(a.designators[0].identifier == Data([0x60] + Array(repeating: 0x23, count: 15)))
    #expect(a.canonicalBytes == b.canonicalBytes)
    #expect(throws: ProtocolError.self) { try SCSILogicalUnitIdentity(data: identityPage(ports)) }
}

@Test func identityKeepsEveryDistinctNameAndCanonicalizesDescriptorOrder() throws {
    let naa = identityDescriptor(3, [0x50] + Array(repeating: 4, count: 7))
    let eui = identityDescriptor(2, Array(1...12))
    let vendor = identityDescriptor(1, Array("SobaDev ".utf8) + [0, 1, 2, 3])
    let uuid = identityDescriptor(10, [0x10, 0] + Array(1...16))
    let names = [naa, eui, vendor, uuid]
    let a = try SCSILogicalUnitIdentity(data: identityPage(names))
    let b = try SCSILogicalUnitIdentity(data: identityPage(names.reversed() + [eui]))
    #expect(a == b)
    #expect(a.designators.map(\.kind) == [.vendor, .eui, .naa, .uuid])
    #expect(a.designators.last?.identifier == Data(1...16))
    let changed = try SCSILogicalUnitIdentity(data: identityPage([naa, eui, vendor]))
    #expect(a.canonicalBytes != changed.canonicalBytes)
}

@Test(arguments: [8, 12, 16])
func identityAcceptsCompleteEUILengths(_ count: Int) throws {
    let value = Array(repeating: UInt8(0x34), count: count)
    let identity = try SCSILogicalUnitIdentity(data: identityPage([identityDescriptor(2, value)]))
    #expect(identity.designators[0].identifier == Data(value))
}

@Test(arguments: [UInt8(0x20), 0x30, 0x50, 0x60])
func identityValidatesNAASpecificLength(_ first: UInt8) throws {
    let size = first == 0x60 ? 16 : 8
    let good = [first] + Array(repeating: UInt8(1), count: size - 1)
    #expect(
        try SCSILogicalUnitIdentity(data: identityPage([identityDescriptor(3, good)]))
            .designators[0].identifier.count == size)
    #expect(throws: ProtocolError.self) {
        try SCSILogicalUnitIdentity(data: identityPage([identityDescriptor(3, good + [0])]))
    }
}

@Test(arguments: [
    "eui.0011223344556677", "naa.60014050000000010000000000000001",
    "iqn.2026-10.dev.soba:storage,L,0x0000000000000001",
])
func identityNormalizesOnlyNullPaddingOfSCSIName(_ name: String) throws {
    let a = try SCSILogicalUnitIdentity(
        data: identityPage([identityDescriptor(8, paddedName(name), code: 3)]))
    let b = try SCSILogicalUnitIdentity(
        data: identityPage([identityDescriptor(8, paddedName(name, extra: 4), code: 3)]))
    #expect(a == b)
    #expect(a.designators[0].identifier == Data(name.utf8))
}

@Test func identityRejectsTruncatedAndMalformedRecognizedNames() throws {
    let full = identityPage([identityDescriptor(3, [0x60] + Array(repeating: 3, count: 15))])
    for count in 0..<full.count {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(data: full.prefix(count))
        }
    }
    var damaged = Array(full)
    for (offset, value): (Int, UInt8) in [(0, 0x20), (1, 0x80), (7, 255)] {
        damaged = Array(full)
        damaged[offset] = value
        #expect(throws: ProtocolError.self) { try SCSILogicalUnitIdentity(data: Data(damaged)) }
    }
    for bad in [
        identityDescriptor(2, [1, 2, 3]),
        identityDescriptor(3, [0x10] + Array(repeating: 2, count: 7)),
        identityDescriptor(3, [0x50] + Array(repeating: 2, count: 7), code: 2),
        identityDescriptor(1, Array("SobaDev ".utf8)),
        identityDescriptor(10, [0x20, 0] + Array(1...16)),
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(data: identityPage([bad]))
        }
    }
    #expect(throws: ProtocolError.self) {
        try SCSILogicalUnitIdentity(data: Data(repeating: 0, count: 65_536))
    }
}

@Test func identityRejectsUnterminatedNamesEmbeddedNullsAndMissingLUNSuffix() throws {
    var badUTF8 = paddedName("iqn.2026-10.dev.soba:test,L,0x1")
    badUTF8[6] = 255
    let values = [
        Array("naa.5000000000000001".utf8), paddedName("iqn.2026-10.dev.soba:test"),
        paddedName("naa.500000000000000g"), paddedName("iqn.2026-10.dev.soba:t,L,0x"),
        paddedName("iqn.2026-10.dev.soba:t,L,0x10000000000000000"),
        paddedName("iqn.2026-10.dev.soba:t\n,L,0x1"),
        [UInt8(0x6E), 0x61, 0x61, 0, 0x31, 0, 0, 0], badUTF8,
    ]
    for bytes in values {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(data: identityPage([identityDescriptor(8, bytes, code: 3)]))
        }
    }
}

@Test func identitySupportsNonzeroDataStartIndexAndIgnoresAllocationPadding() throws {
    let page = identityPage([identityDescriptor(2, Array(1...8))])
    var containing = Data(repeating: 0xFA, count: 19)
    containing.append(page)
    let sliced = containing.dropFirst(19)
    #expect(sliced.startIndex != 0)
    #expect(try SCSILogicalUnitIdentity(data: sliced) == SCSILogicalUnitIdentity(data: page))
    #expect(
        try SCSILogicalUnitIdentity(data: page + Data(repeating: 0xFF, count: 16))
            == SCSILogicalUnitIdentity(data: page))
}

@Test func identityReviewRejectsTextualNAAWithWrongAuthorityOrWidth() throws {
    for name in [
        "naa.1000000000000001", "naa.6000000000000001",
        "naa.50000000000000010000000000000001", "naa.30000000000000010000000000000001",
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(
                data: identityPage([identityDescriptor(8, paddedName(name), code: 3)]))
        }
    }
}

@Test func identityReviewRejectsInvalidIQNDateAndDomainGrammar() throws {
    for node in [
        "iqn.x", "iqn.2026-13.dev.soba:test", "iqn.2026-00.dev.soba:test",
        "iqn.2026-10.-dev.soba:test", "iqn.2026-10.dev..soba:test", "iqn.2026-10.dev.soba:st ore",
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(
                data: identityPage([identityDescriptor(8, paddedName(node + ",L,0x1"), code: 3)]))
        }
    }
}

@Test(arguments: [
    "iqn.2001-04.com.example", "iqn.2026-10.dev.soba:storage:child",
    "iqn.2026-10.dev.soba-1:disk.2",
])
func identityAcceptsNormalizedIQNSyntaxWithoutClaimingDomainOwnership(_ node: String) throws {
    let name = node + ",L,0x0000000000000001"
    let result = try SCSILogicalUnitIdentity(
        data: identityPage([identityDescriptor(8, paddedName(name), code: 3)]))
    #expect(result.designators[0].identifier == Data(name.utf8))
}

@Test(arguments: [
    "iqn.2026-10.dev.Soba:test", "iqn.2026-10.dev.soba:tést",
    "iqn.2026-10.dev.soba:under_score", "iqn.2026-10.dev.soba:slash/name",
])
func identityDeclinesUnsupportedIQNCharacterProfilesWithoutRewriting(_ node: String) throws {
    #expect(throws: ProtocolError.unsupported("iSCSI name character profile")) {
        try SCSILogicalUnitIdentity(
            data: identityPage([identityDescriptor(8, paddedName(node + ",L,0x1"), code: 3)]))
    }
}

@Test func identityAcceptsKernelIBLOCKTerminalNullWithIndependentLUNNAA() throws {
    let raw = Array("LIO-ORG IBLOCK:00000000-1111-2222-3333-444444444444".utf8) + [UInt8(0)]
    let naa = [UInt8(0x60)] + Array(repeating: UInt8(0x11), count: 15)
    let a = try SCSILogicalUnitIdentity(
        data: identityPage([
            identityDescriptor(1, raw, code: 2),
            identityDescriptor(3, naa),
        ]))
    #expect(a.designators.contains { $0.kind == .vendor && $0.identifier == Data(raw) })
    #expect(a.usedLIOBlockIOTerminalNullCompatibility)
    #expect(!a.usedLIOFileIOTerminalNullCompatibility)
    let noNull = try SCSILogicalUnitIdentity(
        data: identityPage([
            identityDescriptor(1, Array(raw.dropLast()), code: 2), identityDescriptor(3, naa),
        ]))
    #expect(a.canonicalBytes != noNull.canonicalBytes)
    #expect(!noNull.usedLIOBlockIOTerminalNullCompatibility)
    let otherBackend = try SCSILogicalUnitIdentity(
        data: identityPage([
            identityDescriptor(
                1, Array("LIO-ORG FILEIO:00000000-1111-2222-3333-444444444444".utf8) + [0], code: 2),
            identityDescriptor(3, naa),
        ]))
    #expect(a.canonicalBytes != otherBackend.canonicalBytes)
    #expect(otherBackend.usedLIOFileIOTerminalNullCompatibility)
    #expect(!otherBackend.usedLIOBlockIOTerminalNullCompatibility)
}

@Test func identityRejectsIBLOCKNullWithoutValidLUNNAAAndMalformedNames() throws {
    let prefix = "LIO-ORG IBLOCK:"
    let serial = "00000000-1111-2222-3333-444444444444"
    let vendor = identityDescriptor(1, Array((prefix + serial).utf8) + [0], code: 2)
    let naa = identityDescriptor(3, [0x60] + Array(repeating: 0x22, count: 15))
    for others in [
        [], [identityDescriptor(3, [0x60] + Array(repeating: 0x22, count: 15), association: 1)],
        [identityDescriptor(3, [0x60] + Array(repeating: 0x22, count: 14))],
        [naa, identityDescriptor(2, [1, 2, 3])],
    ] {
        for page in [others + [vendor], [vendor] + others] {
            #expect(throws: ProtocolError.self) {
                try SCSILogicalUnitIdentity(data: identityPage(page))
            }
        }
    }
    for text in [
        prefix + serial + "\0", prefix + "00000000-1111-2222-3333-44444444444A",
        prefix + "00000000-1111-2222-3333-44444444444g",
        prefix + "000000001111-2222-3333-444444444444",
        "SobaDev IBLOCK:" + serial, "LIO-ORG IBLOCKX:" + serial, "LIO-ORG iblock:" + serial,
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(
                data: identityPage([naa, identityDescriptor(1, Array(text.utf8) + [0], code: 2)]))
        }
    }
    let ordered = try SCSILogicalUnitIdentity(data: identityPage([vendor, naa]))
    let reversed = try SCSILogicalUnitIdentity(data: identityPage([naa, vendor, vendor]))
    #expect(ordered == reversed)
}

@Test func identityPreservesObservedLIOTerminalNullWithoutCollapsingNames() throws {
    let raw = Array("LIO-ORG FILEIO:00000000-1111-2222-3333-444444444444".utf8) + [UInt8(0)]
    let naa = identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 15))
    let a = try SCSILogicalUnitIdentity(
        data: identityPage([naa, identityDescriptor(1, raw, code: 2)]))
    let b = try SCSILogicalUnitIdentity(
        data: identityPage([identityDescriptor(1, Array(raw.dropLast()), code: 2), naa]))
    #expect(a.designators.count == 2)
    #expect(a.usedLIOFileIOTerminalNullCompatibility)
    #expect(!b.usedLIOFileIOTerminalNullCompatibility)
    #expect(a.designators.first?.identifier == Data(raw))
    #expect(a.canonicalBytes != b.canonicalBytes)
    #expect(
        a
            == (try SCSILogicalUnitIdentity(
                data: identityPage([identityDescriptor(1, raw, code: 2), naa, naa]))))
}

@Test func identityRejectsUnobservedVendorNullAndMalformedLIOSuffixes() throws {
    let prefix = Array("LIO-ORG ".utf8)
    let naa = identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 15))
    for bytes in [
        prefix + [0], prefix + [0x20, 0], prefix + [0x41, 0, 0],
        prefix + [0x41, 0, 0x42], prefix + [0x1F, 0], prefix + [0x7F, 0],
        prefix + [0x80, 0], Array("SobaDev fixture".utf8) + [0],
        Array("LIO-ORG".utf8) + [0, 0x41, 0],
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(
                data: identityPage([naa, identityDescriptor(1, bytes, code: 2)]))
        }
    }
}

@Test func identityDoesNotPromoteLIOTargetPortNameToLogicalUnit() throws {
    let raw = Array("LIO-ORG FILEIO:00000000-1111-2222-3333-444444444444".utf8) + [UInt8(0)]
    #expect(throws: ProtocolError.self) {
        try SCSILogicalUnitIdentity(
            data: identityPage([identityDescriptor(1, raw, code: 2, association: 1)]))
    }
}

@Test func identityRequiresValidLUNNAAForObservedLIOCompatibilityInEitherOrder() throws {
    let raw = Array("LIO-ORG FILEIO:00000000-1111-2222-3333-444444444444".utf8) + [UInt8(0)]
    let vendor = identityDescriptor(1, raw, code: 2)
    let naa = identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 15))
    for others in [
        [], [identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 15), association: 1)],
        [identityDescriptor(3, [0x60] + Array(repeating: 0x23, count: 14))],
        [naa, identityDescriptor(2, [1, 2, 3])],
    ] {
        for page in [others + [vendor], [vendor] + others] {
            #expect(throws: ProtocolError.self) {
                try SCSILogicalUnitIdentity(data: identityPage(page))
            }
        }
    }
    for text in [
        "LIO-ORG PSCSI:00000000-1111-2222-3333-444444444444",
        "SobaDev FILEIO:00000000-1111-2222-3333-444444444444",
        "LIO-ORG FILEIO:00000000-1111-2222-3333-44444444444g",
        "LIO-ORG FILEIO:00000000-1111-2222-3333-44444444444A",
        "LIO-ORG FILEIO:000000001111-2222-3333-444444444444",
    ] {
        #expect(throws: ProtocolError.self) {
            try SCSILogicalUnitIdentity(
                data: identityPage([naa, identityDescriptor(1, Array(text.utf8) + [0], code: 2)]))
        }
    }
}

@Test func identityRetainsChangesToBothObservedLIONames() throws {
    let raw = Array("LIO-ORG FILEIO:00000000-1111-2222-3333-444444444444".utf8) + [UInt8(0)]
    let naa = [UInt8(0x60)] + Array(repeating: 0x23, count: 15)
    let initial = try SCSILogicalUnitIdentity(
        data: identityPage([identityDescriptor(1, raw, code: 2), identityDescriptor(3, naa)]))
    var changedVendor = raw
    changedVendor[changedVendor.count - 2] = 0x35
    var changedNAA = naa
    changedNAA[changedNAA.count - 1] = 0x24
    for page in [
        [identityDescriptor(1, changedVendor, code: 2), identityDescriptor(3, naa)],
        [identityDescriptor(1, raw, code: 2), identityDescriptor(3, changedNAA)],
    ] {
        #expect(
            try SCSILogicalUnitIdentity(data: identityPage(page)).canonicalBytes
                != initial.canonicalBytes)
    }
}
