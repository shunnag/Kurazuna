import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

@Test func discoveredAddressesRetainGroupsAndOnlyEmptyListsUseTheDiscoveryEndpoint() throws {
    let fallback = try Portal("discovery.local:3269")
    let empty = DiscoveredTarget(name: "iqn.2026-10.test:disk")
    #expect(try empty.connectionAddresses(fallback: fallback) == [TargetAddress(portal: fallback)])
    let target = DiscoveredTarget(
        name: empty.name,
        addresses: [
            "nas.local:0x0CBC,0bAAE=", "[::1]:3261,2", "NAS.local:3260,1",
        ])
    let addresses = try target.connectionAddresses(fallback: fallback)
    #expect(addresses.map(\.portal) == [try Portal("nas.local"), try Portal("[::1]:3261")])
    #expect(addresses.map(\.portalGroupTag) == [1, 2])
}

@Test(arguments: [
    ["nas.local"], ["nas.local:0,1"], ["nas.local,1", "nas.local,2"],
    ["[::1]:3260,"], Array(repeating: "nas.local,1", count: 17),
])
func invalidAdvertisedAddressesNeverFallBackToTheConfiguredServer(_ addresses: [String]) throws {
    let target = DiscoveredTarget(name: "iqn.2026-10.test:disk", addresses: addresses)
    #expect(throws: ProtocolError.self) {
        try target.connectionAddresses(fallback: Portal("discovery.local"))
    }
}

@Test(arguments: ["nas.local", "[::1]:0,1", "nas.local,70000"])
func malformedDiscoveryAddressesFailTheSessionBeforePublishingTargets(_ address: String)
    async throws
{
    let entries: [TextParameters.Entry] = [
        .init("TargetName", "iqn.2026-10.test:disk"), .init("TargetAddress", address),
    ]
    var responses = try loginFixtures()
    responses.append(
        try fixture(
            opcode: 0x24, flags: 0x80, tag: 2, stat: 2, data: TextParameters(entries).encoded()))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration())
    try await session.login()
    await #expect(throws: ProtocolError.self) { try await session.discover() }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}

private func continuedDiscoveryReplies(_ data: Data) throws -> [Data] {
    var replies = try loginFixtures()
    let fragments = stride(from: 0, to: data.count, by: 8192)
    for (index, offset) in fragments.enumerated() {
        let final = offset + 8192 >= data.count
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x24
        header[1] = final ? 0x80 : 0x40
        header.put(UInt32(2), at: 16)
        header.put(final ? UInt32.max : UInt32(42), at: 20)
        header.put(UInt32(index + 2), at: 24)
        header.put(UInt32(1), at: 28)
        header.put(UInt32(32), at: 32)
        replies.append(
            try PDU(header: header, data: Data(data.dropFirst(offset).prefix(8192))).encoded())
    }
    return replies
}

@Test(arguments: [
    ISCSISession.maximumDiscoveryTargets - 1, ISCSISession.maximumDiscoveryTargets,
    ISCSISession.maximumDiscoveryTargets + 1,
])
func discoveryTargetLimitIsIndependentOfTextBytesAndEntries(_ count: Int) async throws {
    let entries = (0..<count).flatMap { index -> [TextParameters.Entry] in
        [
            .init("TargetName", "iqn.2026-10.test:disk\(index)"),
            .init("TargetAddress", "nas.local,1"),
        ]
    }
    let text = try TextParameters(entries).encoded()
    let transport = ScriptedTransport(try continuedDiscoveryReplies(text))
    let session = try ISCSISession(transport: transport, configuration: configuration())
    try await session.login()
    if count <= ISCSISession.maximumDiscoveryTargets {
        let targets = try await session.discover()
        #expect(targets.count == count)
        #expect(targets.last?.name == "iqn.2026-10.test:disk\(count - 1)")
        #expect(targets.allSatisfy { $0.addresses == ["nas.local,1"] })
        await session.close()
    } else {
        await #expect(throws: ProtocolError.limitExceeded("discovery targets")) {
            try await session.discover()
        }
        #expect(await session.state == .failed)
        #expect(await transport.isClosed)
    }
}

@Test func discoveryEntryLimitAppliesAcrossContinuationFragments() async throws {
    let text = Data(String(repeating: "a=\0", count: TextParameters.maximumEntryCount + 1).utf8)
    let transport = ScriptedTransport(try continuedDiscoveryReplies(text))
    let session = try ISCSISession(transport: transport, configuration: configuration())
    try await session.login()
    await #expect(throws: ProtocolError.limitExceeded("text entries")) {
        try await session.discover()
    }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
}
