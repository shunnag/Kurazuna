import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

@Test func localNetworkPermissionFailureDoesNotTryOtherAddressesOrSendLogin() async throws {
    let first = try Portal("first.local")
    let alternate = try Portal("alternate.local")
    let denied = ConnectorTransport(connectError: .localNetworkAccessRequired)
    let factory = ConnectorFactory([first: denied])
    await #expect(throws: ProtocolError.localNetworkAccessRequired) {
        try await SessionConnector.connect(
            addresses: [TargetAddress(portal: first), TargetAddress(portal: alternate)],
            configuration: configuration(normal: true), clock: .continuous,
            factory: { portal, _ in try factory.make(portal) })
    }
    #expect(factory.portals == [first])
    #expect(await denied.closed)
    #expect(await denied.inner.writes.isEmpty)
}

@Test func aFailedPermanentRedirectBranchDoesNotBecomeASavedRoute() async throws {
    let a = try Portal("first.local")
    let b = try Portal("unavailable.local")
    let c = try Portal("alternate.local")
    let factory = try ConnectorFactory([
        a: ConnectorTransport([moved([b.description], permanent: true)]),
        b: ConnectorTransport(connectError: .connectionClosed),
        c: ConnectorTransport(loginFixtures(normal: true)),
    ])
    let result = try await SessionConnector.connect(
        addresses: [TargetAddress(portal: a), TargetAddress(portal: c)],
        configuration: configuration(normal: true), clock: .continuous,
        factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == c && result.permanentRedirects.isEmpty)
    #expect(result.contactedPortals == [c])
    #expect(factory.portals == [a, b, c])
    await result.session.close()
}

@Test(arguments: [false, true])
func onlyPermanentStepsInTheSuccessfulPathAreRemembered(_ permanentFirst: Bool) async throws {
    let a = try Portal("first.local")
    let b = try Portal("middle.local")
    let c = try Portal("last.local")
    let factory = try ConnectorFactory([
        a: ConnectorTransport([moved([b.description], permanent: permanentFirst)]),
        b: ConnectorTransport([moved([c.description], permanent: !permanentFirst)]),
        c: ConnectorTransport(loginFixtures(normal: true)),
    ])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(normal: true), clock: .continuous,
        factory: { portal, _ in try factory.make(portal) })
    #expect(
        result.permanentRedirects == [
            try PermanentPortalRedirect(
                source: permanentFirst ? a : b, destinations: [permanentFirst ? b : c])
        ])
    #expect(result.contactedPortals == [a, b, c])
    await result.session.close()
}

@Test func aRedirectToAnAlreadyQueuedAlternateRetainsItsSuccessfulProvenance() async throws {
    let a = try Portal("first.local")
    let b = try Portal("alternate.local")
    let factory = try ConnectorFactory([
        a: ConnectorTransport([moved([b.description], permanent: true)]),
        b: ConnectorTransport(loginFixtures(normal: true)),
    ])
    let result = try await SessionConnector.connect(
        addresses: [TargetAddress(portal: a), TargetAddress(portal: b)],
        configuration: configuration(normal: true), clock: .continuous,
        factory: { portal, _ in try factory.make(portal) })
    #expect(
        result.permanentRedirects == [try PermanentPortalRedirect(source: a, destinations: [b])])
    #expect(factory.portals == [a, b])
    await result.session.close()
}

@Test func cachedPermanentHopsCanBypassUnavailableOriginalEndpoints() async throws {
    let a = try Portal("first.local")
    let b = try Portal("middle.local")
    let c = try Portal("last.local")
    let hints = try [
        PermanentPortalRedirect(source: a, destinations: [b]),
        PermanentPortalRedirect(source: b, destinations: [c]),
    ]
    let factory = try ConnectorFactory([c: ConnectorTransport(loginFixtures(normal: true))])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(normal: true), cachedRedirects: hints,
        clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == c && result.permanentRedirects == hints)
    #expect(result.contactedPortals == [c])
    #expect(result.invalidatedRedirectSources.isEmpty && factory.portals == [c])
    await result.session.close()
}

@Test(arguments: [false, true])
func aStalePermanentHintConsultsItsSourceOnlyAfterATransportFailure(_ authenticate: Bool)
    async throws
{
    let a = try Portal("source.local")
    let b = try Portal("cached.local")
    let remote =
        try authenticate
        ? ConnectorTransport([authRejected()]) : ConnectorTransport(connectError: .connectionClosed)
    let factory = try ConnectorFactory([
        a: ConnectorTransport(loginFixtures(normal: true)), b: remote,
    ])
    let hints = try [PermanentPortalRedirect(source: a, destinations: [b])]
    if authenticate {
        await #expect(throws: ProtocolError.loginRejected(statusClass: 2, detail: 1)) {
            try await SessionConnector.connect(
                portal: a, configuration: configuration(normal: true), cachedRedirects: hints,
                clock: .continuous, factory: { portal, _ in try factory.make(portal) })
        }
        #expect(factory.portals == [b])
    } else {
        let result = try await SessionConnector.connect(
            portal: a, configuration: configuration(normal: true), cachedRedirects: hints,
            clock: .continuous, factory: { portal, _ in try factory.make(portal) })
        #expect(result.portal == a && result.permanentRedirects.isEmpty)
        #expect(result.invalidatedRedirectSources == [a] && factory.portals == [b, a])
        await result.session.close()
    }
}

@Test func aCachedCycleCanBeRefreshedWithoutSavingTheContradictingHint() async throws {
    let a = try Portal("source.local")
    let b = try Portal("cached.local")
    let hints = try [
        PermanentPortalRedirect(source: a, destinations: [b]),
        PermanentPortalRedirect(source: b, destinations: [a]),
    ]
    let factory = try ConnectorFactory([a: ConnectorTransport(loginFixtures(normal: true))])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(normal: true), cachedRedirects: hints,
        clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    #expect(factory.portals == [a] && result.invalidatedRedirectSources == [a])
    #expect(result.permanentRedirects == [hints[1]])
    await result.session.close()
}

@Test func aSuccessfulCachedAlternateBecomesThePreferredSavedDestination() async throws {
    let a = try Portal("source.local")
    let b = try Portal("unavailable.local")
    let c = try Portal("available.local")
    let hint = try PermanentPortalRedirect(source: a, destinations: [b, c])
    let factory = try ConnectorFactory([
        b: ConnectorTransport(connectError: .connectionClosed),
        c: ConnectorTransport(portalGroupFixtures(9)),
    ])
    let result = try await SessionConnector.connect(
        addresses: [TargetAddress(portal: a, portalGroupTag: 7)],
        configuration: configuration(normal: true), cachedRedirects: [hint], clock: .continuous,
        factory: { portal, _ in try factory.make(portal) })
    let preferred = try hint.preferring(c)
    #expect(result.portal == c && result.permanentRedirects == [preferred])
    #expect(await result.session.targetPortalGroupTag == 9)
    #expect(factory.portals == [b, c])
    await result.session.close()
}

private func moved(_ addresses: [String], permanent: Bool = false) throws -> Data {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header.replaceSubrange(8..<14, with: [0x80, 1, 2, 3, 4, 5])
    header.put(UInt32(1), at: 16)
    header[36] = 1
    header[37] = permanent ? 2 : 1
    return try PDU(
        header: header, data: TextParameters(addresses.map { .init("TargetAddress", $0) }).encoded()
    ).encoded()
}

private func authRejected() throws -> Data {
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header.replaceSubrange(8..<14, with: [0x80, 1, 2, 3, 4, 5])
    header.put(UInt32(1), at: 16)
    header[36] = 2
    header[37] = 1
    return try PDU(header: header).encoded()
}

private func portalGroupFixtures(_ tag: UInt16?) throws -> [Data] {
    var responses = try loginFixtures(normal: true)
    var decoder = try PDUDecoder()
    let original = try #require(decoder.append(responses[0]).first)
    var entries = try TextParameters(data: original.data).entries
    entries.removeAll { $0.key == "TargetPortalGroupTag" }
    if let tag {
        entries.append(.init("TargetPortalGroupTag", String(tag)))
    }
    responses[0] = try PDU(header: original.header, data: TextParameters(entries).encoded())
        .encoded()
    return responses
}

@Test func discoveryCandidatesUseTheNextEndpointOnlyForTransportFailure() async throws {
    let first = try Portal("unavailable.local")
    let second = try Portal("available.local:3271")
    let unavailable = ConnectorTransport(connectError: .connectionClosed)
    let available = try ConnectorTransport(portalGroupFixtures(7))
    let factory = ConnectorFactory([first: unavailable, second: available])
    let result = try await SessionConnector.connect(
        addresses: [
            TargetAddress(portal: first, portalGroupTag: 1),
            TargetAddress(portal: second, portalGroupTag: 7),
        ],
        configuration: configuration(normal: true), clock: .continuous,
        factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == second && result.redirects.isEmpty)
    #expect(await result.session.targetPortalGroupTag == 7)
    #expect(factory.portals == [first, second])
    #expect(await unavailable.closed)
    await result.session.close()
}

@Test(arguments: [false, true])
func missingOrDifferentAdvertisedPortalGroupStopsBeforeAnySCSIOrOtherCandidate(_ missing: Bool)
    async throws
{
    let first = try Portal("first.local")
    let second = try Portal("second.local")
    let wrong = try ConnectorTransport(portalGroupFixtures(missing ? nil : 2))
    let factory = ConnectorFactory([first: wrong])
    await #expect(throws: ProtocolError.malformed("target portal group")) {
        try await SessionConnector.connect(
            addresses: [
                TargetAddress(portal: first, portalGroupTag: 1),
                TargetAddress(portal: second, portalGroupTag: 1),
            ],
            configuration: configuration(normal: true), clock: .continuous,
            factory: { portal, _ in try factory.make(portal) })
    }
    #expect(factory.portals == [first])
    #expect(await wrong.closed)
    #expect(await wrong.inner.writes.count == (missing ? 1 : 2))
}

@Test(arguments: [false, true])
func missingGroupWithoutExpectedTagStopsDirectAndDiscoveryFallbackConnections(_ discovery: Bool)
    async throws
{
    let portal = try Portal("server.local")
    let peer = try ConnectorTransport(portalGroupFixtures(nil))
    let factory = ConnectorFactory([portal: peer])
    let addresses =
        discovery
        ? try DiscoveredTarget(name: "iqn.2026-10.test:disk").connectionAddresses(fallback: portal)
        : [TargetAddress(portal: portal)]
    #expect(addresses.count == 1 && addresses[0].portalGroupTag == nil)
    await #expect(throws: ProtocolError.malformed("target portal group")) {
        try await SessionConnector.connect(
            addresses: addresses, configuration: configuration(normal: true), clock: .continuous,
            factory: { portal, _ in try factory.make(portal) })
    }
    #expect(factory.portals == [portal])
    #expect(await peer.closed)
    #expect(await peer.inner.writes.count == 1)
}

@Test func conflictingPortalGroupsAreRejectedBeforeCreatingAnyTransport() async throws {
    let first = try TargetAddress("NAS.local,1")
    let second = try TargetAddress("nas.local,2")
    let factory = ConnectorFactory([:])
    await #expect(throws: ProtocolError.malformed("conflicting target portal group")) {
        try await SessionConnector.connect(
            addresses: [first, second], configuration: configuration(normal: true),
            clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    }
    #expect(factory.portals.isEmpty)
}

private actor ConnectorTransport: ConnectableByteTransport {
    let inner: ScriptedTransport
    private let hold: Bool
    private let connectError: ProtocolError?
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var connecting = false
    private(set) var closed = false

    init(_ responses: [Data] = [], hold: Bool = false, connectError: ProtocolError? = nil) {
        inner = ScriptedTransport(responses)
        self.hold = hold
        self.connectError = connectError
    }
    func connect() async throws {
        connecting = true
        if hold, !closed { await withCheckedContinuation { waiter = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
        if let connectError { throw connectError }
    }
    func release() {
        waiter?.resume()
        waiter = nil
    }
    func send(_ data: Data) async throws { try await inner.send(data) }
    func receive(maximumLength: Int) async throws -> Data {
        try await inner.receive(maximumLength: maximumLength)
    }
    func close() async {
        closed = true
        release()
        await inner.close()
    }
}

private final class ConnectorFactory: @unchecked Sendable {
    private let lock = NSLock()
    private let transports: [Portal: ConnectorTransport]
    private var made: [Portal] = []
    private var limits: [TimeInterval] = []
    var portals: [Portal] { lock.withLock { made } }
    var connectionTimeouts: [TimeInterval] { lock.withLock { limits } }
    init(_ transports: [Portal: ConnectorTransport]) { self.transports = transports }
    func make(_ portal: Portal, timeout: TimeInterval? = nil) throws -> any ConnectableByteTransport
    {
        try lock.withLock {
            made.append(portal)
            if let timeout { limits.append(timeout) }
            guard let result = transports[portal] else { throw ProtocolError.invalidState }
            return result
        }
    }
}

private func connectorPhase(_ condition: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
        try await Task.sleep(for: .milliseconds(1))
    }
}

private func expectConnectorFailure(
    _ expected: ProtocolError, portal: Portal, factory: ConnectorFactory,
    maximumRedirects: Int = 4, maximumAttempts: Int = 16
) async throws {
    do {
        let connection = try await SessionConnector.connect(
            portal: portal, configuration: configuration(), maximumRedirects: maximumRedirects,
            maximumAttempts: maximumAttempts, clock: .continuous,
            factory: { portal, _ in try factory.make(portal) })
        await connection.session.close()
        Issue.record("A failed connection unexpectedly succeeded")
    } catch {
        #expect(error as? ProtocolError == expected)
    }
}

@Test func connectorFollowsTemporaryAndPermanentRedirectsAndClosesOldSessions() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let first = try ConnectorTransport([moved([b.description])])
    let second = try ConnectorTransport([moved([c.description], permanent: true)])
    let last = try ConnectorTransport(loginFixtures())
    let factory = ConnectorFactory([a: first, b: second, c: last])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(),
        clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == c)
    #expect(result.redirects.map(\.kind) == [.temporary, .permanent])
    #expect(factory.portals == [a, b, c])
    #expect(await first.closed)
    #expect(await second.closed)
    #expect(await result.session.state == .ready)
    await result.session.close()
    #expect(await last.closed)
}

@Test func unreachableRedirectAddressCanUseTheNextProvidedAddress() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let first = try ConnectorTransport([moved([b.description, c.description])])
    let bad = ConnectorTransport(connectError: .connectionClosed)
    let last = try ConnectorTransport(loginFixtures())
    let factory = ConnectorFactory([a: first, b: bad, c: last])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(),
        clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == c && factory.portals == [a, b, c])
    #expect(await first.closed)
    #expect(await bad.closed)
    await result.session.close()
}

@Test(arguments: [false, true])
func authenticationFailureDoesNotTryAnotherRedirectAddress(_ duringConnect: Bool) async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let first = try ConnectorTransport([moved([b.description, c.description])])
    let bad = try ConnectorTransport(
        duringConnect ? [] : [authRejected()],
        connectError: duringConnect ? .authenticationFailed : nil)
    let last = try ConnectorTransport(loginFixtures())
    let factory = ConnectorFactory([a: first, b: bad, c: last])
    try await expectConnectorFailure(
        duringConnect ? .authenticationFailed : .loginRejected(statusClass: 2, detail: 1),
        portal: a, factory: factory)
    #expect(factory.portals == [a, b])
    #expect(await first.closed)
    #expect(await bad.closed)
    #expect(await !last.connecting)
}

@Test func redirectLoopsAndLimitsStopBeforeOpeningMoreConnections() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let loop = try ConnectorTransport([moved(["A.LOCAL:3260"])])
    let loopFactory = ConnectorFactory([a: loop])
    try await expectConnectorFailure(
        .limitExceeded("login redirect loop"), portal: a, factory: loopFactory)
    #expect(loopFactory.portals == [a])
    let first = try ConnectorTransport([moved([b.description])])
    let second = try ConnectorTransport([moved([c.description])])
    let factory = ConnectorFactory([a: first, b: second])
    try await expectConnectorFailure(
        .limitExceeded("login redirects"), portal: a, factory: factory, maximumRedirects: 1)
    #expect(factory.portals == [a, b])
    #expect(await first.closed)
    #expect(await second.closed)
}

@Test func connectionAttemptLimitDoesNotOpenTheNextCandidate() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let c = try Portal("c.local")
    let first = try ConnectorTransport([moved([b.description, c.description])])
    let bad = ConnectorTransport(connectError: .connectionClosed)
    let factory = ConnectorFactory([a: first, b: bad])
    try await expectConnectorFailure(
        .limitExceeded("login connection attempts"), portal: a,
        factory: factory, maximumAttempts: 2)
    #expect(factory.portals == [a, b])
}

@Test func duplicateRedirectAddressesDoNotDivideTheConnectionBudget() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let first = try ConnectorTransport([moved(Array(repeating: b.description, count: 16))])
    let last = try ConnectorTransport(loginFixtures())
    let factory = ConnectorFactory([a: first, b: last])
    let time = ManualSessionTime()
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(), clock: time.source,
        factory: { portal, timeout in try factory.make(portal, timeout: timeout) })
    #expect(factory.portals == [a, b])
    #expect(factory.connectionTimeouts == [15, 15])
    await result.session.close()
}

@Test(arguments: [false, true])
func wholeConnectionDeadlineClosesEvenAnUncooperativeConnect(_ wakeTimer: Bool) async throws {
    let portal = try Portal("a.local")
    let time = ManualSessionTime()
    let transport = ConnectorTransport(hold: true)
    let task = Task {
        try await SessionConnector.connect(
            portal: portal, configuration: configuration(),
            timeout: .seconds(45), clock: time.source, factory: { _, _ in transport })
    }
    try await connectorPhase { await transport.connecting && time.hasSleeper(after: .seconds(45)) }
    time.advance(by: .seconds(45), wakeTimers: wakeTimer)
    if !wakeTimer { await transport.release() }
    await #expect(throws: ProtocolError.timedOut) { try await task.value }
    #expect(await transport.closed)
    #expect(time.pendingCount == 0)
    #expect(await transport.inner.writes.isEmpty)
}

@Test func cancellingConnectionClosesTransportBeforeReturning() async throws {
    let portal = try Portal("a.local")
    let transport = ConnectorTransport(hold: true)
    let task = Task {
        try await SessionConnector.connect(
            portal: portal, configuration: configuration(),
            clock: .continuous, factory: { _, _ in transport })
    }
    try await connectorPhase { await transport.connecting }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await transport.closed)
}

@Test func expiryDuringTransportCreationDoesNotStartAConnection() async throws {
    let portal = try Portal("a.local")
    let time = ManualSessionTime()
    let transport = try ConnectorTransport(loginFixtures())
    await #expect(throws: ProtocolError.timedOut) {
        try await SessionConnector.connect(
            portal: portal, configuration: configuration(),
            clock: time.source,
            factory: { _, _ in
                time.advance(by: .seconds(45))
                return transport
            })
    }
    #expect(await !transport.connecting)
    #expect(await transport.closed)
    #expect(await transport.inner.writes.isEmpty)
    #expect(time.pendingCount == 0)
}

@Test func aRedirectRestartsAuthenticationWithoutCarryingThePreviousProof() async throws {
    let a = try Portal("a.local")
    let b = try Portal("b.local")
    let selection = try fixture(
        opcode: 0x23, flags: 0, tag: 1, stat: 0, exp: UInt32.max,
        data: TextParameters([.init("AuthMethod", "CHAP"), .init("TargetPortalGroupTag", "1")])
            .encoded())
    let challenge = try fixture(
        opcode: 0x23, flags: 0, tag: 1, stat: 1, exp: UInt32.max,
        data: TextParameters([
            .init("CHAP_A", "5"), .init("CHAP_I", "7"),
            .init("CHAP_C", "0x" + String(repeating: "22", count: 32)),
        ]).encoded())
    let first = try ConnectorTransport([selection, challenge, moved([b.description])])
    let second = try ConnectorTransport([authRejected()])
    let factory = ConnectorFactory([a: first, b: second])
    let configuration = try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:initiator",
        targetName: "iqn.2026-10.test:disk",
        credentials: CHAPCredentials(
            username: "user", password: "first secret value",
            targetUsername: "server", targetPassword: "second secret value"),
        isid: [0x80, 1, 2, 3, 4, 5], initialCommandSequenceNumber: UInt32.max)
    await #expect(throws: ProtocolError.loginRejected(statusClass: 2, detail: 1)) {
        try await SessionConnector.connect(
            portal: a, configuration: configuration,
            clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    }
    let original = await first.inner.writes
    let redirected = await second.inner.writes
    try #require(original.count == 3 && redirected.count == 1)
    var decoder = try PDUDecoder(maximumDataLength: 8192)
    let proof = try #require(decoder.append(original[2]).first)
    #expect(try TextParameters(data: proof.data).uniqueValue(for: "CHAP_R") != nil)
    var freshDecoder = try PDUDecoder(maximumDataLength: 8192)
    let fresh = try #require(freshDecoder.append(redirected[0]).first)
    let text = try TextParameters(data: fresh.data)
    #expect(try text.uniqueValue(for: "AuthMethod") == "CHAP")
    #expect(try text.uniqueValue(for: "TargetName") == "iqn.2026-10.test:disk")
    #expect(try text.uniqueValue(for: "CHAP_N") == nil)
    #expect(try text.uniqueValue(for: "CHAP_R") == nil)
    #expect(Array(fresh.header[8..<14]) == configuration.isid)
    #expect(Array(fresh.header[24..<28]) == [0xFF, 0xFF, 0xFF, 0xFF])
    #expect(await first.closed)
    #expect(await second.closed)
}

@Test func ipv6ZoneIdentifiersAreNotCaseFoldedForLoopDetection() async throws {
    let a = try Portal("[fe80::1%UPPER]:3260")
    let b = try Portal("[FE80::1%upper]:3260")
    let first = try ConnectorTransport([moved([b.description])])
    let last = try ConnectorTransport(loginFixtures())
    let factory = ConnectorFactory([a: first, b: last])
    let result = try await SessionConnector.connect(
        portal: a, configuration: configuration(),
        clock: .continuous, factory: { portal, _ in try factory.make(portal) })
    #expect(result.portal == b && factory.portals == [a, b])
    await result.session.close()
}

/// Linux LIO refuses a wrong CHAP secret only after checking CHAP_R, with a header zeroed
/// apart from the opcode, the status and the task tag (no ISID echo). At first login and at
/// discovery that must still be the authentication rejection, never a malformed response.
@Test(arguments: [false, true])
func aWrongCHAPSecretRejectedWithoutTheISIDEchoIsAnAuthenticationFailure(_ normal: Bool)
    async throws
{
    let portal = try Portal("lio.local")
    var selected: [TextParameters.Entry] = [.init("AuthMethod", "CHAP")]
    if normal { selected.append(.init("TargetPortalGroupTag", "1")) }
    let selection = try fixture(
        opcode: 0x23, flags: 0, tag: 1, stat: 0, data: TextParameters(selected).encoded())
    let challenge = try fixture(
        opcode: 0x23, flags: 0, tag: 1, stat: 1,
        data: TextParameters([
            .init("CHAP_A", "5"), .init("CHAP_I", "9"),
            .init("CHAP_C", "0x" + String(repeating: "5a", count: 32)),
        ]).encoded())
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header.put(UInt32(1), at: 16)
    header[36] = 2
    header[37] = 1
    let rejection = try PDU(header: header).encoded()
    let transport = ConnectorTransport([selection, challenge, rejection])
    let factory = ConnectorFactory([portal: transport])
    let configuration = try LoginConfiguration(
        initiatorName: "iqn.2026-10.test:initiator",
        targetName: normal ? "iqn.2026-10.test:disk" : nil,
        credentials: CHAPCredentials(username: "user", password: "wrong secret value"),
        isid: [0x80, 1, 2, 3, 4, 5])
    await #expect(throws: ProtocolError.loginRejected(statusClass: 2, detail: 1)) {
        try await SessionConnector.connect(
            portal: portal, configuration: configuration, clock: .continuous,
            factory: { portal, _ in try factory.make(portal) })
    }
    // The CHAP response was sent before the rejection; nothing else was tried.
    let writes = await transport.inner.writes
    try #require(writes.count == 3)
    var decoder = try PDUDecoder(maximumDataLength: 8192)
    let proof = try #require(decoder.append(writes[2]).first)
    #expect(try TextParameters(data: proof.data).uniqueValue(for: "CHAP_R") != nil)
    #expect(factory.portals == [portal])
    #expect(await transport.closed)
}
