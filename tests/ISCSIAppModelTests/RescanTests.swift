import Dispatch
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private enum Rescan: String, CaseIterable { case search, inspect }
private enum RescanEnd: String, CaseIterable { case success, failure, cancel }

@Test @MainActor private func aFreshAppInspectionSupersedesADelayedReportFromAnAlreadyMountedDisk()
    async throws
{
    let transport = RescanTransport(.inspect)
    let destination = try Portal("newer.local")
    let (model, backend, storage, server) = try await mountedRouteFixture(
        initial: .absent,
        sessionFactory: { addresses, login, _ in
            let session = try ISCSISession(transport: transport, configuration: login)
            try await session.login()
            let route = try PermanentPortalRedirect(
                source: #require(addresses.first).portal, destinations: [destination])
            return SessionConnection(
                session: session, portal: destination, permanentRedirects: [route])
        })
    let target = try #require(model.attached.first?.descriptor.targetName)
    #expect(storage.load().handledMountRedirects.isEmpty)
    model.inspect(DiscoveredTarget(name: target), server: server)
    try await awaitRescanPhase { await transport.logoutPending }
    try await transport.completeLogout(success: true)
    try await finishMountedRouteOperation(model)
    #expect(storage.load().handledMountRedirects == model.attached.map(\.id))
    #expect(storage.load().permanentRedirects.first?.redirect.destinations == [destination])
    let saves = storage.saveCount
    await backend.setObservation(.good)
    await model.refreshConnectionHealth()
    #expect(storage.load().permanentRedirects.first?.redirect.destinations == [destination])
    #expect(storage.saveCount == saves && model.issue == nil)
}

private final class PermanentRouteSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProfileDocument
    init(_ value: ProfileDocument) { self.value = value }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func save(_ document: ProfileDocument) { lock.withLock { value = document } }
}

private actor PermanentRouteCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw ProtocolError.invalidState
    }
}

private actor PermanentRouteRequests {
    private(set) var values: [[PermanentPortalRedirect]] = []
    func append(_ value: [PermanentPortalRedirect]) { values.append(value) }
}

private final class PausedPermanentRouteSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private let released = DispatchSemaphore(value: 0)
    private var value: ProfileDocument
    private var entered = false
    init(_ value: ProfileDocument) { self.value = value }
    var savePending: Bool { lock.withLock { entered } }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { value } }
    func resumeSave() { released.signal() }
    func save(_ document: ProfileDocument) throws {
        lock.withLock { entered = true }
        guard released.wait(timeout: .now() + 2) == .success else { throw POSIXError(.ETIMEDOUT) }
        lock.withLock { value = document }
    }
}

@Test(arguments: Rescan.allCases)
@MainActor private func cancellingWhileARedirectIsBeingSavedCannotPublishLateResults(
    _ operation: Rescan
) async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let destination = try Portal("moved.local")
    let hint = try PermanentPortalRedirect(source: server.portal, destinations: [destination])
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let storage = PausedPermanentRouteSettings(document)
    let credentials = PermanentRouteCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let transport = RescanTransport(operation)
    let model = AppModel(
        configuration: configuration, credentials: credentials,
        sessionFactory: { _, login, _ in
            let session = try ISCSISession(transport: transport, configuration: login)
            try await session.login()
            return SessionConnection(
                session: session, portal: destination, permanentRedirects: [hint])
        })
    model.document = document
    model.recoveryComplete = true
    let target = DiscoveredTarget(name: "iqn.2026-10.test:new")
    if operation == .search { model.search(server) } else { model.inspect(target, server: server) }
    try await awaitRescanPhase { await transport.logoutPending }
    try await transport.completeLogout(success: true)
    try await awaitRescanPhase { storage.savePending }
    #expect(model.busy && model.canCancel)
    model.cancel()
    #expect(model.busy && !model.canCancel)
    #expect(model.activity == String(localized: "Canceling…"))
    let pendingActivity = model.activity
    model.cancel()
    #expect(model.activity == pendingActivity)
    storage.resumeSave()
    try await awaitRescanPhase { !model.busy }
    #expect(!model.canCancel && model.activity.isEmpty)
    #expect(model.targets[server.id] == nil)
    #expect(model.choices[model.choiceKey(server, target.name)] == nil)
    #expect(model.issue == nil)
    // The completed discovery/probe and Logout made the saved hint valid. A cancellation
    // during durable replacement must not pretend that replacement was rolled back.
    #expect(storage.load().permanentRedirects.count == 1)
    #expect(model.document == storage.load())
}

@Test(arguments: Rescan.allCases, RescanEnd.allCases)
@MainActor private func permanentRoutesAreSavedOnlyAfterLogoutAndUsedByTheNextModel(
    _ operation: Rescan, _ end: RescanEnd
) async throws {
    let server = try ServerProfile(name: "Archive", portal: Portal("source.local"))
    let destination = try Portal("moved.local:3271")
    let hint = try PermanentPortalRedirect(source: server.portal, destinations: [destination])
    let target = DiscoveredTarget(name: "iqn.2026-10.test:new")
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    let storage = PermanentRouteSettings(document)
    let credentials = PermanentRouteCredentials()
    let configuration = try ServerConfiguration(storage: storage, credentials: credentials)
    let transport = RescanTransport(operation)
    let model = AppModel(
        configuration: configuration, credentials: credentials,
        sessionFactory: { _, login, cached in
            #expect(cached.isEmpty)
            let session = try ISCSISession(transport: transport, configuration: login)
            try await session.login()
            return SessionConnection(
                session: session, portal: destination, permanentRedirects: [hint])
        })
    model.document = document
    model.recoveryComplete = true
    model.extensionState = .ready
    if operation == .search { model.search(server) } else { model.inspect(target, server: server) }
    try await awaitRescanPhase { await transport.logoutPending }
    #expect(storage.load().permanentRedirects.isEmpty)
    if end == .cancel {
        model.cancel()
    } else {
        try await transport.completeLogout(success: end == .success)
    }
    try await awaitRescanPhase { !model.busy }
    #expect(storage.load().servers == [server])
    #expect(storage.load().permanentRedirects.count == (end == .success ? 1 : 0))
    let observed = PermanentRouteRequests()
    let reopened = AppModel(
        configuration: configuration, credentials: credentials,
        sessionFactory: { _, _, cached in
            await observed.append(cached)
            throw ProtocolError.connectionClosed
        })
    reopened.document = storage.load()
    reopened.recoveryComplete = true
    reopened.extensionState = .ready
    if operation == .search {
        reopened.search(server)
    } else {
        reopened.inspect(target, server: server)
    }
    try await awaitRescanPhase { !reopened.busy }
    #expect(await observed.values == [end == .success ? [hint] : []])
}

/// Runs real session/login/discovery/probe code while withholding only the Logout Response.
private actor RescanTransport: ByteTransport {
    private let operation: Rescan
    private let empty: Bool
    private let addresses: [String]
    private let portalGroupTag: UInt16?
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private var logout: PDU?
    private(set) var isClosed = false
    var logoutPending: Bool { logout != nil }

    init(
        _ operation: Rescan, empty: Bool = false, addresses: [String] = [],
        portalGroupTag: UInt16? = nil
    ) {
        self.operation = operation
        self.empty = empty
        self.addresses = addresses
        self.portalGroupTag = portalGroupTag
    }

    func send(_ data: Data) throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 262_144)
        let pdus = try decoder.append(data)
        let request = try #require(pdus.count == 1 ? pdus.first : nil)
        switch request.opcode {
        case 0x03:
            let operational = (request.flags >> 2) & 3 == 1
            var header = replyHeader(opcode: 0x23, flags: operational ? 0x87 : 0x81, tag: 1)
            header.replaceSubrange(8..<14, with: request.header[8..<14])
            header.put(UInt16(1), at: 14)
            header.put(UInt32(operational ? 1 : 0), at: 24)
            var entries: [TextParameters.Entry] =
                operational
                ? [
                    .init("HeaderDigest", "None"), .init("DataDigest", "None"),
                    .init("MaxRecvDataSegmentLength", "8192"),
                ] : [.init("AuthMethod", "None")]
            if operational, operation == .inspect {
                entries += [
                    .init("MaxConnections", "1"), .init("InitialR2T", "Yes"),
                    .init("ImmediateData", "No"), .init("MaxBurstLength", "262144"),
                    .init("FirstBurstLength", "65536"), .init("MaxOutstandingR2T", "1"),
                    .init("DataPDUInOrder", "Yes"), .init("DataSequenceInOrder", "Yes"),
                    .init("ErrorRecoveryLevel", "0"), .init("DefaultTime2Wait", "2"),
                    .init("DefaultTime2Retain", "0"),
                ]
            }
            if !operational,
                try TextParameters(data: request.data).uniqueValue(for: "TargetName") != nil
            {
                entries.append(.init("TargetPortalGroupTag", String(portalGroupTag ?? 1)))
            }
            enqueue(try PDU(header: header, data: TextParameters(entries).encoded()).encoded())
        case 0x04:
            enqueue(
                try PDU(
                    header: replyHeader(opcode: 0x24, tag: request.taskTag),
                    data: empty
                        ? Data()
                        : TextParameters(
                            [.init("TargetName", "iqn.2026-10.test:new")]
                                + addresses.map { .init("TargetAddress", $0) }
                        ).encoded()
                ).encoded())
            status &+= 1
        case 0x01:
            #expect(request.header.uint32(at: 24) == expectedCommand)
            expectedCommand &+= 1
            let payload: Data
            switch request.header[32] {
            case 0xA0:
                payload =
                    empty
                    ? Data(repeating: 0, count: 8)
                    : Data([0, 0, 0, 8]) + Data(repeating: 0, count: 12)
            case 0x12: payload = inquiryData()
            case 0x9E:
                var bytes = Array(repeating: UInt8(0), count: 32)
                bytes.put(UInt64(7), at: 0)
                bytes.put(UInt32(512), at: 8)
                payload = Data(bytes)
            case 0x5A:
                #expect(request.header[33] == 8 && request.header[34] == 0x3F)
                payload = Data([0, 6, 0, 0, 0, 0, 0, 0])
            default: throw ProtocolError.malformed("unexpected probe command")
            }
            let length = request.header.uint32(at: 20)
            var header = replyHeader(
                opcode: 0x25, flags: payload.count < length ? 0x83 : 0x81, tag: request.taskTag)
            header.put(length - UInt32(payload.count), at: 44)
            enqueue(try PDU(header: header, data: payload).encoded())
            status &+= 1
        case 0x06: logout = request
        default: throw ProtocolError.malformed("unexpected rescan request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !isClosed { await withCheckedContinuation { reader = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(input.count, maximumLength)
        let data = Data(input.prefix(count))
        input.removeFirst(count)
        return data
    }

    func close() {
        isClosed = true
        reader?.resume()
        reader = nil
    }

    func completeLogout(success: Bool) throws {
        let request = try #require(logout)
        var header = replyHeader(opcode: 0x26, tag: request.taskTag)
        header[2] = success ? 0 : 1
        logout = nil
        enqueue(try PDU(header: header).encoded())
    }

    private func replyHeader(opcode: UInt8, flags: UInt8 = 0x80, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = flags
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(expectedCommand, at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    private func enqueue(_ data: Data) {
        input.append(data)
        reader?.resume()
        reader = nil
    }
}

private actor DiscoveryRouteRequests {
    private(set) var values: [[TargetAddress]] = []
    func append(_ addresses: [TargetAddress]) { values.append(addresses) }
}

@Test(arguments: [false, true])
@MainActor private func inspectionUsesAdvertisedAddressesOrTheEffectiveDiscoveryEndpoint(
    _ advertised: Bool
) async throws {
    let initial = try Portal("discovery.local")
    let discoveryEndpoint = try Portal("redirected-discovery.local:3261")
    let storageEndpoint = try Portal("storage.local:3271")
    let search = RescanTransport(.search, addresses: advertised ? ["storage.local:3271,7"] : [])
    let inspection = RescanTransport(.inspect, portalGroupTag: advertised ? 7 : nil)
    let requests = DiscoveryRouteRequests()
    let server = try ServerProfile(name: "Archive", portal: initial)
    let model = AppModel(sessionFactory: { addresses, configuration, _ in
        await requests.append(addresses)
        let session = try ISCSISession(
            transport: configuration.targetName == nil ? search : inspection,
            configuration: configuration)
        try await session.login()
        return SessionConnection(
            session: session,
            portal: configuration.targetName == nil ? discoveryEndpoint : addresses[0].portal)
    })
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.search(server)
    try await awaitRescanPhase { await search.logoutPending }
    try await search.completeLogout(success: true)
    try await awaitRescanPhase { !model.busy }
    let found = try #require(model.targets[server.id]?.first)
    model.inspect(found, server: server)
    try await awaitRescanPhase { await inspection.logoutPending }
    #expect(model.choices[model.choiceKey(server, found.name)] == nil)
    try await inspection.completeLogout(success: true)
    try await awaitRescanPhase { !model.busy }
    #expect(model.issue == nil)
    let selected = try #require(
        model.choices[model.choiceKey(server, found.name)]?.first?.connectionAddress)
    #expect(selected.portal == (advertised ? storageEndpoint : discoveryEndpoint))
    #expect(selected.portalGroupTag == (advertised ? 7 : 1))
    let captured = await requests.values
    #expect(
        captured.map { $0.map(\.portal) } == [
            [initial], [advertised ? storageEndpoint : discoveryEndpoint],
        ])
}

private func inquiryData() -> Data {
    var bytes = Array(repeating: UInt8(0x20), count: 36)
    bytes.replaceSubrange(0..<8, with: [0, 0, 6, 2, 31, 0, 0, 0])
    return Data(bytes)
}

private func oldDisk(_ target: String) throws -> FoundDisk {
    var bytes = Array(repeating: UInt8(0), count: 8)
    bytes.put(UInt32(127), at: 0)
    bytes.put(UInt32(512), at: 4)
    return FoundDisk(
        targetName: target,
        inspection: LogicalUnitInspection(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: inquiryData()),
                    capacity: try DiskCapacity(readCapacity10: Data(bytes))))))
}

@MainActor private func rescanModel(
    factory:
        @escaping @Sendable ([TargetAddress], LoginConfiguration, [PermanentPortalRedirect])
        async throws -> SessionConnection
) throws -> (AppModel, ServerProfile, ServerProfile, DiscoveredTarget) {
    let first = try ServerProfile(name: "First", portal: Portal("192.0.2.10"))
    let second = try ServerProfile(name: "Second", portal: Portal("192.0.2.11"))
    let target = DiscoveredTarget(name: "iqn.2026-10.test:old")
    let other = DiscoveredTarget(name: "iqn.2026-10.test:other")
    let model = AppModel(sessionFactory: factory)
    model.document = try ProfileDocument(identity: .makeNew(), servers: [first, second])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.targets[first.id] = [target, other]
    model.targets[second.id] = [other]
    model.choices[model.choiceKey(first, target.name)] = [try oldDisk(target.name)]
    model.choices[model.choiceKey(first, other.name)] = [try oldDisk(other.name)]
    model.choices[model.choiceKey(second, other.name)] = [try oldDisk(other.name)]
    return (model, first, second, target)
}

@MainActor private func awaitRescanPhase(_ condition: @MainActor () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@MainActor private func expectCacheScope(
    _ model: AppModel, operation: Rescan, first: ServerProfile, second: ServerProfile,
    target: DiscoveredTarget
) {
    #expect(model.targets[second.id]?.map(\.name) == ["iqn.2026-10.test:other"])
    #expect(model.choices[model.choiceKey(second, "iqn.2026-10.test:other")]?.count == 1)
    #expect(model.choices[model.choiceKey(first, target.name)] == nil)
    if operation == .search {
        #expect(model.targets[first.id] == nil)
        #expect(model.choices.keys.allSatisfy { !$0.hasPrefix("\(first.id)|") })
    } else {
        #expect(model.targets[first.id]?.count == 2)
        #expect(model.choices[model.choiceKey(first, "iqn.2026-10.test:other")]?.count == 1)
    }
}

@Test(arguments: Rescan.allCases, RescanEnd.allCases)
@MainActor private func rescanResultsAppearOnlyAfterCompletionAndNeverAfterCancellation(
    _ operation: Rescan, _ end: RescanEnd
) async throws {
    let transport = RescanTransport(operation)
    let (model, first, second, target) = try rescanModel { addresses, configuration, _ in
        let session = try ISCSISession(transport: transport, configuration: configuration)
        try await session.login()
        return SessionConnection(session: session, portal: addresses[0].portal)
    }
    if operation == .search { model.search(first) } else { model.inspect(target, server: first) }
    try await awaitRescanPhase { await transport.logoutPending }
    expectCacheScope(model, operation: operation, first: first, second: second, target: target)
    // A second request rejected as busy must not invalidate a different server's cache.
    model.search(second)
    #expect(model.targets[second.id]?.count == 1)
    #expect(model.choices[model.choiceKey(second, "iqn.2026-10.test:other")]?.count == 1)
    if end == .cancel {
        model.cancel()
    } else {
        try await transport.completeLogout(success: end == .success)
    }
    try await awaitRescanPhase { !model.busy }
    #expect(await transport.isClosed)
    #expect(model.canCancel == false)
    #expect(model.activity.isEmpty)
    if end == .success {
        #expect(model.issue == nil)
        if operation == .search {
            #expect(model.targets[first.id]?.map(\.name) == ["iqn.2026-10.test:new"])
            #expect(model.choices.keys.allSatisfy { !$0.hasPrefix("\(first.id)|") })
        } else {
            let disks = try #require(model.choices[model.choiceKey(first, target.name)])
            #expect(disks.count == 1 && disks[0].information?.capacity.byteCount == 4096)
        }
    } else {
        #expect((model.issue != nil) == (end == .failure))
        expectCacheScope(model, operation: operation, first: first, second: second, target: target)
    }
}

@Test(arguments: Rescan.allCases)
@MainActor private func aFailedRescanConnectionCannotLeaveOldChoicesLookingCurrent(
    _ operation: Rescan
)
    async throws
{
    let (model, first, second, target) = try rescanModel { _, _, _ in throw ProtocolError.timedOut }
    if operation == .search { model.search(first) } else { model.inspect(target, server: first) }
    try await awaitRescanPhase { !model.busy }
    #expect(model.issue != nil)
    expectCacheScope(model, operation: operation, first: first, second: second, target: target)
}

@Test(arguments: Rescan.allCases)
@MainActor private func anEmptyRescanIsAResultOnlyAfterSuccessfulCompletion(_ operation: Rescan)
    async throws
{
    let transport = RescanTransport(operation, empty: true)
    let (model, first, second, target) = try rescanModel { addresses, configuration, _ in
        let session = try ISCSISession(transport: transport, configuration: configuration)
        try await session.login()
        return SessionConnection(session: session, portal: addresses[0].portal)
    }
    if operation == .search { model.search(first) } else { model.inspect(target, server: first) }
    try await awaitRescanPhase { await transport.logoutPending }
    expectCacheScope(model, operation: operation, first: first, second: second, target: target)
    try await transport.completeLogout(success: true)
    try await awaitRescanPhase { !model.busy }
    #expect(model.issue == nil)
    #expect(await transport.isClosed)
    if operation == .search {
        #expect(model.targets[first.id]?.isEmpty == true)
    } else {
        #expect(model.choices[model.choiceKey(first, target.name)]?.isEmpty == true)
    }
}
