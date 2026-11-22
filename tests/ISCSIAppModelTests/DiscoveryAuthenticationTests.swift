import Foundation
import ISCSICore
import ISCSINetwork
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

private actor SearchCredentials: CredentialStore {
    private(set) var requested: [CredentialContext] = []
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        requested.append(context)
        return try CHAPCredentials(
            username: context.username,
            password: context.use == .discovery
                ? "discovery disposable secret" : "connection disposable secret",
            targetUsername: context.targetUsername,
            targetPassword: context.targetUsername == nil ? nil : "target disposable secret")
    }
}

private struct SelectedAuthentication: Sendable, Equatable {
    let target: String?
    let username: String?
    let targetUsername: String?
}

private actor SelectedLoginRecorder {
    private(set) var sessions: [SelectedAuthentication] = []
    func record(_ configuration: LoginConfiguration) {
        sessions.append(
            SelectedAuthentication(
                target: configuration.targetName,
                username: configuration.credentials?.username,
                targetUsername: configuration.credentials?.targetUsername))
    }
}

/// The alert's title keeps the server's name on one line.
func findDisksTitle(_ server: ServerProfile) -> String {
    let title = String(
        localized: "Couldn’t Find Disks on “\(AppName.inSentence(server.displayName))”")
    if server.displayName == "LIO Test VM" {
        #expect(title == "Couldn’t Find Disks on “LIO\u{00A0}Test\u{00A0}VM”")
    }
    return title
}

/// A server whose Finding Disks sends no password (0), the Connection password (1), or its
/// own (2), as `AppIssue.FindingDisksCredentials` names them.
private func searchServer(_ credentials: Int, mutual: Bool = false) throws -> ServerProfile {
    try ServerProfile(
        name: "LIO Test VM", portal: Portal("nas.local"),
        chapUsername: credentials == 1 ? "Connection User" : nil,
        credentialID: credentials == 1 ? UUID() : nil,
        targetCHAPUsername: credentials == 1 && mutual ? "Connection Server" : nil,
        discoveryAuthentication: credentials == 2
            ? .chap(
                try CHAPIdentity(
                    username: "Search User", targetUsername: mutual ? "Search Server" : nil,
                    credentialID: UUID()))
            : credentials == 0 ? .none : .sameAsConnection)
}

@Test(arguments: [0, 1, 2])
func findingDisksCredentialsFollowTheServerSettings(_ credentials: Int) throws {
    let expected: [AppIssue.FindingDisksCredentials] = [.none, .connection, .findingDisks]
    #expect(
        AppIssue.FindingDisksCredentials(try searchServer(credentials)) == expected[credentials])
    // Same as Connection sends nothing when the connection has no password.
    let open = try ServerProfile(
        name: "Open", portal: Portal("nas.local"), discoveryAuthentication: .sameAsConnection)
    #expect(AppIssue.FindingDisksCredentials(open) == .none)
}

/// The alert names the section whose user name and password were sent, uses the app's own
/// terms, and offers Edit Server…. A refusal never points only at the password.
@Test(arguments: [0, 1, 2])
@MainActor func searchAuthenticationProblemsNameWhatToChange(_ credentials: Int) throws {
    let server = try searchServer(credentials, mutual: true)
    let title = findDisksTitle(server)
    func issue(_ error: any Error) -> AppIssue { AppIssue(error, context: .findingDisks(server)) }
    let required =
        "This server requires a user name and password to find disks. Edit this server and choose an authentication method under Finding Disks, then try again."
    let notUsed =
        "This server doesn’t use a user name and password to find disks. Edit this server and choose None for authentication under Finding Disks, then try again."
    let refused = [
        required,
        "The server didn’t accept the user name and password under Connection. Edit this server and check them, or choose a different authentication method under Finding Disks, then try again.",
        "The server didn’t accept the user name and password under Finding Disks. Edit this server and check them, or choose a different authentication method, then try again.",
    ][credentials]
    let mismatch = [
        nil,
        "The server user name and password under Connection don’t match the server. Edit this server and check them, then try again.",
        "The server user name and password under Finding Disks don’t match the server. Edit this server and check them, then try again.",
    ][credentials]
    var expected: [(any Error, String?)] = [
        (ProtocolError.loginRejected(statusClass: 2, detail: 1), refused),
        (ProtocolError.unsupported("authentication required"), required),
        (ProtocolError.authenticationFailed, mismatch),
    ]
    if credentials != 0 {
        // A server that doesn't use CHAP to find disks answers with another method, or
        // moves on without choosing one.
        expected += [
            (ProtocolError.unsupported("authentication method"), notUsed),
            (ProtocolError.malformed("CHAP selection"), notUsed),
        ]
    }
    for (error, message) in expected {
        let found = issue(error)
        guard let message else {
            #expect(found.recoveryAction == nil && found.title != title)
            continue
        }
        #expect(found.title == title && found.message == message)
        #expect(found.recoveryAction == .editServer && found.serverID == server.id)
        #expect(!found.title.contains("Disk Search") && !found.message.contains("disk search"))
    }
    // Other failures while finding disks keep their own guidance and offer no editor.
    for error: any Error in [ProtocolError.connectionClosed, ProtocolError.timedOut] {
        #expect(issue(error).message == AppIssue(error).message)
        #expect(issue(error).recoveryAction == nil && issue(error).serverID == nil)
    }
}

/// A server with connected disks can't be edited, so each message says to eject its disks
/// first, then edit the server, and the alert offers only OK.
@Test(arguments: [0, 1, 2])
@MainActor func searchProblemsOnAServerWithConnectedDisksSayToEjectThemFirst(_ credentials: Int)
    throws
{
    let server = try searchServer(credentials, mutual: true)
    let title = findDisksTitle(server)
    func issue(_ error: any Error) -> AppIssue {
        AppIssue(error, context: .findingDisks(server, disksConnected: true))
    }
    let required =
        "This server requires a user name and password to find disks. To choose an authentication method under Finding Disks, eject this server’s disks, then edit the server."
    let notUsed =
        "This server doesn’t use a user name and password to find disks. To choose None for authentication under Finding Disks, eject this server’s disks, then edit the server."
    let refused = [
        required,
        "The server didn’t accept the user name and password under Connection. To check them, or to choose a different authentication method under Finding Disks, eject this server’s disks, then edit the server.",
        "The server didn’t accept the user name and password under Finding Disks. To check them, or to choose a different authentication method, eject this server’s disks, then edit the server.",
    ][credentials]
    let mismatch = [
        nil,
        "The server user name and password under Connection don’t match the server. To check them, eject this server’s disks, then edit the server.",
        "The server user name and password under Finding Disks don’t match the server. To check them, eject this server’s disks, then edit the server.",
    ][credentials]
    var expected: [(any Error, String?)] = [
        (ProtocolError.loginRejected(statusClass: 2, detail: 1), refused),
        (ProtocolError.unsupported("authentication required"), required),
        (ProtocolError.authenticationFailed, mismatch),
    ]
    if credentials != 0 {
        expected += [
            (ProtocolError.unsupported("authentication method"), notUsed),
            (ProtocolError.malformed("CHAP selection"), notUsed),
        ]
    }
    for (error, message) in expected {
        let found = issue(error)
        guard let message else {
            #expect(found.recoveryAction == nil && found.title != title)
            continue
        }
        #expect(found.title == title && found.message == message)
        #expect(found.recoveryAction == nil && found.serverID == nil)
    }
    let missing = issue(NSError(domain: NSOSStatusErrorDomain, code: -25300))
    #expect(missing.title == String(localized: "Saved Password Is Missing"))
    #expect(
        missing.message
            == (credentials == 2
                ? "To enter the password under Finding Disks, eject this server’s disks, then edit the server."
                : "To enter this server’s password, eject its disks, then edit the server."))
    #expect(missing.recoveryAction == nil && missing.serverID == nil)
}

@Test(arguments: [0, 1, 2])
@MainActor func aMissingSearchPasswordNamesItsSection(_ credentials: Int) throws {
    let server = try searchServer(credentials)
    let error = NSError(domain: NSOSStatusErrorDomain, code: -25300)
    let issue = AppIssue(error, context: .findingDisks(server))
    #expect(issue.title == String(localized: "Saved Password Is Missing"))
    #expect(
        issue.message
            == (credentials == 2
                ? "Edit this server and enter the password under Finding Disks, then try again."
                : "Edit this server and enter its password, then try again."))
    #expect(issue.recoveryAction == .editServer && issue.serverID == server.id)
    #expect(AppIssue(error).recoveryAction == nil)
}

/// A Mac that sends a user name and password offers only CHAP. A server that doesn't use
/// CHAP to find disks answers with None, and the search fails. A new server therefore
/// finds disks without a password, and the failure says to choose None.
@Test @MainActor func aNewServerFindsDisksWithoutAPassword() throws {
    #expect(FindingDisksAuthenticationChoice(nil) == .none)
    #expect(FindingDisksAuthenticationChoice(DiscoveryAuthentication.none) == .none)
    #expect(FindingDisksAuthenticationChoice(.sameAsConnection) == .sameAsConnection)
    let chap = try CHAPIdentity(username: "Search User", credentialID: UUID())
    let mutual = try CHAPIdentity(
        username: "Search User", targetUsername: "Search Server", credentialID: UUID())
    #expect(FindingDisksAuthenticationChoice(.chap(chap)) == .chap)
    #expect(FindingDisksAuthenticationChoice(.chap(mutual)) == .mutualCHAP)
    // The menu order the editor's tags rely on.
    #expect(FindingDisksAuthenticationChoice.allCases.map(\.rawValue) == [0, 1, 2, 3])

    let isid: [UInt8] = [0x80, 1, 3, 5, 7, 9]
    var machine = LoginMachine(
        configuration: try LoginConfiguration(
            initiatorName: "iqn.2026-11.dev.soba:search-test", targetName: nil,
            credentials: try CHAPCredentials(
                username: "Connection User", password: "disposable connection secret"),
            isid: isid))
    let offer = try machine.start()
    #expect(try TextParameters(data: offer.data).uniqueValue(for: "AuthMethod") == "CHAP")
    var header = [UInt8](repeating: 0, count: 48)
    header[0] = 0x23
    header.replaceSubrange(8..<14, with: isid)
    header.put(UInt32(1), at: 16)
    header.put(UInt32(1), at: 28)
    header.put(UInt32(32), at: 32)
    let answer = try PDU(
        header: header, data: try TextParameters([.init("AuthMethod", "None")]).encoded())
    #expect(throws: ProtocolError.unsupported("authentication method")) {
        try machine.accept(answer)
    }
    let issue = AppIssue(
        ProtocolError.unsupported("authentication method"),
        context: .findingDisks(try searchServer(1)))
    #expect(issue.message.contains("choose None for authentication under Finding Disks"))
}

private actor SeededCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        try CHAPCredentials(username: context.username, password: "disposable search secret")
    }
}

/// Edit Server… is offered only when the editor will open, and opens the named server.
@Test(arguments: [false, true])
@MainActor func searchAuthenticationFailuresOfferTheServerEditor(_ connected: Bool) async throws {
    let server = try searchServer(1)
    let model = AppModel(
        credentials: SeededCredentials(),
        sessionFactory: { _, _, _ in
            throw ProtocolError.loginRejected(statusClass: 2, detail: 1)
        })
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.document = document
    model.recoveryComplete = true
    model.extensionState = .ready
    if connected {
        let id = UUID()
        let descriptor = try ConnectionDescriptor(
            profileID: server.id, portal: server.portal, initiatorName: document.identity.name,
            targetName: "iqn.2026-11.dev.soba:search-test", lun: LogicalUnit(0),
            readOnly: false, isid: document.identity.seed, mountID: id)
        var disk = AttachedDisk(
            entry: try AttachmentJournalEntry(
                id: id, descriptor: descriptor,
                bridgeURL: URL(fileURLWithPath: "/unused-search-test/\(id.uuidString)"),
                phase: .connected))
        disk.verificationFailed = false
        model.attached = [disk]
    }
    model.search(server)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
    let issue = try #require(model.issue)
    #expect(issue.title == findDisksTitle(server))
    guard !connected else {
        // The server can't be edited while its disks are connected, so the alert says to
        // eject them first and offers only OK.
        #expect(
            issue.message
                == "The server didn’t accept the user name and password under Connection. To check them, or to choose a different authentication method under Finding Disks, eject this server’s disks, then edit the server."
        )
        #expect(issue.recoveryAction == nil && issue.serverID == nil)
        return
    }
    #expect(
        issue.message
            == "The server didn’t accept the user name and password under Connection. Edit this server and check them, or choose a different authentication method under Finding Disks, then try again."
    )
    #expect(issue.recoveryAction == .editServer && issue.serverID == server.id)
    model.editServer(for: issue)
    #expect(model.issue == nil && model.showingServerEditor && model.editingServer == server)
}

@Test(arguments: [0, 1, 2], [0, 1, 2, 3])
@MainActor func diskSearchAndInspectionUseOnlyTheirConfiguredAuthentication(
    _ connection: Int, _ discovery: Int
) async throws {
    let search: DiscoveryAuthentication
    switch discovery {
    case 0: search = .sameAsConnection
    case 1: search = .none
    default:
        search = .chap(
            try CHAPIdentity(
                username: "Search User",
                targetUsername: discovery == 3 ? "Search Server" : nil, credentialID: UUID()))
    }
    let server = try ServerProfile(
        name: "Archive", portal: Portal("nas.local"),
        chapUsername: connection == 0 ? nil : "Connection User",
        credentialID: connection == 0 ? nil : UUID(),
        targetCHAPUsername: connection == 2 ? "Connection Server" : nil,
        discoveryAuthentication: search)
    let credentials = SearchCredentials()
    let recorder = SelectedLoginRecorder()
    let model = AppModel(
        credentials: credentials,
        sessionFactory: { _, configuration, _ in
            await recorder.record(configuration)
            // Stop at the factory boundary: this test selects credentials without network or OS I/O.
            throw ProtocolError.connectionClosed
        })
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    func finishOperation() async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while model.busy {
            guard clock.now < deadline else { throw ProtocolError.timedOut }
            try await clock.sleep(for: .milliseconds(2))
        }
    }
    model.search(server)
    try await finishOperation()
    let target = DiscoveredTarget(name: "iqn.2026-10.test:disk")
    model.inspect(target, server: server)
    try await finishOperation()
    let connectionName: String? = connection == 0 ? nil : "Connection User"
    let connectionTarget: String? = connection == 2 ? "Connection Server" : nil
    let searchName: String? = discovery == 0 ? connectionName : discovery == 1 ? nil : "Search User"
    let searchTarget: String? =
        discovery == 0 ? connectionTarget : discovery == 3 ? "Search Server" : nil
    let expected = [
        SelectedAuthentication(target: nil, username: searchName, targetUsername: searchTarget),
        SelectedAuthentication(
            target: target.name, username: connectionName, targetUsername: connectionTarget),
    ]
    #expect(await recorder.sessions == expected)
    let connectionContext = connectionName.map {
        CredentialContext(
            profileID: server.id, portal: server.portal, username: $0,
            credentialID: server.credentialID, targetUsername: connectionTarget)
    }
    let searchContext: CredentialContext?
    if discovery == 0 {
        searchContext = connectionContext
    } else if let searchName, case .chap(let identity) = search {
        searchContext = CredentialContext(
            profileID: server.id, portal: server.portal, username: searchName,
            credentialID: identity.credentialID, targetUsername: searchTarget, use: .discovery)
    } else {
        searchContext = nil
    }
    let contexts = [searchContext, connectionContext].compactMap { $0 }
    #expect(await credentials.requested == contexts)
}
