import Darwin
import Dispatch
import Foundation
import ISCSICore
import ISCSINetwork
import Network
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

/// A server that accepts the connection and then closes it, as Linux LIO does when it requires
/// CHAP and is offered no authentication: it reads the Login Request and closes the connection
/// without a Login Response. A receive after the close throws `ProtocolError.connectionClosed`,
/// as `TCPTransport` does when the connection's input ends without data.
private actor ClosingServer: ByteTransport {
    enum Close: Sendable {
        /// Before any Login Response, as LIO did (bytes in/out 0/160).
        case beforeAnyResponse
        /// After answering the first Login Request, before the login finished.
        case afterFirstResponse
        /// After the login finished, when the Mac asks for its targets.
        case afterLogin
    }

    private let ending: Close
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var ended = false
    private(set) var requests: [PDU] = []
    private(set) var requestBytes: [Int] = []
    private(set) var responses = 0

    init(_ ending: Close) { self.ending = ending }

    func send(_ data: Data) throws {
        guard !ended else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 262_144)
        let pdus = try decoder.append(data)
        let request = try #require(pdus.count == 1 ? pdus.first : nil)
        requests.append(request)
        requestBytes.append(data.count)
        switch (request.opcode, ending) {
        case (0x03, .beforeAnyResponse): end()
        case (0x03, .afterFirstResponse) where responses == 1: end()
        case (0x03, _): try respond(to: request)
        case (0x04, .afterLogin): end()
        default: throw ProtocolError.malformed("unexpected request")
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !ended { await withCheckedContinuation { reader = $0 } }
        guard !input.isEmpty else { throw ProtocolError.connectionClosed }
        let count = min(input.count, maximumLength)
        let data = Data(input.prefix(count))
        input.removeFirst(count)
        return data
    }

    func close() { end() }

    private func end() {
        ended = true
        reader?.resume()
        reader = nil
    }

    /// A discovery login without authentication, in two exchanges as `LoginMachine` makes it.
    private func respond(to request: PDU) throws {
        let operational = (request.flags >> 2) & 3 == 1
        var header = [UInt8](repeating: 0, count: 48)
        header[0] = 0x23
        header[1] = operational ? 0x87 : 0x81
        header.replaceSubrange(8..<14, with: request.header[8..<14])
        header.put(UInt16(1), at: 14)
        header.put(UInt32(1), at: 16)
        header.put(UInt32(responses), at: 24)
        header.put(UInt32(1), at: 28)
        header.put(UInt32(32), at: 32)
        let entries: [TextParameters.Entry] =
            operational
            ? [
                .init("HeaderDigest", "None"), .init("DataDigest", "None"),
                .init("MaxRecvDataSegmentLength", "8192"),
            ] : [.init("AuthMethod", "None")]
        responses += 1
        input.append(try PDU(header: header, data: TextParameters(entries).encoded()).encoded())
        reader?.resume()
        reader = nil
    }
}

private actor ClosedLoginCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        try CHAPCredentials(username: context.username, password: "disposable login secret")
    }
}

/// A server whose Finding Disks sends no password (0), the Connection password (1), or its
/// own (2), as `AppIssue.FindingDisksCredentials` names them.
private func closingServer(_ credentials: Int) throws -> ServerProfile {
    try ServerProfile(
        name: "LIO Test VM", portal: Portal("nas.local"),
        chapUsername: credentials == 1 ? "Connection User" : nil,
        credentialID: credentials == 1 ? UUID() : nil,
        discoveryAuthentication: credentials == 2
            ? .chap(try CHAPIdentity(username: "Search User", credentialID: UUID()))
            : credentials == 0 ? .none : .sameAsConnection)
}

private let viewTitle = "Couldn’t View Disks on “LIO\u{00A0}Test\u{00A0}VM”"
private let closedTarget = DiscoveredTarget(name: "iqn.2026-11.dev.soba:recheck")

@MainActor private func closedLoginModel(
    _ server: ServerProfile, connected: Bool = false,
    sessionFactory:
        @escaping @Sendable ([TargetAddress], LoginConfiguration, [PermanentPortalRedirect])
        async throws -> SessionConnection
) throws -> AppModel {
    let model = AppModel(credentials: ClosedLoginCredentials(), sessionFactory: sessionFactory)
    let document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.document = document
    model.recoveryComplete = true
    model.extensionState = .ready
    if connected {
        let id = UUID()
        let descriptor = try ConnectionDescriptor(
            profileID: server.id, portal: server.portal, initiatorName: document.identity.name,
            targetName: "iqn.2026-11.dev.soba:connected", lun: LogicalUnit(0),
            readOnly: false, isid: document.identity.seed, mountID: id)
        var disk = AttachedDisk(
            entry: try AttachmentJournalEntry(
                id: id, descriptor: descriptor,
                bridgeURL: URL(fileURLWithPath: "/unused-closed-login-test/\(id.uuidString)"),
                phase: .connected))
        disk.verificationFailed = false
        model.attached = [disk]
    }
    return model
}

/// Logs in over the given transport, as the production session factory does over TCP.
private func loggingIn(over server: ClosingServer)
    -> @Sendable ([TargetAddress], LoginConfiguration, [PermanentPortalRedirect]) async throws ->
    SessionConnection
{
    { addresses, configuration, _ in
        let session = try ISCSISession(transport: server, configuration: configuration)
        try await session.login()
        return SessionConnection(session: session, portal: addresses[0].portal)
    }
}

@MainActor private func finish(_ model: AppModel) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(10))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

private let networkTitle = "The Operation Couldn’t Be Completed"
private let networkMessage = "Check the server address and network connection, then try again."

/// The case seen with LIO: the server reads the first Login Request and closes the connection
/// without a response. The search reports it under the server's name, says what happened and,
/// for each kind of authentication finding disks used, what to check, and offers Edit Server…
/// unless the server's disks are connected.
@Test(arguments: [0, 1, 2], [false, true])
@MainActor func aSearchLoginClosedWithoutAResponseSaysWhatToCheck(
    _ credentials: Int, _ connected: Bool
) async throws {
    let server = try closingServer(credentials)
    let transport = ClosingServer(.beforeAnyResponse)
    let model = try closedLoginModel(
        server, connected: connected, sessionFactory: loggingIn(over: transport))
    model.search(server)
    try await finish(model)
    // One Login Request and nothing back. With this app's initiator names, the request without
    // authentication is the 160 bytes that the app's connection sent to LIO.
    let requests = await transport.requests
    let responses = await transport.responses
    #expect(requests.count == 1 && responses == 0)
    if credentials == 0 { #expect(await transport.requestBytes == [160]) }
    let issue = try #require(model.issue)
    #expect(issue.title == "Couldn’t Find Disks on “LIO\u{00A0}Test\u{00A0}VM”")
    #expect(issue.title == findDisksTitle(server))
    let messages: [(String, String)] = [
        (
            "The server closed the connection. If it requires a user name and password to find disks, edit this server and choose an authentication method under Finding Disks, then try again.",
            "The server closed the connection. If it requires a user name and password to find disks, eject this server’s disks, then edit the server and choose an authentication method under Finding Disks."
        ),
        (
            "The server closed the connection. Edit this server and check the server address and the user name and password under Connection, then try again.",
            "The server closed the connection. To check the server address and the user name and password under Connection, eject this server’s disks, then edit the server."
        ),
        (
            "The server closed the connection. Edit this server and check the server address and the user name and password under Finding Disks, then try again.",
            "The server closed the connection. To check the server address and the user name and password under Finding Disks, eject this server’s disks, then edit the server."
        ),
    ]
    #expect(issue.message == (connected ? messages[credentials].1 : messages[credentials].0))
    #expect(issue.detail == "The server closed the connection.")
    if connected {
        // The server can't be edited until its disks are ejected, so the alert offers only OK.
        #expect(issue.recoveryAction == nil && issue.serverID == nil)
    } else {
        #expect(issue.recoveryAction == .editServer && issue.serverID == server.id)
        model.editServer(for: issue)
        #expect(model.issue == nil && model.showingServerEditor && model.editingServer == server)
    }
}

/// Within the login, the app can't tell a close before any response from a close after one:
/// both end the login with `ProtocolError.connectionClosed`. Such a close gets the same alert,
/// whose wording says only that the server closed the connection.
@Test @MainActor func aSearchLoginClosedAfterAResponseGetsTheSameAlert() async throws {
    let server = try closingServer(0)
    let transport = ClosingServer(.afterFirstResponse)
    let model = try closedLoginModel(server, sessionFactory: loggingIn(over: transport))
    model.search(server)
    try await finish(model)
    let requests = await transport.requests
    let responses = await transport.responses
    #expect(requests.count == 2 && responses == 1)
    let issue = try #require(model.issue)
    #expect(issue.title == findDisksTitle(server))
    #expect(issue.message.hasPrefix("The server closed the connection. If it requires"))
    #expect(issue.recoveryAction == .editServer)
}

/// A server that closes the connection after the login finished, while the Mac asks for its
/// targets, isn't refusing the login: the search keeps today's message and offers no editor.
@Test(arguments: [false, true])
@MainActor func aConnectionClosedAfterTheLoginKeepsTodaysMessage(_ connected: Bool) async throws {
    let server = try closingServer(0)
    let transport = ClosingServer(.afterLogin)
    let model = try closedLoginModel(
        server, connected: connected, sessionFactory: loggingIn(over: transport))
    model.search(server)
    try await finish(model)
    #expect(await transport.responses == 2)
    #expect(await transport.requests.last?.opcode == 0x04)
    let issue = try #require(model.issue)
    #expect(issue.title == networkTitle && issue.message == networkMessage)
    #expect(issue.recoveryAction == nil && issue.serverID == nil)
}

/// Failures that aren't a login the server closed keep today's messages, whether finding disks
/// or reading a target's disks: a refused connection, a timeout, a name or route that can't be
/// reached, and a reset, which can also come from something between the Mac and the server.
@Test(arguments: [false, true])
@MainActor func otherConnectionFailuresKeepTodaysMessages(_ viewing: Bool) async throws {
    let failures: [any Error] = [
        NWError.posix(.ECONNREFUSED), ProtocolError.timedOut, NWError.posix(.ETIMEDOUT),
        NWError.dns(-65554),  // kDNSServiceErr_NoSuchRecord
        NWError.posix(.EHOSTUNREACH), NWError.posix(.ENETUNREACH), NWError.posix(.ECONNRESET),
    ]
    for failure in failures {
        let server = try closingServer(0)
        let model = try closedLoginModel(server) { _, _, _ in throw failure }
        if viewing { model.inspect(closedTarget, server: server) } else { model.search(server) }
        try await finish(model)
        let issue = try #require(model.issue)
        let today = AppIssue(failure)
        #expect(issue.title == today.title && issue.message == today.message)
        #expect(issue.recoveryAction == nil && issue.serverID == nil)
        if case NWError.posix(.ECONNREFUSED) = failure {
            #expect(issue.title == networkTitle && issue.message == networkMessage)
        }
        #expect(issue.title != viewTitle && !issue.message.contains("closed the connection"))
    }
}

/// Reading a target's disks logs in with the authentication under Connection. A login the
/// server closed names the server, says what to check under Connection, and offers Edit
/// Server… unless the server's disks are connected.
@Test(arguments: [false, true], [false, true])
@MainActor func aDiskReadingLoginClosedWithoutAResponseNamesConnection(
    _ credentials: Bool, _ connected: Bool
) async throws {
    let server = try closingServer(credentials ? 1 : 0)
    let transport = ClosingServer(.beforeAnyResponse)
    let model = try closedLoginModel(
        server, connected: connected, sessionFactory: loggingIn(over: transport))
    model.inspect(closedTarget, server: server)
    try await finish(model)
    let request = try #require(await transport.requests.first)
    #expect(
        try TextParameters(data: request.data).uniqueValue(for: "TargetName") == closedTarget.name)
    let issue = try #require(model.issue)
    #expect(issue.title == viewTitle)
    let message: String
    switch (credentials, connected) {
    case (false, false):
        message =
            "The server closed the connection. If it requires a user name and password to connect to its disks, edit this server and choose an authentication method under Connection, then try again."
    case (false, true):
        message =
            "The server closed the connection. If it requires a user name and password to connect to its disks, eject this server’s disks, then edit the server and choose an authentication method under Connection."
    case (true, false):
        message =
            "The server closed the connection. Edit this server and check the user name and password under Connection, then try again."
    case (true, true):
        message =
            "The server closed the connection. To check the user name and password under Connection, eject this server’s disks, then edit the server."
    }
    #expect(issue.message == message)
    if connected {
        #expect(issue.recoveryAction == nil && issue.serverID == nil)
    } else {
        #expect(issue.recoveryAction == .editServer && issue.serverID == server.id)
        model.editServer(for: issue)
        #expect(model.showingServerEditor && model.editingServer == server)
    }
}

/// Other failures while reading a target's disks keep today's messages and offer no editor:
/// the context only adds the message for a login the server closed.
@Test @MainActor func otherDiskReadingFailuresKeepTodaysMessages() throws {
    let server = try closingServer(1)
    for failure: any Error in [
        ProtocolError.loginRejected(statusClass: 2, detail: 1), ProtocolError.authenticationFailed,
        ProtocolError.connectionClosed, ProtocolError.unsupported("authentication method"),
        NSError(domain: NSOSStatusErrorDomain, code: -25300),
    ] {
        let issue = AppIssue(failure, context: .viewingDisks(server))
        let today = AppIssue(failure)
        #expect(issue.title == today.title && issue.message == today.message)
        #expect(issue.recoveryAction == nil && issue.serverID == nil)
    }
    // Outside finding or reading disks, a closed login has no server to name.
    #expect(AppIssue(LoginClosedByServer()).title == networkTitle)
    #expect(AppIssue(LoginClosedByServer()).message == networkMessage)
}

/// Connecting a disk logs in from the file system extension, which reports a closed login to
/// the app only as the mount command's failure. That alert doesn't send the user to check the
/// network; it is unchanged.
@Test @MainActor func aClosedLoginWhileConnectingKeepsTheDiskPreparationMessage() {
    let bridged = ProtocolError.connectionClosed as NSError
    let failure = SystemCommandError.failed(
        program: "mount", status: 69,
        detail:
            "mount: Loading resource: The operation couldn’t be completed. (\(bridged.domain) error \(bridged.code).)\nmount: Unable to invoke task\n"
    )
    let issue = AppIssue(failure, context: .connectingDisk)
    #expect(issue.title == "The Disk Couldn’t Be Connected")
    #expect(issue.message == "The disk couldn’t be prepared for use on this Mac. Try again.")
    #expect(issue.recoveryAction == nil)
}

/// Names in alert titles keep their words on one line, as the application's name does, when
/// they fit on about one line. The saved name and the rows keep ordinary spaces.
@Test @MainActor func namesInAlertTitlesStayOnOneLine() throws {
    #expect(NameInTitle.keptTogether("LIO Test VM") == "LIO\u{00A0}Test\u{00A0}VM")
    #expect(NameInTitle.keptTogether("Archive") == "Archive")
    let longest = String(repeating: "a b ", count: 6)
    #expect(longest.count == NameInTitle.longestKeptTogether)
    #expect(!NameInTitle.keptTogether(longest).contains(" "))
    // A longer name couldn't fit on one line anyway, so it still wraps at its spaces.
    let longer = longest + "c"
    #expect(NameInTitle.keptTogether(longer) == longer)
    let server = try closingServer(0)
    #expect(server.displayName == "LIO Test VM")
    let inUse = AppIssue(
        POSIXError(.EBUSY), context: .ejectingDisk("Disk 0", connectionState: .connected))
    #expect(inUse.title == "“Disk\u{00A0}0” Is in Use")
    let long = "Disk 0 — iqn.2026-11.dev.soba:recheck-239ad2f08ddf"
    let named = AppIssue(
        POSIXError(.EBUSY), context: .ejectingDisk(long, connectionState: .connected))
    #expect(named.title == "“\(long)” Is in Use")
}

// MARK: - The production session factory over loopback TCP

/// A listener on 127.0.0.1 that accepts one connection, reads one Login Request and closes
/// the connection, in order (FIN) or with a reset (RST).
private final class LoopbackLoginServer: @unchecked Sendable {
    let port: UInt16
    private let finished = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var bytes = 0

    init(reset: Bool) throws {
        let listener = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.EBADF) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, length) == 0 && Darwin.listen(listener, 1) == 0
                    && getsockname(listener, $0, &length) == 0
            }
        }
        guard bound else {
            Darwin.close(listener)
            throw POSIXError(.EADDRNOTAVAIL)
        }
        port = UInt16(bigEndian: address.sin_port)
        Thread.detachNewThread { [self] in
            defer {
                Darwin.close(listener)
                finished.signal()
            }
            let client = Darwin.accept(listener, nil, nil)
            guard client >= 0 else { return }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(
                client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var received = [UInt8]()
            var buffer = [UInt8](repeating: 0, count: 4096)
            var expected = 48
            while received.count < expected {
                let count = Darwin.read(client, &buffer, buffer.count)
                guard count > 0 else { break }
                received += buffer[0..<count]
                if received.count >= 48 {
                    let data = Int(received[5]) << 16 | Int(received[6]) << 8 | Int(received[7])
                    expected = 48 + data + (4 - data % 4) % 4
                }
            }
            lock.withLock { bytes = received.count }
            if reset {
                var linger = Darwin.linger(l_onoff: 1, l_linger: 0)
                setsockopt(
                    client, SOL_SOCKET, SO_LINGER, &linger,
                    socklen_t(MemoryLayout<Darwin.linger>.size))
            }
            Darwin.close(client)
        }
    }

    /// The bytes of the Login Request it read, once it has closed the connection.
    func receivedBytes() -> Int? {
        guard finished.wait(timeout: .now() + 10) == .success else { return nil }
        return lock.withLock { bytes }
    }
}

/// A port on 127.0.0.1 with nothing listening, so a connection is refused.
private func closedLoopbackPort() throws -> UInt16 {
    let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    defer { Darwin.close(socket) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(socket, $0, length) == 0 && getsockname(socket, $0, &length) == 0
        }
    }
    guard bound else { throw POSIXError(.EADDRNOTAVAIL) }
    return UInt16(bigEndian: address.sin_port)
}

/// The app's own session factory over a real TCP connection on this Mac: a server that reads
/// the Login Request and closes the connection in order gets the new alert, as LIO did. A
/// reset or a refused connection keeps today's message.
@Test(arguments: ["close", "reset", "refuse"])
@MainActor func theAppsSessionFactoryReportsWhatTheLoopbackServerDid(_ ending: String)
    async throws
{
    let listener = ending == "refuse" ? nil : try LoopbackLoginServer(reset: ending == "reset")
    let port = try listener?.port ?? closedLoopbackPort()
    let server = try ServerProfile(
        name: "LIO Test VM", portal: Portal("127.0.0.1:\(port)"),
        discoveryAuthentication: DiscoveryAuthentication.none)
    let model = AppModel(credentials: ClosedLoginCredentials())
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.search(server)
    try await finish(model)
    if let listener { #expect(listener.receivedBytes() == 160) }
    let issue = try #require(model.issue)
    print("Loopback \(ending): \(issue.title) / \(issue.message) / \(issue.detail)")
    if ending == "close" {
        #expect(issue.title == findDisksTitle(server))
        #expect(
            issue.message
                == "The server closed the connection. If it requires a user name and password to find disks, edit this server and choose an authentication method under Finding Disks, then try again."
        )
        #expect(issue.recoveryAction == .editServer)
    } else {
        #expect(issue.title == networkTitle && issue.message == networkMessage)
        #expect(issue.recoveryAction == nil)
    }
}
