import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform

private actor UnusedRedirectCredentialStore: CredentialStore {
    private(set) var calls = 0
    func save(password: String, context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        calls += 1
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
}

enum PermanentRedirectProbe {
    static func run(portal: String, discovery: Bool, credentials: CHAPCredentials?) async throws {
        let source = try Portal(portal)
        guard source.host == "127.0.0.1",
            let path = ProcessInfo.processInfo.environment["ISCSI_TEST_REDIRECT_SETTINGS"]
        else { throw ProtocolError.invalidState }
        let store = try ProfileStore(url: URL(fileURLWithPath: path))
        var document = try store.loadOrCreate()
        if document.servers.isEmpty {
            document.servers = [
                try ServerProfile(
                    name: "RAM fixture", portal: source, chapUsername: credentials?.username,
                    credentialID: credentials == nil ? nil : UUID(),
                    targetCHAPUsername: credentials?.targetUsername)
            ]
            try store.save(document)
            document = try store.load()
        }
        guard document.servers.count == 1, let server = document.servers.first,
            server.portal == source, server.chapUsername == credentials?.username,
            server.targetCHAPUsername == credentials?.targetUsername
        else { throw ProtocolError.invalidState }
        let target = discovery ? nil : "iqn.2026-10.test:memory"
        let cached = document.permanentRedirects(for: server, targetName: target)
        guard
            cached.allSatisfy({
                $0.source.host == "127.0.0.1"
                    && $0.destinations.allSatisfy { $0.host == "127.0.0.1" }
            })
        else { throw ProtocolError.invalidState }
        let noSecrets = UnusedRedirectCredentialStore()
        let settings = try ServerConfiguration(storage: store, credentials: noSecrets)
        do {
            let connection = try await SessionConnector.connect(
                portal: source,
                configuration: LoginConfiguration(
                    initiatorName: document.identity.name, targetName: target,
                    credentials: credentials),
                timeout: .seconds(5), cachedRedirects: cached)
            do {
                if discovery {
                    guard
                        try await connection.session.discover().contains(where: {
                            $0.name == "iqn.2026-10.test:memory"
                        })
                    else {
                        throw ProtocolError.malformed("permanent redirect discovery fixture")
                    }
                } else {
                    let lun = try LogicalUnit(0)
                    let info = try await DiskProbe.diskInformation(
                        session: connection.session, lun: lun)
                    guard info.capacity.byteCount == 65_536 else {
                        throw ProtocolError.invalidState
                    }
                    let disk = RemoteDisk(
                        session: connection.session, lun: lun, capacity: info.capacity,
                        readOnly: false)
                    let bytes = Data((0..<4129).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
                    try await disk.write(offset: 509, data: bytes)
                    try await disk.synchronize()
                    guard try await disk.read(offset: 509, length: bytes.count) == bytes,
                        try await disk.read(offset: 0, length: 509)
                            == Data((0..<509).map { UInt8(truncatingIfNeeded: $0 * 3) })
                    else { throw ProtocolError.malformed("permanent redirect contents") }
                }
                try await connection.session.logout()
                try Task.checkCancellation()
                try await settings.rememberPermanentRedirects(
                    connection.permanentRedirects,
                    invalidating: connection.invalidatedRedirectSources,
                    for: server, targetName: target)
            } catch {
                await connection.session.closeGracefully()
                throw error
            }
            let saved = try store.load()
            guard saved.servers == document.servers, saved.identity == document.identity,
                saved.pendingCredentialRemovals == document.pendingCredentialRemovals,
                await noSecrets.calls == 0
            else { throw ProtocolError.invalidState }
            try report([
                "success": true, "discovery": discovery, "portal": connection.portal.description,
                "configuredPortal": source.description, "providedHints": cached.count,
                "routes": saved.permanentRedirects.map {
                    [
                        "source": $0.redirect.source.description,
                        "destinations": $0.redirect.destinations.map(\.description),
                    ]
                },
                "version": saved.version, "credentialStoreCalls": 0,
            ])
        } catch {
            let kind: String
            switch error {
            case ProtocolError.authenticationFailed,
                ProtocolError.loginRejected(statusClass: 2, detail: 1):
                kind = "authentication"
            default: kind = "connection"
            }
            try report([
                "success": false, "error": kind,
                "savedRoutes": try store.load().permanentRedirects.count,
            ])
            throw error
        }
    }

    private static func report(_ object: [String: Any]) throws {
        print(
            "PERMANENT_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: object, options: .sortedKeys), as: UTF8.self))
    }
}
