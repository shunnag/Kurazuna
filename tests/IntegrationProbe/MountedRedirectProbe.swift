import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform

private actor MountedFixtureCredentials: CredentialStore {
    let expected: CredentialContext?
    let value: CHAPCredentials?
    private(set) var reads = 0
    init(expected: CredentialContext?, value: CHAPCredentials?) {
        self.expected = expected
        self.value = value
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        guard context == expected, let value else { throw ProtocolError.invalidState }
        reads += 1
        return value
    }
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
}

/// Exercises the exact production volume factory and xattr implementation in a command
/// process. It deliberately does not claim to mount FSKit or inspect an OS-owned namespace.
enum MountedRedirectProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let source = try Portal(portal)
        guard source.host == "127.0.0.1",
            let path = ProcessInfo.processInfo.environment["ISCSI_TEST_REDIRECT_SETTINGS"]
        else {
            throw ProtocolError.invalidState
        }
        let store = try ProfileStore(url: URL(fileURLWithPath: path))
        var document = try store.loadOrCreate()
        guard document.servers.isEmpty else { throw ProtocolError.invalidState }
        let server = try ServerProfile(
            name: "RAM fixture", portal: source,
            chapUsername: credentials?.username, credentialID: credentials == nil ? nil : UUID(),
            targetCHAPUsername: credentials?.targetUsername)
        document.servers = [server]
        try store.save(document)
        let descriptor = try ConnectionDescriptor(
            profileID: server.id, portal: source,
            initiatorName: document.identity.name, targetName: "iqn.2026-10.test:memory",
            lun: LogicalUnit(0),
            readOnly: false, chapUsername: server.chapUsername,
            isid: document.identity.isid(
                targetName: "iqn.2026-10.test:memory", lun: LogicalUnit(0)),
            mountID: UUID(), credentialID: server.credentialID,
            targetCHAPUsername: server.targetCHAPUsername,
            settingsBinding: server.connectionSettingsBinding)
        let fixtureCredentials = MountedFixtureCredentials(
            expected: server.credentialContext, value: credentials)
        let volume = try await LUNVolumeFactory.open(
            descriptor, readOnly: false, credentials: fixtureCredentials)
        do {
            let (image, _) = try await (volume as any FSVolume.Operations).lookupItem(
                named: FSFileName(string: LUNImageVolume.imageName), inDirectory: volume.rootItem)
            let name = FSFileName(string: ConnectionDescriptor.connectionRouteAttributeName)
            let encoded = try await volume.xattr(named: name, of: volume.rootItem)
            let report = try ConnectionRouteReport(data: encoded, descriptor: descriptor)
            guard report.connectedPortal.host == "127.0.0.1",
                try await volume.xattr(
                    named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
                    of: volume.rootItem) == DiskConnectionState.connected.encoded,
                try await volume.xattr(named: name, of: image) == encoded,
                await fixtureCredentials.reads == (credentials == nil ? 0 : 1)
            else { throw ProtocolError.malformed("production volume route metadata") }
            do {
                try await volume.setXattr(
                    named: name, to: Data([0]), on: volume.rootItem, policy: .alwaysSet)
                throw ProtocolError.invalidState
            } catch let error as POSIXError where error.code == .EPERM {}
            let bytes = Data((0..<4129).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
            guard
                try await volume.write(contents: bytes, to: image, at: 509)
                    == bytes.count
            else {
                throw ProtocolError.malformed("production volume write")
            }
            let configuration = try ServerConfiguration(
                storage: store, credentials: fixtureCredentials)
            await configuration.setMountedRedirectContext(
                epoch: 1, descriptors: [descriptor], inventoryVerified: true)
            try await configuration.rememberMountedRedirects(
                report, descriptor: descriptor, contextEpoch: 1)
            let saved = try store.load()
            guard saved.servers == [server], saved.identity == document.identity,
                saved.handledMountRedirects == [descriptor.mountID!],
                saved.pendingCredentialRemovals.isEmpty,
                saved.permanentRedirects(for: server, targetName: descriptor.targetName)
                    == report.permanentRedirects
            else { throw ProtocolError.malformed("production mounted route persistence") }
            await volume.shutdown()
            let output: [String: Any] = [
                "success": true, "portal": report.connectedPortal.description,
                "contacted": report.contactedPortals.map(\.description),
                "permanentSources": report.permanentRedirects.map { $0.source.description },
                "metadataBytes": encoded.count, "credentialReads": await fixtureCredentials.reads,
                "mountID": descriptor.mountID!.uuidString, "noNativeMountUsed": true,
            ]
            let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
            print("MOUNTED_RESULT " + String(decoding: data, as: UTF8.self))
        } catch {
            await volume.shutdown()
            throw error
        }
    }
}
