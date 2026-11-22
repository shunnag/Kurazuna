import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

private actor NativeRouteUnusedCredentials: CredentialStore {
    private(set) var calls = 0
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        calls += 1
        throw ProtocolError.invalidState
    }
    func save(password: String, context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws {
        calls += 1
        throw ProtocolError.invalidState
    }
}

/// A command-only check of the real FSKit namespace and the app's persistence actor.
/// It does not launch the GUI or claim to exercise AppModel's scheduling.
enum NativeMountedRouteProbe {
    static func run(portal: Portal, root: URL, nonce: UUID) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let authentication = environment["ISCSI_TEST_NATIVE_ROUTE_AUTH"],
            ["none", "chap", "mutual"].contains(authentication),
            let finalAddress = environment["ISCSI_TEST_NATIVE_ROUTE_FINAL"],
            let permanent = environment["ISCSI_TEST_NATIVE_ROUTE_PERMANENT"],
            ["0", "1"].contains(permanent)
        else { throw ProtocolError.malformed("native route fixture environment") }
        let final = try Portal(finalAddress)
        guard final.host == "127.0.0.1", final != portal else {
            throw ProtocolError.malformed("native route fixture destination")
        }
        let chap = authentication != "none"
        let mutual = authentication == "mutual"
        let store = try ProfileStore(url: root.appendingPathComponent("Servers.json"))
        var initial = try store.loadOrCreate()
        guard initial.servers.isEmpty else { throw ProtocolError.invalidState }
        let server = try ServerProfile(
            id: nonce, name: "Native RAM route fixture", portal: portal,
            chapUsername: chap ? "test-user" : nil, credentialID: chap ? nonce : nil,
            targetCHAPUsername: mutual ? "test-server" : nil)
        initial.servers = [server]
        try store.save(initial)
        if chap {
            try await FSKitProbe.saveFixtureCredential(
                portal: portal, root: root, nonce: nonce, mutualCHAP: mutual)
        }
        do {
            try await validate(
                portal: portal, final: final, permanent: permanent == "1", root: root,
                nonce: nonce, store: store, initial: initial, server: server)
        } catch {
            try? await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
            throw error
        }
        try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func validate(
        portal: Portal, final: Portal, permanent: Bool, root: URL, nonce: UUID,
        store: ProfileStore, initial: ProfileDocument, server: ServerProfile
    ) async throws {
        let target = "iqn.2026-10.test:fskit-" + nonce.uuidString.lowercased()
        let descriptor = try ConnectionDescriptor(
            profileID: nonce, portal: portal, initiatorName: initial.identity.name,
            targetName: target, lun: LogicalUnit(0), readOnly: true,
            chapUsername: server.chapUsername,
            isid: initial.identity.isid(targetName: target, lun: LogicalUnit(0)),
            credentialID: server.credentialID, targetCHAPUsername: server.targetCHAPUsername,
            settingsBinding: server.connectionSettingsBinding)
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: SystemAttachmentBackend(root: mounts),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        let record = try await coordinator.connect(descriptor)
        do {
            guard !record.needsCleanup, record.connectionState == .connected,
                record.connectedPortal == final, let report = record.connectionRoute,
                report.contactedPortals == [portal, final],
                report.permanentRedirects
                    == (permanent
                        ? [try PermanentPortalRedirect(source: portal, destinations: [final])]
                        : []),
                record.attachment?.volumeURLs.count == 1,
                let volume = record.attachment?.volumeURLs.first,
                try Data(contentsOf: volume.appendingPathComponent("FSKit-validation.txt"))
                    == Data("FSKit validation \(nonce.uuidString.lowercased())\n".utf8)
            else { throw ProtocolError.malformed("native mounted route or fixture volume") }
            try report.validate(for: record.descriptor)
            try DirectoryEnumerationProbe.validate(record.bridgeURL, requireFSKit: true)
            var denialCodes: [Int32] = []
            for path in [record.bridgeURL, record.bridgeURL.appendingPathComponent("Disk.img")] {
                let before = try routeAttribute(at: path)
                guard
                    try ConnectionRouteReport(data: before, descriptor: record.descriptor) == report
                else { throw ProtocolError.malformed("native root/image route attribute") }
                var replacement: UInt8 = 0
                errno = 0
                let changed = setxattr(
                    path.path, ConnectionDescriptor.connectionRouteAttributeName, &replacement,
                    1, 0, 0)
                let changeError = errno
                errno = 0
                let removed = removexattr(
                    path.path, ConnectionDescriptor.connectionRouteAttributeName, 0)
                let removeError = errno
                let unchanged = try routeAttribute(at: path) == before
                print(
                    "NATIVE_ROUTE_MUTATION path=\(path.lastPathComponent) set=\(changed) setErrno=\(changeError) remove=\(removed) removeErrno=\(removeError) unchanged=\(unchanged)"
                )
                guard changed == -1, removed == -1,
                    [EPERM, EACCES, EROFS].contains(changeError),
                    [EPERM, EACCES, EROFS].contains(removeError),
                    unchanged
                else { throw ProtocolError.malformed("native route attribute mutation") }
                denialCodes += [changeError, removeError]
            }
            await coordinator.refreshHealth()
            guard let refreshed = await coordinator.disks.first,
                refreshed.connectedPortal == final, refreshed.connectionRoute == report,
                await coordinator.recoveryReady
            else { throw ProtocolError.malformed("native route refresh") }

            let noSecrets = NativeRouteUnusedCredentials()
            let configuration = try ServerConfiguration(storage: store, credentials: noSecrets)
            await configuration.setMountedRedirectContext(
                epoch: 1, descriptors: [record.descriptor], inventoryVerified: true)
            try await configuration.rememberMountedRedirects(
                report, descriptor: record.descriptor, contextEpoch: 1)
            let saved = try store.load()
            guard saved.version == 6, saved.identity == initial.identity,
                saved.servers == initial.servers, saved.pendingCredentialRemovals.isEmpty,
                saved.handledMountRedirects == [record.id],
                saved.permanentRedirects(for: server, targetName: target)
                    == report.permanentRedirects
            else { throw ProtocolError.malformed("native route persistence") }
            let savedBytes = try Data(contentsOf: store.url)
            let reopened = try ServerConfiguration(storage: store, credentials: noSecrets)
            await reopened.setMountedRedirectContext(
                epoch: 1, descriptors: [record.descriptor], inventoryVerified: true)
            try await reopened.rememberMountedRedirects(
                report, descriptor: record.descriptor, contextEpoch: 1)
            guard try Data(contentsOf: store.url) == savedBytes else {
                throw ProtocolError.malformed("reopened native route receipt replay")
            }
            try await coordinator.eject(record.id)
            guard await coordinator.disks.isEmpty, await coordinator.recoveryReady else {
                throw AttachmentError.recoveryRequired
            }
            await reopened.setMountedRedirectContext(
                epoch: 2, descriptors: [], inventoryVerified: true)
            try await reopened.pruneMountedRedirectReceipts(contextEpoch: 2)
            let pruned = try store.load()
            guard pruned.handledMountRedirects.isEmpty,
                pruned.permanentRedirects == saved.permanentRedirects,
                pruned.servers == initial.servers, pruned.identity == initial.identity,
                pruned.pendingCredentialRemovals.isEmpty, await noSecrets.calls == 0
            else { throw ProtocolError.malformed("native route receipt cleanup") }
            let result: [String: Any] = [
                "nativeMountUsed": true, "guiUsed": false,
                "configuredPortal": portal.description, "connectedPortal": final.description,
                "contactedPortals": report.contactedPortals.map(\.description),
                "permanentSources": report.permanentRedirects.map { $0.source.description },
                "rootAndImageAttributesMatched": true, "attributeMutationDenialCodes": denialCodes,
                "healthyCoordinatorRouteMatched": true, "nativeMarkerMatched": true,
                "durableReceiptSaved": true, "reopenedReceiptReplayPreservedFile": true,
                "receiptPrunedAfterEject": true,
                "savedPermanentRoutes": pruned.permanentRedirects.count,
                "configurationCredentialCalls": 0, "normalEjectCompleted": true,
                "serverAndIdentityUnchanged": true, "mountID": record.id.uuidString,
            ]
            print(
                "NATIVE_MOUNTED_ROUTE_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
        } catch {
            try? await coordinator.eject(record.id)
            throw error
        }
    }

    private static func routeAttribute(at url: URL) throws -> Data {
        var bytes = Data(count: ConnectionRouteReport.maximumEncodedLength + 1)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                url.path, ConnectionDescriptor.connectionRouteAttributeName, $0.baseAddress,
                $0.count, 0, 0)
        }
        guard (1...ConnectionRouteReport.maximumEncodedLength).contains(count) else {
            throw ProtocolError.malformed("native route attribute size")
        }
        return bytes.prefix(count)
    }
}
