import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform
import Security

/// Read-only verification of nonce-bound credentials created through the graphical app.
/// The app performs all saves and removals. This probe never writes a Keychain item.
enum AppCredentialProbe {
    private struct Snapshot: Decodable {
        let schemaVersion: Int
        let nonce: UUID
        let profileID: UUID
        let contexts: [CredentialContext]
    }

    static func run(mode: String, snapshot: String, root: URL, nonce: UUID) async throws {
        guard ["--app-credentials-check", "--app-credentials-missing"].contains(mode),
            ["initial", "renamed", "moved", "removed", "invalid"].contains(snapshot),
            geteuid() != 0, getuid() == geteuid()
        else { throw ProtocolError.malformed("graphical credential probe arguments") }
        let file = root.appendingPathComponent(snapshot + ".json")
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard file.resolvingSymlinksInPath().path == file.path,
            attributes[.type] as? FileAttributeType == .typeRegular,
            (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
            (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
            let size = attributes[.size] as? NSNumber, size.intValue <= 65536
        else { throw ProtocolError.malformed("graphical credential snapshot file") }
        let saved = try JSONDecoder().decode(Snapshot.self, from: Data(contentsOf: file))
        guard saved.schemaVersion == 1, saved.nonce == nonce, saved.contexts.count == 2,
            Set(saved.contexts.map(\.use)) == Set([.connection, .discovery])
        else { throw ProtocolError.malformed("graphical credential snapshot") }
        let suffix = nonce.uuidString.lowercased()
        for context in saved.contexts {
            let search = context.use == .discovery
            guard context.profileID == saved.profileID, context.credentialID != nil,
                context.portal.host == "127.0.0.1", [3260, 3271].contains(context.portal.port),
                context.username == (search ? "gui-search-" : "gui-mac-") + suffix,
                context.targetUsername == (search ? "gui-search-server-" : "gui-server-") + suffix
            else { throw ProtocolError.malformed("graphical credential fixture scope") }
        }
        // Validate every context before the first lookup. No caller-selected general
        // credential query, secret output, save, copy, or removal is available here.
        let store = KeychainCredentialStore.sharedForCurrentBundle()
        let present = mode == "--app-credentials-check"
        for context in saved.contexts {
            if present {
                let value = try await store.credentials(context: context)
                guard value.username == context.username,
                    value.targetUsername == context.targetUsername
                else { throw ProtocolError.malformed("graphical credential restored identity") }
                let search = context.use == .discovery
                try MutualCredentialProbe.validate(
                    value, password: (search ? "gui-search-secret-" : "gui-mac-secret-") + suffix,
                    targetPassword: (search ? "gui-search-server-secret-" : "gui-server-secret-")
                        + suffix)
            } else {
                do {
                    _ = try await store.credentials(context: context)
                    throw ProtocolError.malformed("graphical credential still present")
                } catch let error as NSError
                    where error.domain == NSOSStatusErrorDomain
                    && error.code == Int(errSecItemNotFound)
                {}
            }
        }
        let result: [String: Any] = [
            "snapshot": snapshot, "contextsChecked": 2, "expectedPresent": present,
            "bothCHAPDirectionsVerified": present, "UID": getuid(), "EUID": geteuid(),
            "KeychainWrites": 0, "KeychainRemovals": 0, "secretsPrinted": false,
        ]
        print(
            "APP_CREDENTIAL_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: result, options: [.sortedKeys]),
                    as: UTF8.self))
    }
}
