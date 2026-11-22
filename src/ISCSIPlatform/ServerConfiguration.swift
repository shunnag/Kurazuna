import Foundation
import ISCSICore

public enum ServerConfigurationError: Error, Sendable {
    case passwordRequired
    case bothPasswordsRequired
    case discoveryPasswordRequired
    case discoveryBothPasswordsRequired
    case settingsUnavailable
    case settingsLoadFailed(any Error)
    case settingsSaveFailed(any Error)
    case passwordSaveFailed(any Error)
    case passwordRemovalFailed(any Error)
}

/// Publishes a new credential reference atomically with the server settings. Secrets are never
/// overwritten in place, and every item to delete is recorded before touching the Keychain.
public actor ServerConfiguration {
    public private(set) var document: ProfileDocument?
    public private(set) var cleanupIssue: (any Error)?
    private let storage: any ProfileStorage
    private let credentials: any CredentialStore
    private var busy = false
    private var mountedRedirectEpoch: UInt64 = 0
    private var mountedRedirectDescriptors: [UUID: ConnectionDescriptor] = [:]
    private var mountedRedirectInventoryVerified = false

    public init(storage: any ProfileStorage, credentials: any CredentialStore) throws {
        self.storage = storage
        self.credentials = credentials
        document = try storage.loadOrCreate()
    }

    public var cleanupNeeded: Bool {
        document?.pendingCredentialRemovals.isEmpty == false || cleanupIssue != nil
    }

    public func cleanupNeeded(protecting contexts: [CredentialContext]) -> Bool {
        let protected = Set(contexts.map(\.account))
        return cleanupIssue != nil
            || document?.pendingCredentialRemovals.contains {
                !protected.contains($0.account)
            } == true
    }

    /// The mount URL stays bound to the selected endpoint. Record removal intent before
    /// copying a credential, then retain it only while an attachment references it.
    public func prepareConnectionIdentity(for server: ServerProfile, portal: Portal) async throws
        -> CHAPIdentity?
    {
        guard !busy else { throw ProtocolError.busy }
        busy = true
        defer { busy = false }
        try Task.checkCancellation()
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        guard current.servers.contains(server) else { throw ProtocolError.invalidState }
        guard let source = server.credentialContext else { return nil }
        if portal == server.portal {
            return try CHAPIdentity(
                username: source.username, targetUsername: source.targetUsername,
                credentialID: source.credentialID)
        }
        let identity = try CHAPIdentity(
            username: source.username, targetUsername: source.targetUsername, credentialID: UUID())
        let destination = identity.context(profileID: server.id, portal: portal, use: .connection)
        current.pendingCredentialRemovals.append(destination)
        try persist(current)
        try Task.checkCancellation()
        do { try await credentials.copyCredentials(from: source, to: destination) } catch {
            throw ServerConfigurationError.passwordSaveFailed(error)
        }
        try Task.checkCancellation()
        return identity
    }

    public func reload() throws {
        guard !busy else { throw ProtocolError.busy }
        do { document = try storage.load() } catch {
            document = nil
            throw error
        }
    }

    /// Call only after the selected login's operation and normal Logout succeeded.
    /// No password or credential reference is rewritten by remembering a route.
    public func rememberPermanentRedirects(
        _ redirects: [PermanentPortalRedirect], invalidating sources: [Portal] = [],
        for server: ServerProfile, targetName: String?, contextEpoch: UInt64? = nil
    ) throws {
        let superseded: [UUID]
        if let contextEpoch {
            guard contextEpoch == mountedRedirectEpoch else { throw CancellationError() }
            superseded = mountedRedirectDescriptors.compactMap { id, descriptor in
                descriptor.profileID == server.id && descriptor.targetName == targetName ? id : nil
            }.sorted { $0.uuidString < $1.uuidString }
        } else {
            superseded = []
        }
        guard !redirects.isEmpty || !sources.isEmpty || !superseded.isEmpty else { return }
        guard !busy else { throw ProtocolError.busy }
        try Task.checkCancellation()
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        guard current.servers.contains(server) else { throw ProtocolError.invalidState }
        guard redirects.count <= 128, sources.count <= 128 else {
            throw ProtocolError.limitExceeded("saved permanent redirects")
        }
        if mountedRedirectInventoryVerified {
            current.handledMountRedirects.removeAll { mountedRedirectDescriptors[$0] == nil }
        }
        for id in superseded where !current.handledMountRedirects.contains(id) {
            current.handledMountRedirects.append(id)
        }
        try updatePermanentRedirects(
            redirects, invalidating: sources, for: server, targetName: targetName,
            document: &current)
        if current != document { try persist(current) }
    }

    private func updatePermanentRedirects(
        _ redirects: [PermanentPortalRedirect], invalidating sources: [Portal],
        for server: ServerProfile,
        targetName: String?, document current: inout ProfileDocument
    ) throws {
        current.permanentRedirects.removeAll { saved in
            saved.profileID == server.id && saved.targetName == targetName
                && sources.contains(where: { $0.isSameEndpoint(as: saved.redirect.source) })
        }
        for redirect in redirects {
            let saved = try SavedPermanentRedirect(
                profileID: server.id, targetName: targetName, redirect: redirect)
            if current.permanentRedirects.contains(saved) { continue }
            current.permanentRedirects.removeAll { $0.isSameKey(as: saved) }
            current.permanentRedirects.append(saved)
        }
        if current.permanentRedirects.count > 64 {
            current.permanentRedirects.removeFirst(current.permanentRedirects.count - 64)
        }
    }

    /// Epochs are assigned on the app's main actor before an operation starts. A late
    /// health observation cannot re-register an ejected or replaced connection.
    public func setMountedRedirectContext(
        epoch: UInt64, descriptors: [ConnectionDescriptor], inventoryVerified: Bool
    ) {
        guard epoch >= mountedRedirectEpoch else { return }
        mountedRedirectEpoch = epoch
        let entries = descriptors.compactMap { descriptor in
            descriptor.mountID.map { ($0, descriptor) }
        }
        guard entries.count == descriptors.count, entries.count <= 128,
            Set(entries.map(\.0)).count == entries.count
        else {
            mountedRedirectDescriptors = [:]
            mountedRedirectInventoryVerified = false
            return
        }
        mountedRedirectDescriptors = Dictionary(uniqueKeysWithValues: entries)
        mountedRedirectInventoryVerified = inventoryVerified
    }

    public func rememberMountedRedirects(
        _ report: ConnectionRouteReport, descriptor: ConnectionDescriptor, contextEpoch: UInt64
    ) throws {
        guard !busy else { throw ProtocolError.busy }
        try Task.checkCancellation()
        guard contextEpoch == mountedRedirectEpoch, mountedRedirectInventoryVerified,
            let id = descriptor.mountID, mountedRedirectDescriptors[id] == descriptor
        else { return }
        try report.validate(for: descriptor)
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        current.handledMountRedirects.removeAll { mountedRedirectDescriptors[$0] == nil }
        guard !current.handledMountRedirects.contains(id) else { return }
        // Cache changes and the durable receipt share one replacement, including when
        // an old/mismatched settings snapshot is deliberately ignored.
        current.handledMountRedirects.append(id)
        if let server = current.servers.first(where: { $0.id == descriptor.profileID }),
            let binding = descriptor.settingsBinding,
            binding == (try server.connectionSettingsBinding),
            descriptor.chapUsername == server.chapUsername,
            descriptor.targetCHAPUsername == server.targetCHAPUsername
        {
            try updatePermanentRedirects(
                report.permanentRedirects, invalidating: report.contactedPortals, for: server,
                targetName: descriptor.targetName, document: &current)
        }
        if current != document { try persist(current) }
    }

    public func pruneMountedRedirectReceipts(contextEpoch: UInt64) throws {
        guard !busy else { throw ProtocolError.busy }
        guard contextEpoch == mountedRedirectEpoch, mountedRedirectInventoryVerified else { return }
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        current.handledMountRedirects.removeAll { mountedRedirectDescriptors[$0] == nil }
        if current != document { try persist(current) }
    }

    public func save(
        _ proposed: ServerProfile, password: String, targetPassword: String = "",
        discoveryPassword: String = "", discoveryTargetPassword: String = "",
        protecting contexts: [CredentialContext] = []
    ) async throws {
        guard !busy else { throw ProtocolError.busy }
        busy = true
        defer { busy = false }
        try Task.checkCancellation()
        guard !contexts.contains(where: { $0.profileID == proposed.id }) else {
            throw ProtocolError.busy
        }
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        let previous = current.servers.first { $0.id == proposed.id }
        var writes: [CredentialWrite] = []
        var connection: CHAPIdentity?
        if let username = proposed.chapUsername {
            connection = try resolve(
                CHAPIdentity(username: username, targetUsername: proposed.targetCHAPUsername),
                previous: previous?.credentialContext, profile: proposed, use: .connection,
                password: password, targetPassword: targetPassword, writes: &writes)
        }
        let discovery: DiscoveryAuthentication
        switch proposed.discoveryAuthentication {
        case .sameAsConnection: discovery = .sameAsConnection
        case .none: discovery = .none
        case .chap(let identity):
            discovery = .chap(
                try resolve(
                    identity, previous: previous?.discoveryCredentialContext,
                    profile: proposed, use: .discovery, password: discoveryPassword,
                    targetPassword: discoveryTargetPassword, writes: &writes))
        }
        let server = try ServerProfile(
            id: proposed.id, name: proposed.name, portal: proposed.portal,
            chapUsername: connection?.username, credentialID: connection?.credentialID,
            targetCHAPUsername: connection?.targetUsername, discoveryAuthentication: discovery)
        // Check limits before recording intent or creating a credential.
        var replacement = current.servers.filter { $0.id != server.id }
        if let index = current.servers.firstIndex(where: { $0.id == server.id }) {
            replacement.insert(server, at: index)
        } else {
            replacement.append(server)
        }
        _ = try ProfileDocument(identity: current.identity, servers: replacement)
        if !writes.isEmpty {
            current.pendingCredentialRemovals += writes.map(\.context)
            try persist(current)
            for write in writes {
                try Task.checkCancellation()
                do {
                    if let targetPassword = write.targetPassword {
                        try await credentials.save(
                            password: write.password,
                            targetPassword: targetPassword, context: write.context)
                    } else {
                        try await credentials.save(password: write.password, context: write.context)
                    }
                } catch {
                    throw ServerConfigurationError.passwordSaveFailed(error)
                }
                try Task.checkCancellation()
            }
        }
        try Task.checkCancellation()
        current.servers = replacement
        if previous != server { current.permanentRedirects.removeAll { $0.profileID == server.id } }
        let stagedAccounts = Set(writes.map(\.context.account))
        current.pendingCredentialRemovals.removeAll { stagedAccounts.contains($0.account) }
        let keptAccounts = Set(server.credentialContexts.map(\.account))
        for old in previous?.credentialContexts ?? [] where !keptAccounts.contains(old.account) {
            current.pendingCredentialRemovals.append(old)
        }
        try persist(current)
        await finishCleanup(protecting: Set(contexts.map(\.account)))
    }

    private struct CredentialWrite {
        let context: CredentialContext
        let password: String
        let targetPassword: String?
    }

    private func resolve(
        _ identity: CHAPIdentity, previous: CredentialContext?,
        profile: ServerProfile, use: CredentialContext.Use, password: String,
        targetPassword: String,
        writes: inout [CredentialWrite]
    ) throws -> CHAPIdentity {
        let required: ServerConfigurationError =
            use == .discovery
            ? (identity.targetUsername == nil
                ? .discoveryPasswordRequired : .discoveryBothPasswordsRequired)
            : (identity.targetUsername == nil ? .passwordRequired : .bothPasswordsRequired)
        if password.isEmpty && targetPassword.isEmpty {
            guard let previous else { throw required }
            let retained = try CHAPIdentity(
                username: identity.username, targetUsername: identity.targetUsername,
                credentialID: previous.credentialID)
            guard
                retained.context(profileID: profile.id, portal: profile.portal, use: use).account
                    == previous.account
            else {
                throw required
            }
            return retained
        }
        if identity.targetUsername != nil {
            guard !password.isEmpty, !targetPassword.isEmpty else { throw required }
        } else if !targetPassword.isEmpty {
            throw ProtocolError.malformed("mutual CHAP credentials")
        }
        _ = try CHAPCredentials(
            username: identity.username, password: password,
            targetUsername: identity.targetUsername,
            targetPassword: identity.targetUsername == nil ? nil : targetPassword)
        let resolved = try CHAPIdentity(
            username: identity.username, targetUsername: identity.targetUsername,
            credentialID: UUID())
        writes.append(
            CredentialWrite(
                context: resolved.context(profileID: profile.id, portal: profile.portal, use: use),
                password: password,
                targetPassword: identity.targetUsername == nil ? nil : targetPassword))
        return resolved
    }

    public func remove(_ id: UUID, protecting contexts: [CredentialContext] = []) async throws {
        guard !busy else { throw ProtocolError.busy }
        busy = true
        defer { busy = false }
        try Task.checkCancellation()
        guard !contexts.contains(where: { $0.profileID == id }) else { throw ProtocolError.busy }
        guard var current = document else { throw ServerConfigurationError.settingsUnavailable }
        guard let server = current.servers.first(where: { $0.id == id }) else { return }
        current.servers.removeAll { $0.id == id }
        current.permanentRedirects.removeAll { $0.profileID == id }
        current.pendingCredentialRemovals += server.credentialContexts
        try persist(current)
        await finishCleanup(protecting: Set(contexts.map(\.account)))
    }

    /// The app supplies credentials still referenced by restored mounts. Never remove those items.
    public func retryCleanup(protecting contexts: [CredentialContext] = []) async throws {
        guard !busy else { throw ProtocolError.busy }
        busy = true
        defer { busy = false }
        do {
            try await cleanup(protecting: Set(contexts.map(\.account)))
            cleanupIssue = nil
        } catch {
            cleanupIssue = error
            throw error
        }
    }

    private func finishCleanup(protecting accounts: Set<String>) async {
        do {
            try await cleanup(protecting: accounts)
            cleanupIssue = nil
        } catch {
            // The settings change has committed. Keep the durable removal intent and surface it
            // separately, so retrying the settings operation cannot create a duplicate server.
            cleanupIssue = error
        }
    }

    private func cleanup(protecting accounts: Set<String>) async throws {
        guard let current = document else { throw ServerConfigurationError.settingsUnavailable }
        // Retry the persistence barrier too, including a prior error after rename/fsync.
        if current.pendingCredentialRemovals.isEmpty, cleanupIssue != nil { try persist(current) }
        for context in current.pendingCredentialRemovals where !accounts.contains(context.account) {
            try Task.checkCancellation()
            do { try await credentials.remove(context: context) } catch {
                throw ServerConfigurationError.passwordRemovalFailed(error)
            }
            guard var updated = document else { throw ServerConfigurationError.settingsUnavailable }
            updated.pendingCredentialRemovals.removeAll { $0.account == context.account }
            try persist(updated)
        }
    }

    private func persist(_ proposed: ProfileDocument) throws {
        let validated = try ProfileDocument(
            identity: proposed.identity, servers: proposed.servers,
            pendingCredentialRemovals: proposed.pendingCredentialRemovals,
            permanentRedirects: proposed.permanentRedirects,
            handledMountRedirects: proposed.handledMountRedirects)
        do {
            try storage.save(validated)
            document = validated
        } catch {
            // A save may have failed after rename. Use the actual file, never an assumed rollback.
            // If it cannot be read, stop mutations and cleanup until an explicit reload succeeds.
            document = try? storage.load()
            throw ServerConfigurationError.settingsSaveFailed(error)
        }
    }
}
