import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Network
import Security
import SwiftUI

/// A development-only host for the production views. All attachment operations use the memory
/// backend below; no FSKit extension, NAS, disk image, profile file, or Keychain entry is created.
@main
struct StatePreview: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model: AppModel?
    @State private var pendingDiskInformation: [FoundDisk] = []
    @State private var screen = PreviewScreen()

    var body: some Scene {
        // The preview's name, like the application's, isn't a localized string.
        Window(AppName.display, id: "preview") {
            Group {
                if let model {
                    MainView(model: model)
                        .onAppear {
                            if CommandLine.arguments.contains("--quit-during-search")
                                || CommandLine.arguments.contains("--quit-with-connected-disk")
                            {
                                delegate.model = model
                            }
                        }
                        .toolbar {
                            if CommandLine.arguments.contains("--dynamic-disk-information") {
                                Button {
                                    guard let server = model.document?.servers.first,
                                        let target = model.targets[server.id]?.first
                                    else { return }
                                    model.choices[model.choiceKey(server, target.name)] =
                                        pendingDiskInformation
                                } label: {
                                    Text(verbatim: "Load Disk Information")
                                }.accessibilityIdentifier("preview-load-disk-information")
                            }
                        }
                } else {
                    ProgressView().task { model = try? await makePreview() }
                }
            }
            .environment(
                \.serverEditorHeightLimit,
                CommandLine.arguments.contains("--compact-editor") ? 440 : nil
            )
            #if ISCSI_PREVIEW_DARK
                .preferredColorScheme(.dark)
            #else
                .preferredColorScheme(
                    CommandLine.arguments.contains("--dark-appearance") ? .dark : .light)
            #endif
        }
        // The same default size as the application's main window.
        .defaultSize(
            width: CommandLine.arguments.contains("--small-window") ? 780 : 960,
            height: CommandLine.arguments.contains("--small-window") ? 600 : 800
        )
        .commands {
            // A menu, unlike the toolbar, stays available while an alert is shown.
            if CommandLine.arguments.contains("--metadata-cleanup-while-locked") {
                CommandMenu(Text(verbatim: "Preview")) {
                    Button {
                        screen.unlock()
                    } label: {
                        Text(verbatim: "Unlock Screen")
                    }
                }
            }
        }
        Settings {
            if let model {
                InitiatorSettings(model: model)
                    #if ISCSI_PREVIEW_DARK
                        .preferredColorScheme(.dark)
                    #else
                        .preferredColorScheme(
                            CommandLine.arguments.contains("--dark-appearance") ? .dark : .light)
                    #endif
            }
        }
    }

    init() {
        // Each run starts at the default window size, as on first launch, rather than at a
        // size that an earlier run saved.
        let saved = UserDefaults.standard
        for key in saved.dictionaryRepresentation().keys
        where key.hasPrefix("NSWindow Frame") || key.hasPrefix("NSSplitView Subview Frames") {
            saved.removeObject(forKey: key)
        }
    }

    @MainActor private func makePreview() async throws -> AppModel {
        let protectedPreview = CommandLine.arguments.contains("--write-protected")
        let writeCompletionPreview = CommandLine.arguments.contains(
            "--write-completion-unavailable")
        let dynamicInformation = CommandLine.arguments.contains("--dynamic-disk-information")
        // A search refused as with --search-authentication-failure, on a server with a
        // connected disk, which can't be edited until its disks are ejected.
        let searchWithDiskPreview = CommandLine.arguments.contains(
            "--search-failure-with-connected-disk")
        let searchAuthenticationPreview =
            CommandLine.arguments.contains("--search-authentication-failure")
            || searchWithDiskPreview
        // Finding Disks is Same as Connection, and the server refuses the connection password.
        let connectionPasswordPreview = CommandLine.arguments.contains(
            "--search-uses-connection-password")
        // The search fails for a reason other than authentication; the error offers only OK.
        let searchNetworkPreview = CommandLine.arguments.contains("--search-network-failure")
        // The server accepts the connection and closes it during the login, as Linux LIO does
        // when it requires CHAP and is offered none: finding disks, and reading a target's
        // disks with Refresh, fail. With a password, the server uses the Connection password,
        // and Finding Disks is Same as Connection. With a connected disk, it can't be edited.
        let closedLoginWithPasswordPreview = CommandLine.arguments.contains(
            "--server-closes-login-with-password")
        let closedLoginWithDiskPreview = CommandLine.arguments.contains(
            "--server-closes-login-with-connected-disk")
        let closedLoginPreview =
            CommandLine.arguments.contains("--server-closes-login")
            || closedLoginWithPasswordPreview || closedLoginWithDiskPreview
        let quitDuringSearch = CommandLine.arguments.contains("--quit-during-search")
        let quitWithConnectedDisk = CommandLine.arguments.contains("--quit-with-connected-disk")
        let connectionPreview =
            protectedPreview || writeCompletionPreview || dynamicInformation
            || searchAuthenticationPreview || quitDuringSearch || searchNetworkPreview
            || connectionPasswordPreview || closedLoginPreview
        let selectionPreview = CommandLine.arguments.contains("--server-selection")
        let settingsFailure = CommandLine.arguments.contains("--settings-load-failure")
        let emptyServers = CommandLine.arguments.contains("--empty-servers")
        // Connection information can't be removed until Unlock Screen in the Preview menu,
        // rather than only the first time.
        let lockedCleanupPreview = CommandLine.arguments.contains(
            "--metadata-cleanup-while-locked")
        let metadataCleanupPreview =
            CommandLine.arguments.contains("--metadata-cleanup-failure") || lockedCleanupPreview
        let forceEjectionPreview = CommandLine.arguments.contains("--force-ejection")
        let inUsePreview = CommandLine.arguments.contains("--force-ejection-in-use")
        let unverifiedPreview = CommandLine.arguments.contains("--unverified-connection")
        let reconnectingPreview = CommandLine.arguments.contains("--reconnecting")
        // Two connected disks without volumes, LUN 0 of two targets, beside a found LUN 0 of
        // a third: each name adds its target.
        let sameLUNPreview = CommandLine.arguments.contains("--same-lun-disks")
        // A connected disk without a volume, as a new disk is before it's initialized.
        let unformattedPreview =
            CommandLine.arguments.contains("--unformatted-disk") || sameLUNPreview
        // The connected disks are the found target's disks, so each shows in both lists.
        let sharedTarget =
            CommandLine.arguments.contains("--shared-target")
            || (unformattedPreview && !sameLUNPreview)
        // How long the reconnecting disk had been reconnecting at launch, in seconds, as
        // `--reconnecting-for=N`: a separate value argument would be opened as a document,
        // and the window would not open. Without it, the coordinator's clock stands still,
        // so the disk keeps the state it launched with.
        let reconnectingFor = CommandLine.arguments.lazy
            .compactMap { argument -> Int? in
                guard argument.hasPrefix("--reconnecting-for=") else { return nil }
                return Int(argument.dropFirst("--reconnecting-for=".count))
            }.first
        let clock = PreviewClock(startedAgo: reconnectingFor.map { .seconds($0) })
        // States that show connected disks with the extension ready and no other notice.
        let diskStatePreview =
            inUsePreview || unverifiedPreview || reconnectingPreview || unformattedPreview
        let server = try ServerProfile(
            name: "Test Storage", portal: Portal("192.0.2.10"),
            chapUsername: connectionPasswordPreview || closedLoginWithPasswordPreview
                ? "preview-user" : nil,
            credentialID: connectionPasswordPreview || closedLoginWithPasswordPreview
                ? UUID() : nil)
        let identity = try InitiatorIdentity.makeNew()
        var entries: [AttachmentJournalEntry] = []
        let states: [DiskConnectionState]
        if forceEjectionPreview || unverifiedPreview {
            states = [.interrupted]
        } else if reconnectingPreview {
            states = [.connected, .reconnecting]
        } else if sameLUNPreview {
            states = [.connected, .connected]
        } else if inUsePreview || metadataCleanupPreview || quitWithConnectedDisk
            || unformattedPreview || searchWithDiskPreview || closedLoginWithDiskPreview
        {
            states = [.connected]
        } else if connectionPreview || selectionPreview || settingsFailure {
            states = []
        } else {
            states = [.connected, .interrupted, .unknown, .connected]
        }
        var observations: [UUID: AttachmentInspection] = [:]
        for index in states.indices {
            let id = UUID()
            let descriptor = try ConnectionDescriptor(
                profileID: server.id, portal: server.portal, initiatorName: identity.name,
                targetName: sharedTarget
                    ? "iqn.2026-10.example:available" : "iqn.2026-10.example:preview-\(index)",
                lun: LogicalUnit(UInt16(sameLUNPreview ? 0 : index)),
                readOnly: index == 0 && CommandLine.arguments.contains("--read-only-disk"),
                isid: identity.seed, mountID: id)
            entries.append(
                try AttachmentJournalEntry(
                    id: id, descriptor: descriptor,
                    bridgeURL: URL(fileURLWithPath: "/private/tmp/iSCSI-Preview/\(id.uuidString)"),
                    phase: index == 3 ? .detachingImage : .connected))
            observations[id] = AttachmentInspection(
                ownership: .verified,
                attachment: DiskAttachment(
                    device: "/dev/disk\(900000 + index)",
                    volumeURLs: unformattedPreview
                        ? []
                        : [
                            URL(
                                fileURLWithPath:
                                    "/Volumes/\(["Archive", "Work", "Projects", "Photos"][index])"
                            )
                        ]),
                connectionState: states[index])
        }
        let backend = PreviewBackend(
            observations: observations,
            failEjection: CommandLine.arguments.contains("--eject-fails"),
            allowsReadOnlyConnection: connectionPreview,
            requiresReadOnlyPolicy: writeCompletionPreview,
            failMetadataRemovalOnce: metadataCleanupPreview,
            delaysMetadataCleanup: CommandLine.arguments.contains("--metadata-cleanup-delay"),
            allowsForceEjection: forceEjectionPreview || inUsePreview || unverifiedPreview
                || reconnectingFor != nil,
            uninspectable: unverifiedPreview ? Set(entries.map(\.id)) : [],
            // The server comes back just as Force Eject is chosen.
            reconnectsOnForcedInspection: CommandLine.arguments.contains(
                "--reconnects-on-force-eject"),
            lockedScreen: lockedCleanupPreview ? screen : nil)
        let coordinator = try AttachmentCoordinator(
            backend: backend, journal: MemoryAttachmentJournal(entries: entries),
            now: { clock.now })
        if unverifiedPreview {
            // The disk's extension doesn't answer, so restoring reports it as unverified.
            try? await coordinator.restore()
        } else {
            try await coordinator.restore()
        }
        // Restoring observed the reconnecting disk; from now on the clock runs, if it does.
        clock.start()
        let pending = CredentialContext(
            profileID: server.id, portal: server.portal,
            username: "Preview User", credentialID: UUID())
        let document = try ProfileDocument(
            identity: identity, servers: emptyServers ? [] : [server],
            pendingCredentialRemovals: connectionPreview || selectionPreview || settingsFailure
                || metadataCleanupPreview || quitWithConnectedDisk || diskStatePreview
                ? [] : [pending])
        let credentials = PreviewCredentials(
            allowsSaving: CommandLine.arguments.contains("--save-credentials"),
            saved: server.credentialContext.map { [$0] } ?? [])
        let configuration = try ServerConfiguration(
            storage: PreviewSettings(document, failFirstReload: settingsFailure),
            credentials: credentials)
        let model = AppModel(
            coordinator: coordinator, configuration: configuration, credentials: credentials,
            sessionFactory: { _, _, _ in
                if quitDuringSearch { try await Task.sleep(for: .seconds(12)) }
                if searchAuthenticationPreview || quitDuringSearch || connectionPasswordPreview {
                    throw ProtocolError.loginRejected(statusClass: 2, detail: 1)
                }
                // A refused connection, which gets the general network message.
                if searchNetworkPreview { throw NWError.posix(.ECONNREFUSED) }
                // The session factory logs in, so the app reads this as a closed login.
                if closedLoginPreview { throw ProtocolError.connectionClosed }
                throw ProtocolError.invalidState
            },
            extensionCheck: {
                connectionPreview || selectionPreview || settingsFailure || metadataCleanupPreview
                    || quitWithConnectedDisk || forceEjectionPreview || diskStatePreview
                    ? .ready : .disabled
            },
            // Unlocking the Mac that runs the preview never changes it, and neither does the
            // preview becoming active, which a test doesn't control: only Unlock Screen in the
            // Preview menu removes connection information without Check Connections.
            unlockNotifications: screen.notifications,
            activationNotifications: NotificationCenter())
        if selectionPreview || settingsFailure || metadataCleanupPreview {
            await model.load()
            if CommandLine.arguments.contains("--no-server-selection") {
                model.selectedServerID = nil
            }
            return model
        }
        model.document = document
        model.credentialCleanupNeeded = await configuration.cleanupNeeded
        model.selectedServerID = server.id
        model.attached = await coordinator.disks
        model.recoveryComplete = true
        model.extensionState =
            connectionPreview || metadataCleanupPreview || quitWithConnectedDisk
                || forceEjectionPreview || diskStatePreview
            ? .ready : .disabled
        let target = DiscoveredTarget(
            name: dynamicInformation
                ? "iqn.2026-10.example:discovered-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                : "iqn.2026-10.example:available")
        model.targets[server.id] = [target]
        var inquiry = Array(repeating: UInt8(0x20), count: 36)
        inquiry.replaceSubrange(0..<8, with: [0, 0, 6, 2, 31, 0, 0, 0])
        inquiry.replaceSubrange(8..<16, with: "SobaDev ".utf8)
        inquiry.replaceSubrange(16..<32, with: "Archive Disk    ".utf8)
        var capacity = Array(repeating: UInt8(0), count: 8)
        capacity.put(UInt32(8_388_607), at: 0)
        capacity.put(UInt32(512), at: 4)
        let information = DiskInformation(
            device: try SCSIInquiry(data: Data(inquiry)),
            capacity: try DiskCapacity(readCapacity10: Data(capacity)), isWriteProtected: false)
        let protectedInformation = DiskInformation(
            device: information.device, capacity: information.capacity, isWriteProtected: true)
        let results: [Result<DiskInformation, DiskProbeIssue>]
        if protectedPreview {
            results = [.success(protectedInformation), .success(information)]
        } else if diskStatePreview {
            results = [.success(information), .success(protectedInformation), .failure(.notReady)]
        } else if writeCompletionPreview || dynamicInformation {
            results = [.success(information)]
        } else {
            results = [
                .success(information), .failure(.notReady), .failure(.unsupportedDevice(type: 1)),
                .failure(.noMedia), .failure(.accessRestricted), .failure(.invalidInformation),
            ]
        }
        // The server reports its disks in any order; the list shows them by LUN.
        let choices = try results.enumerated().reversed().map {
            FoundDisk(
                targetName: target.name,
                inspection: LogicalUnitInspection(
                    lun: try LogicalUnit(UInt16($0.offset)), result: $0.element),
                connectionAddress: TargetAddress(
                    portal: try Portal(dynamicInformation ? "127.0.0.1:3260" : "192.0.2.24:3261"),
                    portalGroupTag: 1))
        }
        if dynamicInformation {
            pendingDiskInformation = choices
        } else {
            model.choices[model.choiceKey(server, target.name)] = choices
        }
        return model
    }
}

/// The coordinator's clock, which decides when a reconnecting disk is offered Force Eject.
/// By default it stands still at launch, so screenshots and tests never depend on timing.
/// Given how long the disk had been reconnecting, it reads that much earlier while the
/// coordinator first observes the disk, then runs in real time.
private final class PreviewClock: @unchecked Sendable {
    private let lock = NSLock()
    private let startedAgo: Duration?
    private var frozen: ContinuousClock.Instant?
    private var offset = Duration.zero

    init(startedAgo: Duration?) {
        self.startedAgo = startedAgo
        if let startedAgo {
            offset = .zero - startedAgo
        } else {
            frozen = ContinuousClock.now
        }
    }

    var now: ContinuousClock.Instant {
        lock.withLock { frozen ?? ContinuousClock.now.advanced(by: offset) }
    }

    func start() {
        lock.withLock { if startedAgo != nil { offset = .zero } }
    }
}

/// Stands in for the Mac's screen lock. The model hears that the screen was unlocked from
/// here, never from the Mac running the preview. With --metadata-cleanup-while-locked, the
/// screen is locked until Unlock Screen in the Preview menu.
private final class PreviewScreen: @unchecked Sendable {
    private let lock = NSLock()
    private var locked = true
    let notifications = NotificationCenter()
    var isLocked: Bool { lock.withLock { locked } }

    /// Unlocks the screen, then says so, as the system does.
    func unlock() {
        lock.withLock { locked = false }
        notifications.post(name: AppModel.screenUnlockedNotification, object: nil)
    }
}

private final class PreviewSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var document: ProfileDocument
    private var failFirstReload: Bool
    init(_ document: ProfileDocument, failFirstReload: Bool = false) {
        self.document = document
        self.failFirstReload = failFirstReload
    }
    func loadOrCreate() -> ProfileDocument { lock.withLock { document } }
    func load() throws -> ProfileDocument {
        try lock.withLock {
            if failFirstReload {
                failFirstReload = false
                throw POSIXError(.EACCES)
            }
            return document
        }
    }
    func save(_ document: ProfileDocument) { lock.withLock { self.document = document } }
}

private actor PreviewCredentials: CredentialStore {
    private let allowsSaving: Bool
    private var values: [String: CHAPCredentials] = [:]

    /// `saved` are passwords already in the memory store, as if saved earlier.
    init(allowsSaving: Bool, saved: [CredentialContext] = []) {
        self.allowsSaving = allowsSaving
        for context in saved {
            values[context.account] = try? CHAPCredentials(
                username: context.username, password: "preview connection secret")
        }
    }

    func save(password: String, context: CredentialContext) throws {
        guard allowsSaving else { throw POSIXError(.EACCES) }
        values[context.account] = try CHAPCredentials(
            username: context.username, password: password)
    }

    func save(password: String, targetPassword: String, context: CredentialContext) throws {
        guard allowsSaving else { throw POSIXError(.EACCES) }
        values[context.account] = try CHAPCredentials(
            username: context.username, password: password,
            targetUsername: context.targetUsername, targetPassword: targetPassword)
    }

    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        guard let value = values[context.account] else { throw POSIXError(.ENOENT) }
        return value
    }

    func remove(context: CredentialContext) throws {
        guard allowsSaving else { throw POSIXError(.EACCES) }
        values[context.account] = nil
    }
}

private actor PreviewBackend: AttachmentBackend {
    private var observations: [UUID: AttachmentInspection]
    private let failEjection: Bool
    private let allowsReadOnlyConnection: Bool
    private let requiresReadOnlyPolicy: Bool
    private var failMetadataRemovalOnce: Bool
    private let delaysMetadataCleanup: Bool
    private let allowsForceEjection: Bool
    private let uninspectable: Set<UUID>
    private let reconnectsOnForcedInspection: Bool
    /// While this screen is locked, connection information can't be removed.
    private let lockedScreen: PreviewScreen?
    init(
        observations: [UUID: AttachmentInspection], failEjection: Bool = false,
        allowsReadOnlyConnection: Bool = false, requiresReadOnlyPolicy: Bool = false,
        failMetadataRemovalOnce: Bool = false, delaysMetadataCleanup: Bool = false,
        allowsForceEjection: Bool = false, uninspectable: Set<UUID> = [],
        reconnectsOnForcedInspection: Bool = false, lockedScreen: PreviewScreen? = nil
    ) {
        self.observations = observations
        self.failEjection = failEjection
        self.allowsReadOnlyConnection = allowsReadOnlyConnection
        self.requiresReadOnlyPolicy = requiresReadOnlyPolicy
        self.failMetadataRemovalOnce = failMetadataRemovalOnce
        self.delaysMetadataCleanup = delaysMetadataCleanup
        self.allowsForceEjection = allowsForceEjection
        self.uninspectable = uninspectable
        self.reconnectsOnForcedInspection = reconnectsOnForcedInspection
        self.lockedScreen = lockedScreen
    }

    private var lockedCleanupError: MountResourceCleanupError {
        MountResourceCleanupError(
            underlying: NSError(
                domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed)))
    }
    func bridgeURL(for id: UUID) async throws -> URL {
        guard allowsReadOnlyConnection else { throw ProtocolError.invalidState }
        return URL(fileURLWithPath: "/private/tmp/iSCSI-Preview/\(id.uuidString)")
    }
    func untrackedBridges(excluding trackedURLs: [URL]) async throws -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        if requiresReadOnlyPolicy && !descriptor.readOnly {
            throw AttachmentError.writeCompletionUnavailable
        }
        guard allowsReadOnlyConnection, descriptor.readOnly, let id = descriptor.mountID else {
            throw ProtocolError.invalidState
        }
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: nil, connectionState: .connected)
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    {
        guard let id = descriptor.mountID else { throw ProtocolError.invalidState }
        // A stopped extension doesn't answer an ordinary inspection.
        if uninspectable.contains(id), observations[id] != nil {
            throw SystemCommandError.failed(program: "stat", status: 1, detail: "Preview")
        }
        return observations[id] ?? AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws -> AttachmentInspection
    {
        guard let id = descriptor.mountID else { throw ProtocolError.invalidState }
        if reconnectsOnForcedInspection, let observation = observations[id],
            observation.connectionState == .reconnecting
        {
            observations[id] = AttachmentInspection(
                ownership: observation.ownership, attachment: observation.attachment,
                connectionState: .connected)
        }
        return observations[id] ?? AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> DiskAttachment
    {
        guard allowsReadOnlyConnection, descriptor.readOnly, let id = descriptor.mountID else {
            throw ProtocolError.invalidState
        }
        let attachment = DiskAttachment(
            device: "/dev/disk900010",
            volumeURLs: [URL(fileURLWithPath: "/Volumes/Read-only Archive")])
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: attachment, connectionState: .connected)
        return attachment
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        async throws
    {
        guard let id = descriptor.mountID else { throw ProtocolError.invalidState }
        if allowsForceEjection { throw POSIXError(.EBUSY) }
        if failEjection {
            throw SystemCommandError.failed(
                program: "hdiutil", status: 1, detail: "Preview failure")
        }
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: nil, connectionState: .closed)
    }
    func forceEjectionIdentity(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws -> DiskAttachmentIdentity {
        guard allowsForceEjection, let id = descriptor.mountID, observations[id] != nil
        else { throw AttachmentError.recoveryRequired }
        return DiskAttachmentIdentity(
            imageURL: bridgeURL.appendingPathComponent("Disk.img"), device: attachment.device,
            unmountDevices: [attachment.device], mediaIdentifiers: [attachment.device: 41])
    }
    func forceDetachImage(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws {
        guard allowsForceEjection, let id = descriptor.mountID,
            let attachment = observations[id]?.attachment,
            identity
                == (try forceEjectionIdentity(
                    attachment, descriptor: descriptor, bridgeURL: bridgeURL))
        else { throw AttachmentError.recoveryRequired }
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: nil, connectionState: .closed)
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        if let id = descriptor.mountID { observations[id] = nil }
        if failMetadataRemovalOnce || lockedScreen?.isLocked == true {
            failMetadataRemovalOnce = false
            throw lockedCleanupError
        }
        if delaysMetadataCleanup { try await Task.sleep(for: .seconds(3)) }
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        if lockedScreen?.isLocked == true { throw lockedCleanupError }
    }
}
