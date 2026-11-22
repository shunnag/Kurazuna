import AppKit
import ISCSINetwork
import ISCSIPlatform
import SwiftUI

struct MainView: View {
    @Bindable var model: AppModel
    @State private var contentHeight: CGFloat?
    /// The issue whose Edit Server… was chosen. Its editor opens once the alert's sheet has
    /// ended, so that only one sheet is attached to the window at a time.
    @State private var serverEditAfterAlert: AppIssue?

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            VStack(spacing: 0) {
                switch model.notice {
                case .connectionRecovery: recoveryNotice
                case .settingsUnavailable: settingsNotice
                case .extensionSetup: setupNotice
                case .credentialCleanup: credentialCleanupNotice
                case nil: EmptyView()
                }
                if let server = model.selectedServer {
                    serverDetail(server)
                } else if !model.servers.isEmpty {
                    ContentUnavailableView {
                        Label(
                            "Select a Server", systemImage: "externaldrive.connected.to.line.below")
                    } description: {
                        Text("Choose a server in the sidebar to find and connect its disks.")
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ContentUnavailableView {
                        Label("No Servers", systemImage: "externaldrive.badge.wifi")
                    } description: {
                        Text("Add a storage server to find and connect its disks.")
                    } actions: {
                        Button("Add Server…") {
                            model.addServer()
                        }
                        .disabled(!model.canAddServer)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                if model.busy { activityBar }
            }
            .navigationTitle(model.selectedServer?.displayName ?? AppName.display)
            .toolbar {
                // Each item keeps its title for Icon and Text. The symbols show disks on the
                // network and checking again, rather than Search and Reload.
                ToolbarItemGroup(placement: .primaryAction) {
                    if let server = model.selectedServer {
                        Button("Find Disks", systemImage: "externaldrive.badge.wifi") {
                            model.search(server)
                        }
                        .help(Text("Find Disks"))
                        .disabled(model.busy)
                    }
                    Button(
                        "Check Connections",
                        systemImage: "checkmark.arrow.trianglehead.counterclockwise"
                    ) {
                        model.checkConnections()
                    }
                    .help(Text("Check Connections"))
                    .disabled(model.busy)
                }
            }
            .frame(minWidth: 560, minHeight: 420)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .onGeometryChange(for: CGFloat.self) {
            $0.size.height
        } action: {
            contentHeight = $0
        }
        .sheet(isPresented: $model.showingServerEditor) {
            ServerEditor(model: model, server: model.editingServer)
                .environment(\.serverEditorWindowHeight, contentHeight)
        }
        // The recovery action is the default, at the trailing edge or at the top when the
        // buttons are stacked; Cancel is at the other end. Force Eject is never the default.
        .alert(
            model.issue?.title ?? "",
            isPresented: Binding(
                get: { actionIssue != nil },
                set: {
                    if !$0, actionIssue != nil { model.issue = nil }
                }
            )
        ) {
            if model.issue?.recoveryAction == .openDiskUtility {
                Button("Open Disk Utility") {
                    model.issue = nil
                    model.openDiskUtility()
                }.keyboardShortcut(.defaultAction)
                if let id = model.issue?.forceEjectionDiskID {
                    Button("Force Eject…", role: .destructive) {
                        model.issue = nil
                        model.prepareForceEjection(id)
                    }
                }
                Button("Cancel", role: .cancel) { model.issue = nil }
            } else if let issue = model.issue, issue.recoveryAction == .editServer {
                // Dismissing the alert can clear the issue before a button's action runs, so
                // each button keeps the issue it was shown for.
                Button("Edit Server…") {
                    serverEditAfterAlert = issue
                }.keyboardShortcut(.defaultAction)
                Button("Cancel", role: .cancel) { model.issue = nil }
            } else if let action = model.issue?.recoveryAction,
                action == .openSystemSettings || action == .openExtensionSettings
            {
                Button("Open System Settings") {
                    model.issue = nil
                    if action == .openExtensionSettings {
                        model.openExtensionSettings()
                    } else {
                        model.openSystemSettings()
                    }
                }.keyboardShortcut(.defaultAction)
                Button("Cancel", role: .cancel) { model.issue = nil }
            }
        } message: {
            Text(model.issue?.message ?? "")
        }
        .background {
            // Errors without a recovery action, including a disk in use that can be force
            // ejected, use a native alert whose safe response is the trailing default.
            ErrorAcknowledgement(
                issue: acknowledgementIssue,
                dismiss: { id in
                    if model.issue?.id == id { model.issue = nil }
                },
                forceEject: { id, diskID in
                    guard model.issue?.id == id else { return }
                    model.issue = nil
                    model.prepareForceEjection(diskID)
                }
            )
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            ReadOnlyConnectionConfirmation(
                request: model.issue?.readOnlyConnectionRequest,
                title: model.issue?.title ?? "", message: model.issue?.message ?? "",
                confirm: { model.confirmReadOnlyConnection($0) },
                cancel: { model.cancelReadOnlyConnection($0) }
            )
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            ServerRemovalConfirmation(
                request: model.serverRemovalRequest,
                confirm: { model.confirmServerRemoval($0) },
                cancel: { model.cancelServerRemoval($0) }
            )
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            ForceEjectionConfirmation(
                request: model.busy ? nil : model.forceEjectionRequest,
                name: model.forceEjectionRequest.map { model.forceEjectionName($0) } ?? "",
                message: model.forceEjectionRequest.map { model.forceEjectionMessage($0) } ?? "",
                confirm: { model.forceEject($0) },
                cancel: { model.dismissForceEjection($0) }
            )
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            // The alert's explicit default button takes Return; keep Escape on Cancel.
            ConfirmationEscapeHandler(isPresented: actionIssue != nil) {
                if let issue = actionIssue, model.issue?.id == issue.id { model.issue = nil }
            }
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
        }
        // Like the force ejection confirmation, the editor waits until the alert that offered
        // it has ended, so the window never begins a sheet while another is ending. If another
        // sheet is already up by then, the editor isn't opened at all.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didEndSheetNotification)) {
            notification in
            guard let issue = serverEditAfterAlert else { return }
            serverEditAfterAlert = nil
            if (notification.object as? NSWindow)?.attachedSheet == nil {
                model.editServer(for: issue)
            }
        }
        .onReceive(
            NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
        ) { _ in
            Task {
                await model.refreshExtension()
                await model.refreshConnectionHealth()
            }
        }
        // Connection information left while the Mac was locked is removed once it's unlocked.
        // The model keeps this going after the window closes.
        .onAppear { model.startRetryingLockedCleanup() }
    }

    private var sidebar: some View {
        List(selection: $model.selectedServerID) {
            Section("Servers") {
                ForEach(model.servers) { server in
                    Label(
                        server.displayName, systemImage: "externaldrive.connected.to.line.below"
                    )
                    .badge(connectedCount(server))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                    .tag(server.id)
                }
            }
        }
        .contextMenu(forSelectionType: UUID.self) { ids in
            if let server = server(in: ids) {
                Button("Edit Server…") {
                    model.editServer(server)
                }.disabled(!model.canEditServer(server))
                Button("Remove Server…", role: .destructive) {
                    model.removeServer(server)
                }.disabled(!model.canEditServer(server))
            }
        } primaryAction: { ids in
            // Return and double-click edit the server, like other macOS source lists.
            if let server = server(in: ids), model.canEditServer(server) {
                model.editServer(server)
            }
        }
        .onDeleteCommand {
            if let server = model.selectedServer, model.canEditServer(server) {
                model.removeServer(server)
            }
        }
        .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 320)
        .toolbar {
            ToolbarItem {
                Button("Add Server", systemImage: "plus") {
                    model.addServer()
                }
                .help(Text("Add Server"))
                .disabled(!model.canAddServer)
            }
        }
    }

    private func connectedCount(_ server: ServerProfile) -> Int {
        model.attached.filter { $0.descriptor.profileID == server.id }.count
    }

    /// The activity and its Cancel button, in a bar along the bottom of the window.
    private var activityBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    if model.waitingForLocalNetworkAccess && model.canCancel {
                        Text("Waiting for Local Network Access…").foregroundStyle(.secondary)
                    } else {
                        Text(model.activity).foregroundStyle(.secondary)
                    }
                }
                // VoiceOver reads the activity as the progress indicator's label.
                .accessibilityElement(children: .combine)
                Spacer()
                if model.canCancel {
                    if model.waitingForLocalNetworkAccess {
                        Button("Open System Settings") { model.openSystemSettings() }
                    }
                    Button("Cancel") { model.cancel() }
                }
            }
            if model.waitingForLocalNetworkAccess && model.canCancel {
                Text(AppPermissionGuidance().localNetworkMessage)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .controlSize(.small)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    /// An issue shown in the alert with a recovery action and a Cancel button.
    private var actionIssue: AppIssue? {
        guard let issue = model.issue, issue.readOnlyConnectionRequest == nil,
            issue.recoveryAction != nil
        else { return nil }
        return issue
    }

    private var acknowledgementIssue: AppIssue? {
        guard let issue = model.issue, issue.readOnlyConnectionRequest == nil,
            issue.recoveryAction == nil
        else { return nil }
        return issue
    }

    private var setupNotice: some View {
        NoticeBanner(
            title: model.extensionState.noticeTitle,
            message: model.extensionState.noticeMessage,
            systemImage: model.extensionState == .disabled
                ? "puzzlepiece.extension.fill" : "exclamationmark.triangle.fill",
            tone: model.extensionState == .disabled ? .information : .warning
        ) {
            if model.isCheckingExtension {
                ProgressView().controlSize(.small)
                    .accessibilityLabel("Checking File System Extension")
            }
            Button("Check Again") { Task { await model.refreshExtension() } }
                .disabled(model.isCheckingExtension)
            if model.extensionState == .disabled {
                Button("Open System Settings") { model.openExtensionSettings() }
            }
        }
    }

    private var settingsNotice: some View {
        NoticeBanner(
            title: String(localized: "Server Settings Are Unavailable"),
            message: String(
                localized: "Click Check Connections to read your server settings again."),
            systemImage: "exclamationmark.triangle.fill"
        ) {
            Button("Check Connections") { model.checkConnections() }
        }
    }

    private var credentialCleanupNotice: some View {
        NoticeBanner(
            title: String(localized: "Saved Passwords Need Attention"),
            message: model.credentialCleanupNeedsEject
                ? String(
                    localized:
                        "To finish removing saved passwords, eject the disks using them, then try again."
                )
                : String(
                    localized:
                        "Some changes to saved passwords couldn’t be completed. Unlock your Mac and try again."
                ),
            systemImage: "key.fill"
        ) {
            Button("Try Again") { model.retryCredentialCleanup() }
                .disabled(
                    model.busy || model.document == nil || model.connectionStatusNeedsAttention
                        || model.credentialCleanupNeedsEject)
        }
    }

    private var recoveryNotice: some View {
        let notice = model.connectionRecoveryNotice
        return NoticeBanner(
            title: notice.title, message: notice.message,
            systemImage: notice.showsDiskUtility
                ? "exclamationmark.triangle.fill" : "info.circle.fill",
            tone: notice.showsDiskUtility ? .warning : .information
        ) {
            if notice.showsDiskUtility {
                Button("Open Disk Utility") { model.openDiskUtility() }
            }
            Button(notice.actionTitle) { model.checkConnections() }
        } details: {
            if !model.untrackedBridgeURLs.isEmpty {
                DisclosureGroup("Unverified Connections") {
                    ForEach(model.untrackedBridgeURLs, id: \.path) { url in
                        Text(url.path).font(.callout.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .font(.callout)
                .padding(.top, 4)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("connection-recovery-notice")
    }

    private func server(in ids: Set<UUID>) -> ServerProfile? {
        guard ids.count == 1, let id = ids.first else { return nil }
        return model.servers.first { $0.id == id }
    }

    private func serverDetail(_ server: ServerProfile) -> some View {
        let connected = model.connectedDisks(on: server)
        let targets = model.availableTargets(on: server)
        return Form {
            Section {
                LabeledContent("Server Address") {
                    Text(server.portal.description).textSelection(.enabled)
                }
            }
            if !connected.isEmpty {
                Section(
                    connected.contains(where: { $0.resourceCleanupError != nil })
                        ? String(localized: "Connections") : String(localized: "Connected Disks")
                ) {
                    ForEach(connected) { disk in
                        ConnectedDiskRow(model: model, disk: disk)
                    }
                }
            }
            if let targets, !targets.isEmpty {
                ForEach(targets) { target in
                    Section {
                        targetRows(target, server: server)
                    } header: {
                        if target.id == targets.first?.id { Text("Available Disks") }
                    } footer: {
                        if target.id == targets.last?.id { availableDisksFooter }
                    }
                }
            } else {
                Section {
                    if targets == nil {
                        // Like the Add Server… button of the empty window, the text names a
                        // button right beside it, not only the toolbar's unlabeled symbol.
                        HStack(spacing: 12) {
                            Text("Click Find Disks to see the disks available on this server.")
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Button("Find Disks") { model.search(server) }
                                .disabled(model.busy)
                                .accessibilityIdentifier("find-disks-placeholder")
                        }
                    } else {
                        Text("No disks were found on this server.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } header: {
                    Text("Available Disks")
                } footer: {
                    availableDisksFooter
                }
            }
        }
        .formStyle(.grouped)
    }

    private var availableDisksFooter: some View {
        Text(
            "Use a disk with one computer at a time. Eject it before connecting it to another computer."
        )
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private func targetRows(_ target: DiscoveredTarget, server: ServerProfile)
        -> some View
    {
        let disks = model.availableDisks(target, on: server)
        TargetRow(model: model, target: target, server: server, viewed: disks != nil)
        if let disks {
            if disks.isEmpty {
                Text("No disks are available.")
            }
            ForEach(disks) { disk in
                FoundDiskRow(model: model, disk: disk, target: target, server: server)
            }
        }
    }
}
