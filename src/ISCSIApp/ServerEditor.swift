import AppKit
import ISCSICore
import ISCSIPlatform
import SwiftUI

struct ServerEditor: View {
    @Bindable var model: AppModel
    let server: ServerProfile?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.serverEditorHeightLimit) private var heightLimit
    @Environment(\.serverEditorWindowHeight) private var windowHeight
    @State private var screenHeight = NSScreen.main?.visibleFrame.height ?? 720
    @State private var name = ""
    @State private var address = ""
    @State private var authentication = 0
    @State private var username = ""
    @State private var password = ""
    @State private var targetUsername = ""
    @State private var targetPassword = ""
    @State private var discoveryMode = FindingDisksAuthenticationChoice(nil).rawValue
    @State private var discoveryUsername = ""
    @State private var discoveryPassword = ""
    @State private var discoveryTargetUsername = ""
    @State private var discoveryTargetPassword = ""
    @State private var saving = false
    @State private var problem: AppIssue?
    @State private var profileID = UUID()
    @State private var fieldsHeight: CGFloat = 0
    @State private var headingHeight: CGFloat = 0
    @State private var actionsHeight: CGFloat = 0
    private var useCHAP: Bool { authentication != 0 }
    private var useMutualCHAP: Bool { authentication == 2 }

    private var parsedPortal: Portal? {
        try? Portal(address.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private var canKeepPassword: Bool {
        guard let server, let portal = parsedPortal, let old = server.credentialContext else {
            return false
        }
        return old.account
            == CredentialContext(
                profileID: server.id, portal: portal, username: username,
                credentialID: server.credentialID,
                targetUsername: useMutualCHAP ? targetUsername : nil
            ).account
    }

    private var canKeepDiscoveryPassword: Bool {
        guard let server, let portal = parsedPortal,
            case .chap(let identity) = server.discoveryAuthentication
        else { return false }
        return identity.context(profileID: server.id, portal: server.portal, use: .discovery)
            .account
            == CredentialContext(
                profileID: server.id, portal: portal, username: discoveryUsername,
                credentialID: identity.credentialID,
                targetUsername: discoveryMode == 3 ? discoveryTargetUsername : nil, use: .discovery
            ).account
    }

    private func proposedDiscovery() throws -> DiscoveryAuthentication {
        switch discoveryMode {
        case 0: .sameAsConnection
        case 1: .none
        default:
            .chap(
                try CHAPIdentity(
                    username: discoveryUsername,
                    targetUsername: discoveryMode == 3 ? discoveryTargetUsername : nil))
        }
    }

    private func credentialsValid(
        mode: Int, username: String, password: String,
        targetUsername: String, targetPassword: String, canKeep: Bool
    ) -> Bool {
        if mode == 0 { return true }
        if mode == 2 {
            if password.isEmpty && targetPassword.isEmpty { return canKeep }
            return password.count >= 12 && targetPassword.count >= 12
                && (try? CHAPCredentials(
                    username: username, password: password,
                    targetUsername: targetUsername, targetPassword: targetPassword)) != nil
        }
        return password.isEmpty
            ? canKeep
            : password.count >= 12
                && (try? CHAPCredentials(username: username, password: password)) != nil
    }

    private var valid: Bool {
        guard let portal = parsedPortal,
            let discovery = try? proposedDiscovery(),
            (try? ServerProfile(
                id: profileID, name: name, portal: portal,
                chapUsername: useCHAP ? username : nil,
                targetCHAPUsername: useMutualCHAP ? targetUsername : nil,
                discoveryAuthentication: discovery)) != nil
        else { return false }
        return credentialsValid(
            mode: authentication, username: username, password: password,
            targetUsername: targetUsername, targetPassword: targetPassword, canKeep: canKeepPassword
        )
            && credentialsValid(
                mode: max(0, discoveryMode - 1), username: discoveryUsername,
                password: discoveryPassword, targetUsername: discoveryTargetUsername,
                targetPassword: discoveryTargetPassword, canKeep: canKeepDiscoveryPassword)
    }

    /// Where passwords are kept and, for a saved password, how to keep it. A mutual CHAP pair
    /// is saved together, so changing either of its passwords needs both.
    private var passwordNote: String {
        let keepsConnection = useCHAP && canKeepPassword
        let keepsDiscovery = discoveryMode >= 2 && canKeepDiscoveryPassword
        if (keepsConnection && useMutualCHAP) || (keepsDiscovery && discoveryMode == 3) {
            return String(
                localized:
                    "Your passwords are stored in your keychain. To keep a saved password, leave its field blank. To change a mutual CHAP password, enter both."
            )
        }
        if keepsConnection || keepsDiscovery {
            return String(
                localized:
                    "Your passwords are stored in your keychain. To keep a saved password, leave its field blank."
            )
        }
        return String(localized: "Your passwords are stored in your keychain.")
    }

    private var maximumHeight: CGFloat {
        min(
            heightLimit ?? .infinity, windowHeight.map { $0 - 8 } ?? .infinity,
            max(1, screenHeight - 24))
    }

    /// The fields keep their natural height unless the window, the screen, or an explicit
    /// limit is too short for the whole sheet. Only then does the area between the title and
    /// the buttons scroll, so the buttons always stay visible.
    private var fieldsFrameHeight: CGFloat? {
        guard fieldsHeight > 0 else { return nil }
        let chrome = headingHeight + actionsHeight + 2 * Self.spacing + 2 * Self.verticalPadding
        return min(fieldsHeight, max(120, (maximumHeight - chrome).rounded(.down)))
    }

    // The grouped form adds its own margins above and below its sections.
    private static let spacing: CGFloat = 4
    private static let verticalPadding: CGFloat = 16

    var body: some View {
        VStack(alignment: .leading, spacing: Self.spacing) {
            heading.padding(.horizontal, 20)
                .onGeometryChange(for: CGFloat.self) {
                    $0.size.height
                } action: {
                    headingHeight = $0
                }
            ScrollView {
                fields
                    .onGeometryChange(for: CGFloat.self) {
                        $0.size.height
                    } action: {
                        fieldsHeight = $0
                    }
            }
            .scrollBounceBehavior(.basedOnSize)
            .frame(height: fieldsFrameHeight)
            .accessibilityIdentifier("server-editor-fields")
            actions.padding(.horizontal, 20)
                .onGeometryChange(for: CGFloat.self) {
                    $0.size.height
                } action: {
                    actionsHeight = $0
                }
        }
        // Wide enough that the closing notes wrap to few lines in English and Japanese.
        .padding(.vertical, Self.verticalPadding).frame(width: 500)
        .onAppear {
            updateScreenHeight()
            if let server { profileID = server.id }
            name = server?.name ?? ""
            address = server?.portal.description ?? ""
            username = server?.chapUsername ?? ""
            targetUsername = server?.targetCHAPUsername ?? ""
            authentication =
                server?.targetCHAPUsername != nil ? 2 : server?.chapUsername != nil ? 1 : 0
            discoveryMode =
                FindingDisksAuthenticationChoice(server?.discoveryAuthentication).rawValue
            if case .chap(let identity) = server?.discoveryAuthentication {
                discoveryUsername = identity.username
                discoveryTargetUsername = identity.targetUsername ?? ""
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didChangeScreenNotification))
        {
            _ in updateScreenHeight()
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: NSApplication.didChangeScreenParametersNotification)
        ) {
            _ in updateScreenHeight()
        }
        .interactiveDismissDisabled(saving)
    }

    private func updateScreenHeight() {
        screenHeight = (NSApp.keyWindow?.screen ?? NSScreen.main)?.visibleFrame.height ?? 720
    }

    private var heading: some View {
        Text(
            server == nil
                ? String(localized: "Add Server")
                : String(localized: "Edit Server")
        )
        .font(.headline)
        .accessibilityAddTraits(.isHeader)
    }

    private var fields: some View {
        VStack(alignment: .leading, spacing: 4) {
            // The outer view decides whether the sheet scrolls; the form keeps its content size.
            Form {
                Section {
                    // A grouped form shows each title as a separate label, which the text
                    // field does not expose as its name. Give each field its name directly.
                    TextField("Name", text: $name)
                        .accessibilityLabel("Name")
                    TextField(
                        "Server Address", text: $address, prompt: Text(verbatim: "nas.local:3260")
                    )
                    .autocorrectionDisabled()
                    .accessibilityLabel("Server Address")
                }
                Section {
                    Picker("Authentication", selection: $authentication) {
                        Text("None").tag(0)
                        Text("CHAP").tag(1)
                        Text("Mutual CHAP").tag(2)
                    }
                    .accessibilityLabel("Connection Authentication")
                    .accessibilityInputLabels([
                        Text("Authentication"), Text("Connection Authentication"),
                    ])
                    if useCHAP {
                        AuthenticationFields(
                            username: $username, password: $password,
                            targetUsername: $targetUsername, targetPassword: $targetPassword,
                            context: .connection, mutual: useMutualCHAP,
                            canKeep: canKeepPassword)
                    }
                } header: {
                    Text("Connection")
                }
                Section {
                    Picker("Authentication", selection: $discoveryMode) {
                        Text("Same as Connection").tag(0)
                        Text("None").tag(1)
                        Text("CHAP").tag(2)
                        Text("Mutual CHAP").tag(3)
                    }
                    .accessibilityLabel("Authentication for Finding Disks")
                    .accessibilityInputLabels([
                        Text("Authentication"), Text("Authentication for Finding Disks"),
                    ])
                    if discoveryMode >= 2 {
                        AuthenticationFields(
                            username: $discoveryUsername, password: $discoveryPassword,
                            targetUsername: $discoveryTargetUsername,
                            targetPassword: $discoveryTargetPassword,
                            context: .findingDisks, mutual: discoveryMode == 3,
                            canKeep: canKeepDiscoveryPassword)
                    }
                } header: {
                    Text("Finding Disks")
                } footer: {
                    // Notes that apply to every password in the form come once, at its end,
                    // so that editing a server with saved passwords needs no more room.
                    if discoveryMode >= 2 || useCHAP {
                        VStack(alignment: .leading, spacing: 4) {
                            if useMutualCHAP || discoveryMode == 3 {
                                Text("Use different passwords for your Mac and the server.")
                            }
                            Text(passwordNote)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .formStyle(.grouped)
            // The sheet provides the background, so the form matches it in Dark Mode too.
            .scrollContentBackground(.hidden)
            .scrollDisabled(true)
            .fixedSize(horizontal: false, vertical: true)
            .disabled(saving)
            if let problem {
                Label {
                    Text(problem.message).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                }
                .font(.callout)
                .padding(.horizontal, 20)
            }
        }
    }

    private var actions: some View {
        HStack {
            if saving {
                ProgressView().controlSize(.small)
                    .accessibilityLabel(Text("Saving server…"))
            }
            Spacer()
            Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(saving)
            Button(server == nil ? String(localized: "Add") : String(localized: "Save")) {
                saving = true
                Task {
                    do {
                        try await model.saveServer(
                            id: profileID, name: name, address: address,
                            username: useCHAP ? username : nil,
                            password: password,
                            targetUsername: useMutualCHAP ? targetUsername : nil,
                            targetPassword: useMutualCHAP ? targetPassword : "",
                            discoveryAuthentication: proposedDiscovery(),
                            discoveryPassword: discoveryMode >= 2 ? discoveryPassword : "",
                            discoveryTargetPassword: discoveryMode == 3
                                ? discoveryTargetPassword : "")
                        dismiss()
                    } catch {
                        problem = AppIssue(error)
                        saving = false
                    }
                }
            }.keyboardShortcut(.defaultAction).disabled(!valid || saving)
        }
    }
}

private struct ServerEditorHeightLimitKey: EnvironmentKey {
    static let defaultValue: CGFloat? = nil
}

private struct ServerEditorWindowHeightKey: EnvironmentKey {
    static let defaultValue: CGFloat? = nil
}

extension EnvironmentValues {
    var serverEditorHeightLimit: CGFloat? {
        get { self[ServerEditorHeightLimitKey.self] }
        set { self[ServerEditorHeightLimitKey.self] = newValue }
    }

    /// The height of the presenting window's content, below its toolbar. The editor stays
    /// within it, like any sheet, and scrolls its fields only when they don't fit.
    var serverEditorWindowHeight: CGFloat? {
        get { self[ServerEditorWindowHeightKey.self] }
        set { self[ServerEditorWindowHeightKey.self] = newValue }
    }
}

private enum AuthenticationContext {
    case connection, findingDisks

    var userNameLabel: String {
        switch self {
        case .connection: String(localized: "Connection User Name")
        case .findingDisks: String(localized: "User Name for Finding Disks")
        }
    }

    var passwordLabel: String {
        switch self {
        case .connection: String(localized: "Connection Password")
        case .findingDisks: String(localized: "Password for Finding Disks")
        }
    }

    var serverUserNameLabel: String {
        switch self {
        case .connection: String(localized: "Connection Server User Name")
        case .findingDisks: String(localized: "Server User Name for Finding Disks")
        }
    }

    var serverPasswordLabel: String {
        switch self {
        case .connection: String(localized: "Connection Server Password")
        case .findingDisks: String(localized: "Server Password for Finding Disks")
        }
    }
}

private struct AuthenticationFields: View {
    @Binding var username: String
    @Binding var password: String
    @Binding var targetUsername: String
    @Binding var targetPassword: String
    let context: AuthenticationContext
    let mutual: Bool
    let canKeep: Bool

    private var passwordPrompt: String {
        canKeep ? String(localized: "Saved password") : String(localized: "At least 12 characters")
    }

    var body: some View {
        TextField("User Name", text: $username).autocorrectionDisabled()
            .accessibilityLabel(Text(context.userNameLabel))
            .accessibilityInputLabels([Text("User Name"), Text(context.userNameLabel)])
        SecureField("Password", text: $password, prompt: Text(passwordPrompt))
            .accessibilityLabel(Text(context.passwordLabel))
            .accessibilityInputLabels([Text("Password"), Text(context.passwordLabel)])
        if mutual {
            TextField("Server User Name", text: $targetUsername).autocorrectionDisabled()
                .accessibilityLabel(Text(context.serverUserNameLabel))
                .accessibilityInputLabels([
                    Text("Server User Name"), Text(context.serverUserNameLabel),
                ])
            SecureField("Server Password", text: $targetPassword, prompt: Text(passwordPrompt))
                .accessibilityLabel(Text(context.serverPasswordLabel))
                .accessibilityInputLabels([
                    Text("Server Password"), Text(context.serverPasswordLabel),
                ])
        }
    }
}
