import AppKit
@preconcurrency import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Observation
import Security

struct FoundDisk: Identifiable, Sendable, Equatable {
    let targetName: String
    let inspection: LogicalUnitInspection
    var connectionAddress: TargetAddress? = nil
    var lun: LogicalUnit { inspection.lun }
    var information: DiskInformation? { try? inspection.result.get() }
    var isWriteProtected: Bool { information?.isWriteProtected == true }
    var id: String { "\(targetName)|\(lun.addressKey)" }
}

extension DiscoveredTarget {
    /// A short name for lists: the part of an IQN after its last colon, if any.
    /// Other names, such as EUI or NAA designators, are shown unchanged.
    static func friendlyName(for name: String) -> String {
        guard name.lowercased().hasPrefix("iqn."), let colon = name.lastIndex(of: ":") else {
            return name
        }
        let suffix = name[name.index(after: colon)...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return suffix.isEmpty ? name : suffix
    }

    var friendlyName: String { Self.friendlyName(for: name) }
}

extension DiskProbeIssue {
    var userMessage: String {
        switch self {
        case .unavailable:
            String(localized: "This disk is unavailable. Check the server, then try again.")
        case .unsupportedDevice:
            String(localized: "Kurazuna doesn’t support this type of storage device.")
        case .notReady:
            String(
                localized:
                    "This disk isn’t ready. Check its status on the server, then try again.")
        case .noMedia:
            String(localized: "No media is available in this device.")
        case .accessRestricted:
            String(
                localized:
                    "Access to this disk is restricted. Check the server’s access settings, then try again."
            )
        case .invalidInformation, .commandFailed:
            String(localized: "Disk information couldn’t be read. Try again.")
        }
    }
}

extension AttachedDisk {
    /// A disk with a mounted volume is called by the volume's name. Any other disk is
    /// called by its LUN, as under Available Disks, with its target on the line below.
    /// `AppModel.name(of:)` adds the target when another disk would have the same name.
    var displayName: String {
        attachment?.volumeURLs.first?.lastPathComponent
            ?? String(localized: "Disk \(descriptor.lun.displayIdentifier)")
    }

    var hasNoMountedVolumes: Bool {
        guard !needsCleanup, connectionState == .connected, let attachment else { return false }
        return attachment.volumeURLs.isEmpty
    }
}

struct ServerRemovalRequest: Identifiable, Sendable, Equatable {
    let id = UUID()
    let server: ServerProfile
}

/// A single disk and the settings that were current when a writable attempt failed.
struct ReadOnlyConnectionRequest: Identifiable, Sendable, Equatable {
    let id = UUID()
    let server: ServerProfile
    let disk: FoundDisk
    let identity: InitiatorIdentity
}

private enum ReadOnlyConnectionError: Error { case contextChanged }

/// The server accepted the connection, then closed it before the login finished. A server
/// may do this instead of refusing the login, for example Linux LIO when it requires CHAP and
/// is offered no authentication. Whether the server answered any part of the login first
/// isn't known here, so the alert says only that it closed the connection.
struct LoginClosedByServer: Error, LocalizedError {
    var errorDescription: String? { ProtocolError.connectionClosed.errorDescription }
}

/// A forced release that no longer applies: the disk is connected to its server again.
private struct ForcedReleaseWithdrawn: Error {}

/// The banners above the server detail, most severe first. Only one is shown at a time.
enum AppNotice: Equatable, Sendable {
    case connectionRecovery, settingsUnavailable, extensionSetup, credentialCleanup
}

struct ConnectionRecoveryNotice {
    let title: String
    let message: String
    let actionTitle: String
    let showsDiskUtility: Bool
}

/// The quit confirmation's text while the connection status needs attention.
struct QuitWarning: Equatable, Sendable {
    let title: String
    let message: String
}

/// What prompts another try at removing connection information left while the Mac was locked.
enum LockedCleanupRetryEvent: Sendable, CaseIterable {
    case screenUnlocked, applicationActivated
}

/// The choices in the server editor's Finding Disks pop-up menu, in menu order.
enum FindingDisksAuthenticationChoice: Int, CaseIterable, Sendable {
    case sameAsConnection, none, chap, mutualCHAP

    /// A saved server keeps its choice. A new server finds disks without a password: a Mac
    /// that sends a user name and password offers only CHAP, so a server that doesn't use
    /// them to find disks, as is common when only its disks are protected, would refuse
    /// every search if Finding Disks were the same as Connection.
    init(_ authentication: DiscoveryAuthentication?) {
        switch authentication {
        case .some(.sameAsConnection): self = .sameAsConnection
        case .some(.none), nil: self = .none
        case .some(.chap(let identity)):
            self = identity.targetUsername == nil ? .chap : .mutualCHAP
        }
    }
}

struct AppIssue: Identifiable {
    enum Context: Sendable {
        case general
        /// Finding disks on this server, with the authentication it was set to use. A server
        /// with connected disks can't be edited until they're ejected.
        case findingDisks(ServerProfile, disksConnected: Bool = false)
        /// Reading a target's disks on this server, which logs in with the authentication
        /// under Connection. Only a login the server closed has its own message here.
        case viewingDisks(ServerProfile, disksConnected: Bool = false)
        case connectingDisk
        case ejectingDisk(
            String, connectionState: DiskConnectionState = .unknown, id: UUID? = nil)
    }
    enum RecoveryAction: Equatable {
        case openDiskUtility, openSystemSettings, openExtensionSettings
        /// Edit the server in `AppIssue.serverID`, whose settings need to change.
        case editServer
    }
    /// The user name and password that finding disks sent to the server, if any.
    enum FindingDisksCredentials: Sendable, Equatable {
        case none, connection, findingDisks

        init(_ server: ServerProfile) {
            switch server.discoveryAuthentication {
            case .none: self = .none
            case .sameAsConnection: self = server.chapUsername == nil ? .none : .connection
            case .chap: self = .findingDisks
            }
        }
    }
    let id = UUID()
    let title: String
    let message: String
    let detail: String
    var recoveryAction: RecoveryAction?
    var forceEjectionDiskID: UUID?
    /// The server that `RecoveryAction.editServer` opens.
    var serverID: UUID?
    let readOnlyConnectionRequest: ReadOnlyConnectionRequest?
    /// The issue says that a disconnected disk's connection information couldn't be removed.
    let reportsResourceCleanup: Bool

    private static func isRedirectFailure(_ error: any Error) -> Bool {
        switch error {
        case ProtocolError.loginRedirect,
            ProtocolError.malformed("redirect TargetAddress"),
            ProtocolError.malformed("redirect TargetAddress portal group"),
            ProtocolError.malformed("TargetAddress"),
            ProtocolError.malformed("server address"),
            ProtocolError.malformed("discovery portal group"),
            ProtocolError.malformed("conflicting target portal group"),
            ProtocolError.malformed("target portal group"):
            true
        case ProtocolError.limitExceeded(let field):
            field.hasPrefix("login redirect") || field == "login connection attempts"
                || field == "discovery addresses"
        default: false
        }
    }

    private static func isExtensionLaunchFailure(_ error: any Error) -> Bool {
        guard case SystemCommandError.failed(let program, let status, let diagnostic) = error,
            program == "mount", status == 69
        else { return false }
        // Match the observed NSError domain and code, rather than the localized
        // description or EX_UNAVAILABLE alone. Other mount failures need their own guidance.
        return diagnostic.contains("(com.apple.extensionKit.errorDomain error 2.)")
            || diagnostic.range(
                of: #"\bError Domain=com\.apple\.extensionKit\.errorDomain Code=2(?:\s|$)"#,
                options: .regularExpression) != nil
    }

    /// What to change when the server refused how finding disks authenticated, or nil for
    /// any other error. It names the section whose user name and password were sent. A
    /// server may refuse a password because it doesn't use one to find disks, so a refusal
    /// also offers a different method rather than only the password. A server with connected
    /// disks can't be edited, so its message says to eject them first.
    ///
    /// A server that closed the connection during the login may require a user name and
    /// password, or the address may not be its iSCSI service. The message says only what
    /// happened and what to check, without claiming the cause.
    private static func findingDisksAuthenticationMessage(
        _ error: any Error, credentials: FindingDisksCredentials, disksConnected: Bool
    ) -> String? {
        if error is LoginClosedByServer {
            switch (credentials, disksConnected) {
            case (.none, false):
                return String(
                    localized:
                        "The server closed the connection. If it requires a user name and password to find disks, edit this server and choose an authentication method under Finding Disks, then try again."
                )
            case (.none, true):
                return String(
                    localized:
                        "The server closed the connection. If it requires a user name and password to find disks, eject this server’s disks, then edit the server and choose an authentication method under Finding Disks."
                )
            case (.connection, false):
                return String(
                    localized:
                        "The server closed the connection. Edit this server and check the server address and the user name and password under Connection, then try again."
                )
            case (.connection, true):
                return String(
                    localized:
                        "The server closed the connection. To check the server address and the user name and password under Connection, eject this server’s disks, then edit the server."
                )
            case (.findingDisks, false):
                return String(
                    localized:
                        "The server closed the connection. Edit this server and check the server address and the user name and password under Finding Disks, then try again."
                )
            case (.findingDisks, true):
                return String(
                    localized:
                        "The server closed the connection. To check the server address and the user name and password under Finding Disks, eject this server’s disks, then edit the server."
                )
            }
        }
        guard let error = error as? ProtocolError else { return nil }
        switch (error, credentials) {
        case (.loginRejected(statusClass: 2, detail: 1), .none),
            (.unsupported("authentication required"), _):
            return disksConnected
                ? String(
                    localized:
                        "This server requires a user name and password to find disks. To choose an authentication method under Finding Disks, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "This server requires a user name and password to find disks. Edit this server and choose an authentication method under Finding Disks, then try again."
                )
        case (.loginRejected(statusClass: 2, detail: 1), .connection):
            return disksConnected
                ? String(
                    localized:
                        "The server didn’t accept the user name and password under Connection. To check them, or to choose a different authentication method under Finding Disks, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "The server didn’t accept the user name and password under Connection. Edit this server and check them, or choose a different authentication method under Finding Disks, then try again."
                )
        case (.loginRejected(statusClass: 2, detail: 1), .findingDisks):
            return disksConnected
                ? String(
                    localized:
                        "The server didn’t accept the user name and password under Finding Disks. To check them, or to choose a different authentication method, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "The server didn’t accept the user name and password under Finding Disks. Edit this server and check them, or choose a different authentication method, then try again."
                )
        case (.authenticationFailed, .connection):
            return disksConnected
                ? String(
                    localized:
                        "The server user name and password under Connection don’t match the server. To check them, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "The server user name and password under Connection don’t match the server. Edit this server and check them, then try again."
                )
        case (.authenticationFailed, .findingDisks):
            return disksConnected
                ? String(
                    localized:
                        "The server user name and password under Finding Disks don’t match the server. To check them, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "The server user name and password under Finding Disks don’t match the server. Edit this server and check them, then try again."
                )
        // A server that doesn't use CHAP to find disks answers a CHAP offer with another
        // method, or moves on without choosing one.
        case (.unsupported("authentication method"), .connection),
            (.unsupported("authentication method"), .findingDisks),
            (.malformed("CHAP selection"), .connection),
            (.malformed("CHAP selection"), .findingDisks):
            return disksConnected
                ? String(
                    localized:
                        "This server doesn’t use a user name and password to find disks. To choose None for authentication under Finding Disks, eject this server’s disks, then edit the server."
                )
                : String(
                    localized:
                        "This server doesn’t use a user name and password to find disks. Edit this server and choose None for authentication under Finding Disks, then try again."
                )
        default:
            return nil
        }
    }

    /// What to check when the server closed the connection during the login that reads a
    /// target's disks. That login uses the authentication under Connection. It goes to the
    /// address that finding disks reported, not to the server address that the editor shows,
    /// so the message doesn't ask to check that address.
    private static func viewingDisksClosedMessage(credentialsSent: Bool, disksConnected: Bool)
        -> String
    {
        switch (credentialsSent, disksConnected) {
        case (false, false):
            String(
                localized:
                    "The server closed the connection. If it requires a user name and password to connect to its disks, edit this server and choose an authentication method under Connection, then try again."
            )
        case (false, true):
            String(
                localized:
                    "The server closed the connection. If it requires a user name and password to connect to its disks, eject this server’s disks, then edit the server and choose an authentication method under Connection."
            )
        case (true, false):
            String(
                localized:
                    "The server closed the connection. Edit this server and check the user name and password under Connection, then try again."
            )
        case (true, true):
            String(
                localized:
                    "The server closed the connection. To check the user name and password under Connection, eject this server’s disks, then edit the server."
            )
        }
    }

    init(
        _ error: any Error, context: Context = .general,
        readOnlyConnectionRequest: ReadOnlyConnectionRequest? = nil
    ) {
        switch error {
        case AttachmentError.readOnlyGeometryRequired, AttachmentError.writeCompletionUnavailable:
            if case .connectingDisk = context {
                self.readOnlyConnectionRequest = readOnlyConnectionRequest
            } else {
                self.readOnlyConnectionRequest = nil
            }
        default: self.readOnlyConnectionRequest = nil
        }
        // The disk's name appears only in titles, kept on one line where it fits.
        let diskName: String?
        let connectionState: DiskConnectionState
        switch context {
        case .general, .findingDisks, .viewingDisks, .connectingDisk:
            diskName = nil
            connectionState = .unknown
        case .ejectingDisk(let name, let state, _):
            diskName = NameInTitle.keptTogether(name)
            connectionState = state
        }
        let credentialError: NSError
        switch error {
        case ServerConfigurationError.passwordSaveFailed(let underlying),
            ServerConfigurationError.passwordRemovalFailed(let underlying):
            credentialError = underlying as NSError
        default: credentialError = error as NSError
        }
        let search: ServerProfile?
        // The editor opens only for a server without connected disks; see `canEditServer(_:)`.
        let searchServerHasDisks: Bool
        if case .findingDisks(let server, let disksConnected) = context {
            search = server
            searchServerHasDisks = disksConnected
        } else {
            search = nil
            searchServerHasDisks = false
        }
        if let search,
            let guidance = Self.findingDisksAuthenticationMessage(
                error, credentials: FindingDisksCredentials(search),
                disksConnected: searchServerHasDisks)
        {
            let name = NameInTitle.keptTogether(search.displayName)
            title = String(localized: "Couldn’t Find Disks on “\(name)”")
            message = guidance
            if !searchServerHasDisks {
                recoveryAction = .editServer
                serverID = search.id
            }
        } else if error is LoginClosedByServer,
            case .viewingDisks(let server, let disksConnected) = context
        {
            let name = NameInTitle.keptTogether(server.displayName)
            title = String(localized: "Couldn’t View Disks on “\(name)”")
            message = Self.viewingDisksClosedMessage(
                credentialsSent: server.chapUsername != nil, disksConnected: disksConnected)
            if !disksConnected {
                recoveryAction = .editServer
                serverID = server.id
            }
        } else if case ProtocolError.localNetworkAccessRequired = error {
            title = String(localized: "Local Network Access Is Needed")
            message = AppPermissionGuidance().localNetworkIssueMessage
            recoveryAction = .openSystemSettings
        } else if let cleanup = error as? MountResourceCleanupError {
            let cause = cleanup.underlying as NSError
            title = String(localized: "Connection Information Couldn’t Be Removed")
            if cause.domain == NSOSStatusErrorDomain,
                cause.code == Int(errSecInteractionNotAllowed)
            {
                message = String(
                    localized:
                        "The disk is disconnected. Unlock your Mac, then click Check Connections to remove its connection information."
                )
            } else if cause.domain == NSOSStatusErrorDomain,
                cause.code == Int(errSecMissingEntitlement)
            {
                message = String(
                    localized:
                        "The disk is disconnected, but this copy of Kurazuna can’t remove its connection information. Contact the developer for assistance."
                )
            } else {
                message = String(
                    localized:
                        "The disk is disconnected, but its connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
                )
            }
        } else if (error as? POSIXError)?.code == .EBUSY {
            if let diskName,
                connectionState == .interrupted || connectionState == .closed
                    || connectionState == .reconnecting
            {
                title = String(localized: "“\(diskName)” Couldn’t Be Ejected")
                message = String(
                    localized:
                        "The connection was interrupted, and recent changes may not have been saved. Check the disk in Disk Utility, then try ejecting it again."
                )
                recoveryAction = .openDiskUtility
            } else if let diskName {
                title = String(localized: "“\(diskName)” Is in Use")
                message = String(
                    localized:
                        "Close any files or apps using this disk, then try ejecting it again."
                )
            } else {
                title = String(localized: "The Disk Is in Use")
                message = String(
                    localized:
                        "Close any files or apps using this disk, then try ejecting it again."
                )
            }
        } else if (error as? POSIXError)?.code == .EWOULDBLOCK {
            title = String(localized: "Kurazuna Is Already Running")
            message = String(localized: "Close the other copy of Kurazuna, then click Check Again.")
        } else if error is VolumeMountIssue {
            title = String(localized: "Volumes Couldn’t Be Mounted")
            message = String(
                localized:
                    "The disk is connected, but one or more volumes couldn’t be mounted. Check the disk in Disk Utility."
            )
            recoveryAction = .openDiskUtility
        } else if case AttachmentError.readOnlyGeometryRequired = error {
            title = String(localized: "Read-Only Connection Required")
            message =
                self.readOnlyConnectionRequest != nil
                ? String(
                    localized: "You can connect to this disk read-only to view and copy files.")
                : String(
                    localized:
                        "Kurazuna can currently connect this disk only as read-only. To view and copy files, choose Connect Read-Only from the Connect menu."
                )
        } else if case AttachmentError.writeCompletionUnavailable = error {
            title = String(localized: "Read-Only Connection Required")
            message =
                self.readOnlyConnectionRequest != nil
                ? String(
                    localized:
                        "This connection can’t confirm when writes are complete. You can connect read-only to view and copy files."
                )
                : String(
                    localized:
                        "This connection can’t confirm when writes are complete. To view and copy files, choose Connect Read-Only from the Connect menu."
                )
        } else if error is ReadOnlyConnectionError {
            title = String(localized: "The Connection Has Changed")
            message = String(localized: "Find disks on this server again, then try connecting.")
        } else if error is ForcedReleaseWithdrawn {
            // Nothing needs checking: the disk is connected and can be used or ejected.
            title =
                diskName.map { String(localized: "“\($0)” Is Connected Again") }
                ?? String(localized: "The Disk Is Connected Again")
            message = String(
                localized:
                    "The connection to the server was restored, so the disk wasn’t force ejected."
            )
        } else if case AttachmentError.ownershipUnverified = error {
            title = String(localized: "The Connection Has Changed")
            message = String(
                localized: "Check the connected disks in Disk Utility, then click Check Again.")
        } else if case AttachmentError.imageIdentityChanged = error {
            title = String(localized: "The Connection Has Changed")
            message = String(
                localized: "Check the connected disks in Disk Utility, then click Check Again.")
        } else if case AttachmentError.recoveryRequired = error, diskName == nil {
            // A named disk refused while an earlier ejection of it is still pending, or whose
            // forced release no longer applies, gets its own message below.
            title = String(localized: "Check Connected Disks")
            message = String(
                localized:
                    "Click Check Again to verify the connected disks before connecting another disk."
            )
        } else if case AttachmentError.journalUnreadable = error {
            title = String(localized: "Connection Information Couldn’t Be Read")
            message = String(
                localized: "Check the connected disks in Disk Utility, then click Check Again.")
        } else if case AttachmentError.journalUnavailable = error {
            title = String(localized: "Connection Information Couldn’t Be Saved")
            message = String(
                localized: "Check the available storage on your Mac, then click Check Again.")
        } else if case AttachmentError.connectionInterrupted = error {
            title = String(localized: "The Connection Was Interrupted")
            message = String(
                localized: "Check the server and network connection, then try again.")
        } else if case ProtocolError.targetEvent = error {
            title = String(localized: "The Connection Was Interrupted")
            message = String(localized: "Check the server and network connection, then try again.")
        } else if case ProtocolError.loginRejected(let status, let code) = error,
            status == 2 && code == 1
        {
            title = String(localized: "Authentication Failed")
            message = String(localized: "Check your user name and password, then try again.")
        } else if case ProtocolError.authenticationFailed = error {
            title = String(localized: "Server Authentication Failed")
            message = String(
                localized: "Check the server’s user name and password, then try again.")
        } else if Self.isRedirectFailure(error) {
            title = String(localized: "Couldn’t Connect to the Server")
            message = String(
                localized:
                    "Check the server’s connection addresses and iSCSI settings, then try again.")
        } else if case ProtocolError.scsiFailure(let status, let data) = error,
            status == 2, let sense = try? SCSISense(data: data), sense.isDeferred
        {
            title = String(localized: "The Disk Reported a Problem")
            message = String(
                localized:
                    "The disk reported a problem with an earlier operation. Recent changes may not have been saved. Check the disk on the server before connecting again."
            )
        } else if let issue = error as? DiskProbeIssue {
            title = String(localized: "Disk Information Is Unavailable")
            message = issue.userMessage
        } else if case ProtocolError.unsupported = error {
            title = String(localized: "Server Settings Aren’t Supported")
            message = String(
                localized:
                    "This server uses connection settings that Kurazuna doesn’t support. Check the server’s iSCSI settings, then try again."
            )
        } else if case AttachmentError.alreadyConnected = error {
            title = String(localized: "Disk Already Connected")
            message = String(localized: "This disk is already connected to this Mac.")
        } else if case AttachmentError.duplicateConnections = error {
            title = String(localized: "Check Connected Disks")
            message = String(
                localized:
                    "A disk has more than one connection. Eject its connections before connecting it again."
            )
            recoveryAction = .openDiskUtility
        } else if credentialError.domain == NSOSStatusErrorDomain,
            credentialError.code == Int(errSecMissingEntitlement)
        {
            title = String(localized: "Saved Passwords Are Unavailable")
            message = String(
                localized:
                    "This copy of Kurazuna can’t access saved passwords. Contact the developer for assistance."
            )
        } else if credentialError.domain == NSOSStatusErrorDomain,
            credentialError.code == Int(errSecItemNotFound)
        {
            title = String(localized: "Saved Password Is Missing")
            switch (search.map(FindingDisksCredentials.init) == .findingDisks, searchServerHasDisks)
            {
            case (true, false):
                message = String(
                    localized:
                        "Edit this server and enter the password under Finding Disks, then try again."
                )
            case (true, true):
                message = String(
                    localized:
                        "To enter the password under Finding Disks, eject this server’s disks, then edit the server."
                )
            case (false, false):
                message = String(
                    localized: "Edit this server and enter its password, then try again.")
            case (false, true):
                message = String(
                    localized:
                        "To enter this server’s password, eject its disks, then edit the server.")
            }
            if let search, !searchServerHasDisks {
                recoveryAction = .editServer
                serverID = search.id
            }
        } else if (error as NSError).domain == NSOSStatusErrorDomain {
            title = String(localized: "Saved Password Is Unavailable")
            message = String(
                localized:
                    "Your saved password couldn’t be accessed. Unlock your Mac and try again.")
        } else if case ServerConfigurationError.discoveryBothPasswordsRequired = error {
            title = String(localized: "Enter Both Passwords for Finding Disks")
            message = String(
                localized: "To change mutual CHAP for finding disks, enter both passwords.")
        } else if case ServerConfigurationError.discoveryPasswordRequired = error {
            title = String(localized: "Enter a Password for Finding Disks")
            message = String(
                localized: "Enter a password for the user name under Finding Disks.")
        } else if case ServerConfigurationError.bothPasswordsRequired = error {
            title = String(localized: "Enter Both Passwords")
            message = String(
                localized: "To change mutual CHAP authentication, enter both passwords.")
        } else if case ServerConfigurationError.passwordRequired = error {
            title = String(localized: "Enter a Password")
            message = String(localized: "Enter a password for this server and user name.")
        } else if case ServerConfigurationError.settingsLoadFailed = error {
            title = String(localized: "Server Settings Are Unavailable")
            message = String(
                localized:
                    "Kurazuna couldn’t read its saved server settings. Click Check Connections to try again."
            )
        } else if case ServerConfigurationError.settingsUnavailable = error {
            title = String(localized: "Server Settings Are Unavailable")
            message = String(
                localized: "Click Check Connections to read your server settings again.")
        } else if case ServerConfigurationError.settingsSaveFailed = error {
            title = String(localized: "Server Settings Couldn’t Be Saved")
            message = String(localized: "Check the available storage on your Mac, then try again.")
        } else if case ServerConfigurationError.passwordSaveFailed = error {
            title = String(localized: "Password Couldn’t Be Saved")
            message = String(localized: "Unlock your Mac, then try saving the password again.")
        } else if case ServerConfigurationError.passwordRemovalFailed = error {
            title = String(localized: "Saved Passwords Couldn’t Be Removed")
            message = String(
                localized: "Unlock your Mac, then try removing the saved passwords again.")
        } else if let diskName {
            title = String(localized: "“\(diskName)” Couldn’t Be Ejected")
            message = String(
                localized:
                    "The disk may still be connected. Check it in Disk Utility, then try again.")
            recoveryAction = .openDiskUtility
        } else if case SystemCommandError.timedOut = error {
            title = String(localized: "The Operation Couldn’t Be Completed")
            message = String(localized: "The operation took too long. Try again.")
        } else if case .connectingDisk = context, Self.isExtensionLaunchFailure(error) {
            let guidance = AppPermissionGuidance()
            title = guidance.launchFailureTitle
            message = guidance.launchFailureMessage
            recoveryAction = .openExtensionSettings
        } else if case .connectingDisk = context, case SystemCommandError.failed = error {
            title = String(localized: "The Disk Couldn’t Be Connected")
            message = String(
                localized: "The disk couldn’t be prepared for use on this Mac. Try again.")
        } else {
            title = String(localized: "The Operation Couldn’t Be Completed")
            message = String(
                localized: "Check the server address and network connection, then try again.")
        }
        reportsResourceCleanup = error is MountResourceCleanupError
        if let cleanup = error as? MountResourceCleanupError {
            detail = cleanup.underlying.localizedDescription
        } else if case ServerConfigurationError.settingsLoadFailed(let underlying) = error {
            detail = underlying.localizedDescription
        } else if case ServerConfigurationError.settingsSaveFailed(let underlying) = error {
            detail = underlying.localizedDescription
        } else if case ServerConfigurationError.passwordSaveFailed(let underlying) = error {
            detail = underlying.localizedDescription
        } else if case ServerConfigurationError.passwordRemovalFailed(let underlying) = error {
            detail = underlying.localizedDescription
        } else if let mountIssue = error as? VolumeMountIssue {
            detail = "diskutil (\(mountIssue.status)): \(mountIssue.detail)"
        } else if case SystemCommandError.failed(let program, let status, let detail) = error {
            self.detail = "\(program) (\(status)): \(detail)"
        } else if case SystemCommandError.timedOut(let program) = error {
            detail = "\(program): timed out"
        } else {
            detail = error.localizedDescription
        }
    }
}

@MainActor @Observable
final class AppModel {
    enum ExtensionState: Sendable {
        case checking, unavailable, disabled, differentCopy, readOnlyLocation, ready

        var noticeTitle: String {
            switch self {
            case .disabled: AppPermissionGuidance().enableTitle
            case .differentCopy: AppPermissionGuidance().installationTitle
            case .readOnlyLocation: AppPermissionGuidance().moveTitle
            default: String(localized: "File System Extension Is Unavailable")
            }
        }

        var noticeMessage: String {
            switch self {
            case .disabled:
                AppPermissionGuidance().enableMessage
            case .differentCopy:
                AppPermissionGuidance().installationMessage
            case .readOnlyLocation:
                AppPermissionGuidance().moveMessage
            default:
                AppPermissionGuidance().unavailableMessage
            }
        }
    }
    var document: ProfileDocument?
    var selectedServerID: UUID?
    var targets: [UUID: [DiscoveredTarget]] = [:]
    private var discoveryPortals: [UUID: Portal] = [:]
    var choices: [String: [FoundDisk]] = [:]
    var attached: [AttachedDisk] = [] {
        didSet { scheduleForcedReleaseOffer() }
    }
    var untrackedBridgeURLs: [URL] = []
    var busy = false {
        // An offer that came due during an operation is evaluated when it ends.
        didSet { if oldValue && !busy { scheduleForcedReleaseOffer() } }
    }
    var activity = ""
    var waitingForLocalNetworkAccess = false
    private var networkAccessWait: LocalNetworkAccessWait?
    private var networkAccessWaitID: UUID?
    var issue: AppIssue?
    var forceEjectionRequest: ForceEjectionRequest?
    private(set) var serverRemovalRequest: ServerRemovalRequest?
    var extensionState = ExtensionState.checking
    private(set) var isCheckingExtension = false
    var recoveryComplete = false
    private(set) var resourceCleanupOnly = false
    var showingServerEditor = false
    private(set) var editingServer: ServerProfile?
    var credentialCleanupNeeded = false
    private var configuration: ServerConfiguration?
    private var coordinator: AttachmentCoordinator?
    private var supportURL: URL?
    private var loaded = false
    private var loadTask: Task<Void, Never>?
    private var startupConnectionsRestored = false
    private let credentials: any CredentialStore
    private let sessionFactory:
        @Sendable (
            [TargetAddress], LoginConfiguration, [PermanentPortalRedirect], LocalNetworkAccessWait?
        ) async throws ->
            SessionConnection
    private var work: Task<Void, Never>?
    private var operationID: UUID?
    private var connectionRevision = UUID()
    private var mountedRedirectEpoch: UInt64 = 0
    private var monitorID: UUID?
    private var extensionCheckID: UUID?
    private var pendingExtensionChecks = 0
    private let extensionCheck: @MainActor @Sendable () async throws -> ExtensionState
    private let extensionCheckTimeout: Duration
    private let usesSystemExtensionCheck: Bool
    private let extensionPreparation:
        (@MainActor @Sendable (URL) async throws -> FileSystemExtensionPreparation.Outcome)?
    private let applicationSupportDirectory: @MainActor @Sendable () throws -> URL
    /// Waits until an instant of the coordinator's clock; see `scheduleForcedReleaseOffer()`.
    @ObservationIgnored private let waitUntil:
        @Sendable (ContinuousClock.Instant) async throws -> Void
    @ObservationIgnored private var forcedReleaseOffer:
        (deadline: ContinuousClock.Instant, task: Task<Void, Never>)?
    @ObservationIgnored private var lastForcedReleaseOfferDeadline: ContinuousClock.Instant?
    /// Where the screen's unlocking is posted (`screenUnlockedNotification`) and where the
    /// application's activation is posted; see `unlockEvents()`.
    @ObservationIgnored private let unlockNotifications: NotificationCenter
    @ObservationIgnored private let activationNotifications: NotificationCenter
    /// Waits before the second try after an unlock; see `scheduleLockedCleanupFollowUp()`.
    @ObservationIgnored private let retryDelay: @Sendable (Duration) async throws -> Void
    @ObservationIgnored private var lockedCleanupObservation:
        (task: Task<Void, Never>, events: AsyncStream<LockedCleanupRetryEvent>.Continuation)?
    @ObservationIgnored private var lockedCleanupFollowUp: (id: UUID, task: Task<Void, Never>)?
    /// The operation removing connection information on its own, and whether it follows an
    /// unlock of the screen.
    @ObservationIgnored private var automaticCheck: (operation: UUID, followsUnlock: Bool)?

    /// The system posts this to the distributed notification center when the user unlocks
    /// the screen.
    nonisolated static let screenUnlockedNotification = Notification.Name(
        "com.apple.screenIsUnlocked")
    /// How long after an unlock's failed check the connection information is tried once more.
    nonisolated static let lockedCleanupFollowUpDelay = Duration.seconds(2)

    init(
        coordinator: AttachmentCoordinator? = nil, configuration: ServerConfiguration? = nil,
        credentials: any CredentialStore = KeychainCredentialStore.sharedForCurrentBundle(),
        sessionFactory:
            (
                @Sendable ([TargetAddress], LoginConfiguration, [PermanentPortalRedirect])
                    async throws -> SessionConnection
            )? =
            nil,
        extensionCheck: (@MainActor @Sendable () async throws -> ExtensionState)? = nil,
        extensionPreparation:
            (@MainActor @Sendable (URL) async throws -> FileSystemExtensionPreparation.Outcome)? =
            nil,
        extensionCheckTimeout: Duration = .seconds(10),
        applicationSupportDirectory: @escaping @MainActor @Sendable () throws -> URL = {
            try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil,
                create: false)
        },
        waitUntil: @escaping @Sendable (ContinuousClock.Instant) async throws -> Void = {
            try await ContinuousClock().sleep(until: $0)
        },
        unlockNotifications: NotificationCenter = DistributedNotificationCenter.default(),
        activationNotifications: NotificationCenter = .default,
        retryDelay: @escaping @Sendable (Duration) async throws -> Void = {
            try await Task.sleep(for: $0)
        }
    ) {
        self.waitUntil = waitUntil
        self.unlockNotifications = unlockNotifications
        self.activationNotifications = activationNotifications
        self.retryDelay = retryDelay
        self.coordinator = coordinator
        self.configuration = configuration
        self.credentials = credentials
        if let sessionFactory {
            self.sessionFactory = { addresses, configuration, cached, _ in
                try await sessionFactory(addresses, configuration, cached)
            }
        } else {
            self.sessionFactory = Self.openSession
        }
        self.extensionCheck = extensionCheck ?? Self.installedExtensionState
        self.usesSystemExtensionCheck = extensionCheck == nil
        self.extensionPreparation = extensionPreparation
        self.extensionCheckTimeout = extensionCheckTimeout
        self.applicationSupportDirectory = applicationSupportDirectory
    }

    var servers: [ServerProfile] {
        var servers = document?.servers ?? []
        for disk in attached where !servers.contains(where: { $0.id == disk.descriptor.profileID })
        {
            if let server = try? ServerProfile(
                id: disk.descriptor.profileID,
                name: String(disk.descriptor.portal.description.prefix(80)),
                portal: disk.descriptor.portal,
                chapUsername: disk.descriptor.chapUsername,
                credentialID: disk.descriptor.credentialID,
                targetCHAPUsername: disk.descriptor.targetCHAPUsername)
            {
                servers.append(server)
            }
        }
        return servers
    }
    var selectedServer: ServerProfile? { servers.first(where: { $0.id == selectedServerID }) }
    var identityName: String { document?.identity.name ?? "" }
    var canConnect: Bool {
        document != nil && extensionState == .ready && !isCheckingExtension && !busy
            && loadTask == nil
            && !connectionStatusNeedsAttention && serverRemovalRequest == nil
    }
    var connectionStatusNeedsAttention: Bool {
        !recoveryComplete || attached.contains(where: \.verificationFailed)
    }
    /// The single banner to show. Unverified connections come first because they can
    /// affect data on connected disks; saved-password cleanup is the least urgent.
    var notice: AppNotice? {
        if connectionStatusNeedsAttention && !busy { return .connectionRecovery }
        if document == nil && !busy { return .settingsUnavailable }
        if extensionState != .ready && extensionState != .checking { return .extensionSetup }
        if credentialCleanupNeeded { return .credentialCleanup }
        return nil
    }
    /// Menu commands stay available while a sheet is up; the toolbar and rows do not.
    /// Start window work from the menu only when no sheet or confirmation is pending.
    var canRunMenuCommand: Bool {
        !busy && !showingServerEditor && issue == nil && forceEjectionRequest == nil
            && serverRemovalRequest == nil
    }
    var canFindDisksOnSelectedServer: Bool { selectedServer != nil && canRunMenuCommand }
    /// When the only problem is connection information that couldn't be removed from disks
    /// that are already disconnected, why it couldn't be removed, for each such disk.
    private var resourceCleanupCauses: [NSError]? {
        let pending = attached.filter(\.verificationFailed)
        guard resourceCleanupOnly, untrackedBridgeURLs.isEmpty, !pending.isEmpty,
            pending.allSatisfy({ $0.resourceCleanupError != nil })
        else { return nil }
        return pending.compactMap(\.resourceCleanupError).map { $0.underlying as NSError }
    }

    nonisolated private static func isLockedKeychain(_ cause: NSError) -> Bool {
        cause.domain == NSOSStatusErrorDomain && cause.code == Int(errSecInteractionNotAllowed)
    }

    nonisolated private static func isMissingEntitlement(_ cause: NSError) -> Bool {
        cause.domain == NSOSStatusErrorDomain && cause.code == Int(errSecMissingEntitlement)
    }

    /// Whether the only problem is connection information that couldn't be removed because
    /// the Mac was locked, so that unlocking the Mac is all that removing it needs.
    var lockedResourceCleanupPending: Bool {
        resourceCleanupCauses?.allSatisfy(Self.isLockedKeychain) ?? false
    }

    var connectionRecoveryNotice: ConnectionRecoveryNotice {
        if let causes = resourceCleanupCauses {
            let message: String
            if causes.allSatisfy(Self.isLockedKeychain) {
                message = String(
                    localized:
                        "Connection information couldn’t be removed. Unlock your Mac, then click Check Connections to try again."
                )
            } else if causes.contains(where: Self.isMissingEntitlement) {
                message = String(
                    localized:
                        "This copy of Kurazuna can’t remove the connection information. Contact the developer for assistance."
                )
            } else {
                message = String(
                    localized:
                        "Some connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
                )
            }
            return ConnectionRecoveryNotice(
                title: String(localized: "Connection Information Remains"), message: message,
                actionTitle: String(localized: "Check Connections"), showsDiskUtility: false)
        }
        return ConnectionRecoveryNotice(
            title: String(localized: "Check Connected Disks"),
            message: String(
                localized:
                    "Some connection information couldn’t be verified. Check the disks in Disk Utility before continuing."
            ), actionTitle: String(localized: "Check Again"), showsDiskUtility: true)
    }
    /// What the quit confirmation says while the connection status needs attention. When every
    /// disk left is disconnected and only its connection information remains, it says so, as
    /// the alert after ejecting the disk did; otherwise it asks to check the disks in Disk
    /// Utility, because which disks are connected isn't known.
    var quitWarning: QuitWarning {
        if let causes = resourceCleanupCauses,
            attached.allSatisfy({ $0.resourceCleanupError != nil })
        {
            let several = causes.count > 1
            let message: String
            if causes.allSatisfy(Self.isLockedKeychain) {
                message =
                    several
                    ? String(
                        localized:
                            "The disks are disconnected. Unlock your Mac, then click Check Connections to remove their connection information."
                    )
                    : String(
                        localized:
                            "The disk is disconnected. Unlock your Mac, then click Check Connections to remove its connection information."
                    )
            } else if causes.contains(where: Self.isMissingEntitlement) {
                message =
                    several
                    ? String(
                        localized:
                            "The disks are disconnected, but this copy of Kurazuna can’t remove their connection information. Contact the developer for assistance."
                    )
                    : String(
                        localized:
                            "The disk is disconnected, but this copy of Kurazuna can’t remove its connection information. Contact the developer for assistance."
                    )
            } else {
                message =
                    several
                    ? String(
                        localized:
                            "The disks are disconnected, but their connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
                    )
                    : String(
                        localized:
                            "The disk is disconnected, but its connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
                    )
            }
            return QuitWarning(
                title: String(localized: "Connection Information Remains"), message: message)
        }
        return QuitWarning(
            title: String(localized: "Connection Status Is Unavailable"),
            message: String(
                localized:
                    "\(AppName.inSentence) couldn’t verify which disks are connected. Check the disks in Disk Utility before quitting."
            ))
    }
    func diskStatus(_ disk: AttachedDisk) -> String {
        if disk.resourceCleanupError != nil { return String(localized: "Disconnected") }
        if disk.verificationFailed { return String(localized: "Check this connection") }
        if disk.needsCleanup {
            return String(localized: "Not fully disconnected. Eject to finish.")
        }
        switch disk.connectionState {
        case .connected: return String(localized: "Connected")
        // The extension is logging in again; I/O waits and the disk can still be ejected.
        case .reconnecting: return String(localized: "Reconnecting…")
        case .interrupted, .closed: return String(localized: "Connection interrupted")
        case .unknown: return String(localized: "Connection status unavailable")
        }
    }
    var canCancel: Bool { work.map { !$0.isCancelled } ?? false }
    var credentialCleanupNeedsEject: Bool {
        let accounts = Set(mountedCredentials.map(\.account))
        guard let pending = document?.pendingCredentialRemovals, !pending.isEmpty else {
            return false
        }
        return pending.allSatisfy { accounts.contains($0.account) }
    }
    var canInstallSoftwareUpdate: Bool {
        !busy && !connectionStatusNeedsAttention && attached.isEmpty && untrackedBridgeURLs.isEmpty
    }

    var canEditServers: Bool {
        document != nil && recoveryComplete && !connectionStatusNeedsAttention && !busy
            && serverRemovalRequest == nil
    }
    var canAddServer: Bool { canEditServers && !showingServerEditor }

    func canEditServer(_ server: ServerProfile) -> Bool {
        canAddServer && document?.servers.contains(where: { $0.id == server.id }) == true
            && !attached.contains(where: { $0.descriptor.profileID == server.id })
    }

    func addServer() {
        guard canAddServer else { return }
        dismissReadOnlyConnection()
        editingServer = nil
        showingServerEditor = true
    }

    func editServer(_ server: ServerProfile) {
        guard canEditServer(server),
            let saved = document?.servers.first(where: { $0.id == server.id })
        else { return }
        dismissReadOnlyConnection()
        editingServer = saved
        showingServerEditor = true
    }

    /// Whether the server could be edited once the operation in progress ends: everything
    /// `canEditServer(_:)` checks except that the app is busy.
    private func canEditServerAfterOperation(_ id: UUID) -> Bool {
        document?.servers.contains(where: { $0.id == id }) == true && recoveryComplete
            && !connectionStatusNeedsAttention && serverRemovalRequest == nil
            && !showingServerEditor && !attached.contains(where: { $0.descriptor.profileID == id })
    }

    /// An issue's Edit Server… action: dismiss the issue if it's still shown, then edit the
    /// server it names.
    func editServer(for issue: AppIssue) {
        guard issue.recoveryAction == .editServer, let id = issue.serverID else { return }
        if self.issue?.id == issue.id { self.issue = nil }
        if let server = document?.servers.first(where: { $0.id == id }) { editServer(server) }
    }

    func load() async {
        if let loadTask {
            await loadTask.value
            return
        }
        guard !loaded else { return }
        loaded = true
        busy = true
        // Invalidate any earlier query before reserving the shared startup task.
        extensionCheckID = UUID()
        isCheckingExtension = true
        let task = Task { await loadContents() }
        loadTask = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        loadTask = nil
    }

    private func loadContents() async {
        activity = String(localized: "Checking connected disks…")
        defer {
            startupConnectionsRestored = false
            busy = false
            activity = ""
        }
        do {
            try resolveSupportDirectory()
            do { try await loadConfiguration() } catch { issue = AppIssue(error) }
            try await restoreConnections()
            startupConnectionsRestored = true
            await rememberMountedRedirects(epoch: mountedRedirectEpoch)
            if document != nil, let configuration, !connectionStatusNeedsAttention {
                try? await configuration.retryCleanup(protecting: mountedCredentials)
                await updateConfigurationState()
            }
        } catch { issue = AppIssue(error) }
        if selectedServerID == nil { selectedServerID = servers.first?.id }
        let preparation = await prepareExtensionForStartup()
        await refreshExtensionState(recheckAfterSubmission: preparation == .submitted)
    }

    private var canPrepareExtensionForStartup: Bool {
        startupConnectionsRestored && busy && recoveryComplete
            && attached.isEmpty && untrackedBridgeURLs.isEmpty
            && !connectionStatusNeedsAttention
    }

    private func prepareExtensionForStartup() async -> FileSystemExtensionPreparation.Outcome? {
        guard canPrepareExtensionForStartup, let supportURL,
            usesSystemExtensionCheck || extensionPreparation != nil
        else { return nil }
        let id = UUID()
        ExtensionRegistrationDiagnostics.preparationStarted(id)
        do {
            try Task.checkCancellation()
            let outcome: FileSystemExtensionPreparation.Outcome
            if let extensionPreparation {
                outcome = try await extensionPreparation(supportURL)
            } else {
                outcome = try await FileSystemExtensionPreparation.prepare(
                    applicationURL: Bundle.main.bundleURL, supportURL: supportURL,
                    permitted: { [weak self] in
                        await self?.canPrepareExtensionForStartup ?? false
                    })
            }
            ExtensionRegistrationDiagnostics.preparationCompleted(id, outcome: outcome)
            return outcome
        } catch {
            ExtensionRegistrationDiagnostics.preparationFailed(id, error: error)
            return nil
        }
    }

    func checkConnections() {
        perform(activity: String(localized: "Checking connected disks…")) { [self] in
            try await checkConnectionsOperation()
        }
    }

    private func checkConnectionsOperation() async throws {
        try resolveSupportDirectory()
        try await restoreConnections()
        try await loadConfiguration()
        await synchronizeMountedRedirectContext()
        await rememberMountedRedirects(epoch: mountedRedirectEpoch)
        if let configuration, !connectionStatusNeedsAttention {
            do { try await configuration.retryCleanup(protecting: mountedCredentials) } catch {
                await updateConfigurationState()
                throw error
            }
            await updateConfigurationState()
        }
    }

    /// Starts trying again, after each unlock and activation, to remove connection information
    /// that couldn't be removed while the Mac was locked; see `retryLockedResourceCleanup`. The
    /// model, not a window, keeps this going, so it continues while the window is closed.
    /// Starting it again changes nothing.
    func startRetryingLockedCleanup() {
        guard lockedCleanupObservation == nil else { return }
        let (events, continuation) = unlockEvents()
        let task = Task { [weak self] in
            for await event in events {
                guard let self, !Task.isCancelled else { return }
                retryLockedResourceCleanup(after: event)
            }
        }
        lockedCleanupObservation = (task, continuation)
    }

    /// Stops what `startRetryingLockedCleanup()` started, including a later attempt it scheduled.
    /// Nothing is observed after this returns.
    func stopRetryingLockedCleanup() {
        lockedCleanupObservation?.task.cancel()
        lockedCleanupObservation?.events.finish()
        lockedCleanupObservation = nil
        lockedCleanupFollowUp?.task.cancel()
        lockedCleanupFollowUp = nil
    }

    /// Tries once to remove connection information that couldn't be removed while the Mac was
    /// locked, as Check Connections does, after the Mac is unlocked or Kurazuna becomes active.
    /// Nothing starts while another operation is in progress, or while a confirmation, the
    /// server editor or an unrelated alert waits for an answer. The alert that reported this
    /// connection information may be up: the check runs behind it, and closes it once the
    /// connection information is gone. The check can be canceled like any other. What it finds
    /// is shown by the notice and the disk rows, never in a new alert.
    ///
    /// The Keychain may still be locked for a moment after the screen is unlocked. So when the
    /// check after an unlock fails for that reason alone, it's tried once more, a little
    /// later; see `scheduleLockedCleanupFollowUp()`. Otherwise a check that fails waits for the
    /// next unlock or activation, so it's never repeated on its own.
    func retryLockedResourceCleanup(after event: LockedCleanupRetryEvent = .applicationActivated) {
        // An unlock while the check after an activation runs is the same moment, so that
        // check is treated as the one after the unlock.
        if event == .screenUnlocked, busy, let check = automaticCheck,
            check.operation == operationID
        {
            automaticCheck?.followsUnlock = true
            return
        }
        guard canRetryLockedCleanup else { return }
        // A check that comes before the second try after an unlock takes its place, so if it
        // fails, the second try is still made.
        let replacesFollowUp = lockedCleanupFollowUp != nil
        lockedCleanupFollowUp?.task.cancel()
        lockedCleanupFollowUp = nil
        runLockedCleanupCheck(followsUnlock: event == .screenUnlocked || replacesFollowUp)
    }

    private var canRetryLockedCleanup: Bool {
        lockedResourceCleanupPending && !busy && loadTask == nil && !showingServerEditor
            && forceEjectionRequest == nil && serverRemovalRequest == nil
            && (issue.map(\.reportsResourceCleanup) ?? true)
    }

    private func runLockedCleanupCheck(followsUnlock: Bool) {
        perform(
            activity: String(localized: "Checking connected disks…"), reportsFailure: false
        ) { [self] in
            let operation = operationID
            do {
                try await checkConnectionsOperation()
            } catch {
                if !(error is CancellationError), !Task.isCancelled,
                    let check = automaticCheck, check.operation == operation, check.followsUnlock,
                    lockedResourceCleanupPending
                {
                    scheduleLockedCleanupFollowUp()
                }
                throw error
            }
            // An alert that still asks to remove this connection information would ask for
            // something already done, so it closes, as alerts about a condition that has
            // cleared do. Any other alert stays.
            if issue?.reportsResourceCleanup == true, !resourceCleanupOnly,
                !attached.contains(where: { $0.resourceCleanupError != nil })
            {
                issue = nil
            }
        }
        if busy, let operationID { automaticCheck = (operationID, followsUnlock) }
    }

    /// Tries once more after `lockedCleanupFollowUpDelay`, unless another operation started
    /// meanwhile, something else is in progress or waits for an answer, or the connection
    /// information no longer needs only an unlocked Mac. That attempt schedules nothing more.
    private func scheduleLockedCleanupFollowUp() {
        lockedCleanupFollowUp?.task.cancel()
        let id = UUID()
        let revision = connectionRevision
        let delay = retryDelay
        let task = Task { [weak self] in
            do { try await delay(Self.lockedCleanupFollowUpDelay) } catch { return }
            guard let self, lockedCleanupFollowUp?.id == id, !Task.isCancelled else { return }
            lockedCleanupFollowUp = nil
            guard connectionRevision == revision, canRetryLockedCleanup else { return }
            runLockedCleanupCheck(followsUnlock: false)
        }
        lockedCleanupFollowUp = (id, task)
    }

    /// One event each time the screen is unlocked or the application becomes active, from now
    /// until the stream ends; finishing it stops observing.
    private func unlockEvents() -> (
        AsyncStream<LockedCleanupRetryEvent>, AsyncStream<LockedCleanupRetryEvent>.Continuation
    ) {
        let (events, continuation) = AsyncStream.makeStream(
            of: LockedCleanupRetryEvent.self)
        let relay = NotificationRelay(continuation)
        let screen = unlockNotifications
        let application = activationNotifications
        let unlocked = #selector(NotificationRelay.screenUnlocked(_:))
        if let distributed = screen as? DistributedNotificationCenter {
            // AppKit holds distributed notifications while the application is in the
            // background, which is when an unlock most often comes.
            distributed.addObserver(
                relay, selector: unlocked, name: Self.screenUnlockedNotification, object: nil,
                suspensionBehavior: .deliverImmediately)
        } else {
            screen.addObserver(
                relay, selector: unlocked, name: Self.screenUnlockedNotification, object: nil)
        }
        application.addObserver(
            relay, selector: #selector(NotificationRelay.applicationActivated(_:)),
            name: NSApplication.didBecomeActiveNotification, object: nil)
        continuation.onTermination = { _ in
            screen.removeObserver(relay)
            application.removeObserver(relay)
        }
        return (events, continuation)
    }

    private func resolveSupportDirectory() throws {
        guard supportURL == nil else { return }
        supportURL = ApplicationIdentity.current.supportDirectory(
            in: try applicationSupportDirectory())
    }

    func monitorConnections() async {
        let id = UUID()
        monitorID = id
        defer { if monitorID == id { monitorID = nil } }
        while !Task.isCancelled, monitorID == id {
            await refreshConnectionHealth()
            guard monitorID == id else { return }
            do {
                try await Task.sleep(
                    for: NSApplication.shared.isActive ? .seconds(15) : .seconds(60))
            } catch { return }
        }
    }

    func refreshConnectionHealth() async {
        guard !busy, let coordinator, !attached.isEmpty else { return }
        let revision = connectionRevision
        let epoch = mountedRedirectEpoch
        await coordinator.refreshHealth()
        let disks = await coordinator.disks
        let recoveryState = await coordinator.recoveryState
        guard !busy, connectionRevision == revision, self.coordinator === coordinator,
            !Task.isCancelled
        else { return }
        attached = disks
        applyRecoveryState(recoveryState)
        await synchronizeMountedRedirectContext()
        await rememberMountedRedirects(epoch: epoch)
    }

    func openDiskUtility() {
        if let url = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: "com.apple.DiskUtility")
        {
            NSWorkspace.shared.open(url)
        }
    }

    func openSystemSettings() {
        if let url = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: "com.apple.systempreferences")
        {
            NSWorkspace.shared.open(url)
        }
    }

    private func applyRecoveryState(_ state: AttachmentRecoveryState) {
        recoveryComplete = state == .ready
        resourceCleanupOnly = state == .resourceCleanupPending
    }

    private func restoreConnections() async throws {
        guard let supportURL else { throw ProtocolError.invalidState }
        if coordinator == nil {
            let root = supportURL.appendingPathComponent("Mounts", isDirectory: true)
            do {
                let journal = try FileAttachmentJournal(directory: supportURL, bridgeRoot: root)
                coordinator = try AttachmentCoordinator(
                    backend: SystemAttachmentBackend(root: root), journal: journal)
            } catch let error as POSIXError where error.code == .EWOULDBLOCK {
                throw error
            } catch { throw AttachmentError.journalUnreadable }
        }
        guard let coordinator else { throw ProtocolError.invalidState }
        do { try await coordinator.restore() } catch {
            attached = await coordinator.disks
            untrackedBridgeURLs = await coordinator.untrackedBridgeURLs
            applyRecoveryState(await coordinator.recoveryState)
            await synchronizeMountedRedirectContext()
            if selectedServerID == nil { selectedServerID = attached.first?.descriptor.profileID }
            throw error
        }
        attached = await coordinator.disks
        untrackedBridgeURLs = await coordinator.untrackedBridgeURLs
        applyRecoveryState(await coordinator.recoveryState)
        await synchronizeMountedRedirectContext()
        if selectedServerID == nil { selectedServerID = attached.first?.descriptor.profileID }
    }

    func refreshExtension() async {
        // Activation notifications and Check Again join startup instead of querying
        // while the current bundle is still being registered. Injected checks keep
        // memory-only previews and tests independent of the user's installation.
        if !loaded, usesSystemExtensionCheck {
            await load()
            return
        }
        if let loadTask {
            await loadTask.value
            return
        }
        await refreshExtensionState()
    }

    private func refreshExtensionState(recheckAfterSubmission: Bool = false) async {
        let id = UUID()
        extensionCheckID = id
        isCheckingExtension = true
        let state: ExtensionState
        do {
            state = try await checkExtensionCancellably(
                recheckAfterSubmission: recheckAfterSubmission)
            try Task.checkCancellation()
        } catch {
            guard extensionCheckID == id else { return }
            ExtensionRegistrationDiagnostics.checkFailed(id, error: error)
            extensionState = .unavailable
            isCheckingExtension = false
            return
        }
        guard extensionCheckID == id else { return }
        extensionState = state
        isCheckingExtension = false
    }

    private func checkExtensionCancellably(recheckAfterSubmission: Bool = false) async throws
        -> ExtensionState
    {
        try Task.checkCancellation()
        // An SDK query may ignore cancellation. Bound outstanding queries while allowing
        // their callers to stop waiting without changing network cleanup semantics.
        guard pendingExtensionChecks < 8 else { throw ProtocolError.busy }
        pendingExtensionChecks += 1
        let check = extensionCheck
        let reply = ExtensionCheckReply()
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: extensionCheckTimeout)
        func checkDeadline() throws {
            try Task.checkCancellation()
            guard clock.now < deadline else { throw ProtocolError.timedOut }
        }
        let query = Task { [weak self] in
            defer { self?.pendingExtensionChecks -= 1 }
            do {
                try checkDeadline()
                var state = try await check()
                try checkDeadline()
                if recheckAfterSubmission {
                    // Registration command completion can precede FSKit visibility.
                    // Confirm only this provisional mismatch; do not register again.
                    for delay in [Duration.milliseconds(100), .milliseconds(300)] {
                        guard state == .differentCopy else { break }
                        try await Task.sleep(for: delay)
                        try checkDeadline()
                        state = try await check()
                        try checkDeadline()
                    }
                }
                reply.finish(.success(state))
            } catch {
                reply.finish(.failure(error))
            }
        }
        let timeout = Task {
            do { try await clock.sleep(until: deadline) } catch { return }
            reply.finish(.failure(ProtocolError.timedOut))
            query.cancel()
        }
        defer { timeout.cancel() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { reply.wait($0) }
        } onCancel: {
            reply.finish(.failure(CancellationError()))
            query.cancel()
        }
    }

    private static func installedExtensionState() async throws -> ExtensionState {
        let id = UUID()
        ExtensionRegistrationDiagnostics.started(id)
        do {
            let modules = try await FSClient.shared.installedExtensions
            try Task.checkCancellation()
            let registrations = modules.map {
                FileSystemExtensionRegistration(
                    bundleIdentifier: $0.bundleIdentifier, moduleURL: $0.url,
                    isEnabled: $0.isEnabled)
            }
            let application = Bundle.main.bundleURL
            let assessment = await Task.detached(priority: .userInitiated) {
                FileSystemExtensionAvailability.assess(registrations, applicationURL: application)
            }.value
            try Task.checkCancellation()
            ExtensionRegistrationDiagnostics.completed(id, assessment: assessment)
            return state(
                for: assessment.availability,
                readOnly: FileSystemExtensionPreparation.isReadOnlyInstallation(application))
        } catch {
            ExtensionRegistrationDiagnostics.failed(id, error: error)
            if FileSystemExtensionPreparation.isReadOnlyInstallation(Bundle.main.bundleURL) {
                return .readOnlyLocation
            }
            throw error
        }
    }

    nonisolated static func assessExtension(
        _ registrations: [FileSystemExtensionRegistration], applicationURL: URL
    ) -> ExtensionState {
        state(
            for: FileSystemExtensionAvailability.evaluate(
                registrations, applicationURL: applicationURL))
    }

    nonisolated static func state(
        for availability: FileSystemExtensionAvailability, readOnly: Bool = false
    ) -> ExtensionState {
        if readOnly && availability != .ready { return .readOnlyLocation }
        return switch availability {
        case .ready: .ready
        case .disabled: .disabled
        case .differentCopy: .differentCopy
        case .unavailable: .unavailable
        }
    }

    private var disksClearForRegistration: Bool {
        recoveryComplete && attached.isEmpty && untrackedBridgeURLs.isEmpty
            && !connectionStatusNeedsAttention
    }

    var canUseRunningCopy: Bool {
        (extensionState == .differentCopy || extensionState == .unavailable) && !busy
            && !isCheckingExtension && disksClearForRegistration && usesSystemExtensionCheck
    }

    func useRunningCopy() {
        guard canUseRunningCopy else { return }
        perform(activity: String(localized: "Registering the file system extension…")) { [self] in
            try await restoreConnections()
            guard disksClearForRegistration else { throw POSIXError(.EBUSY) }
            do {
                try await FileSystemExtensionPreparation.useRunningCopy(
                    applicationURL: Bundle.main.bundleURL,
                    permitted: { [weak self] in await self?.disksClearForRegistration ?? false })
            } catch {
                await refreshExtensionState()
                throw error
            }
            await refreshExtensionState(recheckAfterSubmission: true)
        }
    }

    func openExtensionSettings() {
        // Keep the Settings URL for a request that FSKit declines.
        if FSClient.shared.openFileSystemExtensionsSettings() { return }
        if let url = URL(
            string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        {
            NSWorkspace.shared.open(url)
        }
    }

    private func loadConfiguration() async throws {
        guard let supportURL else { throw ServerConfigurationError.settingsUnavailable }
        do {
            if let configuration {
                try await configuration.reload()
            } else {
                configuration = try ServerConfiguration(
                    storage: ProfileStore(url: supportURL.appendingPathComponent("Servers.json")),
                    credentials: credentials)
            }
            await updateConfigurationState()
        } catch {
            if configuration != nil { await updateConfigurationState() } else { document = nil }
            // Preserve cancellation and the process-held lease's specific recovery guidance.
            if error is CancellationError || (error as? POSIXError)?.code == .EWOULDBLOCK {
                throw error
            }
            throw ServerConfigurationError.settingsLoadFailed(error)
        }
    }

    private func updateConfigurationState() async {
        guard let configuration else { return }
        let previous = document?.servers ?? []
        let updated = await configuration.document
        let ids = Set(previous.map(\.id) + (updated?.servers.map(\.id) ?? []))
        for id in ids
        where previous.first(where: { $0.id == id })
            != updated?.servers.first(where: { $0.id == id })
        {
            targets[id] = nil
            discoveryPortals[id] = nil
            choices = choices.filter { !$0.key.hasPrefix("\(id)|") }
        }
        document = updated
        if let selectedServerID, !servers.contains(where: { $0.id == selectedServerID }) {
            self.selectedServerID = nil
        }
        credentialCleanupNeeded = await configuration.cleanupNeeded(protecting: mountedCredentials)
    }

    private var mountedCredentials: [CredentialContext] {
        attached.compactMap { disk in
            disk.descriptor.chapUsername.map {
                CredentialContext(
                    profileID: disk.descriptor.profileID, portal: disk.descriptor.portal,
                    username: $0, credentialID: disk.descriptor.credentialID,
                    targetUsername: disk.descriptor.targetCHAPUsername)
            }
        }
    }

    func saveServer(
        id: UUID, name: String, address: String, username: String?, password: String,
        targetUsername: String? = nil, targetPassword: String = "",
        discoveryAuthentication: DiscoveryAuthentication = .sameAsConnection,
        discoveryPassword: String = "", discoveryTargetPassword: String = ""
    )
        async throws
    {
        guard canEditServers, let configuration else {
            throw ServerConfigurationError.settingsUnavailable
        }
        guard !attached.contains(where: { $0.descriptor.profileID == id }) else {
            throw ProtocolError.busy
        }
        dismissReadOnlyConnection()
        busy = true
        activity = String(localized: "Saving server…")
        defer {
            busy = false
            activity = ""
        }
        let server = try ServerProfile(
            id: id, name: name,
            portal: Portal(address.trimmingCharacters(in: .whitespacesAndNewlines)),
            chapUsername: username, targetCHAPUsername: targetUsername,
            discoveryAuthentication: discoveryAuthentication)
        do {
            try await configuration.save(
                server, password: password, targetPassword: targetPassword,
                discoveryPassword: discoveryPassword,
                discoveryTargetPassword: discoveryTargetPassword,
                protecting: mountedCredentials)
        } catch {
            await updateConfigurationState()
            throw error
        }
        await updateConfigurationState()
        selectedServerID = server.id
        editingServer = nil
        showingServerEditor = false
    }

    func removeServer(_ server: ServerProfile) {
        guard canEditServer(server), issue == nil, forceEjectionRequest == nil,
            let saved = document?.servers.first(where: { $0.id == server.id })
        else { return }
        serverRemovalRequest = ServerRemovalRequest(server: saved)
    }

    func cancelServerRemoval(_ request: ServerRemovalRequest) {
        if serverRemovalRequest == request { serverRemovalRequest = nil }
    }

    func confirmServerRemoval(_ request: ServerRemovalRequest) {
        guard serverRemovalRequest == request else { return }
        serverRemovalRequest = nil
        let server = request.server
        guard canEditServer(server),
            document?.servers.first(where: { $0.id == server.id }) == server,
            let configuration
        else { return }
        perform(activity: String(localized: "Removing server…")) { [self] in
            do { try await configuration.remove(server.id, protecting: mountedCredentials) } catch {
                await updateConfigurationState()
                throw error
            }
            await updateConfigurationState()
            if selectedServerID == server.id { selectedServerID = nil }
        }
    }

    func retryCredentialCleanup() {
        guard document != nil, !connectionStatusNeedsAttention, let configuration else { return }
        perform(activity: String(localized: "Updating saved passwords…")) { [self] in
            do { try await configuration.retryCleanup(protecting: mountedCredentials) } catch {
                await updateConfigurationState()
                throw error
            }
            await updateConfigurationState()
        }
    }

    func search(_ server: ServerProfile) {
        perform(activity: String(localized: "Finding disks…"), context: .findingDisks(server)) {
            [self] in
            // A new server search invalidates its old target/LUN inventory, even if opening
            // the replacement session fails. Other servers and mounted disks are unchanged.
            targets.removeValue(forKey: server.id)
            discoveryPortals.removeValue(forKey: server.id)
            choices = choices.filter { !$0.key.hasPrefix("\(server.id)|") }
            let connection = try await session(for: server)
            let session = connection.session
            do {
                let found = try await session.discover()
                try await session.logout()
                try Task.checkCancellation()
                try await rememberRedirects(connection, server: server, targetName: nil)
                try Task.checkCancellation()
                targets[server.id] = found
                discoveryPortals[server.id] = connection.portal
            } catch {
                await session.closeGracefully()
                throw error
            }
        }
    }

    func inspect(_ target: DiscoveredTarget, server: ServerProfile) {
        perform(
            activity: String(localized: "Reading disk information…"),
            context: .viewingDisks(server)
        ) { [self] in
            let key = choiceKey(server, target.name)
            choices.removeValue(forKey: key)
            let connection = try await session(for: server, target: target)
            let session = connection.session
            do {
                let inspections = try await DiskProbe.inspectLogicalUnits(session: session)
                let address = TargetAddress(
                    portal: connection.portal, portalGroupTag: await session.targetPortalGroupTag)
                try await session.logout()
                try Task.checkCancellation()
                try await rememberRedirects(connection, server: server, targetName: target.name)
                try Task.checkCancellation()
                choices[key] = inspections.map {
                    FoundDisk(targetName: target.name, inspection: $0, connectionAddress: address)
                }
            } catch {
                await session.closeGracefully()
                throw error
            }
        }
    }

    /// Connects one disk. A read-only request applies only to this attempt; a write-protected
    /// disk always connects read-only. A writable attempt may offer a read-only retry.
    func connect(_ disk: FoundDisk, server: ServerProfile, readOnly: Bool = false) {
        guard canConnect, disk.information != nil else { return }
        let requestedReadOnly = readOnly || disk.isWriteProtected
        let recovery = (document?.identity).map {
            ReadOnlyConnectionRequest(server: server, disk: disk, identity: $0)
        }
        startConnection(
            disk, server: server, readOnly: requestedReadOnly,
            recovery: requestedReadOnly ? nil : recovery)
    }

    func cancelReadOnlyConnection(_ request: ReadOnlyConnectionRequest) {
        guard issue?.readOnlyConnectionRequest == request else { return }
        issue = nil
    }

    func confirmReadOnlyConnection(_ request: ReadOnlyConnectionRequest) {
        guard issue?.readOnlyConnectionRequest == request else { return }
        issue = nil  // Consume before starting work; repeated actions cannot start another attempt.
        guard canConnect, isCurrentReadOnlyConnection(request) else {
            issue = AppIssue(ReadOnlyConnectionError.contextChanged)
            return
        }
        startConnection(request.disk, server: request.server, readOnly: true, retry: request)
    }

    private func dismissReadOnlyConnection() {
        if issue?.readOnlyConnectionRequest != nil { issue = nil }
    }

    private func isCurrentReadOnlyConnection(_ request: ReadOnlyConnectionRequest) -> Bool {
        document?.identity == request.identity && document?.servers.contains(request.server) == true
            && selectedServerID == request.server.id
            && choices[choiceKey(request.server, request.disk.targetName)]?.contains(request.disk)
                == true
            && request.disk.information != nil && existingConnection(for: request.disk) == nil
            && recoveryComplete && !connectionStatusNeedsAttention && untrackedBridgeURLs.isEmpty
            && extensionState == .ready && !isCheckingExtension && !showingServerEditor
            && serverRemovalRequest == nil && forceEjectionRequest == nil
    }

    private func validateReadOnlyConnection(_ request: ReadOnlyConnectionRequest) async throws {
        if let configuration {
            let current = await configuration.document
            guard current?.identity == request.identity,
                current?.servers.contains(request.server) == true
            else { throw ReadOnlyConnectionError.contextChanged }
        }
        guard isCurrentReadOnlyConnection(request) else {
            throw ReadOnlyConnectionError.contextChanged
        }
    }

    private func startConnection(
        _ disk: FoundDisk, server: ServerProfile, readOnly: Bool,
        recovery: ReadOnlyConnectionRequest? = nil, retry: ReadOnlyConnectionRequest? = nil
    ) {
        perform(
            activity: String(localized: "Connecting disk…"), context: .connectingDisk,
            readOnlyRecovery: recovery
        ) {
            [self] in
            if let retry, !isCurrentReadOnlyConnection(retry) {
                throw ReadOnlyConnectionError.contextChanged
            }
            await refreshExtension()
            try Task.checkCancellation()
            if let retry {
                try await configuration?.reload()
                try await validateReadOnlyConnection(retry)
            }
            guard extensionState == .ready, !isCheckingExtension else { return }
            guard let identity = document?.identity, let coordinator else {
                throw ProtocolError.invalidState
            }
            let address = disk.connectionAddress ?? TargetAddress(portal: server.portal)
            let connected: AttachedDisk
            do {
                let authentication: CHAPIdentity?
                if let configuration {
                    authentication = try await configuration.prepareConnectionIdentity(
                        for: server, portal: address.portal)
                } else {
                    guard address.portal == server.portal || server.chapUsername == nil else {
                        throw ServerConfigurationError.settingsUnavailable
                    }
                    authentication = try server.chapUsername.map {
                        try CHAPIdentity(
                            username: $0, targetUsername: server.targetCHAPUsername,
                            credentialID: server.credentialID)
                    }
                }
                try Task.checkCancellation()
                if let retry {
                    try await validateReadOnlyConnection(retry)
                }
                let descriptor = try ConnectionDescriptor(
                    profileID: server.id, portal: address.portal,
                    initiatorName: identity.name, targetName: disk.targetName, lun: disk.lun,
                    readOnly: readOnly || disk.isWriteProtected,
                    chapUsername: authentication?.username,
                    isid: identity.isid(targetName: disk.targetName, lun: disk.lun),
                    credentialID: authentication?.credentialID,
                    targetCHAPUsername: authentication?.targetUsername,
                    portalGroupTag: address.portalGroupTag,
                    settingsBinding: document?.servers.contains(server) == true
                        ? try server.connectionSettingsBinding : nil)
                connected = try await coordinator.connect(descriptor)
            } catch {
                attached = await coordinator.disks
                applyRecoveryState(await coordinator.recoveryState)
                await cleanupUnusedConnectionCredentials()
                throw error
            }
            attached = await coordinator.disks
            applyRecoveryState(await coordinator.recoveryState)
            await cleanupUnusedConnectionCredentials()
            await rememberMountedRedirects(epoch: mountedRedirectEpoch)
            if issue == nil, !Task.isCancelled,
                let mountIssue = connected.attachment?.volumeMountIssue
            {
                issue = AppIssue(mountIssue)
            }
        }
    }

    private func ejectionContext(for disk: AttachedDisk) -> AppIssue.Context {
        .ejectingDisk(
            name(of: disk),
            connectionState: attached.first { $0.id == disk.id }?.connectionState
                ?? disk.connectionState, id: disk.id)
    }

    func eject(_ disk: AttachedDisk) {
        let removingConnectionInformation =
            attached.first { $0.id == disk.id }?.resourceCleanupError != nil
        perform(
            activity: removingConnectionInformation
                ? String(localized: "Removing connection information…")
                : String(localized: "Ejecting disk…"),
            context: .ejectingDisk(name(of: disk)),
            failureContext: { [self] in ejectionContext(for: disk) },
            operation: { [self] in
                guard let coordinator else { throw ProtocolError.invalidState }
                do { try await coordinator.eject(disk.id) } catch {
                    attached = await coordinator.disks
                    applyRecoveryState(await coordinator.recoveryState)
                    await cleanupUnusedConnectionCredentials()
                    throw error
                }
                attached = await coordinator.disks
                applyRecoveryState(await coordinator.recoveryState)
                await cleanupUnusedConnectionCredentials()
            })
    }

    /// A disk whose connection couldn't be verified, or that is only partly ejected, can be
    /// force ejected directly. A healthy disk offers this only after a normal eject failed.
    func offersForceEjection(_ disk: AttachedDisk) -> Bool {
        (attached.first { $0.id == disk.id } ?? disk).offersForcedRelease
    }

    /// A reconnecting disk is offered a forced release once it has kept reconnecting for
    /// `AttachedDisk.forcedReleaseReconnectingDelay`, but the coordinator evaluates that only
    /// when it reports its disks. Rather than wait up to a minute for the next health check,
    /// check once more when the earliest such delay ends. Each delay is checked at most once,
    /// so a disk still not offered then waits for the next health check, never a loop.
    private func scheduleForcedReleaseOffer() {
        let deadline = attached.compactMap { disk -> ContinuousClock.Instant? in
            guard disk.connectionState == .reconnecting, !disk.reconnectingLongEnough,
                let since = disk.reconnectingSince
            else { return nil }
            return since.advanced(by: AttachedDisk.forcedReleaseReconnectingDelay)
        }
        .filter { deadline in lastForcedReleaseOfferDeadline.map { deadline > $0 } ?? true }
        .min()
        if forcedReleaseOffer?.deadline == deadline { return }
        forcedReleaseOffer?.task.cancel()
        forcedReleaseOffer = nil
        guard let deadline else { return }
        let wait = waitUntil
        let task = Task { [weak self] in
            do { try await wait(deadline) } catch { return }
            await self?.checkForcedReleaseOffer(due: deadline)
        }
        forcedReleaseOffer = (deadline, task)
    }

    private func checkForcedReleaseOffer(due deadline: ContinuousClock.Instant) async {
        guard forcedReleaseOffer?.deadline == deadline, !Task.isCancelled else { return }
        forcedReleaseOffer = nil
        // An operation in progress keeps its own view of the disks; `busy` ends it.
        guard !busy else { return }
        lastForcedReleaseOfferDeadline = deadline
        await refreshConnectionHealth()
    }

    /// The confirmation explains a lost connection only when one was observed; a disk still
    /// connected to its server, for example one in use, keeps the general warning.
    func forceEjectionMessage(_ request: ForceEjectionRequest) -> String {
        request.reportsLostConnection
            ? String(
                localized:
                    "The connection to the server was lost. Changes that haven’t been saved to the disk will be lost."
            )
            : String(localized: "Unsaved changes on this disk may be lost.")
    }

    /// The name in a force ejection's confirmation: the name the disk's row shows, unless
    /// the request knows a volume name that the row no longer can.
    func forceEjectionName(_ request: ForceEjectionRequest) -> String {
        guard let disk = attached.first(where: { $0.id == request.diskID }),
            request.displayName == disk.descriptor.targetName
        else { return request.displayName }
        return name(of: disk)
    }

    func prepareForceEjection(_ id: UUID) {
        perform(
            activity: String(localized: "Checking disk…"),
            failureContext: { [self] in
                attached.first { $0.id == id }.map { ejectionContext(for: $0) } ?? .general
            },
            operation: { [self] in
                guard let coordinator else { throw ProtocolError.invalidState }
                do {
                    forceEjectionRequest = try await coordinator.prepareForceEjection(id)
                } catch {
                    attached = await coordinator.disks
                    applyRecoveryState(await coordinator.recoveryState)
                    // The coordinator refuses a disk observed connected and verified again,
                    // for example a server back before the click; say so rather than suggest
                    // checking a healthy disk.
                    if case AttachmentError.recoveryRequired = error,
                        await coordinator.isOperationReady,
                        let disk = attached.first(where: { $0.id == id }),
                        disk.connectionState == .connected, !disk.needsCleanup,
                        disk.resourceCleanupError == nil
                    {
                        throw ForcedReleaseWithdrawn()
                    }
                    throw error
                }
            })
    }

    func forceEject(_ request: ForceEjectionRequest) {
        guard !busy, forceEjectionRequest == request else { return }
        // Consume the visible confirmation before perform dismisses other pending requests.
        forceEjectionRequest = nil
        let name = forceEjectionName(request)
        perform(
            activity: String(localized: "Ejecting disk…"),
            context: .ejectingDisk(name, id: request.diskID),
            failureContext: { [self] in
                .ejectingDisk(
                    name,
                    connectionState: attached.first { $0.id == request.diskID }?.connectionState
                        ?? .unknown, id: request.diskID)
            },
            operation: { [self] in
                guard let coordinator else { throw ProtocolError.invalidState }
                do {
                    try await coordinator.forceEject(request)
                } catch {
                    attached = await coordinator.disks
                    applyRecoveryState(await coordinator.recoveryState)
                    await cleanupUnusedConnectionCredentials()
                    throw error
                }
                attached = await coordinator.disks
                applyRecoveryState(await coordinator.recoveryState)
                await cleanupUnusedConnectionCredentials()
            })
    }

    func cancelForceEjection(_ request: ForceEjectionRequest) async {
        if forceEjectionRequest == request { forceEjectionRequest = nil }
        await coordinator?.cancelForceEjection(request)
    }

    func dismissForceEjection(_ request: ForceEjectionRequest) {
        if forceEjectionRequest == request { forceEjectionRequest = nil }
        let coordinator = coordinator
        Task { await coordinator?.cancelForceEjection(request) }
    }

    func ejectAll() async -> Bool {
        guard !busy, let coordinator else { return attached.isEmpty }
        let dismissedForceRequest = forceEjectionRequest
        forceEjectionRequest = nil
        serverRemovalRequest = nil
        connectionRevision = UUID()
        mountedRedirectEpoch &+= 1
        busy = true
        activity = String(localized: "Ejecting disks…")
        defer {
            busy = false
            activity = ""
        }
        var failedDisk: AttachedDisk?
        if let dismissedForceRequest {
            await coordinator.cancelForceEjection(dismissedForceRequest)
        }
        await synchronizeMountedRedirectContext()
        do {
            for disk in attached {
                failedDisk = disk
                try await coordinator.eject(disk.id)
            }
        } catch {
            attached = await coordinator.disks
            applyRecoveryState(await coordinator.recoveryState)
            await cleanupUnusedConnectionCredentials()
            issue = await makeIssue(
                error, context: failedDisk.map { ejectionContext(for: $0) } ?? .general)
            return false
        }
        attached = await coordinator.disks
        applyRecoveryState(await coordinator.recoveryState)
        await cleanupUnusedConnectionCredentials()
        return true
    }

    func cancel() {
        guard let work, !work.isCancelled else { return }
        activity = String(localized: "Canceling…")
        work.cancel()
    }
    func choiceKey(_ server: ServerProfile, _ target: String) -> String {
        choiceKey(serverID: server.id, target)
    }
    private func choiceKey(serverID: UUID, _ target: String) -> String { "\(serverID)|\(target)" }

    /// The capacity of a target's only readable disk, when its disks have been viewed.
    func knownCapacity(of target: DiscoveredTarget, on server: ServerProfile) -> UInt64? {
        let capacities = (choices[choiceKey(server, target.name)] ?? []).compactMap {
            $0.information?.capacity.byteCount
        }
        return capacities.count == 1 ? capacities[0] : nil
    }

    func existingConnection(for disk: FoundDisk) -> AttachedDisk? {
        attached.first {
            $0.descriptor.targetName == disk.targetName && $0.descriptor.lun == disk.lun
        }
    }

    /// LUNs in ascending order. Comparing the reported address bytes keeps every address
    /// distinct and orders the usual single-level addresses by number.
    nonisolated static func lunPrecedes(_ lhs: LogicalUnit, _ rhs: LogicalUnit) -> Bool {
        lhs.wireBytes.lexicographicallyPrecedes(rhs.wireBytes)
    }

    /// Target names in the order Finder sorts names, then by their exact text, so the order
    /// never depends on the order the server reported them in.
    nonisolated static func targetNamePrecedes(_ lhs: String, _ rhs: String) -> Bool {
        switch lhs.localizedStandardCompare(rhs) {
        case .orderedAscending: true
        case .orderedDescending: false
        case .orderedSame: lhs < rhs
        }
    }

    /// The targets found on a server, in a stable order, or nil before a search.
    func availableTargets(on server: ServerProfile) -> [DiscoveredTarget]? {
        targets[server.id]?.sorted { Self.targetNamePrecedes($0.name, $1.name) }
    }

    /// A target's disks by LUN, or nil before they're read.
    func availableDisks(_ target: DiscoveredTarget, on server: ServerProfile) -> [FoundDisk]? {
        choices[choiceKey(server, target.name)]?.sorted { Self.lunPrecedes($0.lun, $1.lun) }
    }

    /// The disks connected from a server, by target and LUN like Available Disks. The order
    /// of `attached` itself is unchanged.
    func connectedDisks(on server: ServerProfile) -> [AttachedDisk] {
        attached.filter { $0.descriptor.profileID == server.id }.sorted {
            if $0.descriptor.targetName != $1.descriptor.targetName {
                return Self.targetNamePrecedes($0.descriptor.targetName, $1.descriptor.targetName)
            }
            if $0.descriptor.lun != $1.descriptor.lun {
                return Self.lunPrecedes($0.descriptor.lun, $1.descriptor.lun)
            }
            return $0.id.uuidString < $1.id.uuidString
        }
    }

    /// The name of a connected disk in its row, its VoiceOver labels and its alerts. A disk
    /// without a mounted volume is called by its LUN, which a disk of another target on the
    /// same server can share, under Connected Disks or Available Disks. Then, as Finder tells
    /// apart items of the same name, the name adds its target's short name, the one Available
    /// Disks shows: "Disk 0 — archive". If another such target has the same short name, the
    /// name adds the target's full name instead.
    func name(of disk: AttachedDisk) -> String {
        let name = disk.displayName
        guard disk.attachment?.volumeURLs.first == nil else { return name }
        let server = disk.descriptor.profileID
        let target = disk.descriptor.targetName
        let lun = disk.descriptor.lun
        // The same target and LUN is the same disk, as `existingConnection(for:)` finds it.
        var namesakes = attached.filter {
            $0.descriptor.profileID == server && $0.displayName == name
                && !($0.descriptor.targetName == target && $0.descriptor.lun == lun)
        }.map(\.descriptor.targetName)
        for listed in targets[server] ?? [] {
            for found in choices[choiceKey(serverID: server, listed.name)] ?? []
            where String(localized: "Disk \(found.lun.displayIdentifier)") == name
                && !(found.targetName == target && found.lun == lun)
            {
                namesakes.append(found.targetName)
            }
        }
        guard !namesakes.isEmpty else { return name }
        let short = DiscoveredTarget.friendlyName(for: target)
        let qualifier =
            namesakes.contains { DiscoveredTarget.friendlyName(for: $0) == short } ? target : short
        return String(
            localized: "\(name) — \(qualifier)",
            comment: "A disk's name, then the target that tells it apart from another disk")
    }

    private func cleanupUnusedConnectionCredentials() async {
        await synchronizeMountedRedirectContext()
        guard let configuration else { return }
        if !connectionStatusNeedsAttention {
            try? await configuration.pruneMountedRedirectReceipts(
                contextEpoch: mountedRedirectEpoch)
        }
        // A cancelled connect still needs to recover its durable cleanup intent.
        if !connectionStatusNeedsAttention {
            let contexts = mountedCredentials
            try? await Task.detached { try await configuration.retryCleanup(protecting: contexts) }
                .value
        }
        await updateConfigurationState()
    }

    private func synchronizeMountedRedirectContext() async {
        guard let configuration else { return }
        await configuration.setMountedRedirectContext(
            epoch: mountedRedirectEpoch, descriptors: attached.map(\.descriptor),
            inventoryVerified: !connectionStatusNeedsAttention)
    }

    /// Remember metadata without disturbing a disk that has already connected. The
    /// actor also checks the epoch, descriptor and durable receipt before saving.
    private func rememberMountedRedirects(epoch: UInt64) async {
        guard epoch == mountedRedirectEpoch, !connectionStatusNeedsAttention,
            document != nil, let configuration
        else { return }
        let revision = connectionRevision
        let observations = attached.compactMap {
            disk -> (ConnectionDescriptor, ConnectionRouteReport)? in
            guard disk.phase == .connected, !disk.verificationFailed,
                disk.connectionState == .connected, disk.attachment != nil,
                let report = disk.connectionRoute
            else { return nil }
            return (disk.descriptor, report)
        }.sorted { $0.1.creationOrder < $1.1.creationOrder }
        do {
            for (descriptor, report) in observations {
                guard epoch == mountedRedirectEpoch, revision == connectionRevision else { return }
                try await configuration.rememberMountedRedirects(
                    report, descriptor: descriptor, contextEpoch: epoch)
            }
            guard epoch == mountedRedirectEpoch, revision == connectionRevision else { return }
            try await configuration.pruneMountedRedirectReceipts(contextEpoch: epoch)
        } catch {
            guard epoch == mountedRedirectEpoch, revision == connectionRevision else { return }
            if !(error is CancellationError) { issue = AppIssue(error) }
        }
        guard epoch == mountedRedirectEpoch, revision == connectionRevision else { return }
        await updateConfigurationState()
    }

    private func session(for server: ServerProfile, target: DiscoveredTarget? = nil) async throws
        -> SessionConnection
    {
        guard let identity = document?.identity else { throw ProtocolError.invalidState }
        let addresses =
            try target?.connectionAddresses(
                fallback: discoveryPortals[server.id] ?? server.portal)
            ?? [TargetAddress(portal: server.portal)]
        let chap: CHAPCredentials?
        let context =
            target == nil ? server.discoveryCredentialContext : server.credentialContext
        if let context {
            chap = try await credentials.credentials(context: context)
        } else {
            chap = nil
        }
        let configuration = try LoginConfiguration(
            initiatorName: identity.name, targetName: target?.name, credentials: chap)
        let cached = document?.permanentRedirects(for: server, targetName: target?.name) ?? []
        let id = UUID()
        let wait = LocalNetworkAccessWait { [weak self] in
            Task { @MainActor [weak self] in
                guard let self, networkAccessWaitID == id else { return }
                waitingForLocalNetworkAccess = networkAccessWait?.isWaiting ?? false
            }
        }
        networkAccessWaitID = id
        networkAccessWait = wait
        defer {
            if networkAccessWaitID == id {
                networkAccessWaitID = nil
                networkAccessWait = nil
                waitingForLocalNetworkAccess = false
            }
        }
        do {
            return try await sessionFactory(addresses, configuration, cached, wait)
        } catch ProtocolError.connectionClosed where !Task.isCancelled {
            // The session factory connects and logs in, so the server closed the connection
            // during the login. A refused connection, a timeout or a reset is another error.
            throw LoginClosedByServer()
        }
    }

    private func rememberRedirects(
        _ connection: SessionConnection, server: ServerProfile, targetName: String?
    ) async throws {
        guard let configuration, document?.servers.contains(server) == true else { return }
        do {
            try await configuration.rememberPermanentRedirects(
                connection.permanentRedirects, invalidating: connection.invalidatedRedirectSources,
                for: server, targetName: targetName, contextEpoch: mountedRedirectEpoch)
        } catch {
            await updateConfigurationState()
            throw error
        }
        await updateConfigurationState()
    }

    nonisolated private static func openSession(
        addresses: [TargetAddress], configuration: LoginConfiguration,
        cachedRedirects: [PermanentPortalRedirect], localNetworkAccessWait: LocalNetworkAccessWait?
    )
        async throws -> SessionConnection
    {
        try await SessionConnector.connect(
            addresses: addresses, configuration: configuration, cachedRedirects: cachedRedirects,
            localNetworkAccessWait: localNetworkAccessWait)
    }

    /// Runs one operation at a time. Unless `reportsFailure` is false, as for a check that
    /// nobody asked for, a failure is shown in an alert.
    private func perform(
        activity: String, context: AppIssue.Context = .general,
        failureContext: (@MainActor () -> AppIssue.Context)? = nil,
        readOnlyRecovery: ReadOnlyConnectionRequest? = nil, reportsFailure: Bool = true,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        guard !busy else { return }
        dismissReadOnlyConnection()
        let dismissedForceRequest = forceEjectionRequest
        forceEjectionRequest = nil
        serverRemovalRequest = nil
        connectionRevision = UUID()
        mountedRedirectEpoch &+= 1
        let id = UUID()
        operationID = id
        busy = true
        self.activity = activity
        work = Task {
            defer {
                if operationID == id {
                    busy = false
                    self.activity = ""
                    work = nil
                }
            }
            do {
                if let dismissedForceRequest {
                    await coordinator?.cancelForceEjection(dismissedForceRequest)
                }
                await synchronizeMountedRedirectContext()
                try Task.checkCancellation()
                try await operation()
            } catch {
                if reportsFailure, !(error is CancellationError) {
                    issue = await makeIssue(
                        error, context: failureContext?() ?? context,
                        readOnlyRecovery: readOnlyRecovery)
                }
            }
        }
    }

    private func makeIssue(
        _ error: any Error, context: AppIssue.Context,
        readOnlyRecovery: ReadOnlyConnectionRequest? = nil
    ) async -> AppIssue {
        let recovery = readOnlyRecovery.flatMap { isCurrentReadOnlyConnection($0) ? $0 : nil }
        var context = context
        // A refusal because the connections must be checked again isn't about this disk;
        // only one still waiting for an earlier ejection of it is.
        if case AttachmentError.recoveryRequired = error, case .ejectingDisk = context,
            let coordinator, !(await coordinator.isOperationReady)
        {
            context = .general
        }
        // A server can't be edited while its disks are connected, so a search's or a disk
        // reading's issue says to eject them first rather than offer an editor that won't open.
        switch context {
        case .findingDisks(let server, _)
        where attached.contains(where: { $0.descriptor.profileID == server.id }):
            context = .findingDisks(server, disksConnected: true)
        case .viewingDisks(let server, _)
        where attached.contains(where: { $0.descriptor.profileID == server.id }):
            context = .viewingDisks(server, disksConnected: true)
        default: break
        }
        var issue = AppIssue(error, context: context, readOnlyConnectionRequest: recovery)
        if case .ejectingDisk(_, _, let id) = context, let id, let coordinator,
            await coordinator.canPrepareForceEjection(id)
        {
            issue.forceEjectionDiskID = id
        }
        // Offer to edit the server only when its editor will open. The issue still says what
        // to change, for example after its disks are ejected.
        if issue.recoveryAction == .editServer,
            !(issue.serverID.map(canEditServerAfterOperation) ?? false)
        {
            issue.recoveryAction = nil
            issue.serverID = nil
        }
        return issue
    }
}

/// Passes each notification it observes on as an event, whichever thread posts it.
private final class NotificationRelay: NSObject, Sendable {
    private let continuation: AsyncStream<LockedCleanupRetryEvent>.Continuation

    init(_ continuation: AsyncStream<LockedCleanupRetryEvent>.Continuation) {
        self.continuation = continuation
    }

    @objc func screenUnlocked(_ notification: Notification) {
        continuation.yield(.screenUnlocked)
    }

    @objc func applicationActivated(_ notification: Notification) {
        continuation.yield(.applicationActivated)
    }
}

/// Cancellation and an SDK response can race, including before the waiter is installed.
/// The lock protects a single result; continuations always resume outside the lock.
private final class ExtensionCheckReply: @unchecked Sendable {
    private typealias Outcome = Result<AppModel.ExtensionState, any Error>
    private let lock = NSLock()
    private var result: Outcome?
    private var waiter: CheckedContinuation<AppModel.ExtensionState, any Error>?

    func wait(_ continuation: CheckedContinuation<AppModel.ExtensionState, any Error>) {
        let completed = lock.withLock { () -> Outcome? in
            if let result { return result }
            waiter = continuation
            return nil
        }
        if let completed { continuation.resume(with: completed) }
    }

    func finish(_ outcome: Result<AppModel.ExtensionState, any Error>) {
        let continuation = lock.withLock {
            () -> CheckedContinuation<AppModel.ExtensionState, any Error>? in
            guard result == nil else { return nil }
            result = outcome
            defer { waiter = nil }
            return waiter
        }
        continuation?.resume(with: outcome)
    }
}
