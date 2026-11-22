import Foundation
import ISCSIPlatform

/// Settings lists the development app separately from the distributed app.
/// Name the entry the user actually needs to select.
struct AppPermissionGuidance {
    private let name: String

    init(identity: ApplicationIdentity = .current) {
        name = identity.applicationName
    }

    var enableTitle: String { String(localized: "Allow \(name) to Connect Disks") }
    var installationTitle: String { String(localized: "Check the \(name) Installation") }
    var moveTitle: String { String(localized: "Move \(name) in Finder") }
    var moveMessage: String {
        String(
            localized:
                "This copy is running from a read-only location. Eject connected disks and quit \(name). In Finder, drag the app into Applications and open it there. If it is already there, move it to another folder in Finder, then move it back."
        )
    }
    var launchFailureTitle: String {
        String(localized: "The \(name) Extension Couldn’t Be Started")
    }
    var enableMessage: String {
        String(
            localized:
                "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then turn on \(name)."
        )
    }
    var installationMessage: String {
        String(
            localized:
                "macOS has registered another copy of \(name). Eject connected disks and quit any other copy, then click Use This Copy to switch the registration to the app you opened."
        )
    }
    var unavailableMessage: String {
        String(
            localized:
                "\(name) couldn’t check its file system extension. Click Check Again. If the problem continues, reinstall \(name)."
        )
    }
    var launchFailureMessage: String {
        String(
            localized:
                "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then check that \(name) is enabled. If it’s already enabled, eject any connected iSCSI disks and restart your Mac, then try again."
        )
    }
    var localNetworkMessage: String {
        String(
            localized:
                "Allow access when asked, or check \(name) in System Settings > Privacy & Security > Local Network."
        )
    }
    var localNetworkIssueMessage: String {
        String(
            localized:
                "Check \(name)’s access in System Settings > Privacy & Security > Local Network. If you just allowed access, try again."
        )
    }
}

/// The name people see for this copy of the app, such as in its window and alerts.
/// The Development edition and the memory-only preview have their own names.
enum AppName {
    static var display: String {
        if let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String,
            !name.isEmpty
        {
            return name
        }
        return ApplicationIdentity.current.applicationName
    }

    /// The name within an alert's sentence. No-break spaces keep a name of several words,
    /// such as the Development edition's, on one line when the sentence wraps.
    static var inSentence: String { inSentence(display) }

    static func inSentence(_ name: String) -> String {
        name.replacingOccurrences(of: " ", with: "\u{00A0}")
    }
}

/// A name someone chose, such as a server's or a volume's, within an alert's title. Like the
/// application's name, a short name of several words stays on one line when the title wraps.
/// A longer name couldn't fit on one line of an alert anyway, so it still wraps at its spaces.
/// Only the title's text changes: the saved name and the rows and their VoiceOver labels keep
/// ordinary spaces, and speech reads a no-break space as a space. Japanese text can still
/// break between its characters.
enum NameInTitle {
    /// About one line of an alert's title.
    static let longestKeptTogether = 24

    static func keptTogether(_ name: String) -> String {
        name.count <= longestKeptTogether ? AppName.inSentence(name) : name
    }
}
