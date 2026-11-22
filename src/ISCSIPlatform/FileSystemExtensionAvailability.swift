import Darwin
import Foundation

public struct FileSystemExtensionRegistration: Sendable {
    public let bundleIdentifier: String
    public let moduleURL: URL
    public let isEnabled: Bool

    public init(bundleIdentifier: String, moduleURL: URL, isEnabled: Bool) {
        self.bundleIdentifier = bundleIdentifier
        self.moduleURL = moduleURL
        self.isEnabled = isEnabled
    }
}

/// Metadata from the same assessment that controls connection availability.
/// File identities allow diagnostics without retaining installation paths.
public struct FileSystemExtensionAssessment: Sendable, Equatable {
    public struct FileIdentity: Sendable, Equatable {
        public let device: Int32
        public let inode: UInt64
    }

    public let availability: FileSystemExtensionAvailability
    public let matchingModuleCount: Int
    public let enabledMatchingModuleCount: Int
    public let expectedIdentity: FileIdentity?
    public let registeredIdentity: FileIdentity?
}

/// Shared by the app and native validation so neither can select an unrelated
/// installed copy merely because it has the same bundle identifier.
public enum FileSystemExtensionAvailability: Sendable, Equatable {
    case unavailable, disabled, differentCopy, ready

    public static let bundleIdentifier = ApplicationIdentity.current.extensionBundleIdentifier

    public static func expectedModuleURL(in applicationURL: URL) -> URL? {
        guard localPath(applicationURL) != nil, applicationURL.pathExtension.lowercased() == "app"
        else {
            return nil
        }
        return applicationURL.appendingPathComponent(
            "Contents/Extensions/ISCSIFSExtension.appex", isDirectory: true)
    }

    public static func evaluate(
        _ registrations: [FileSystemExtensionRegistration], applicationURL: URL,
        identity: ApplicationIdentity = .current
    ) -> Self {
        assess(registrations, applicationURL: applicationURL, identity: identity).availability
    }

    public static func assess(
        _ registrations: [FileSystemExtensionRegistration], applicationURL: URL,
        identity: ApplicationIdentity = .current
    ) -> FileSystemExtensionAssessment {
        let own = registrations.filter { $0.bundleIdentifier == identity.extensionBundleIdentifier }
        let enabledCount = own.filter(\.isEnabled).count
        func result(
            _ availability: Self,
            expected: FileSystemExtensionAssessment.FileIdentity? = nil,
            registered: FileSystemExtensionAssessment.FileIdentity? = nil
        ) -> FileSystemExtensionAssessment {
            FileSystemExtensionAssessment(
                availability: availability, matchingModuleCount: own.count,
                enabledMatchingModuleCount: enabledCount,
                expectedIdentity: expected, registeredIdentity: registered)
        }
        guard own.count == 1, let expected = expectedModuleURL(in: applicationURL),
            let expectedPath = localPath(expected), let actualPath = localPath(own[0].moduleURL)
        else { return result(.unavailable) }
        var expectedInfo = stat()
        var actualInfo = stat()
        guard stat(expectedPath, &expectedInfo) == 0,
            stat(actualPath, &actualInfo) == 0,
            expectedInfo.st_mode & S_IFMT == S_IFDIR,
            actualInfo.st_mode & S_IFMT == S_IFDIR
        else { return result(.unavailable) }
        let expectedIdentity = FileSystemExtensionAssessment.FileIdentity(
            device: expectedInfo.st_dev, inode: expectedInfo.st_ino)
        let registeredIdentity = FileSystemExtensionAssessment.FileIdentity(
            device: actualInfo.st_dev, inode: actualInfo.st_ino)
        // The same directory may be reached through a symlink, case-insensitive
        // spelling or Unicode normalization. Compare filesystem identity too.
        guard actualInfo.st_dev == expectedInfo.st_dev,
            actualInfo.st_ino == expectedInfo.st_ino
        else {
            return result(
                .differentCopy, expected: expectedIdentity, registered: registeredIdentity)
        }
        return result(
            own[0].isEnabled ? .ready : .disabled,
            expected: expectedIdentity, registered: registeredIdentity)
    }

    private static func localPath(_ url: URL) -> String? {
        guard url.isFileURL, ["", "localhost"].contains(url.host?.lowercased() ?? ""),
            url.query == nil, url.fragment == nil, !url.path.utf8.contains(0)
        else { return nil }
        return url.resolvingSymlinksInPath().standardizedFileURL.path
    }
}
