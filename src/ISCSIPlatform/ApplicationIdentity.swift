import Foundation

/// Identifiers used by the app, its file system extension and their shared keychain.
public enum ApplicationIdentity: Sendable, CaseIterable {
    case release, development

    #if DEBUG
        public static let current: Self = .development
    #else
        public static let current: Self = .release
    #endif

    public var bundleIdentifier: String {
        self == .release ? "dev.soba.iscsi.kurazuna" : "dev.soba.iscsi.kurazuna.development"
    }

    public var extensionBundleIdentifier: String { bundleIdentifier + ".FileSystem" }
    public var keychainGroupSuffix: String { bundleIdentifier + ".shared" }
    public var credentialService: String { bundleIdentifier + ".chap" }
    public var fileSystemType: String { self == .release ? "kurazuna" : "kurazunadev" }
    public var applicationName: String { self == .release ? "Kurazuna" : "Kurazuna Development" }

    public func supportDirectory(in applicationSupport: URL) -> URL {
        applicationSupport.appendingPathComponent(applicationName, isDirectory: true)
    }

    func permitsKeychainGroup(_ group: String) -> Bool {
        let prefix = group.prefix(10)
        return prefix.utf8.count == 10
            && prefix.utf8.allSatisfy { (65...90).contains($0) || (48...57).contains($0) }
            && group == String(prefix) + "." + keychainGroupSuffix
    }
}
