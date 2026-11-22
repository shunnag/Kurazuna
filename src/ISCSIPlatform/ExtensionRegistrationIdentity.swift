import Darwin
import Foundation
import Security

/// Binds a registration attempt to the running code and its current installation.
/// A registration receipt is never evidence that an extension can mount a disk.
struct ExtensionRegistrationIdentity: Codable, Sendable, Equatable {
    struct BundleIdentity: Codable, Sendable, Equatable {
        let path: String
        let device: Int32
        let volumeUUID: UUID
        let inode: UInt64
        let identifier: String
        let team: String
        let codeHash: Data

        var persistent: PersistentBundleIdentity {
            PersistentBundleIdentity(
                path: path, volumeUUID: volumeUUID, inode: inode,
                identifier: identifier, team: team, codeHash: codeHash)
        }
    }

    /// st_dev belongs to a live capture: macOS can renumber it after reboot.
    /// The attempt key still binds the actual volume, placement and signed code.
    struct PersistentBundleIdentity: Codable, Sendable, Equatable {
        let path: String
        let volumeUUID: UUID
        let inode: UInt64
        let identifier: String
        let team: String
        let codeHash: Data
    }

    struct PersistentIdentity: Codable, Sendable, Equatable {
        let uid: UInt32
        let application: PersistentBundleIdentity
        let module: PersistentBundleIdentity
    }

    let uid: UInt32
    let application: BundleIdentity
    let module: BundleIdentity

    var persistent: PersistentIdentity {
        PersistentIdentity(uid: uid, application: application.persistent, module: module.persistent)
    }

    static func capture(applicationURL: URL, identity: ApplicationIdentity) throws -> Self {
        guard let moduleURL = FileSystemExtensionAvailability.expectedModuleURL(in: applicationURL)
        else { throw POSIXError(.EINVAL) }
        var running: SecCode?
        try check(SecCodeCopySelf([], &running))
        guard let running else { throw POSIXError(.EINVAL) }
        try check(SecCodeCheckValidity(running, [], nil))
        let runningInfo = try information(unsafeBitCast(running, to: SecStaticCode.self))
        let (application, appInfo) = try bundle(applicationURL)
        let (module, _) = try bundle(moduleURL)
        guard application.identifier == identity.bundleIdentifier,
            module.identifier == identity.extensionBundleIdentifier,
            !application.team.isEmpty, module.team == application.team,
            runningInfo[kSecCodeInfoIdentifier as String] as? String == application.identifier,
            runningInfo[kSecCodeInfoTeamIdentifier as String] as? String == application.team,
            runningInfo[kSecCodeInfoUnique as String] as? Data == application.codeHash,
            (appInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any])?[
                "com.apple.security.app-sandbox"] as? Bool != true
        else { throw POSIXError(.EACCES) }
        return Self(uid: geteuid(), application: application, module: module)
    }

    private static func bundle(_ url: URL) throws -> (BundleIdentity, [String: Any]) {
        let url = url.resolvingSymlinksInPath().standardizedFileURL
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw posixError() }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0 else { throw posixError() }
        guard before.st_mode & S_IFMT == S_IFDIR else { throw POSIXError(.EINVAL) }
        let volumeUUID = try OwnedBlockResourceFiles.readVolumeUUID(descriptor)
        var code: SecStaticCode?
        try check(SecStaticCodeCreateWithPath(url as CFURL, [], &code))
        guard let code else { throw POSIXError(.EINVAL) }
        try check(
            SecStaticCodeCheckValidity(
                code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode), nil))
        let info = try information(code)
        var after = stat()
        guard lstat(url.path, &after) == 0 else { throw posixError() }
        guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
            let identifier = info[kSecCodeInfoIdentifier as String] as? String,
            let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
            let hash = info[kSecCodeInfoUnique as String] as? Data, !hash.isEmpty
        else { throw POSIXError(.ESTALE) }
        return (
            BundleIdentity(
                path: url.path, device: after.st_dev, volumeUUID: volumeUUID, inode: after.st_ino,
                identifier: identifier, team: team, codeHash: hash), info
        )
    }

    private static func information(_ code: SecStaticCode) throws -> [String: Any] {
        var raw: CFDictionary?
        try check(
            SecCodeCopySigningInformation(
                code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw))
        guard let info = raw as? [String: Any] else { throw POSIXError(.EINVAL) }
        return info
    }

    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
