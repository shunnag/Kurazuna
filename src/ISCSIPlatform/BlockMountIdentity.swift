import Darwin
import Foundation

/// The resource and private mount name retained by one FSKit load generation.
/// Observations read only the cached kernel mount table, never the mounted namespace.
public struct BlockMountIdentity: Sendable, Equatable {
    public let bsdName: String
    public let mountID: UUID
    public let owner: uid_t
    public let application: ApplicationIdentity

    public init(
        bsdName: String, mountID: UUID, owner: uid_t = getuid(),
        application: ApplicationIdentity = .current
    ) throws {
        guard Self.isValidBSDName(bsdName) else { throw POSIXError(.EINVAL) }
        self.bsdName = bsdName
        self.mountID = mountID
        self.owner = owner
        self.application = application
    }

    public static func isValidBSDName(_ name: String) -> Bool {
        name.utf8.count <= 63
            && name.range(of: #"\Adisk[0-9]+(?:s[0-9]+)*\z"#, options: .regularExpression) != nil
    }

    func matches(type: String, source: String, mountPoint: String, owner: uid_t) -> Bool {
        guard type == application.fileSystemType, source == "/dev/" + bsdName,
            owner == self.owner, mountPoint.hasPrefix("/"), !mountPoint.contains("\0")
        else { return false }
        let url = URL(fileURLWithPath: mountPoint, isDirectory: true)
        return url.standardizedFileURL.path == mountPoint
            && url.deletingLastPathComponent().lastPathComponent == "Mounts"
            && url.lastPathComponent == mountID.uuidString
    }

    public func contains() -> Bool {
        guard let entries = Self.mountTable() else { return false }
        return entries.contains {
            matches(type: $0.type, source: $0.source, mountPoint: $0.path, owner: $0.owner)
        }
    }

    /// Whether anything at all is mounted from this device, at any path, of any type or owner:
    /// nil when the kernel's table could not be read. Only a definite `false` may be taken as
    /// proof that nothing is mounted.
    public func deviceMountState() -> Bool? {
        Self.mountTable().map { $0.contains { $0.source == "/dev/" + bsdName } }
    }

    private struct MountTableEntry {
        let type: String
        let source: String
        let path: String
        let owner: uid_t
    }

    private static func mountTable() -> [MountTableEntry]? {
        for _ in 0..<3 {
            let count = getfsstat(nil, 0, MNT_NOWAIT)
            guard count >= 0, count <= 4064 else { return nil }
            var entries: [statfs] = .init(repeating: statfs(), count: Int(count) + 32)
            let actual = entries.withUnsafeMutableBufferPointer {
                getfsstat(
                    $0.baseAddress, Int32($0.count * MemoryLayout<statfs>.stride), MNT_NOWAIT)
            }
            guard actual >= 0, Int(actual) < entries.count else { continue }
            return entries.prefix(Int(actual)).map { entry in
                var entry = entry
                let type = withUnsafeBytes(of: &entry.f_fstypename) {
                    String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                }
                let source = withUnsafeBytes(of: &entry.f_mntfromname) {
                    String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                }
                let path = withUnsafeBytes(of: &entry.f_mntonname) {
                    String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                }
                return MountTableEntry(type: type, source: source, path: path, owner: entry.f_owner)
            }
        }
        return nil
    }
}
