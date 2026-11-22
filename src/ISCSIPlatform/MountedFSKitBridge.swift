import Darwin
import Foundation
import ISCSICore

/// Observes the kernel's cached mount table without making requests to the volume.
public enum MountedFSKitBridge {
    public static func contains(_ descriptor: ConnectionDescriptor, resourceURL: URL? = nil) -> Bool
    {
        guard let mountID = descriptor.mountID,
            let source = mountSource(for: descriptor, resourceURL: resourceURL)
        else { return false }
        for _ in 0..<3 {
            let count = getfsstat(nil, 0, MNT_NOWAIT)
            guard count >= 0, count <= 4064 else { return false }
            var entries: [statfs] = .init(repeating: statfs(), count: Int(count) + 32)
            let actual = entries.withUnsafeMutableBufferPointer { buffer in
                getfsstat(
                    buffer.baseAddress, Int32(buffer.count * MemoryLayout<statfs>.stride),
                    MNT_NOWAIT)
            }
            guard actual >= 0 else { continue }
            guard Int(actual) < entries.count else { continue }
            return entries.prefix(Int(actual)).contains {
                matches($0, source: source, mountID: mountID, owner: getuid())
            }
        }
        return false
    }

    static func mountSource(for descriptor: ConnectionDescriptor, resourceURL: URL?) -> String? {
        if let resourceURL {
            guard descriptor.acceptsResourceURL(resourceURL) else {
                return nil
            }
            // The kernel retains the mounted spelling. Rebuilding query items can
            // change escaping or order even though the connection is identical.
            return resourceURL.absoluteString
        }
        return try? descriptor.resourceURL.absoluteString
    }

    static func matches(
        _ entry: statfs, source: String, mountID: UUID, owner: uid_t,
        identity: ApplicationIdentity = .current
    ) -> Bool {
        var entry = entry
        guard entry.f_owner == owner else {
            return false
        }
        let type = withUnsafeBytes(of: &entry.f_fstypename) {
            String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
        }
        guard type == identity.fileSystemType else { return false }
        let from = withUnsafeBytes(of: &entry.f_mntfromname) { Array($0.prefix { $0 != 0 }) }
        let expected = Array(source.utf8)
        if from == expected { return true }
        // The source field can truncate a long URL. Only an exact-length prefix
        // plus this mount's random UUID directory establishes that observation.
        let limit = MemoryLayout.size(ofValue: entry.f_mntfromname) - 1
        guard expected.count > limit, from.count == limit,
            from.elementsEqual(expected.prefix(limit))
        else { return false }
        let path = withUnsafeBytes(of: &entry.f_mntonname) {
            String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
        }
        return URL(fileURLWithPath: path).lastPathComponent == mountID.uuidString
    }
}
