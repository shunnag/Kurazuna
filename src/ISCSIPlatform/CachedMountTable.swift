import Darwin
import Foundation
import ISCSICore

struct CachedMountTable: Sendable {
    struct FileSystemID: Sendable, Equatable {
        let first: Int32
        let second: Int32
        var isValid: Bool { first != 0 || second != 0 }
    }

    struct Entry: Sendable, Equatable {
        let type: String
        let source: String
        let path: String
        let owner: uid_t
        let flags: UInt32
        let fileSystemID: FileSystemID?

        init(
            type: String, source: String, path: String, owner: uid_t, flags: UInt32,
            fileSystemID: FileSystemID? = nil
        ) {
            self.type = type
            self.source = source
            self.path = path
            self.owner = owner
            self.flags = flags
            self.fileSystemID = fileSystemID
        }
    }

    static func read() throws -> [Entry] {
        for _ in 0..<3 {
            let count = getfsstat(nil, 0, MNT_NOWAIT)
            guard count >= 0 else { throw posixError() }
            guard count <= 4064 else { throw ProtocolError.limitExceeded("mounted filesystems") }
            var entries: [statfs] = .init(repeating: statfs(), count: Int(count) + 32)
            let actual = entries.withUnsafeMutableBufferPointer {
                getfsstat(
                    $0.baseAddress, Int32($0.count * MemoryLayout<statfs>.stride), MNT_NOWAIT)
            }
            guard actual >= 0 else { throw posixError() }
            guard Int(actual) < entries.count else { continue }
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
                return Entry(
                    type: type, source: source, path: path, owner: entry.f_owner,
                    flags: entry.f_flags,
                    fileSystemID: FileSystemID(
                        first: entry.f_fsid.val.0, second: entry.f_fsid.val.1))
            }
        }
        throw ProtocolError.busy
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
