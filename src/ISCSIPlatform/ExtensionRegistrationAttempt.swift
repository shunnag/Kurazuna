import CryptoKit
import Darwin
import Foundation

/// O_EXCL reserves an installed identity before any registration command. Interrupted
/// or failed attempts remain reserved, including after a restart or app rollback.
final class ExtensionRegistrationAttempt {
    private struct Record: Codable {
        let version: Int
        let event: String
        let identity: ExtensionRegistrationIdentity?
    }

    private let descriptor: Int32

    private init(descriptor: Int32) { self.descriptor = descriptor }
    deinit { close(descriptor) }

    static func claim(
        _ identity: ExtensionRegistrationIdentity, in supportURL: URL
    ) throws -> ExtensionRegistrationAttempt? {
        guard
            [identity.application.volumeUUID, identity.module.volumeUUID].allSatisfy({
                $0.uuidString != "00000000-0000-0000-0000-000000000000"
            })
        else { throw POSIXError(.EINVAL) }
        guard supportURL.isFileURL, supportURL.host?.isEmpty != false,
            supportURL.query == nil, supportURL.fragment == nil, !supportURL.path.utf8.contains(0)
        else { throw POSIXError(.EINVAL) }
        let root = open(supportURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard root >= 0 else { throw posixError() }
        defer { close(root) }
        try checkDirectory(root)
        if mkdirat(root, "ExtensionRegistration", 0o700) != 0, errno != EEXIST {
            throw posixError()
        }
        let directory = openat(
            root, "ExtensionRegistration", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw posixError() }
        defer { close(directory) }
        try checkDirectory(directory)
        guard fsync(root) == 0 else { throw posixError() }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let key = try encoder.encode(identity.persistent)
        // Legacy v1 records lack volume UUIDs. Preserve them without treating
        // a volatile device number as evidence of the current volume.
        let name =
            "v2-" + SHA256.hash(data: key).map { String(format: "%02x", $0) }.joined() + ".jsonl"
        let fd = openat(
            directory, name, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
            0o600)
        if fd < 0 {
            guard errno == EEXIST else { throw posixError() }
            try checkExisting(name, directory: directory, identity: identity)
            return nil
        }
        let attempt = ExtensionRegistrationAttempt(descriptor: fd)
        try attempt.append("claimed", identity: identity)
        guard fsync(directory) == 0 else { throw posixError() }
        return attempt
    }

    func append(_ event: String, identity: ExtensionRegistrationIdentity? = nil) throws {
        var data = try JSONEncoder().encode(Record(version: 2, event: event, identity: identity))
        data.append(0x0a)
        guard data.count <= 32_768 else { throw POSIXError(.EFBIG) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw Self.posixError() }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw Self.posixError() }
    }

    private static func checkExisting(
        _ name: String, directory: Int32, identity: ExtensionRegistrationIdentity
    ) throws {
        let fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw posixError() }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
            info.st_mode & 0o077 == 0, info.st_nlink == 1,
            info.st_size > 0, info.st_size <= 65_536
        else { throw POSIXError(.EACCES) }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        try bytes.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.read(
                    fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw POSIXError(.EIO) }
                offset += count
            }
        }
        guard let newline = bytes.firstIndex(of: 0x0a) else { throw POSIXError(.EIO) }
        let first = try JSONDecoder().decode(Record.self, from: Data(bytes[..<newline]))
        guard first.version == 2, first.event == "claimed",
            first.identity?.persistent == identity.persistent
        else {
            throw POSIXError(.EINVAL)
        }
    }

    private static func checkDirectory(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
            info.st_mode & 0o077 == 0
        else { throw POSIXError(.EACCES) }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
