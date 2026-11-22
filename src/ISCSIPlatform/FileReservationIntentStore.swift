import Darwin
import Foundation
import ISCSICore

/// An exclusively leased, bounded intent store. FULL synchronization is required for both the
/// file and its directory. Unsupported synchronization fails closed; ordinary fsync is not a
/// substitute. A publication failure permanently disqualifies this handle from further writes.
public final class FileReservationIntentStore: OwnedReservationIntentStore, @unchecked Sendable {
    private struct Document: Codable {
        let version: Int
        let intents: [OwnedReservationIntent]
    }

    private struct DocumentIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let changedSeconds: Int
        let changedNanoseconds: Int
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        init(_ info: stat) {
            device = info.st_dev
            inode = info.st_ino
            size = info.st_size
            changedSeconds = info.st_ctimespec.tv_sec
            changedNanoseconds = info.st_ctimespec.tv_nsec
            modifiedSeconds = info.st_mtimespec.tv_sec
            modifiedNanoseconds = info.st_mtimespec.tv_nsec
        }
    }

    private let mutex = NSLock()
    private let directory: URL
    private let directoryFD: Int32
    private let lockFD: Int32
    private let lease: FileLease
    private let synchronize: @Sendable (Int32) throws -> Void
    private let name = "ReservationIntents.json"
    private let limit = 16 * 1024 * 1024
    private var uncertain = false
    private var observed: [OwnedReservationIntent]?
    private var observedIdentity: DocumentIdentity?

    public convenience init(directory: URL) throws {
        try self.init(directory: directory, synchronize: Self.fullSync)
    }

    init(directory: URL, synchronize: @escaping @Sendable (Int32) throws -> Void) throws {
        guard directory.isFileURL, directory.host?.isEmpty != false,
            directory.query == nil, directory.fragment == nil,
            directory.standardizedFileURL.path == directory.path
        else { throw POSIXError(.EINVAL) }
        self.directory = directory
        self.synchronize = synchronize
        let parent = directory.deletingLastPathComponent()
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw Self.posix() }
        defer { close(parentFD) }
        try Self.checkDirectory(parentFD)
        var created = false
        if mkdirat(parentFD, directory.lastPathComponent, 0o700) == 0 {
            created = true
        } else if errno != EEXIST {
            throw Self.posix()
        }
        let fd = openat(
            parentFD, directory.lastPathComponent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.posix() }
        do {
            try Self.checkDirectory(fd)
            if created { try synchronize(parentFD) }
            let lockFD = openat(
                fd, "ReservationIntents.lock",
                O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard lockFD >= 0 else { throw Self.posix() }
            do {
                try Self.checkFile(lockFD)
                guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw Self.posix() }
                try Self.verifyAnchor(directory: directory, directoryFD: fd, lockFD: lockFD)
            } catch {
                close(lockFD)
                throw error
            }
            self.directoryFD = fd
            self.lockFD = lockFD
            lease = FileLease(lockedDescriptor: lockFD)
            // Ownership transfers only after all throwing validation. No catch may close a
            // descriptor now owned by deinit/FileLease.
        } catch {
            close(fd)
            throw error
        }
    }

    deinit { close(directoryFD) }

    public func load() throws -> [OwnedReservationIntent] {
        try mutex.withLock {
            guard !uncertain else { throw ProtocolError.invalidState }
            return try read()
        }
    }

    public func insert(_ intent: OwnedReservationIntent) throws {
        try mutex.withLock {
            guard !uncertain else { throw ProtocolError.invalidState }
            try intent.validate()
            var current = try read()
            guard intent.phase == .prepared, intent.revision == 0, current.count < 128,
                !current.contains(where: { $0.id == intent.id || $0.key == intent.key }),
                !current.contains(where: {
                    $0.phase != .released
                        && ($0.binding.logicalUnitNames == intent.binding.logicalUnitNames
                            || ($0.binding.targetName == intent.binding.targetName
                                && $0.binding.lun == intent.binding.lun))
                })
            else { throw ProtocolError.invalidState }
            current.append(intent)
            try publish(current)
        }
    }

    public func advance(_ expected: OwnedReservationIntent, to next: OwnedReservationIntent) throws
    {
        try mutex.withLock {
            guard !uncertain else { throw ProtocolError.invalidState }
            try expected.validate()
            try next.validate()
            guard try expected.advancing(to: next.phase) == next else {
                throw ProtocolError.invalidState
            }
            var current = try read()
            guard let index = current.firstIndex(where: { $0.id == expected.id }),
                current[index] == expected
            else { throw ProtocolError.invalidState }
            current[index] = next
            try publish(current)
        }
    }

    private func read(checkObserved: Bool = true) throws -> [OwnedReservationIntent] {
        try verifyDirectory()
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw Self.posix() }
            try verifyDirectory()
            guard (observed == nil || observed == []) && observedIdentity == nil else {
                throw POSIXError(.ESTALE)
            }
            if checkObserved { observed = [] }
            return []
        }
        defer { close(fd) }
        try Self.checkFile(fd)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size > 0, info.st_size <= limit else {
            throw ProtocolError.limitExceeded("reservation intent store")
        }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        let length = bytes.count
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                Darwin.read(fd, $0.baseAddress!.advanced(by: offset), length - offset)
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw POSIXError(.EIO) }
            offset += count
        }
        var extra: UInt8 = 0
        var count: Int
        repeat { count = Darwin.read(fd, &extra, 1) } while count < 0 && errno == EINTR
        guard count == 0 else { throw POSIXError(.EIO) }
        var finished = stat()
        guard fstat(fd, &finished) == 0, DocumentIdentity(info) == DocumentIdentity(finished) else {
            throw POSIXError(.ESTALE)
        }
        try Self.checkFile(fd)
        try verifyPath(name, descriptor: fd)
        try verifyDirectory()
        let document = try JSONDecoder().decode(Document.self, from: Data(bytes))
        guard document.version == 1, document.intents.count <= 128,
            Set(document.intents.map(\.id)).count == document.intents.count,
            Set(document.intents.map(\.key)).count == document.intents.count
        else { throw ProtocolError.malformed("reservation intent store") }
        for intent in document.intents { try intent.validate() }
        if checkObserved {
            guard
                observed == nil
                    || (observed == document.intents
                        && observedIdentity == DocumentIdentity(finished))
            else { throw POSIXError(.ESTALE) }
            observed = document.intents
        }
        observedIdentity = DocumentIdentity(finished)
        return document.intents
    }

    private func publish(_ intents: [OwnedReservationIntent]) throws {
        let data = try JSONEncoder().encode(Document(version: 1, intents: intents))
        guard data.count <= limit else { throw ProtocolError.limitExceeded("reservation intents") }
        let temporary = ".ReservationIntents-" + UUID().uuidString
        do {
            try verifyDirectory()
            let fd = openat(
                directoryFD, temporary, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw Self.posix() }
            defer { close(fd) }
            // Leave a failed temporary file intact as evidence. Its presence never authorizes I/O.
            try Self.checkFile(fd)
            try data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let count = Darwin.write(
                        fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw Self.posix() }
                    offset += count
                }
            }
            try synchronize(fd)
            try verifyPath(temporary, descriptor: fd)
            try verifyDirectory()
            // Detect unexplained destination changes after the CAS read, including a valid
            // same-content replacement. The private directory remains a trusted user boundary;
            // this check does not promise atomic exclusion of arbitrary same-UID adversaries.
            _ = try read()
            guard renameat(directoryFD, temporary, directoryFD, name) == 0 else {
                throw Self.posix()
            }
            try synchronize(directoryFD)
            try verifyPath(name, descriptor: fd)
            try verifyDirectory()
            guard try read(checkObserved: false) == intents else { throw POSIXError(.EIO) }
            observed = intents
        } catch {
            uncertain = true
            throw error
        }
    }

    private func verifyDirectory() throws {
        try lease.verifyOwner()
        try Self.verifyAnchor(directory: directory, directoryFD: directoryFD, lockFD: lockFD)
    }

    private static func verifyAnchor(directory: URL, directoryFD: Int32, lockFD: Int32) throws {
        try Self.checkDirectory(directoryFD)
        var held = stat()
        var path = stat()
        guard fstat(directoryFD, &held) == 0, lstat(directory.path, &path) == 0,
            held.st_dev == path.st_dev, held.st_ino == path.st_ino,
            path.st_mode & S_IFMT == S_IFDIR
        else { throw POSIXError(.ESTALE) }
        try checkFile(lockFD)
        var locked = stat()
        var lockPath = stat()
        guard fstat(lockFD, &locked) == 0,
            fstatat(directoryFD, "ReservationIntents.lock", &lockPath, AT_SYMLINK_NOFOLLOW) == 0,
            locked.st_dev == lockPath.st_dev, locked.st_ino == lockPath.st_ino
        else { throw POSIXError(.ESTALE) }
    }

    private func verifyPath(_ name: String, descriptor: Int32) throws {
        var held = stat()
        var path = stat()
        guard fstat(descriptor, &held) == 0,
            fstatat(directoryFD, name, &path, AT_SYMLINK_NOFOLLOW) == 0,
            held.st_dev == path.st_dev, held.st_ino == path.st_ino,
            path.st_mode & S_IFMT == S_IFREG, path.st_uid == geteuid(),
            path.st_nlink == 1, path.st_mode & 0o777 == 0o600
        else { throw POSIXError(.ESTALE) }
    }

    private static func checkDirectory(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posix() }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
            info.st_mode & 0o077 == 0
        else { throw POSIXError(.EACCES) }
    }

    private static func checkFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posix() }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
            info.st_nlink == 1, info.st_mode & 0o777 == 0o600
        else { throw POSIXError(.EACCES) }
    }

    private static func fullSync(_ fd: Int32) throws {
        var result: Int32
        repeat { result = fcntl(fd, F_FULLFSYNC) } while result < 0 && errno == EINTR
        guard result == 0 else { throw posix() }
    }

    private static func posix() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
