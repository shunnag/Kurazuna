import Darwin
import Foundation
import ISCSICore

public protocol ProfileStorage: Sendable {
    func loadOrCreate() throws -> ProfileDocument
    func load() throws -> ProfileDocument
    func save(_ document: ProfileDocument) throws
}

/// A private, bounded settings file with a process-held lease and durable atomic replacement.
/// A failed save may have committed; callers must reload before performing credential cleanup.
public final class ProfileStore: ProfileStorage, @unchecked Sendable {
    public let url: URL
    private let lock = NSLock()
    private let directory: URL
    private let directoryFD: Int32
    private let lease: FileLease
    private let name: String
    private let limit = 1_048_576

    public init(url: URL) throws {
        guard url.isFileURL, url.host?.isEmpty != false, url.query == nil, url.fragment == nil,
            !["", ".", ".."].contains(url.lastPathComponent),
            url.lastPathComponent.utf8.count <= 128,
            !url.lastPathComponent.utf8.contains(0)
        else { throw POSIXError(.EINVAL) }
        directory = url.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath()
        name = url.lastPathComponent
        self.url = directory.appendingPathComponent(name)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw Self.posixError() }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw Self.posixError() }
            guard info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
                throw POSIXError(.EACCES)
            }
            let lease = openat(
                fd, name + ".lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
            guard lease >= 0 else { throw Self.posixError() }
            do {
                try Self.checkRegularFile(lease)
                guard flock(lease, LOCK_EX | LOCK_NB) == 0 else { throw Self.posixError() }
            } catch {
                close(lease)
                throw error
            }
            directoryFD = fd
            self.lease = FileLease(lockedDescriptor: lease)
        } catch {
            close(fd)
            throw error
        }
    }

    deinit {
        close(directoryFD)
    }

    public func loadOrCreate() throws -> ProfileDocument {
        try lock.withLock {
            if let document = try readDocument() { return document }
            let document = try ProfileDocument(identity: .makeNew())
            try writeDocument(document)
            return document
        }
    }

    public func load() throws -> ProfileDocument {
        try lock.withLock {
            guard let document = try readDocument() else { throw POSIXError(.ENOENT) }
            return document
        }
    }

    public func save(_ document: ProfileDocument) throws {
        try lock.withLock { try writeDocument(document) }
    }

    private func readDocument() throws -> ProfileDocument? {
        try verifyDirectory()
        let fd = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw Self.posixError()
        }
        defer { close(fd) }
        try Self.checkRegularFile(fd)
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw Self.posixError() }
        guard info.st_size >= 0, info.st_size <= limit else {
            throw ProtocolError.limitExceeded("profile document")
        }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        try bytes.withUnsafeMutableBytes { buffer in
            var position = 0
            while position < buffer.count {
                let count = Darwin.read(
                    fd, buffer.baseAddress!.advanced(by: position), buffer.count - position)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw count == 0 ? POSIXError(.EIO) : Self.posixError() }
                position += count
            }
        }
        var extra: UInt8 = 0
        var count: Int
        repeat { count = Darwin.read(fd, &extra, 1) } while count < 0 && errno == EINTR
        guard count == 0 else { throw POSIXError(.EIO) }
        return try JSONDecoder().decode(ProfileDocument.self, from: Data(bytes))
    }

    private func writeDocument(_ document: ProfileDocument) throws {
        try verifyDirectory()
        let validated = try ProfileDocument(
            identity: document.identity, servers: document.servers,
            pendingCredentialRemovals: document.pendingCredentialRemovals,
            permanentRedirects: document.permanentRedirects,
            handledMountRedirects: document.handledMountRedirects)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(validated)
        guard data.count <= limit else { throw ProtocolError.limitExceeded("profile document") }
        let temporaryName = ".Servers-\(UUID()).tmp"
        let fd = openat(
            directoryFD, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Self.posixError() }
        defer {
            close(fd)
            unlinkat(directoryFD, temporaryName, 0)
        }
        try data.withUnsafeBytes { buffer in
            var position = 0
            while position < buffer.count {
                let count = Darwin.write(
                    fd, buffer.baseAddress!.advanced(by: position), buffer.count - position)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw Self.posixError() }
                position += count
            }
        }
        guard fsync(fd) == 0 else { throw Self.posixError() }
        guard renameat(directoryFD, temporaryName, directoryFD, name) == 0 else {
            throw Self.posixError()
        }
        guard fsync(directoryFD) == 0 else { throw Self.posixError() }
    }

    private func verifyDirectory() throws {
        try lease.verifyOwner()
        var original = stat()
        var current = stat()
        guard fstat(directoryFD, &original) == 0, lstat(directory.path, &current) == 0 else {
            throw Self.posixError()
        }
        guard original.st_dev == current.st_dev, original.st_ino == current.st_ino,
            current.st_mode & S_IFMT == S_IFDIR, current.st_uid == geteuid(),
            current.st_mode & 0o077 == 0
        else { throw POSIXError(.ESTALE) }
    }

    private static func checkRegularFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
            info.st_nlink == 1, info.st_mode & 0o077 == 0
        else { throw POSIXError(.EACCES) }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
