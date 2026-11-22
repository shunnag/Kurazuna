import Darwin
import Foundation
import ISCSICore

public enum AttachmentPhase: String, Codable, Sendable {
    case mountingBridge, attachingImage, connected, detachingImage, unmountingBridge
}

public struct AttachmentJournalEntry: Codable, Sendable, Equatable {
    public let id: UUID
    public let descriptor: ConnectionDescriptor
    public let bridgeURL: URL
    public let phase: AttachmentPhase

    public init(id: UUID, descriptor: ConnectionDescriptor, bridgeURL: URL, phase: AttachmentPhase)
        throws
    {
        guard descriptor.mountID == id, bridgeURL.isFileURL, bridgeURL.host?.isEmpty != false,
            bridgeURL.query == nil, bridgeURL.fragment == nil,
            bridgeURL.lastPathComponent == id.uuidString,
            bridgeURL.standardizedFileURL.path == bridgeURL.path
        else {
            throw ProtocolError.malformed("connection journal entry")
        }
        self.id = id
        self.descriptor = descriptor
        self.bridgeURL = bridgeURL
        self.phase = phase
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: c.decode(UUID.self, forKey: .id),
            descriptor: c.decode(ConnectionDescriptor.self, forKey: .descriptor),
            bridgeURL: c.decode(URL.self, forKey: .bridgeURL),
            phase: c.decode(AttachmentPhase.self, forKey: .phase))
    }
}

public protocol AttachmentJournal: Sendable {
    func load() throws -> [AttachmentJournalEntry]
    func save(_ entries: [AttachmentJournalEntry]) throws
}

public final class MemoryAttachmentJournal: AttachmentJournal, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [AttachmentJournalEntry]
    public init(entries: [AttachmentJournalEntry] = []) { self.entries = entries }
    public func load() -> [AttachmentJournalEntry] { lock.withLock { entries } }
    public func save(_ entries: [AttachmentJournalEntry]) {
        lock.withLock { self.entries = entries }
    }
}

/// A private, bounded, atomically replaced journal. Its kernel-held lease excludes another app
/// instance; the presence of a lock file is never treated as evidence of a running process.
public final class FileAttachmentJournal: AttachmentJournal, @unchecked Sendable {
    private struct Document: Codable {
        let version: Int
        let entries: [AttachmentJournalEntry]
    }
    private let lock = NSLock()
    private let directory: URL
    private let bridgeRoot: URL
    private let directoryFD: Int32
    private let lease: FileLease
    private let name = "Connections.json"
    private let limit = 1_048_576

    public init(directory: URL, bridgeRoot: URL) throws {
        guard directory.isFileURL, bridgeRoot.isFileURL,
            directory.host?.isEmpty != false, bridgeRoot.host?.isEmpty != false
        else { throw POSIXError(.EINVAL) }
        let directory = directory.standardizedFileURL.resolvingSymlinksInPath()
        self.directory = directory
        self.bridgeRoot = bridgeRoot.standardizedFileURL.resolvingSymlinksInPath()
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw Self.posixError() }
        do {
            var info = stat()
            guard fstat(directoryFD, &info) == 0 else { throw Self.posixError() }
            guard info.st_uid == geteuid(), info.st_mode & 0o022 == 0 else {
                throw POSIXError(.EACCES)
            }
            let leaseFD = openat(
                directoryFD, "Connections.lock",
                O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
            guard leaseFD >= 0 else { throw Self.posixError() }
            do {
                try Self.checkRegularFile(leaseFD)
                guard flock(leaseFD, LOCK_EX | LOCK_NB) == 0 else { throw Self.posixError() }
            } catch {
                close(leaseFD)
                throw error
            }
            self.directoryFD = directoryFD
            self.lease = FileLease(lockedDescriptor: leaseFD)
        } catch {
            close(directoryFD)
            throw error
        }
    }

    deinit {
        close(directoryFD)
    }

    public func load() throws -> [AttachmentJournalEntry] {
        try lock.withLock {
            try verifyDirectory()
            let fd = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            if fd < 0 {
                if errno == ENOENT { return [] }
                throw Self.posixError()
            }
            defer { close(fd) }
            try Self.checkRegularFile(fd)
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw Self.posixError() }
            guard info.st_size >= 0, info.st_size <= limit else {
                throw ProtocolError.limitExceeded("connection journal")
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
            let document = try JSONDecoder().decode(Document.self, from: Data(bytes))
            guard [1, 2].contains(document.version) else {
                throw ProtocolError.unsupported("connection journal version")
            }
            try validate(document.entries)
            return document.entries
        }
    }

    public func save(_ entries: [AttachmentJournalEntry]) throws {
        try lock.withLock {
            try verifyDirectory()
            try validate(entries)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let version = entries.contains { $0.descriptor.targetCHAPUsername != nil } ? 2 : 1
            let data = try encoder.encode(Document(version: version, entries: entries))
            guard data.count <= limit else {
                throw ProtocolError.limitExceeded("connection journal")
            }
            let temporaryName = ".Connections-\(UUID()).tmp"
            let fd = openat(
                directoryFD, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0o600)
            guard fd >= 0 else { throw Self.posixError() }
            defer {
                close(fd)
                unlinkat(directoryFD, temporaryName, 0)
            }
            try data.withUnsafeBytes { bytes in
                var position = 0
                while position < bytes.count {
                    let count = Darwin.write(
                        fd, bytes.baseAddress!.advanced(by: position), bytes.count - position)
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
    }

    private func validate(_ entries: [AttachmentJournalEntry]) throws {
        guard entries.count <= 128, Set(entries.map(\.id)).count == entries.count else {
            throw ProtocolError.malformed("duplicate or excessive journal entries")
        }
        for entry in entries {
            guard
                entry.bridgeURL.deletingLastPathComponent().standardizedFileURL.path
                    == bridgeRoot.path,
                entry.descriptor.mountID == entry.id
            else { throw ProtocolError.malformed("journal mount path") }
        }
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
            current.st_mode & 0o022 == 0
        else {
            throw POSIXError(.ESTALE)
        }
    }

    private static func checkRegularFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
            info.st_mode & 0o077 == 0
        else {
            throw POSIXError(.EACCES)
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
