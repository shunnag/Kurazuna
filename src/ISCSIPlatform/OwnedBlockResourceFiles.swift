import Darwin
import Foundation
import ISCSICore

/// Only fixed-format local marker files live here. These methods never open a bridge volume.
struct OwnedBlockResourceFiles: Sendable {
    private static let identityAttribute = "dev.soba.iscsi.marker-file"
    struct Identity: Sendable, Equatable {
        let device: dev_t
        let inode: ino_t
    }
    let bridgeRoot: URL
    let mounts: @Sendable () throws -> [CachedMountTable.Entry]
    var directory: URL { bridgeRoot.appendingPathComponent(".Resources", isDirectory: true) }

    init(
        bridgeRoot: URL,
        mounts: @escaping @Sendable () throws -> [CachedMountTable.Entry] = CachedMountTable.read
    ) {
        self.bridgeRoot = bridgeRoot.standardizedFileURL
        self.mounts = mounts
    }

    func imageURL(for descriptor: ConnectionDescriptor) throws -> URL {
        let reference = try ConnectionResourceReference(descriptor: descriptor)
        return directory.appendingPathComponent(reference.mountID.uuidString + ".img")
    }

    func create(_ descriptor: ConnectionDescriptor) throws -> Identity {
        let body = try imageBytes(descriptor)
        let name = try imageURL(for: descriptor).lastPathComponent
        let value = try withDirectory(create: true) { fd in
            let file = openat(fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard file >= 0 else { throw Self.posixError() }
            defer { close(file) }
            var created = stat()
            guard fstat(file, &created) == 0 else { throw Self.posixError() }
            do {
                try body.withUnsafeBytes { bytes in
                    var offset = 0
                    while offset < bytes.count {
                        let count = Darwin.write(
                            file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                        if count < 0, errno == EINTR { continue }
                        guard count > 0 else { throw Self.posixError() }
                        offset += count
                    }
                }
                let witness = try Self.identityBytes(
                    created, volumeUUID: Self.readVolumeUUID(file), descriptor: descriptor)
                let stored = witness.withUnsafeBytes {
                    fsetxattr(
                        file, Self.identityAttribute, $0.baseAddress, $0.count, 0, XATTR_CREATE)
                }
                guard stored == 0 else { throw Self.posixError() }
                guard fcntl(file, F_FULLFSYNC) == 0, fsync(fd) == 0 else {
                    throw Self.posixError()
                }
                return try inspectFile(file, descriptor: descriptor, full: true)
            } catch {
                // No device has been attached at this point. Remove only this new inode.
                var current = stat()
                if fstatat(fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                    current.st_dev == created.st_dev, current.st_ino == created.st_ino
                {
                    _ = unlinkat(fd, name, 0)
                    _ = fsync(fd)
                }
                throw error
            }
        }
        guard let value else { throw AttachmentError.ownershipUnverified }
        return value
    }

    func inspect(_ descriptor: ConnectionDescriptor, full: Bool = false) throws -> Identity? {
        let name = try imageURL(for: descriptor).lastPathComponent
        return try withDirectory(create: false) { fd -> Identity? in
            let file = openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            if file < 0 {
                if errno == ENOENT { return nil }
                throw Self.posixError()
            }
            defer { close(file) }
            return try inspectFile(file, descriptor: descriptor, full: full)
        } ?? nil
    }

    /// The caller must first prove that image attachment, mounts, and open handles are absent.
    func remove(_ descriptor: ConnectionDescriptor, expected: Identity) throws {
        let name = try imageURL(for: descriptor).lastPathComponent
        _ = try withDirectory(create: false) { fd in
            let file = openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard file >= 0 else { throw Self.posixError() }
            defer { close(file) }
            var opened = stat()
            guard fstat(file, &opened) == 0 else { throw Self.posixError() }
            guard opened.st_dev == expected.device, opened.st_ino == expected.inode else {
                throw AttachmentError.imageIdentityChanged
            }
            guard try inspectFile(file, descriptor: descriptor, full: true) == expected else {
                throw AttachmentError.imageIdentityChanged
            }
            var current = stat()
            guard fstatat(fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                current.st_dev == expected.device, current.st_ino == expected.inode,
                current.st_mode & S_IFMT == S_IFREG
            else { throw AttachmentError.imageIdentityChanged }
            guard unlinkat(fd, name, 0) == 0, fsync(fd) == 0 else { throw Self.posixError() }
        }
    }

    func hasUntrackedFiles(excluding mountIDs: Set<UUID>) throws -> Bool {
        let allowed = Set(mountIDs.map { $0.uuidString + ".img" })
        return try withDirectory(create: false) { fd in
            let duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else { throw Self.posixError() }
            guard let stream = fdopendir(duplicate) else {
                close(duplicate)
                throw Self.posixError()
            }
            defer { closedir(stream) }
            var count = 0
            while true {
                errno = 0
                guard let item = readdir(stream) else {
                    guard errno == 0 else { throw Self.posixError() }
                    break
                }
                let name = withUnsafeBytes(of: item.pointee.d_name) {
                    String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                }
                if name == "." || name == ".." { continue }
                count += 1
                guard count <= 256 else {
                    throw ProtocolError.limitExceeded("block resource files")
                }
                if !allowed.contains(name) { return true }
            }
            return false
        } ?? false
    }

    private func imageBytes(_ descriptor: ConnectionDescriptor) throws -> Data {
        let marker = BlockMountResource(
            reference: try ConnectionResourceReference(descriptor: descriptor))
        return try marker.encodedHeader()
            + Data(
                repeating: 0,
                count: Int(BlockMountResource.mediaByteCount) - BlockMountResource.headerByteCount)
    }

    private func inspectFile(_ fd: Int32, descriptor: ConnectionDescriptor, full: Bool) throws
        -> Identity
    {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw Self.posixError() }
        guard info.st_uid == geteuid(), info.st_nlink == 1,
            info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o7777 == 0o600,
            info.st_size == Int64(BlockMountResource.mediaByteCount)
        else { throw AttachmentError.ownershipUnverified }
        // Keep st_dev for live FD/path comparisons, but never persist it in new
        // witnesses: the same volume can receive another device number after boot.
        var storedIdentity = Data(count: 58)
        let identityCount = storedIdentity.withUnsafeMutableBytes {
            fgetxattr(fd, Self.identityAttribute, $0.baseAddress, $0.count, 0, 0)
        }
        let expectedIdentity: Data
        if identityCount == 45, storedIdentity.first == 1 {
            // A legacy witness can only prove the exact current device/inode.
            // Do not guess a new volume identity or rewrite an unverified old file.
            expectedIdentity = try Self.legacyIdentityBytes(info, descriptor: descriptor)
        } else if identityCount == 57, storedIdentity.first == 2 {
            expectedIdentity = try Self.identityBytes(
                info, volumeUUID: Self.readVolumeUUID(fd), descriptor: descriptor)
        } else {
            throw AttachmentError.ownershipUnverified
        }
        guard identityCount == expectedIdentity.count,
            storedIdentity.prefix(identityCount) == expectedIdentity
        else { throw AttachmentError.ownershipUnverified }
        let count =
            full ? Int(BlockMountResource.mediaByteCount) : BlockMountResource.headerByteCount
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < count {
                let read = pread(
                    fd, buffer.baseAddress!.advanced(by: offset), count - offset, off_t(offset))
                if read < 0, errno == EINTR { continue }
                guard read > 0 else { throw read == 0 ? POSIXError(.EIO) : Self.posixError() }
                offset += read
            }
        }
        guard
            let marker = try? BlockMountResource(
                header: Data(data.prefix(BlockMountResource.headerByteCount))),
            marker.reference == (try ConnectionResourceReference(descriptor: descriptor))
        else { throw AttachmentError.ownershipUnverified }
        if full, try data != imageBytes(descriptor) { throw AttachmentError.ownershipUnverified }
        return Identity(device: info.st_dev, inode: info.st_ino)
    }

    private func withDirectory<T>(create: Bool, _ operation: (Int32) throws -> T) throws -> T? {
        guard bridgeRoot.isFileURL, bridgeRoot.host?.isEmpty != false,
            bridgeRoot.query == nil, bridgeRoot.fragment == nil,
            bridgeRoot.path.hasPrefix("/"), bridgeRoot.path != "/"
        else { throw POSIXError(.EINVAL) }
        guard
            try !mounts().contains(where: {
                $0.path == bridgeRoot.path || $0.path == directory.path
                    || $0.path.hasPrefix(directory.path + "/")
            })
        else { throw POSIXError(.EBUSY) }
        guard bridgeRoot.resolvingSymlinksInPath().path == bridgeRoot.path else {
            throw AttachmentError.ownershipUnverified
        }
        if create {
            try FileManager.default.createDirectory(
                at: bridgeRoot, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        }
        let root = open(bridgeRoot.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        if root < 0 {
            if errno == ENOENT && !create { return nil }
            throw Self.posixError()
        }
        defer { close(root) }
        try Self.privateDirectory(root)
        if create && mkdirat(root, ".Resources", 0o700) != 0 && errno != EEXIST {
            throw Self.posixError()
        }
        let fd = openat(root, ".Resources", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        if fd < 0 {
            if errno == ENOENT && !create { return nil }
            throw Self.posixError()
        }
        defer { close(fd) }
        try Self.privateDirectory(fd)
        if create && fsync(root) != 0 { throw Self.posixError() }
        let result = try operation(fd)
        var opened = stat()
        var current = stat()
        guard fstat(root, &opened) == 0, lstat(bridgeRoot.path, &current) == 0,
            opened.st_dev == current.st_dev, opened.st_ino == current.st_ino
        else { throw AttachmentError.ownershipUnverified }
        guard fstat(fd, &opened) == 0,
            fstatat(root, ".Resources", &current, AT_SYMLINK_NOFOLLOW) == 0,
            opened.st_dev == current.st_dev, opened.st_ino == current.st_ino
        else { throw AttachmentError.ownershipUnverified }
        return result
    }

    private static func privateDirectory(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_uid == geteuid(), info.st_mode & S_IFMT == S_IFDIR,
            info.st_mode & 0o7777 == 0o700
        else { throw AttachmentError.ownershipUnverified }
    }

    static func readVolumeUUID(_ fd: Int32) throws -> UUID {
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr = attrgroup_t(ATTR_CMN_RETURNED_ATTRS)
        attributes.volattr = attrgroup_t(ATTR_VOL_INFO) | attrgroup_t(ATTR_VOL_UUID)
        // uint32 length, five uint32 returned masks, then uuid_t; all align to 4 bytes.
        var buffer = Data(count: 40)
        let result = buffer.withUnsafeMutableBytes {
            fgetattrlist(fd, &attributes, $0.baseAddress, $0.count, 0)
        }
        guard result == 0 else { throw posixError() }
        return try decodeVolumeUUID(buffer)
    }

    static func decodeVolumeUUID(_ buffer: Data) throws -> UUID {
        guard buffer.count == 40 else { throw AttachmentError.ownershipUnverified }
        func word(_ offset: Int) -> UInt32 {
            buffer.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
        }
        guard word(0) == 40, word(4) == UInt32(ATTR_CMN_RETURNED_ATTRS),
            word(8) & UInt32(ATTR_VOL_UUID) != 0,
            word(8) & ~(UInt32(ATTR_VOL_UUID) | UInt32(ATTR_VOL_INFO)) == 0,
            word(12) == 0, word(16) == 0, word(20) == 0,
            buffer[24..<40].contains(where: { $0 != 0 })
        else { throw AttachmentError.ownershipUnverified }
        return buffer.withUnsafeBytes {
            UUID(uuid: $0.loadUnaligned(fromByteOffset: 24, as: uuid_t.self))
        }
    }

    static func identityBytes(_ info: stat, volumeUUID: UUID, descriptor: ConnectionDescriptor)
        throws -> Data
    {
        var uuid = volumeUUID.uuid
        guard info.st_ino != 0, withUnsafeBytes(of: &uuid, { $0.contains(where: { $0 != 0 }) })
        else { throw AttachmentError.ownershipUnverified }
        var bytes = Data([2])
        withUnsafeBytes(of: &uuid) { bytes.append(contentsOf: $0) }
        bytes.append(
            contentsOf: [56, 48, 40, 32, 24, 16, 8, 0].map {
                UInt8(truncatingIfNeeded: UInt64(info.st_ino) >> $0)
            })
        bytes.append(try descriptor.resourceIdentity)
        return bytes
    }

    private static func legacyIdentityBytes(_ info: stat, descriptor: ConnectionDescriptor) throws
        -> Data
    {
        let device = UInt32(bitPattern: info.st_dev)
        let inode = UInt64(info.st_ino)
        var bytes = Data([1])
        bytes.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: device >> $0) })
        bytes.append(
            contentsOf: [56, 48, 40, 32, 24, 16, 8, 0].map {
                UInt8(truncatingIfNeeded: inode >> $0)
            })
        bytes.append(try descriptor.resourceIdentity)
        return bytes
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
