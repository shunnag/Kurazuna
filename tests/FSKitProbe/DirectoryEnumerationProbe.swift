import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Reads a private ordinary directory or an already verified FSKit fixture.
/// Stream positions are only reused on the DIR that produced them.
enum DirectoryEnumerationProbe {
    private struct Entry: Equatable {
        let name: String
        let identifier: UInt64
        let type: UInt8
    }

    static func validate(_ directory: URL, requireFSKit: Bool) throws {
        guard let stream = opendir(directory.path) else { throw systemError() }
        var opened = true
        defer { if opened { _ = closedir(stream) } }
        var volume = statfs()
        guard fstatfs(dirfd(stream), &volume) == 0 else { throw systemError() }
        let typeName = withUnsafeBytes(of: volume.f_fstypename) {
            String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        let expectedType = ApplicationIdentity.current.fileSystemType
        if requireFSKit, typeName != expectedType {
            throw ProtocolError.malformed("directory fixture is not mounted by \(expectedType)")
        }

        func position() throws -> Int {
            errno = 0
            let value = telldir(stream)
            guard errno == 0 else { throw systemError() }
            return value
        }
        func readEntry() throws -> Entry? {
            errno = 0
            guard let value = readdir(stream) else {
                guard errno == 0 else { throw systemError() }
                return nil
            }
            let name = try withUnsafeBytes(of: value.pointee.d_name) { bytes in
                let length = Int(value.pointee.d_namlen)
                guard length > 0, length < bytes.count, bytes[length] == 0 else {
                    throw ProtocolError.malformed("directory entry name length")
                }
                return String(decoding: bytes.prefix(length), as: UTF8.self)
            }
            return Entry(
                name: name, identifier: UInt64(value.pointee.d_ino), type: value.pointee.d_type)
        }
        func remainder() throws -> [Entry] {
            var result: [Entry] = []
            while let entry = try readEntry() {
                guard result.count < 3 else {
                    throw ProtocolError.malformed("unexpected or repeated directory entry")
                }
                result.append(entry)
            }
            return result
        }

        var entries: [Entry] = []
        var positions = [try position()]
        while let entry = try readEntry() {
            guard entries.count < 3 else {
                throw ProtocolError.malformed("unexpected or repeated directory entry")
            }
            entries.append(entry)
            positions.append(try position())
        }
        guard entries.map(\.name).sorted() == [".", "..", "Disk.img"] else {
            throw ProtocolError.malformed("directory fixture entry names")
        }
        for entry in entries {
            let expectedType = entry.name == "Disk.img" ? UInt8(DT_REG) : UInt8(DT_DIR)
            guard entry.type == expectedType else {
                throw ProtocolError.malformed("directory fixture entry type")
            }
            // The host resolves mount/.. outside the mounted root. The root's
            // packed parent ID is instead compared with its own ID below.
            if requireFSKit, entry.name == ".." { continue }
            var info = stat()
            guard lstat(directory.appendingPathComponent(entry.name).path, &info) == 0 else {
                throw systemError()
            }
            guard entry.identifier == UInt64(info.st_ino),
                info.st_mode & S_IFMT == (entry.name == "Disk.img" ? S_IFREG : S_IFDIR)
            else { throw ProtocolError.malformed("directory fixture identifier or type differs") }
        }
        if requireFSKit {
            guard
                entries.first(where: { $0.name == "." })?.identifier
                    == entries.first(where: { $0.name == ".." })?.identifier
            else { throw ProtocolError.malformed("directory root aliases have different IDs") }
        }
        for (index, saved) in positions.enumerated() {
            errno = 0
            seekdir(stream, saved)
            guard errno == 0 else { throw systemError() }
            guard try remainder() == Array(entries.dropFirst(index)) else {
                throw ProtocolError.malformed("directory position lost or repeated entries")
            }
        }
        rewinddir(stream)
        guard try remainder() == entries else {
            throw ProtocolError.malformed("directory rewind changed entries")
        }
        let closed = closedir(stream)
        opened = false
        guard closed == 0 else { throw systemError() }
        let report: [String: Any] = [
            "fileSystem": typeName, "requiredFSKit": requireFSKit,
            "names": entries.map(\.name), "savedPositions": positions.count,
            "positionReplays": positions.count, "rewindVerified": true,
            "entryIdentifiersAndTypesVerified": true,
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: .sortedKeys)
        print("DIRECTORY_ENUMERATION_RESULT " + String(decoding: data, as: UTF8.self))
    }

    private static func systemError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
