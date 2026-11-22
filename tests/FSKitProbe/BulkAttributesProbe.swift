import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Reads SDK-defined attribute records with bounds-checked, unaligned loads.
/// No readdir calls share these descriptors with getattrlistbulk.
enum BulkAttributesProbe {
    private struct Record: Equatable {
        let name: String
        let length: Int
        let common: UInt32
        let file: UInt32
        let values: [String: Int64]

        static func == (left: Self, right: Self) -> Bool {
            // The last record's trailing padding can vary with buffer capacity.
            left.name == right.name && left.common == right.common
                && left.file == right.file && left.values == right.values
        }
    }

    private struct Reader {
        let data: Data
        var offset = 0

        mutating func take<T>(_ type: T.Type) throws -> T {
            let size = MemoryLayout<T>.size
            guard offset >= 0, offset <= data.count, size <= data.count - offset else {
                throw ProtocolError.malformed("truncated bulk attribute field")
            }
            defer { offset += size }
            return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: type) }
        }
    }

    private static func request(extended: Bool) -> attrlist {
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr =
            ATTR_BULK_REQUIRED
            | UInt32(
                ATTR_CMN_ERROR | ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID | ATTR_CMN_PARENTID)
        if extended {
            attributes.commonattr |= UInt32(
                ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME
                    | ATTR_CMN_BKUPTIME | ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK
                    | ATTR_CMN_FLAGS | ATTR_CMN_ADDEDTIME)
            attributes.fileattr = UInt32(
                ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE
                    | ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE)
        }
        return attributes
    }

    private static func read(
        _ descriptor: Int32, attributes: attrlist, capacity: Int, packed: Bool
    ) throws -> Record? {
        var attributes = attributes
        var buffer = Data(repeating: 0xa5, count: capacity)
        let count = buffer.withUnsafeMutableBytes {
            getattrlistbulk(
                descriptor, &attributes, $0.baseAddress, $0.count,
                packed ? UInt64(FSOPT_PACK_INVAL_ATTRS) : 0)
        }
        guard count >= 0 else { throw systemError() }
        if count == 0 { return nil }
        guard count == 1 else { throw ProtocolError.malformed("unexpected bulk entry count") }
        var reader = Reader(data: buffer)
        let length = Int(try reader.take(UInt32.self))
        guard length >= 24, length <= capacity else {
            throw ProtocolError.malformed("bulk record length")
        }
        reader = Reader(data: buffer.prefix(length), offset: reader.offset)
        let returned = try reader.take(attribute_set_t.self)
        guard returned.volattr == 0, returned.dirattr == 0, returned.forkattr == 0,
            returned.commonattr & ~attributes.commonattr == 0,
            returned.fileattr & ~attributes.fileattr == 0,
            returned.commonattr & UInt32(ATTR_BULK_REQUIRED) == UInt32(ATTR_BULK_REQUIRED)
        else { throw ProtocolError.malformed("bulk returned attribute mask") }
        let common = packed ? attributes.commonattr : returned.commonattr
        let file = packed ? attributes.fileattr : returned.fileattr
        if common & UInt32(ATTR_CMN_ERROR) != 0 {
            let error = try reader.take(UInt32.self)
            guard error == 0 else {
                throw ProtocolError.malformed("bulk per-entry error \(error)")
            }
        }
        let referencePosition = reader.offset
        let name = try reader.take(attrreference_t.self)
        let nameStart = Int64(referencePosition) + Int64(name.attr_dataoffset)
        let nameLength = Int64(name.attr_length)
        guard nameStart >= 0, nameLength > 1, nameStart <= Int64(length),
            nameLength <= Int64(length) - nameStart
        else { throw ProtocolError.malformed("bulk name reference") }
        let bytes = buffer[Int(nameStart)..<Int(nameStart + nameLength)]
        guard bytes.last == 0, !bytes.dropLast().contains(0),
            let decoded = String(data: bytes.dropLast(), encoding: .utf8)
        else { throw ProtocolError.malformed("bulk name encoding") }
        var values: [String: Int64] = [:]
        func selected(_ mask: UInt32, _ bit: Int32) -> Bool { mask & UInt32(bit) != 0 }
        func time(_ key: String, _ bit: Int32) throws {
            if selected(common, bit) {
                let value = try reader.take(timespec.self)
                if selected(returned.commonattr, bit) {
                    values[key + "Seconds"] = Int64(value.tv_sec)
                    values[key + "Nanoseconds"] = Int64(value.tv_nsec)
                }
            }
        }
        func number32(_ key: String, _ mask: UInt32, _ bit: Int32) throws {
            if selected(mask, bit) { values[key] = Int64(try reader.take(UInt32.self)) }
        }
        func number64(_ key: String, _ mask: UInt32, _ bit: Int32) throws {
            if selected(mask, bit) {
                let value = try reader.take(UInt64.self)
                guard value <= Int64.max else { throw ProtocolError.malformed("bulk integer") }
                values[key] = Int64(value)
            }
        }
        try number32("type", common, ATTR_CMN_OBJTYPE)
        try time("birth", ATTR_CMN_CRTIME)
        try time("modify", ATTR_CMN_MODTIME)
        try time("change", ATTR_CMN_CHGTIME)
        try time("access", ATTR_CMN_ACCTIME)
        try time("backup", ATTR_CMN_BKUPTIME)
        try number32("uid", common, ATTR_CMN_OWNERID)
        try number32("gid", common, ATTR_CMN_GRPID)
        try number32("mode", common, ATTR_CMN_ACCESSMASK)
        try number32("flags", common, ATTR_CMN_FLAGS)
        try number64("fileID", common, ATTR_CMN_FILEID)
        try number64("parentID", common, ATTR_CMN_PARENTID)
        try time("added", ATTR_CMN_ADDEDTIME)
        try number32("links", file, ATTR_FILE_LINKCOUNT)
        try number64("totalSize", file, ATTR_FILE_TOTALSIZE)
        try number64("allocationSize", file, ATTR_FILE_ALLOCSIZE)
        try number32("ioBlockSize", file, ATTR_FILE_IOBLOCKSIZE)
        try number64("dataSize", file, ATTR_FILE_DATALENGTH)
        try number64("dataAllocationSize", file, ATTR_FILE_DATAALLOCSIZE)
        guard reader.offset <= nameStart else {
            throw ProtocolError.malformed("bulk name overlaps fixed fields")
        }
        return Record(
            name: decoded, length: length, common: returned.commonattr,
            file: returned.fileattr, values: values)
    }

    static func validate(_ directory: URL, requireFSKit: Bool) throws {
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw systemError() }
        defer { _ = close(descriptor) }
        var volume = statfs()
        guard fstatfs(descriptor, &volume) == 0 else { throw systemError() }
        let typeName = withUnsafeBytes(of: volume.f_fstypename) {
            String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        let expectedType = ApplicationIdentity.current.fileSystemType
        guard !requireFSKit || typeName == expectedType else {
            throw ProtocolError.malformed("bulk fixture is not mounted by \(expectedType)")
        }
        var parent = stat()
        var image = stat()
        guard fstat(descriptor, &parent) == 0,
            lstat(directory.appendingPathComponent("Disk.img").path, &image) == 0
        else { throw systemError() }
        guard image.st_mode & S_IFMT == S_IFREG else {
            throw ProtocolError.malformed("bulk fixture image is not a regular file")
        }
        var profiles: [[String: Any]] = []
        for (extended, packed) in [(false, false), (true, false), (true, true)] {
            let attributes = request(extended: extended)
            guard lseek(descriptor, 0, SEEK_SET) == 0 else { throw systemError() }
            guard
                let record = try read(
                    descriptor, attributes: attributes, capacity: 4096, packed: packed)
            else { throw ProtocolError.malformed("bulk directory is empty") }
            var expected: [String: Int64] = [
                "type": Int64(VREG.rawValue), "fileID": Int64(image.st_ino),
                "parentID": Int64(parent.st_ino),
            ]
            if extended {
                let times = [
                    "birth": image.st_birthtimespec, "modify": image.st_mtimespec,
                    "change": image.st_ctimespec, "access": image.st_atimespec,
                ]
                for (key, value) in times {
                    expected[key + "Seconds"] = Int64(value.tv_sec)
                    expected[key + "Nanoseconds"] = Int64(value.tv_nsec)
                }
                expected.merge([
                    "uid": Int64(image.st_uid), "gid": Int64(image.st_gid),
                    "flags": Int64(image.st_flags), "links": Int64(image.st_nlink),
                    "totalSize": image.st_size, "dataSize": image.st_size,
                    "allocationSize": image.st_blocks * 512,
                    "dataAllocationSize": image.st_blocks * 512,
                    "ioBlockSize": Int64(image.st_blksize),
                ]) { _, new in new }
                guard
                    record.values["mode"].map({ $0 & 0o7777 })
                        == Int64(image.st_mode & 0o7777)
                else { throw ProtocolError.malformed("bulk mode differs from stat") }
            }
            guard record.name == "Disk.img",
                expected.allSatisfy({ record.values[$0.key] == $0.value }),
                record.common
                    & (attributes.commonattr & ~UInt32(ATTR_CMN_BKUPTIME | ATTR_CMN_ERROR))
                    == attributes.commonattr & ~UInt32(ATTR_CMN_BKUPTIME | ATTR_CMN_ERROR),
                record.file == attributes.fileattr
            else { throw ProtocolError.malformed("bulk attributes differ from stat: \(record)") }
            for _ in 0..<2 {
                guard
                    try read(
                        descriptor, attributes: attributes, capacity: 4096, packed: packed) == nil
                else { throw ProtocolError.malformed("bulk terminal repeated entry") }
            }
            var attempts: [[String: Int]] = []
            for capacity in [16, record.length - 1, record.length, record.length + 8, 4096] {
                guard lseek(descriptor, 0, SEEK_SET) == 0 else { throw systemError() }
                do {
                    guard
                        let actual = try read(
                            descriptor, attributes: attributes, capacity: capacity, packed: packed),
                        actual == record, capacity >= 24
                    else { throw ProtocolError.malformed("bulk rewind changed entry") }
                    attempts.append([
                        "capacity": capacity, "errno": 0, "returnedRecordLength": actual.length,
                    ])
                } catch let error as POSIXError where error.code == .ERANGE {
                    guard capacity < record.length else { throw error }
                    attempts.append(["capacity": capacity, "errno": Int(ERANGE)])
                    // An unsuccessful pack must leave this immutable entry available.
                    guard
                        try read(
                            descriptor, attributes: attributes, capacity: 4096, packed: packed)
                            == record
                    else { throw ProtocolError.malformed("bulk short buffer lost entry") }
                }
                guard
                    try read(
                        descriptor, attributes: attributes, capacity: 4096, packed: packed) == nil
                else { throw ProtocolError.malformed("bulk capacity test repeated entry") }
            }
            profiles.append([
                "extended": extended, "packInvalidAttributes": packed,
                "recordLength": record.length, "returnedCommonMask": record.common,
                "returnedFileMask": record.file, "statMatchedValues": expected,
                "values": record.values, "bufferAttempts": attempts,
                "shortBufferPreservedEntry": true, "terminalAndRewindVerified": true,
            ])
        }
        let report: [String: Any] = [
            "fileSystem": typeName, "requiredFSKit": requireFSKit,
            "name": "Disk.img", "profiles": profiles,
            "individualStatMatched": true, "onlyExpectedEntryReturned": true,
            "noMixedReaddirOnDescriptor": true,
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print("BULK_ATTRIBUTES_RESULT " + String(decoding: data, as: UTF8.self))
    }

    private static func systemError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
