import CryptoKit
import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Only the disposable probe reads this manifest. It cannot select arbitrary image paths.
enum FixtureFileSystem: String, Codable {
    case apfs
    case exfat
    case hfsPlus = "hfsplus"

    static var usesPlainHFSGeometryControl: Bool {
        ProcessInfo.processInfo.environment["ISCSI_TEST_GEOMETRY_PLAIN_HFS"] == "1"
    }

    private struct Manifest: Decodable { let fileSystem: FixtureFileSystem }

    private struct Space: Codable {
        let total: UInt64
        let free: UInt64
        let available: UInt64
        init(_ url: URL) throws {
            var info = statfs()
            guard statfs(url.path, &info) == 0 else { throw POSIXError(.EIO) }
            let block = UInt64(info.f_bsize)
            total = info.f_blocks * block
            free = info.f_bfree * block
            available = info.f_bavail * block
        }
    }

    static func recordSpace(of volume: URL, at root: URL) throws {
        let data = try JSONEncoder().encode(Space(volume))
        try data.write(to: root.appendingPathComponent("PreparedSpace.json"), options: .atomic)
    }

    static func verifySpace(of volume: URL, at root: URL, readOnly: Bool) throws {
        let file = try FileHandle(forReadingFrom: root.appendingPathComponent("PreparedSpace.json"))
        defer { try? file.close() }
        let data = try file.read(upToCount: 1025) ?? Data()
        guard data.count <= 1024 else {
            throw ProtocolError.limitExceeded("fixture space reference")
        }
        let expected = try JSONDecoder().decode(Space.self, from: data)
        let actual = try Space(volume)
        let tolerance: UInt64 = 1_048_576
        guard actual.total == expected.total,
            actual.free + tolerance >= expected.free, expected.free + tolerance >= actual.free,
            readOnly
                || (actual.available + tolerance >= expected.available
                    && expected.available + tolerance >= actual.available)
        else {
            throw ProtocolError.malformed("native filesystem space differs from prepared fixture")
        }
        print("PASS: native filesystem space agrees with its prepared reference (within 1 MiB)")
    }

    static func at(_ root: URL) throws -> Self {
        let manifest = root.appendingPathComponent("Fixture.json")
        guard FileManager.default.fileExists(atPath: manifest.path) else { return .apfs }
        let handle = try FileHandle(forReadingFrom: manifest)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 1025) ?? Data()
        guard data.count <= 1024 else { throw ProtocolError.limitExceeded("fixture manifest") }
        let format = try JSONDecoder().decode(Manifest.self, from: data).fileSystem
        if usesPlainHFSGeometryControl {
            guard format == .hfsPlus,
                ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "legacy-4k"
            else { throw ProtocolError.malformed("plain HFS geometry control scope") }
        }
        return format
    }

    var imageName: String {
        switch self {
        case .apfs: "APFS.img"
        case .exfat: "ExFAT.img"
        case .hfsPlus: "HFSPlus.cdr"
        }
    }

    var displayName: String {
        switch self {
        case .apfs: "APFS"
        case .exfat: "ExFAT"
        case .hfsPlus:
            Self.usesPlainHFSGeometryControl ? "HFS+ (nonjournaled control)" : "Journaled HFS+"
        }
    }

    static func digest(of image: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: image)
        defer { try? handle.close() }
        var hash = SHA256()
        while let bytes = try handle.read(upToCount: 1_048_576), !bytes.isEmpty {
            hash.update(data: bytes)
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    func create(at root: URL, volumeName: String) async throws {
        let image = root.appendingPathComponent(imageName)
        guard !FileManager.default.fileExists(atPath: image.path) else {
            throw ProtocolError.invalidState
        }
        if self == .hfsPlus {
            // UDTO is a flat sector image. No host disk or caller-supplied device is formatted.
            _ = try await SystemCommand.run(
                "/usr/bin/hdiutil",
                arguments: [
                    "create", "-size", "128m", "-fs", "JHFS+", "-type", "UDTO", "-layout",
                    "GPTSPUD", "-volname", volumeName, image.deletingPathExtension().path,
                ], timeout: 60)
        } else {
            _ = try await SystemCommand.run(
                "/usr/sbin/diskutil",
                arguments: [
                    "image", "create", "blank", "--format", "RAW", "--fs", displayName,
                    "--size", "128MiB", "--volumeName", volumeName, image.path,
                ], timeout: 60)
        }
        // Independently confirm that the file begins with a GPT, not a disk-image wrapper.
        let file = try FileHandle(forReadingFrom: image)
        defer { try? file.close() }
        try file.seek(toOffset: 512)
        guard try file.read(upToCount: 8) == Data("EFI PART".utf8) else {
            throw ProtocolError.malformed("fixture raw partition table")
        }
    }

    func verifyVolume(_ volume: URL, readOnly: Bool) throws {
        var status = statfs()
        guard statfs(volume.path, &status) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let name = withUnsafePointer(to: &status.f_fstypename) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
        }
        let expected = self == .hfsPlus ? "hfs" : rawValue
        guard name == expected, (status.f_flags & UInt32(MNT_RDONLY) != 0) == readOnly else {
            throw ProtocolError.malformed(
                "fixture expected \(expected) readOnly=\(readOnly), found \(name) readOnly=\(status.f_flags & UInt32(MNT_RDONLY) != 0)"
            )
        }
        if self == .hfsPlus,
            ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "legacy-4k"
        {
            let journaled = status.f_flags & UInt32(MNT_JOURNALED) != 0
            guard !Self.usesPlainHFSGeometryControl || !journaled,
                readOnly || Self.usesPlainHFSGeometryControl || journaled
            else {
                throw ProtocolError.malformed("HFS geometry control journal mode")
            }
            print(
                "GEOMETRY_HFS_MOUNT journaled=\(journaled) readOnly=\(readOnly) flags=\(status.f_flags)"
            )
        }
    }
}
