import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Apple sample comparison, restricted by the entry point to a nonce-owned private root.
enum PassthroughControlProbe {
    static func run(root: URL, contents: Data) async throws {
        let files = FileManager.default
        let source = root.appendingPathComponent("PassthroughSource", isDirectory: true)
        let mount = root.appendingPathComponent("PassthroughMount", isDirectory: true)
        guard !files.fileExists(atPath: source.path), !files.fileExists(atPath: mount.path) else {
            throw ProtocolError.invalidState
        }
        try files.createDirectory(
            at: source, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try files.createDirectory(
            at: mount, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let original = root.appendingPathComponent("HFSPlus.cdr")
        let backing = source.appendingPathComponent("HFSPlus.cdr")
        guard clonefile(original.path, backing.path, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard try FixtureFileSystem.digest(of: original) == FixtureFileSystem.digest(of: backing)
        else { throw ProtocolError.malformed("passthrough seed clone") }
        _ = try await SystemCommand.run(
            "/sbin/mount",
            arguments: [
                "-F", "-t", ApplicationIdentity.current.fileSystemType, "-o",
                "nobrowse,nosuid,nodev,noexec,sync", source.path,
                mount.path,
            ], timeout: 60)
        do {
            guard try isMounted(mount) else { throw ProtocolError.invalidState }
            let projected = mount.appendingPathComponent("HFSPlus.cdr")
            try GeometryFixture.validateImage(projected)
            var host = stat()
            var remote = stat()
            guard stat(backing.path, &host) == 0, stat(projected.path, &remote) == 0,
                host.st_size == remote.st_size, host.st_ino == remote.st_ino,
                host.st_dev != remote.st_dev
            else { throw ProtocolError.malformed("passthrough file identity") }
            let data = try JSONSerialization.data(
                withJSONObject: [
                    "sourcePath": source.path, "mountPath": mount.path,
                    "fileID": host.st_ino, "bytes": host.st_size,
                    "distinctMountedDevice": true, "sourceCloneSHA256Matches": true,
                    "officialAppleSample": true, "remoteDurabilityTest": false,
                ], options: [.sortedKeys])
            try data.write(to: root.appendingPathComponent("PassthroughIdentity.json"))
            print("PASS: Apple sample path resource mounted; backing file ID, size and GPT match")
            try await GeometryFixture.writeLocalSynchronizedSnapshot(
                root: root, contents: contents, applePassthrough: true)
            try await recover(root: root)
        } catch {
            try await recover(root: root)
            throw error
        }
    }

    static func recover(root: URL) async throws {
        let mount = root.appendingPathComponent("PassthroughMount", isDirectory: true)
        let images = DiskImages()
        for relative in ["PassthroughMount/HFSPlus.cdr", "HFSPlus.cdr", "Recovered.img"] {
            let image = root.appendingPathComponent(relative)
            if let attachment = try await images.inventory().attachment(at: image) {
                try await images.detach(attachment, at: image)
            }
        }
        if try isMounted(mount) {
            _ = try await SystemCommand.run("/sbin/umount", arguments: [mount.path], timeout: 45)
        }
        guard try !isMounted(mount) else { throw ProtocolError.invalidState }
        print("PASS: private passthrough images and mount normally ejected")
    }

    private static func isMounted(_ mount: URL) throws -> Bool {
        guard FileManager.default.fileExists(atPath: mount.path) else { return false }
        var value = statfs()
        guard statfs(mount.path, &value) == 0 else { throw POSIXError(.EIO) }
        let actual = withUnsafePointer(to: &value.f_mntonname) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
        }
        return actual == mount.path
    }
}
