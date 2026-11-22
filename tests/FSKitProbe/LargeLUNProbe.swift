import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Only accepts a nonce-owned, unformatted 3 TiB loopback LIO fixture.
enum LargeLUNProbe {
    private static let byteCount: UInt64 = 3 * 1024 * 1024 * 1024 * 1024
    private static let boundary: UInt64 = (1 << 32) * 512

    private struct Region: Decodable, Sendable {
        let offset: UInt64
        let before: Data
        let after: Data
    }
    private struct Specification: Decodable, Sendable {
        let nonce: String
        let byteCount: UInt64
        let blockSize: Int
        let regions: [Region]
    }

    static func run(portal: Portal, root: URL, nonce: UUID, readOnly: Bool, chap: Bool) async throws
    {
        let manifest = root.appendingPathComponent("LargeFixture.json")
        let properties = try manifest.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard manifest.resolvingSymlinksInPath() == manifest, properties.isRegularFile == true,
            let length = properties.fileSize, (1...65_536).contains(length)
        else { throw ProtocolError.malformed("large LUN fixture manifest") }
        let spec = try JSONDecoder().decode(Specification.self, from: Data(contentsOf: manifest))
        guard spec.nonce == nonce.uuidString.lowercased(), spec.byteCount == byteCount,
            [512, 4096].contains(spec.blockSize), spec.regions.count == 4,
            readOnly || spec.blockSize == 512,
            spec.regions.map(\.offset) == [
                8 * 1_048_576, boundary - 4096, boundary, byteCount - 4096,
            ],
            spec.regions.allSatisfy({ $0.before.count == 4096 && $0.after.count == 4096 })
        else { throw ProtocolError.malformed("large LUN fixture geometry") }
        if chap {
            try await FSKitProbe.saveFixtureCredential(portal: portal, root: root, nonce: nonce)
        }
        do {
            try await connectAndVerify(
                portal: portal, root: root, nonce: nonce, spec: spec,
                readOnly: readOnly, chap: chap)
        } catch {
            do { try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce) } catch {
                FileHandle.standardError.write(
                    Data("Large fixture credential cleanup failed: \(error)\n".utf8))
            }
            throw error
        }
        try await FSKitProbe.removeFixtureCredential(root: root, nonce: nonce)
    }

    private static func connectAndVerify(
        portal: Portal, root: URL, nonce: UUID, spec: Specification, readOnly: Bool, chap: Bool
    ) async throws {
        let mounts = root.appendingPathComponent("Mounts", isDirectory: true)
        let coordinator = try AttachmentCoordinator(
            backend: SystemAttachmentBackend(root: mounts),
            journal: FileAttachmentJournal(
                directory: root.appendingPathComponent("State", isDirectory: true),
                bridgeRoot: mounts))
        try await coordinator.restore()
        func descriptor(_ readOnly: Bool) throws -> ConnectionDescriptor {
            try ConnectionDescriptor(
                profileID: nonce, portal: portal,
                initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + spec.nonce,
                targetName: "iqn.2026-10.dev.soba:lio-" + spec.nonce, lun: LogicalUnit(0),
                readOnly: readOnly, chapUsername: chap ? "test-user" : nil,
                isid: [0x80, 1, 2, 3, 4, 5], credentialID: chap ? nonce : nil)
        }
        do {
            let initial = try await coordinator.connect(descriptor(readOnly))
            try await exercise(initial, root: root, spec: spec, readOnly: readOnly, changed: false)
            try await coordinator.eject(initial.id)
            if !readOnly {
                let reopened = try await coordinator.connect(descriptor(true))
                try await exercise(reopened, root: root, spec: spec, readOnly: true, changed: true)
                try await coordinator.eject(reopened.id)
            }
            guard await coordinator.disks.isEmpty else { throw AttachmentError.recoveryRequired }
        } catch {
            for disk in await coordinator.disks { try? await coordinator.eject(disk.id) }
            throw error
        }
        print(
            "PASS: 3 TiB capacity, high-offset native and FSKit I/O, readOnly=\(readOnly), normal ejection"
        )
    }

    private static func exercise(
        _ record: AttachedDisk, root: URL, spec: Specification, readOnly: Bool, changed: Bool
    ) async throws {
        guard let attachment = record.attachment, attachment.volumeURLs.isEmpty,
            record.connectionState == .connected, !record.needsCleanup,
            attachment.device.hasPrefix("/dev/disk"), attachment.device.count > 9,
            attachment.device.dropFirst(9).utf8.allSatisfy({ (48...57).contains($0) })
        else { throw ProtocolError.malformed("large LUN native attachment") }
        let image = record.bridgeURL.appendingPathComponent("Disk.img")
        var status = stat()
        guard lstat(image.path, &status) == 0, status.st_size == Int64(byteCount),
            status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), status.st_uid == geteuid(),
            try await DiskImages().inventory().attachment(at: image)?.device == attachment.device
        else { throw AttachmentError.imageIdentityChanged }
        let data = try await SystemCommand.run(
            "/usr/sbin/diskutil", arguments: ["info", "-plist", attachment.device])
        guard
            let info = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any],
            info["TotalSize"] as? UInt64 == byteCount,
            info["DeviceBlockSize"] as? Int == spec.blockSize,
            info["WritableMedia"] as? Bool == !readOnly
        else { throw AttachmentError.invalidImageResponse }
        let raw = URL(fileURLWithPath: "/dev/r" + attachment.device.dropFirst(5))
        let native = try readOnly ? FileHandle(forReadingFrom: raw) : FileHandle(forUpdating: raw)
        defer { try? native.close() }
        let bridge =
            try readOnly ? FileHandle(forReadingFrom: image) : FileHandle(forUpdating: image)
        defer { try? bridge.close() }
        guard fcntl(bridge.fileDescriptor, F_NOCACHE, 1) == 0 else { throw POSIXError(.EIO) }
        let before = spec.regions.map { changed ? $0.after : $0.before }
        try compare(native, regions: spec.regions, contents: before)
        try compare(bridge, regions: spec.regions, contents: before)
        if readOnly {
            try rejectWrite(raw, at: spec.regions[0].offset)
            try rejectWrite(image, at: spec.regions[0].offset)
            try compare(native, regions: spec.regions, contents: before)
        } else {
            for index in [0, 3] {
                try native.seek(toOffset: spec.regions[index].offset)
                try native.write(contentsOf: spec.regions[index].after)
            }
            try bridge.seek(toOffset: boundary - 4096)
            try bridge.write(contentsOf: spec.regions[1].after + Data(repeating: 0x53, count: 4096))
            try bridge.seek(toOffset: boundary + 17)
            try bridge.write(contentsOf: Data(repeating: 0x5A, count: 37))
            try FSKitProbe.checkpoint("before-fsync")
            try native.synchronize()
            try bridge.synchronize()
            try FSKitProbe.checkpoint("after-fsync")
            try FSKitProbe.checkpoint("before-fullfsync")
            guard fcntl(bridge.fileDescriptor, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
            try FSKitProbe.checkpoint("after-fullfsync")
            try compare(native, regions: spec.regions, contents: spec.regions.map(\.after))
            try compare(bridge, regions: spec.regions, contents: spec.regions.map(\.after))
        }
        try bridge.seek(toOffset: byteCount)
        guard try bridge.read(upToCount: 512)?.isEmpty ?? true else {
            throw ProtocolError.malformed("large LUN EOF")
        }
    }

    private static func compare(_ file: FileHandle, regions: [Region], contents: [Data]) throws {
        for (region, expected) in zip(regions, contents) {
            try file.seek(toOffset: region.offset)
            guard try file.read(upToCount: 4096) == expected else {
                throw ProtocolError.malformed("large LUN region at \(region.offset)")
            }
        }
        try file.seek(toOffset: boundary - 4096)
        guard try file.read(upToCount: 8192) == contents[1] + contents[2] else {
            throw ProtocolError.malformed("large LUN boundary crossing")
        }
    }

    private static func rejectWrite(_ url: URL, at offset: UInt64) throws {
        var rejected = false
        do {
            let file = try FileHandle(forUpdating: url)
            defer { try? file.close() }
            try file.seek(toOffset: offset)
            try file.write(contentsOf: Data(repeating: 0xEE, count: 4096))
        } catch { rejected = true }
        guard rejected else { throw ProtocolError.malformed("large LUN read-only write accepted") }
    }
}
