import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform

/// Observes an already captured snapshot without writes, repair, or synchronization calls.
enum JournalViewProbe {
    static func captureIfRequested(root: URL, bridge: URL, attachment: DiskAttachment?) async throws
    {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_JOURNAL_VIEWS"] == "1" else { return }
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_ATTACH_METHOD"] == "legacy-4k",
            try FixtureFileSystem.at(root) == .hfsPlus, let attachment
        else { throw ProtocolError.invalidState }
        let source = root.appendingPathComponent("HFSPlus.cdr")
        try GeometryFixture.validateImage(source)
        // This diagnostic accepts only the particular OS-generated layout that
        // exposed the failure. A different layout must stop, not guess offsets.
        let partition = 24_576
        let volumeHeader = try read(source, offset: partition + 1024, count: 512)
        let bytes = [UInt8](volumeHeader)
        guard volumeHeader.prefix(2) == Data("H+".utf8),
            bytes.uint32(at: 40) == 4096, bytes.uint32(at: 12) == 5
        else { throw ProtocolError.malformed("journal view fixture volume") }
        let info = [UInt8](try read(source, offset: 45_056, count: 180))
        guard info.uint32(at: 0) == 1, info.uint64(at: 36) == 24_576,
            info.uint64(at: 44) == 8_388_608
        else { throw ProtocolError.malformed("journal view fixture info block") }
        let offset = 49_152
        let image = bridge.appendingPathComponent("Disk.img")
        guard try await DiskImages().inventory().attachment(at: image)?.device == attachment.device
        else { throw AttachmentError.imageIdentityChanged }
        let sourceBytes = try read(source, offset: offset, count: 4096)
        let stableBytes = try read(
            root.appendingPathComponent("Stable.img"), offset: offset, count: 4096)
        let cachedBytes = try read(image, offset: offset, count: 4096)
        let raw = URL(fileURLWithPath: "/dev/r" + attachment.device.dropFirst(5))
        let deviceBytes = try read(raw, offset: offset, count: 4096)
        let uncachedBytes = try read(image, offset: offset, count: 4096, uncached: true)
        let views = [
            "source": sourceBytes, "stable": stableBytes, "FSKitCached": cachedBytes,
            "nativeDevice": deviceBytes, "FSKitUncached": uncachedBytes,
        ]
        let record: [String: Any] = [
            "journalAbsoluteOffset": offset, "sectorBytes": 4096,
            "capturedAfterStableSnapshot": true, "fileHandleStillOpen": true,
            "observationOrder": [
                "source", "stable", "FSKitCached", "nativeDevice", "FSKitUncached",
            ],
            "views": views.mapValues { data in
                [
                    "headerHex": data.prefix(64).map { String(format: "%02x", $0) }.joined(),
                    "equalsOriginal": data == sourceBytes,
                ] as [String: Any]
            },
        ]
        for (name, bytes) in views {
            try bytes.write(to: root.appendingPathComponent("JournalView-\(name).bin"))
        }
        try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .prettyPrinted])
            .write(to: root.appendingPathComponent("JournalViews.json"))
        print("CHECK: journal views captured after the pre-close synchronized snapshot")
    }

    private static func read(_ url: URL, offset: Int, count: Int, uncached: Bool = false) throws
        -> Data
    {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        if uncached {
            guard fcntl(file.fileDescriptor, F_NOCACHE, 1) == 0 else { throw POSIXError(.EIO) }
        }
        try file.seek(toOffset: UInt64(offset))
        guard let data = try file.read(upToCount: count), data.count == count else {
            throw POSIXError(.EIO)
        }
        return data
    }
}
