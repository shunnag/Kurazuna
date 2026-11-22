import CryptoKit
import Darwin
import Foundation
import ISCSICore

/// Diagnostic only: each native synchronization boundary is sampled while the
/// same file remains open. The target selects historical commits by these times.
enum SynchronizationBoundaryProbe {
    static var mode: String? {
        ProcessInfo.processInfo.environment["ISCSI_TEST_SYNC_BOUNDARIES"]
    }

    private static func initialByteCount(for mode: String) throws -> Int {
        switch mode {
        case "create": 0
        case "overwrite": 65_573
        case "grow": 4096
        case "shrink": 131_149
        default: throw ProtocolError.invalidState
        }
    }

    static func prepareIfRequested(at volume: URL) throws {
        guard let mode else { return }
        let size = try initialByteCount(for: mode)
        if size > 0 {
            try Data(repeating: 0x5c, count: size).write(
                to: volume.appendingPathComponent("FSKit-written.txt"),
                options: .withoutOverwriting)
        }
    }

    static func run(
        root: URL, volume: URL, contents: Data, deviceSync: HFSDeviceSyncProbe? = nil,
        checkpoint: () throws -> Void
    ) throws {
        defer { deviceSync?.close() }
        guard let mode, contents.count == 65_573 else {
            throw ProtocolError.invalidState
        }
        let initialSize = try initialByteCount(for: mode)
        let scope =
            ProcessInfo.processInfo.environment["ISCSI_TEST_SYNC_BOUNDARY_SCOPE"] ?? "directory"
        guard
            ["directory", "file-repeat", "full-only", "volume-only", "file-device"].contains(scope),
            (scope == "file-device") == (deviceSync != nil)
        else {
            throw ProtocolError.invalidState
        }
        let cacheControl = ProcessInfo.processInfo.environment["ISCSI_TEST_HFS_CACHE_CONTROL"]
        guard
            cacheControl == nil
                || (scope == "file-device"
                    && ["whole-zero", "partition-zero", "whole-full"].contains(cacheControl!))
        else {
            throw ProtocolError.invalidState
        }
        var base = mach_timebase_info_data_t()
        guard mach_timebase_info(&base) == KERN_SUCCESS, base.denom != 0 else {
            throw ProtocolError.invalidState
        }
        func now() throws -> UInt64 {
            let (ticks, overflow) = mach_absolute_time().multipliedReportingOverflow(
                by: UInt64(base.numer))
            guard !overflow else { throw ProtocolError.invalidState }
            return ticks / UInt64(base.denom)
        }
        let target = volume.appendingPathComponent("FSKit-written.txt")
        let flags =
            O_WRONLY | O_CLOEXEC | O_NOFOLLOW
            | (mode == "create" ? O_CREAT | O_EXCL : 0)
        let fd = open(target.path, flags, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        let parent = open(volume.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(parent) }
        var status = stat()
        var directory = stat()
        guard fstat(fd, &status) == 0, fstat(parent, &directory) == 0,
            status.st_mode & S_IFMT == S_IFREG, directory.st_mode & S_IFMT == S_IFDIR,
            status.st_dev == directory.st_dev,
            status.st_size == off_t(initialSize)
        else { throw ProtocolError.invalidState }
        try file.write(contentsOf: contents)
        if mode == "shrink", ftruncate(fd, off_t(contents.count)) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var boundaries: [[String: Any]] = []
        func sample(_ name: String, errorCodeResult: Bool = false, _ operation: () -> Int32)
            throws
        {
            let started = try now()
            let result = operation()
            let errorCode = errorCodeResult ? result : (result == 0 ? 0 : errno)
            let completed = try now()
            boundaries.append([
                "name": name, "startedNS": started, "completedNS": completed,
                "result": result, "errorCode": errorCode,
            ])
        }
        func volumeSync() throws {
            try sample("volume-fullsync", errorCodeResult: true) {
                fsync_volume_np(fd, SYNC_VOLUME_FULLSYNC | SYNC_VOLUME_WAIT)
            }
        }
        switch scope {
        case "file-device":
            guard let deviceSync else { throw ProtocolError.invalidState }
            let fileStarted = try now()
            let fileResult = fcntl(fd, F_FULLFSYNC)
            let fileError = fileResult == 0 ? 0 : errno
            let fileCompleted = try now()
            if let cacheControl {
                let cacheStarted = try now()
                let cacheResult = deviceSync.synchronizeScope(cacheControl)
                let cacheCompleted = try now()
                boundaries = [
                    [
                        "name": "file-fullfsync", "startedNS": fileStarted,
                        "completedNS": fileCompleted, "result": fileResult, "errorCode": fileError,
                    ],
                    [
                        "name": "cache-control-" + cacheControl, "startedNS": cacheStarted,
                        "completedNS": cacheCompleted, "result": cacheResult.status,
                        "errorCode": cacheResult.error,
                    ],
                ]
                break
            }
            let firstCacheStarted = try now()
            let firstCacheResult = deviceSync.synchronizeCache()
            let firstCacheCompleted = try now()
            let volumeStarted = try now()
            let volumeResult = fsync_volume_np(fd, SYNC_VOLUME_WAIT)
            let volumeCompleted = try now()
            let lastCacheStarted = try now()
            let lastCacheResult = deviceSync.synchronizeCache()
            let lastCacheCompleted = try now()
            boundaries = [
                [
                    "name": "file-fullfsync", "startedNS": fileStarted,
                    "completedNS": fileCompleted, "result": fileResult, "errorCode": fileError,
                ],
                [
                    "name": "device-cache-sync-after-file", "startedNS": firstCacheStarted,
                    "completedNS": firstCacheCompleted, "result": firstCacheResult.status,
                    "errorCode": firstCacheResult.error,
                ],
                [
                    "name": "volume-wait", "startedNS": volumeStarted,
                    "completedNS": volumeCompleted, "result": volumeResult,
                    "errorCode": volumeResult,
                ],
                [
                    "name": "device-cache-sync-after-volume", "startedNS": lastCacheStarted,
                    "completedNS": lastCacheCompleted, "result": lastCacheResult.status,
                    "errorCode": lastCacheResult.error,
                ],
            ]
        case "full-only":
            try sample("file-fullfsync") { fcntl(fd, F_FULLFSYNC) }
        case "volume-only":
            try volumeSync()
        default:
            try sample("file-fsync") { fsync(fd) }
            try sample("file-fullfsync") { fcntl(fd, F_FULLFSYNC) }
            if scope == "directory" {
                try sample("directory-fsync") { fsync(parent) }
                try sample("directory-fullfsync") { fcntl(parent, F_FULLFSYNC) }
            } else {
                try sample("file-fsync-repeat") { fsync(fd) }
                try sample("file-fullfsync-repeat") { fcntl(fd, F_FULLFSYNC) }
            }
            try volumeSync()
        }
        let report: [String: Any] = [
            "clock": "mach_absolute_time", "mode": mode, "scope": scope,
            "fileHandleStillOpen": true,
            "parentIsSameFilesystem": true, "payloadBytes": contents.count,
            "fileWasPreviouslyPresent": mode != "create", "boundaries": boundaries,
            "initialByteCount": initialSize, "requestedByteCount": contents.count,
            "truncateCalled": mode == "shrink",
            "volumeFlags": cacheControl != nil
                ? 0
                : scope == "file-device"
                    ? SYNC_VOLUME_WAIT : SYNC_VOLUME_FULLSYNC | SYNC_VOLUME_WAIT,
            "initialFileSyncCalled": ["directory", "file-repeat"].contains(scope),
            "volumeSyncCalled": cacheControl == nil
                && ["directory", "file-repeat", "volume-only", "file-device"].contains(
                    scope),
            "noCheckpointsBetweenCalls": true,
            "cacheControl": cacheControl ?? "legacy-four-stage",
        ]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(
                to: root.appendingPathComponent("SynchronizationBoundaries.json"),
                options: .withoutOverwriting)
        try checkpoint()
        try file.close()
    }

    static func recordRecoveryIfRequested(root: URL, actual: Data, expected: Data) throws {
        guard let mode else { return }
        _ = try initialByteCount(for: mode)
        func digest(_ data: Data) -> String {
            SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        let sharedCount = min(actual.count, expected.count)
        try actual.write(
            to: root.appendingPathComponent("RecoveredFileBytes.bin"), options: .withoutOverwriting)
        let report: [String: Any] = [
            "mode": mode, "actualByteCount": actual.count, "expectedByteCount": expected.count,
            "fullContentsMatch": actual == expected,
            "sharedPrefixMatches": actual.prefix(sharedCount) == expected.prefix(sharedCount),
            "actualSHA256": digest(actual), "expectedSHA256": digest(expected),
            "actualBytesFile": "RecoveredFileBytes.bin",
        ]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(
                to: root.appendingPathComponent("RecoveredFileState.json"),
                options: .withoutOverwriting)
    }
}
