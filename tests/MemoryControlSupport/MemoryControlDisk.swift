import CryptoKit
import Dispatch
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork

/// Test-only diagnostic: callbacks operate on memory, not durable remote storage.
/// The archived control42 factory is required for native reproduction; production
/// targets neither depend on this module nor expose the diagnostic xattrs.
actor MemoryControlDisk: ImageDisk {
    nonisolated let capacity: DiskCapacity
    nonisolated let isReadOnly = false
    static let pageSize = 65_536
    private let source: any ImageDisk
    private let clock: @Sendable () -> UInt64
    private let loadedAt: UInt64
    private let seedSHA256: String
    private var pages: [Data]
    private var changed: Set<Int> = []
    private var versions = 0
    private var closed = false
    private var history: [Snapshot] = []
    private var exportTask: (UInt64, Task<Data, any Error>)?
    private var reads = 0
    private var writes = 0
    private var syncs = 0

    private struct Snapshot: Sendable {
        let completedAt: UInt64
        let pages: [Data]
        let changed: Set<Int>
    }

    static func load(
        source: any ImageDisk,
        clock: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) async throws -> MemoryControlDisk {
        let count = source.capacity.byteCount
        guard !source.isReadOnly, count > 0, count <= 512 * 1_048_576,
            count % UInt64(pageSize) == 0
        else { throw POSIXError(.EINVAL) }
        var pages: [Data] = []
        var hash = SHA256()
        for offset in stride(from: UInt64(0), to: count, by: 1_048_576) {
            let size = Int(min(1_048_576, count - offset))
            let data = try await source.read(offset: Int64(offset), length: size)
            guard data.count == size else { throw POSIXError(.EIO) }
            hash.update(data: data)
            for index in stride(from: 0, to: size, by: pageSize) {
                pages.append(data.subdata(in: index..<(index + pageSize)))
            }
        }
        return MemoryControlDisk(
            source: source, pages: pages,
            seedSHA256: hash.finalize().map { String(format: "%02x", $0) }.joined(), clock: clock)
    }

    private init(
        source: any ImageDisk, pages: [Data], seedSHA256: String,
        clock: @escaping @Sendable () -> UInt64
    ) {
        self.source = source
        self.capacity = source.capacity
        self.pages = pages
        self.clock = clock
        self.loadedAt = clock()
        self.seedSHA256 = seedSHA256
    }

    private func check(offset: Int64, count: Int) throws {
        guard !closed else { throw POSIXError(.ENXIO) }
        guard offset >= 0, count >= 0, UInt64(offset) <= capacity.byteCount,
            UInt64(count) <= capacity.byteCount - UInt64(offset)
        else { throw POSIXError(.EINVAL) }
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        try check(offset: offset, count: length)
        reads += 1
        var result = Data()
        var cursor = Int(offset)
        while result.count < length {
            let index = cursor / Self.pageSize
            let start = cursor % Self.pageSize
            let size = min(Self.pageSize - start, length - result.count)
            result.append(pages[index].subdata(in: start..<(start + size)))
            cursor += size
        }
        return result
    }

    func write(offset: Int64, data: Data) async throws {
        try check(offset: offset, count: data.count)
        let affected =
            data.isEmpty ? 0 : (Int(offset) % Self.pageSize + data.count - 1) / Self.pageSize + 1
        guard versions + affected <= 512 else { throw POSIXError(.ENOSPC) }
        var cursor = 0
        while cursor < data.count {
            let location = Int(offset) + cursor
            let index = location / Self.pageSize
            let start = location % Self.pageSize
            let size = min(Self.pageSize - start, data.count - cursor)
            let from = data.startIndex + cursor
            pages[index].replaceSubrange(start..<(start + size), with: data[from..<(from + size)])
            changed.insert(index)
            cursor += size
        }
        versions += affected
        writes += 1
    }

    func synchronize() async throws {
        try check(offset: 0, count: 0)
        // Array and Data have value semantics. Later writes copy changed pages;
        // no network operation or whole-image copy occurs in this callback.
        history.append(Snapshot(completedAt: clock(), pages: pages, changed: changed))
        if history.count > 64 { history.removeFirst() }
        syncs += 1
    }

    func controlInfo() throws -> Data {
        try JSONSerialization.data(
            withJSONObject: [
                "memoryControl": true, "preloadedBytes": capacity.byteCount,
                "seedSHA256": seedSHA256,
                "networkIOInReadWriteSyncCallbacks": false,
                "productionRemoteDurabilityTest": false,
            ], options: [.sortedKeys])
    }

    func exportSnapshot(completedBy cutoff: UInt64) async throws -> Data {
        try check(offset: 0, count: 0)
        if let exportTask {
            guard exportTask.0 == cutoff else { throw POSIXError(.EPERM) }
            return try await exportTask.1.value
        }
        guard cutoff >= loadedAt, cutoff <= clock() else { throw POSIXError(.EINVAL) }
        guard let snapshot = history.last(where: { $0.completedAt <= cutoff }) else {
            throw POSIXError(.EAGAIN)
        }
        // Only this historical immutable state is transported after selection.
        // Never synchronize the live memory image here.
        let metadata: [String: any Sendable] = [
            "requestedCutoffNS": cutoff, "selectedSyncNS": snapshot.completedAt,
            "selectedBeforeCutoff": true, "exportedPages": snapshot.changed.count,
            "pageBytes": Self.pageSize, "memoryReads": reads, "memoryWrites": writes,
            "memorySynchronizations": syncs, "networkIOInReadWriteSyncCallbacks": false,
            "snapshotTransportAfterHistoricalSelection": true,
            "productionRemoteDurabilityTest": false,
        ]
        let source = source
        let task = Task {
            for index in snapshot.changed.sorted() {
                try Task.checkCancellation()
                try await source.write(
                    offset: Int64(index * Self.pageSize), data: snapshot.pages[index])
            }
            try await source.synchronize()
            var hash = SHA256()
            for page in snapshot.pages { hash.update(data: page) }
            var report = metadata
            report["snapshotSHA256"] = hash.finalize().map { String(format: "%02x", $0) }.joined()
            let result = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            return result
        }
        exportTask = (cutoff, task)
        return try await task.value
    }

    func close() async {
        guard !closed else { return }
        closed = true
        pages.removeAll()
        history.removeAll()
        exportTask?.1.cancel()
        await source.close()
    }

    func connectionState() async -> DiskConnectionState { closed ? .closed : .connected }
}
