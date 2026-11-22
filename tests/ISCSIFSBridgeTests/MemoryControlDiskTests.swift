import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge
@testable import ISCSIMemoryControlSupport

private final class ControlClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 1
    func now() -> UInt64 { lock.withLock { value } }
    func set(_ value: UInt64) { lock.withLock { self.value = value } }
}

private actor ControlSource: ImageDisk {
    nonisolated let capacity: DiskCapacity
    nonisolated let isReadOnly = false
    var reads = 0
    var writes = 0
    var syncs = 0
    var closes = 0
    private var bytes = Data(repeating: 0x31, count: 131_072)

    init() throws {
        var response = [UInt8](repeating: 0, count: 32)
        response.put(UInt64(31), at: 0)
        response.put(UInt32(4096), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(response))
    }
    func read(offset: Int64, length: Int) async throws -> Data {
        reads += 1
        return bytes.subdata(in: Int(offset)..<(Int(offset) + length))
    }
    func write(offset: Int64, data: Data) async throws {
        writes += 1
        bytes.replaceSubrange(Int(offset)..<(Int(offset) + data.count), with: data)
    }
    func synchronize() async throws { syncs += 1 }
    func close() async { closes += 1 }
    func connectionState() async -> DiskConnectionState { .connected }
}

@Test func historicalMemorySnapshotExcludesLaterWritesAndDoesNotFlushLiveState() async throws {
    let source = try ControlSource()
    let clock = ControlClock()
    let disk = try await MemoryControlDisk.load(source: source, clock: clock.now)
    #expect(await source.reads == 1)
    try await disk.write(offset: 65_530, data: Data(repeating: 0xA1, count: 37))
    clock.set(100)
    try await disk.synchronize()
    try await disk.write(offset: 65_530, data: Data(repeating: 0xB2, count: 37))
    clock.set(200)
    try await disk.synchronize()
    #expect(try await disk.read(offset: 65_530, length: 37) == Data(repeating: 0xB2, count: 37))
    #expect(await source.reads == 1)
    #expect(await source.writes == 0)
    #expect(await source.syncs == 0)
    clock.set(300)
    async let first = disk.exportSnapshot(completedBy: 150)
    async let duplicate = disk.exportSnapshot(completedBy: 150)
    let results = try await (first, duplicate)
    #expect(results.0 == results.1)
    #expect(try await source.read(offset: 65_530, length: 37) == Data(repeating: 0xA1, count: 37))
    #expect(await source.writes == 2)
    #expect(await source.syncs == 1)
    #expect(try await disk.read(offset: 65_530, length: 37) == Data(repeating: 0xB2, count: 37))
    let metadata = try #require(try JSONSerialization.jsonObject(with: results.0) as? [String: Any])
    #expect(metadata["selectedSyncNS"] as? UInt64 == 100)
    #expect(metadata["memorySynchronizations"] as? Int == 2)
    await #expect(throws: POSIXError(.EPERM)) {
        try await disk.exportSnapshot(completedBy: 250)
    }
    await disk.close()
    await disk.close()
    #expect(await source.closes == 1)
}

@Test func memoryControlRejectsUnretainedFutureAndInvalidRangesWithoutSourceWrites() async throws {
    let source = try ControlSource()
    let clock = ControlClock()
    let disk = try await MemoryControlDisk.load(source: source, clock: clock.now)
    clock.set(100)
    await #expect(throws: POSIXError(.EAGAIN)) { try await disk.exportSnapshot(completedBy: 50) }
    await #expect(throws: POSIXError(.EINVAL)) { try await disk.exportSnapshot(completedBy: 101) }
    for value in 1...70 {
        clock.set(UInt64(value + 100))
        try await disk.synchronize()
    }
    await #expect(throws: POSIXError(.EAGAIN)) { try await disk.exportSnapshot(completedBy: 102) }
    await #expect(throws: POSIXError(.EINVAL)) {
        try await disk.write(offset: 131_072, data: Data([0]))
    }
    await #expect(throws: POSIXError(.EINVAL)) { try await disk.read(offset: -1, length: 1) }
    #expect(await source.writes == 0)
    #expect(await source.syncs == 0)
    await disk.close()
    await #expect(throws: POSIXError(.ENXIO)) { try await disk.synchronize() }
}
