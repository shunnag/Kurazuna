import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private let chunkSize = 1_048_576

private func imagePattern(offset: Int64, length: Int) -> Data {
    var data = Data(count: length)
    data.withUnsafeMutableBytes { bytes in
        var cursor = 0
        while cursor < length {
            let position = offset + Int64(cursor)
            let count = min(4096 - Int(position % 4096), length - cursor)
            let part = UnsafeMutableRawBufferPointer(rebasing: bytes[cursor..<(cursor + count)])
            part.initializeMemory(as: UInt8.self, repeating: UInt8((position / 4096) % 251))
            cursor += count
        }
    }
    return data
}

private enum ImageRequest: Equatable {
    case read(Int64, Int)
    case write(Int64, Int)
    case flush, close
}

private enum ChunkFailure { case read, shortRead, write }

/// Keeps the production RemoteDisk's request limit, with independent offset-based contents.
private actor SizedDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = false
    private let holdFirst: Bool
    private let failure: ChunkFailure?
    private let holdFlush: Bool
    private let flushFailure: (any Error)?
    private var reads = 0
    private var writes = 0
    private var sender: CheckedContinuation<Void, Never>?
    private(set) var requests: [ImageRequest] = []
    var isHeld: Bool { sender != nil }

    init(
        holdFirst: Bool = false, failure: ChunkFailure? = nil, holdFlush: Bool = false,
        flushFailure: (any Error)? = nil
    ) throws {
        var bytes = Array(repeating: UInt8(0), count: 32)
        bytes.put(UInt64(65_535), at: 0)
        bytes.put(UInt32(512), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(bytes))
        self.holdFirst = holdFirst
        self.failure = failure
        self.holdFlush = holdFlush
        self.flushFailure = flushFailure
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        guard length <= 16_777_216 else { throw POSIXError(.EINVAL) }
        requests.append(.read(offset, length))
        reads += 1
        if holdFirst, reads + writes == 1 { await withCheckedContinuation { sender = $0 } }
        if reads == 2, failure == .read { throw ProtocolError.timedOut }
        return imagePattern(
            offset: offset, length: length - (reads == 2 && failure == .shortRead ? 1 : 0))
    }
    func write(offset: Int64, data: Data) async throws {
        guard data.count <= 16_777_216 else { throw POSIXError(.EINVAL) }
        guard data == imagePattern(offset: offset, length: data.count) else {
            throw ProtocolError.malformed("image chunk content")
        }
        requests.append(.write(offset, data.count))
        writes += 1
        if holdFirst, reads + writes == 1 { await withCheckedContinuation { sender = $0 } }
        if writes == 2, failure == .write { throw ProtocolError.timedOut }
    }
    func release() {
        sender?.resume()
        sender = nil
    }
    func synchronize() async throws {
        requests.append(.flush)
        if holdFlush { await withCheckedContinuation { sender = $0 } }
        if let flushFailure { throw flushFailure }
    }
    func close() async { requests.append(.close) }
    func connectionState() async -> DiskConnectionState { .connected }
}

private final class ReadCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let start: Int64
    private var count = 0
    private var sizes: [Int] = []
    var received: Int { lock.withLock { count } }
    var chunkLengths: [Int] { lock.withLock { sizes } }

    init(start: Int64) { self.start = start }

    func copy(_ data: Data, at displacement: Int) throws {
        try lock.withLock {
            guard displacement == count, data.count <= chunkSize,
                data == imagePattern(offset: start + Int64(displacement), length: data.count)
            else { throw ProtocolError.malformed("image read content or displacement") }
            count += data.count
            sizes.append(data.count)
        }
    }
}

private func imagePhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test func aLargeFSKitWriteIsNotRejectedByTheRemoteDisksRequestLimit() async throws {
    let disk = try SizedDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    // A sliced Data may have a nonzero startIndex. Its first byte still belongs at offset 511.
    let contents = (Data([0, 0, 0]) + imagePattern(offset: 511, length: 16_777_217)).dropFirst(3)
    #expect(contents.startIndex == 3)
    #expect(
        try await volume.write(contents: contents, to: volume.imageItem, at: 511) == contents.count)
    let expected = (0..<17).map { index in
        ImageRequest.write(511 + Int64(index * chunkSize), index == 16 ? 1 : chunkSize)
    }
    #expect(await disk.requests == expected + [.flush])
}

@Test func aLargeFSKitReadStreamsIntoTheDestinationWithoutAnAggregateDiskRead() async throws {
    let disk = try SizedDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let collector = ReadCollector(start: 511)
    let count = 16_777_217
    #expect(
        try await volume.readChunks(
            from: volume.imageItem, at: 511, length: count, bufferLength: count,
            consume: collector.copy) == count)
    #expect(collector.received == count)
    #expect(collector.chunkLengths == Array(repeating: chunkSize, count: 16) + [1])
    #expect(await disk.requests.count == 17)
}

private enum FollowingIO { case synchronize, closeWriter, read, write }

@Test(arguments: [false, true], [FollowingIO.synchronize, .closeWriter, .read, .write])
private func aWholeFSKitTransferKeepsItsPlaceAheadOfFollowingIO(
    _ reading: Bool, _ following: FollowingIO
) async throws {
    let disk = try SizedDisk(holdFirst: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    let count = 2 * chunkSize + 17
    let collector = ReadCollector(start: 511)
    let work = Task {
        if reading {
            _ = try await volume.readChunks(
                from: volume.imageItem, at: 511, length: count, bufferLength: count,
                consume: collector.copy)
        } else {
            _ = try await volume.write(
                contents: imagePattern(offset: 511, length: count), to: volume.imageItem, at: 511)
        }
    }
    try await imagePhase { await disk.isHeld }
    let next = Task {
        switch following {
        case .synchronize: try await volume.synchronize(flags: .wait)
        case .closeWriter: try await volume.closeItem(volume.imageItem, modes: [])
        case .read:
            let collector = ReadCollector(start: 0)
            _ = try await volume.readChunks(
                from: volume.imageItem, at: 0, length: 32, bufferLength: 32,
                consume: collector.copy)
        case .write:
            _ = try await volume.write(
                contents: imagePattern(offset: 0, length: 32), to: volume.imageItem, at: 0)
        }
    }
    try await imagePhase { await volume.queuedIOCount == 1 }
    #expect(await disk.requests.count == 1)
    await disk.release()
    try await work.value
    try await next.value
    var expected = (0..<3).map { index in
        let offset = 511 + Int64(index * chunkSize)
        let size = index == 2 ? 17 : chunkSize
        return reading ? ImageRequest.read(offset, size) : .write(offset, size)
    }
    if !reading { expected.append(.flush) }
    switch following {
    case .synchronize, .closeWriter: expected.append(.flush)
    case .read: expected.append(.read(0, 32))
    case .write: expected += [.write(0, 32), .flush]
    }
    #expect(await disk.requests == expected)
    if reading { #expect(collector.received == count) }
}

@Test(arguments: [ChunkFailure.read, .shortRead, .write])
private func aFailedChunkStopsTheTransferAndDoesNotReplayEarlierChunks(
    _ failure: ChunkFailure
) async throws {
    let disk = try SizedDisk(failure: failure)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let count = 2 * chunkSize + 17
    let collector = ReadCollector(start: 511)
    await #expect(throws: POSIXError(failure == .shortRead ? .EIO : .ETIMEDOUT)) {
        if failure == .write {
            _ = try await volume.write(
                contents: imagePattern(offset: 511, length: count), to: volume.imageItem, at: 511)
        } else {
            _ = try await volume.readChunks(
                from: volume.imageItem, at: 511, length: count, bufferLength: count,
                consume: collector.copy)
        }
    }
    #expect(await disk.requests.count == 2)
    #expect(collector.received == (failure == .write ? 0 : chunkSize))
    // The failed request releases its permit, so a later explicit operation cannot deadlock.
    try await volume.synchronize(flags: .wait)
    #expect(await disk.requests.last == .flush)
}

@Test(arguments: [false, true], [false, true])
private func cancellationAndShutdownStopRemainingChunksAndReleaseQueuedIO(
    _ reading: Bool, _ shutdown: Bool
) async throws {
    let disk = try SizedDisk(holdFirst: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let count = chunkSize + 17
    let collector = ReadCollector(start: 511)
    let work = Task {
        if reading {
            _ = try await volume.readChunks(
                from: volume.imageItem, at: 511, length: count, bufferLength: count,
                consume: collector.copy)
        } else {
            _ = try await volume.write(
                contents: imagePattern(offset: 511, length: count), to: volume.imageItem, at: 511)
        }
    }
    try await imagePhase { await disk.isHeld }
    let flush = Task { try await volume.synchronize(flags: .wait) }
    try await imagePhase { await volume.queuedIOCount == 1 }
    if shutdown { await volume.shutdown() } else { work.cancel() }
    await disk.release()
    await #expect(throws: POSIXError(shutdown ? .EIO : .ECANCELED)) { try await work.value }
    if shutdown {
        await #expect(throws: POSIXError(.EIO)) { try await flush.value }
        #expect(await disk.requests.last == .close)
    } else {
        try await flush.value
        #expect(await disk.requests.last == .flush)
    }
    #expect(await disk.requests.count == 2)
    #expect(collector.received == 0)
}

@Test func imageTransferPreflightChecksRangesAndClipsReadsAtEOF() async throws {
    let disk = try SizedDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let end = Int64(disk.capacity.byteCount)
    let collector = ReadCollector(start: end - 512)
    await #expect(throws: POSIXError(.EFAULT)) {
        try await volume.readChunks(
            from: volume.imageItem, at: 0, length: 1, bufferLength: 0,
            consume: collector.copy)
    }
    await #expect(throws: POSIXError(.ENOSPC)) {
        try await volume.write(
            contents: imagePattern(offset: end - Int64(chunkSize), length: chunkSize + 1),
            to: volume.imageItem, at: end - Int64(chunkSize))
    }
    #expect(await disk.requests.isEmpty)
    #expect(
        try await volume.readChunks(
            from: volume.imageItem, at: end - 512, length: Int.max, bufferLength: 512,
            consume: collector.copy) == 512)
    #expect(collector.received == 512)
    #expect(
        try await volume.readChunks(
            from: volume.imageItem, at: Int64.max, length: Int.max, bufferLength: 0,
            consume: collector.copy) == 0)
    #expect(await disk.requests == [.read(end - 512, 512)])
}

private actor WriteReply {
    private(set) var succeeded = false
    func accept() { succeeded = true }
}

@Test func aWriteWaitsForItsFlushAndKeepsFollowingIOBehindIt() async throws {
    let disk = try SizedDisk(holdFlush: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let reply = WriteReply()
    let write = Task {
        let count = try await volume.write(
            contents: imagePattern(offset: 0, length: 513), to: volume.imageItem, at: 0)
        await reply.accept()
        return count
    }
    try await imagePhase { await disk.isHeld }
    let following = Task {
        try await volume.readChunks(
            from: volume.imageItem, at: 0, length: 1, bufferLength: 1
        ) { _, _ in }
    }
    try await imagePhase { await volume.queuedIOCount == 1 }
    #expect(await disk.requests == [.write(0, 513), .flush])
    #expect(await !reply.succeeded)
    await disk.release()
    #expect(try await write.value == 513)
    #expect(try await following.value == 1)
    #expect(await reply.succeeded)
    #expect(await disk.requests == [.write(0, 513), .flush, .read(0, 1)])
}

@Test(arguments: [false, true])
func aFailedWriteFlushIsReportedWithoutReplayingTheWrite(_ timeout: Bool) async throws {
    let disk = try SizedDisk(
        flushFailure: timeout ? ProtocolError.timedOut : ProtocolError.connectionClosed)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    await #expect(throws: POSIXError(timeout ? .ETIMEDOUT : .EIO)) {
        try await volume.write(
            contents: imagePattern(offset: 0, length: 513), to: volume.imageItem, at: 0)
    }
    #expect(await disk.requests == [.write(0, 513), .flush])
}

@Test func anEmptyWriteDoesNotIssueAFlush() async throws {
    let disk = try SizedDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    #expect(try await volume.write(contents: Data(), to: volume.imageItem, at: 0) == 0)
    #expect(await disk.requests.isEmpty)
}

@Test(arguments: [false, true])
func aLateWriteFlushCannotPublishSuccessAfterCancellationOrShutdown(_ shutdown: Bool) async throws {
    let disk = try SizedDisk(holdFlush: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let write = Task {
        try await volume.write(
            contents: imagePattern(offset: 0, length: 513), to: volume.imageItem, at: 0)
    }
    try await imagePhase { await disk.isHeld }
    if shutdown { await volume.shutdown() } else { write.cancel() }
    await disk.release()
    await #expect(throws: POSIXError(shutdown ? .EIO : .ECANCELED)) { try await write.value }
    #expect(await disk.requests == [.write(0, 513), .flush] + (shutdown ? [.close] : []))
}
