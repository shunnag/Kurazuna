import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor ReplyLatch {
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        released = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

private final class ReplySyncState: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    func finish() { lock.withLock { completed = true } }
    var isCompleted: Bool { lock.withLock { completed } }
}

private actor ReplyDisk: ImageDisk {
    nonisolated let capacity: DiskCapacity
    nonisolated let isReadOnly = false
    nonisolated let syncState = ReplySyncState()
    let syncStarted = ReplyLatch()
    let releaseSync = ReplyLatch()
    private let failSync: Bool
    var writes = 0
    var syncs = 0

    init(failSync: Bool) throws {
        self.failSync = failSync
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes.put(UInt64(7), at: 0)
        bytes.put(UInt32(512), at: 8)
        capacity = try DiskCapacity(readCapacity16: Data(bytes))
    }
    func read(offset: Int64, length: Int) async throws -> Data { Data(count: length) }
    func write(offset: Int64, data: Data) async throws { writes += 1 }
    func synchronize() async throws {
        syncs += 1
        await syncStarted.release()
        await releaseSync.wait()
        syncState.finish()
        if failSync { throw POSIXError(.EIO) }
    }
    func close() async {}
    func connectionState() async -> DiskConnectionState { .connected }
}

private final class ReplyObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var replies: [(Int, Int?, Bool)] = []
    func append(_ count: Int, _ error: (any Error)?, syncCompleted: Bool) {
        lock.withLock { replies.append((count, (error as NSError?)?.code, syncCompleted)) }
    }
    func values() -> [(Int, Int?, Bool)] { lock.withLock { replies } }
}

@Test(arguments: [false, true])
private func objectiveCWriteReplyWaitsForSyncAndReportsTheOutcomeOnce(_ failSync: Bool) async throws
{
    let disk = try ReplyDisk(failSync: failSync)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let observation = ReplyObservation()
    let operation = Task {
        try await withCheckedThrowingContinuation { (reply: CheckedContinuation<Int, any Error>) in
            (volume as any FSVolume.ReadWriteOperations).write(
                contents: Data([1, 2, 3]), to: volume.imageItem, at: 9,
                replyHandler: { count, error in
                    observation.append(count, error, syncCompleted: disk.syncState.isCompleted)
                    if let error {
                        reply.resume(throwing: error)
                    } else {
                        reply.resume(returning: count)
                    }
                })
        }
    }
    await disk.syncStarted.wait()
    #expect(observation.values().isEmpty)
    #expect(await disk.writes == 1)
    await disk.releaseSync.release()
    if failSync {
        await #expect(throws: POSIXError(.EIO)) { try await operation.value }
    } else {
        #expect(try await operation.value == 3)
    }
    let replies = observation.values()
    #expect(replies.count == 1)
    #expect(replies.first?.0 == (failSync ? 0 : 3))
    #expect(replies.first?.1 == (failSync ? Int(EIO) : nil))
    #expect(replies.first?.2 == true)
    #expect(await disk.syncs == 1)
}

@Test(arguments: [false, true])
private func objectiveCSyncReplyWaitsForCompletionAndReportsTheOutcomeOnce(_ failSync: Bool)
    async throws
{
    let disk = try ReplyDisk(failSync: failSync)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let observation = ReplyObservation()
    let operation = Task {
        try await withCheckedThrowingContinuation { (reply: CheckedContinuation<Void, any Error>) in
            (volume as any FSVolume.Operations).synchronize(
                flags: .wait,
                replyHandler: { error in
                    observation.append(0, error, syncCompleted: disk.syncState.isCompleted)
                    if let error {
                        reply.resume(throwing: error)
                    } else {
                        reply.resume()
                    }
                })
        }
    }
    await disk.syncStarted.wait()
    #expect(observation.values().isEmpty)
    #expect(await disk.writes == 0)
    await disk.releaseSync.release()
    if failSync {
        await #expect(throws: POSIXError(.EIO)) { try await operation.value }
    } else {
        try await operation.value
    }
    let replies = observation.values()
    #expect(replies.count == 1)
    #expect(replies.first?.1 == (failSync ? Int(EIO) : nil))
    #expect(replies.first?.2 == true)
    #expect(await disk.syncs == 1)
}
