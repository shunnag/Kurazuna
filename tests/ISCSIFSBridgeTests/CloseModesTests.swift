import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor CloseDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly: Bool
    private let holdFlush: Bool
    private var firstFailure: (any Error)?
    private var release: CheckedContinuation<Void, Never>?
    private(set) var flushes = 0
    private(set) var reads = 0
    var isHeld: Bool { release != nil }

    init(
        readOnly: Bool = false, holdFlush: Bool = false, firstFailure: (any Error)? = nil
    ) throws {
        var bytes = Array(repeating: UInt8(0), count: 8)
        bytes.put(UInt32(7), at: 0)
        bytes.put(UInt32(512), at: 4)
        capacity = try DiskCapacity(readCapacity10: Data(bytes))
        isReadOnly = readOnly
        self.holdFlush = holdFlush
        self.firstFailure = firstFailure
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        reads += 1
        return Data(repeating: 0, count: length)
    }
    func write(offset: Int64, data: Data) async throws {}
    func synchronize() async throws {
        flushes += 1
        if holdFlush { await withCheckedContinuation { release = $0 } }
        if let failure = firstFailure {
            firstFailure = nil
            throw failure
        }
    }
    func releaseFlush() {
        release?.resume()
        release = nil
    }
    func close() async {}
    func connectionState() async -> DiskConnectionState { .connected }
}

@Test(arguments: [false, true])
func removingTheLastWriteAccessSynchronizesWithOrWithoutARemainingReader(
    _ keepReader: Bool
) async throws {
    let disk = try CloseDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    try await volume.closeItem(volume.imageItem, modes: keepReader ? .read : [])
    #expect(await disk.flushes == 1)
    // The later reader close has no writer left to synchronize.
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 1)
}

@Test func retainingAWriterDoesNotMeanThatTheWriterHasClosed() async throws {
    let disk = try CloseDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: .write)
    try await volume.openItem(volume.imageItem, modes: .read)
    try await volume.closeItem(volume.imageItem, modes: [.read, .write])
    try await volume.closeItem(volume.imageItem, modes: .write)
    #expect(await disk.flushes == 0)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 1)
    try await volume.openItem(volume.imageItem, modes: .write)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 2)
}

@Test(arguments: [false, true])
func closingAnItemThatWasOnlyReadDoesNotSendATargetFlush(_ readOnly: Bool) async throws {
    let disk = try CloseDisk(readOnly: readOnly)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: .read)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 0)
}

@Test func aDirectoryOrForeignCloseCannotRemoveTheImagesWriteAccess() async throws {
    let disk = try CloseDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let foreign = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: .write)
    try await volume.openItem(volume.rootItem, modes: .read)
    try await volume.closeItem(volume.rootItem, modes: [])
    await #expect(throws: POSIXError(.ESTALE)) {
        try await volume.closeItem(foreign.imageItem, modes: [])
    }
    #expect(await disk.flushes == 0)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 1)
}

@Test(arguments: [false, true])
func aLastWriterCloseReportsTheBarrierFailureAndRetainsThePendingBarrier(
    _ timeout: Bool
) async throws {
    let disk = try CloseDisk(
        firstFailure: timeout ? ProtocolError.timedOut : ProtocolError.connectionClosed)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: .write)
    await #expect(throws: POSIXError(timeout ? .ETIMEDOUT : .EIO)) {
        try await volume.closeItem(volume.imageItem, modes: [])
    }
    #expect(await disk.flushes == 1)
    // Only this explicit later close may retry the barrier. There is no automatic retry.
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 2)
}

private actor CloseReply {
    private(set) var completed = false
    func complete() { completed = true }
}

private func awaitClosePhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test func theLastWriterCloseWaitsForItsBarrierAndKeepsFollowingIOBehindIt() async throws {
    let disk = try CloseDisk(holdFlush: true)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: .write)
    let reply = CloseReply()
    let close = Task {
        try await volume.closeItem(volume.imageItem, modes: [])
        await reply.complete()
    }
    do {
        try await awaitClosePhase { await disk.isHeld }
        let read = Task {
            try await volume.readChunks(
                from: volume.imageItem, at: 0, length: 1, bufferLength: 1
            ) { _, _ in }
        }
        try await awaitClosePhase { await volume.queuedIOCount == 1 }
        #expect(await !reply.completed)
        #expect(await disk.reads == 0)
        await disk.releaseFlush()
        try await close.value
        #expect(try await read.value == 1)
        #expect(await reply.completed)
        #expect(await disk.flushes == 1)
    } catch {
        await disk.releaseFlush()
        try await close.value
        throw error
    }
}
