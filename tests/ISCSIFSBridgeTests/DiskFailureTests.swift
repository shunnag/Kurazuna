import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor Signal {
    private var signalled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if signalled { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func signal() {
        signalled = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

private actor FaultDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = false
    private let failure: (any Error)?
    private let release: Signal?
    let started = Signal()
    private(set) var reads = 0
    private(set) var writes = 0
    private(set) var flushes = 0
    private(set) var closes = 0
    private var state = DiskConnectionState.connected

    init(failure: (any Error)? = nil, release: Signal? = nil) throws {
        var data = Array(repeating: UInt8(0), count: 8)
        data.put(UInt32(7), at: 0)
        data.put(UInt32(512), at: 4)
        capacity = try DiskCapacity(readCapacity10: Data(data))
        self.failure = failure
        self.release = release
    }

    func read(offset: Int64, length: Int) async throws -> Data {
        reads += 1
        await started.signal()
        if let release { await release.wait() }
        if let failure { throw failure }
        return Data(repeating: 0xA5, count: length)
    }
    func write(offset: Int64, data: Data) async throws {
        writes += 1
        if let failure { throw failure }
    }
    func synchronize() async throws {
        flushes += 1
        if let failure { throw failure }
    }
    func close() async {
        closes += 1
        state = .closed
    }
    func connectionState() async -> DiskConnectionState { state }
}

private struct Failure: Sendable {
    let source: any Error
    let code: POSIXErrorCode
}

@Test(arguments: [
    Failure(source: ProtocolError.connectionClosed, code: .EIO),
    Failure(source: ProtocolError.invalidState, code: .EIO),
    Failure(source: ProtocolError.digestMismatch, code: .EIO),
    Failure(source: ProtocolError.malformed("test"), code: .EIO),
    Failure(source: ProtocolError.timedOut, code: .ETIMEDOUT),
    Failure(source: ProtocolError.busy, code: .EBUSY),
    Failure(source: CancellationError(), code: .ECANCELED),
    Failure(source: POSIXError(.ENOSPC), code: .ENOSPC),
    Failure(source: NSError(domain: "unrecognized", code: 9), code: .EIO),
    Failure(
        source: ProtocolError.scsiFailure(status: 2, sense: Data([0x72, 7, 0x20, 2, 0, 0, 0, 0])),
        code: .EIO),
    Failure(
        source: ProtocolError.scsiFailure(status: 2, sense: Data([0x72, 7, 0x27, 0, 0, 0, 0, 0])),
        code: .EROFS),
    Failure(
        source: ProtocolError.scsiFailure(
            status: 2, sense: Data([0x70, 0, 7, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x27, 0])),
        code: .EROFS),
    Failure(
        source: ProtocolError.scsiFailure(status: 2, sense: Data([0x73, 7, 0x27, 0, 0, 0, 0, 0])),
        code: .EIO),
    Failure(
        source: ProtocolError.scsiFailure(
            status: 2, sense: Data([0x71, 0, 7, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x27, 0])),
        code: .EIO),
    Failure(
        source: ProtocolError.scsiFailure(status: 2, sense: Data([0x72, 3, 0x11, 0, 0, 0, 0, 0])),
        code: .EIO),
])
private func filesystemIOErrorsArePOSIXAndNeverRetryTheOperation(_ failure: Failure) async throws {
    let disk = try FaultDisk(failure: failure.source)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    await #expect(throws: POSIXError(failure.code)) {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    await #expect(throws: POSIXError(failure.code)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
    }
    await #expect(throws: POSIXError(failure.code)) { try await volume.synchronize(flags: .wait) }
    await #expect(throws: POSIXError(failure.code)) {
        try await volume.closeItem(volume.imageItem, modes: [])
    }
    #expect(await disk.reads == 1)
    #expect(await disk.writes == 1)
    #expect(await disk.flushes == 2)
}

@Test func shutdownPreventsNewIOAndDiscardsALateRead() async throws {
    let release = Signal()
    let disk = try FaultDisk(release: release)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let read = Task {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 8, bufferLength: 8) {
            _, _ in
        }
    }
    await disk.started.wait()
    async let first: Void = volume.shutdown()
    async let second: Void = volume.shutdown()
    _ = await (first, second)
    await release.signal()
    await #expect(throws: POSIXError(.EIO)) { try await read.value }
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
    }
    await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
    #expect(await disk.closes == 1)
    #expect(await disk.writes == 0)
    #expect(await disk.flushes == 0)
    #expect(
        try await volume.xattr(
            named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
            of: volume.rootItem)
            == DiskConnectionState.closed.encoded)
}

@Test func deactivationClosesTheSessionWithoutAnUnmountCallback() async throws {
    let disk = try FaultDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    try await volume.deactivate()
    #expect(await disk.closes == 1)
    #expect(await disk.connectionState() == .closed)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
    }
    // A late unmount or unload shares the same completed teardown.
    await volume.unmount()
    await volume.shutdown()
    #expect(await disk.closes == 1)
    #expect(await disk.writes == 0)
    #expect(await disk.flushes == 0)
}

@Test func cancelledReadCannotPublishAnOtherwiseSuccessfulLateResult() async throws {
    let release = Signal()
    let disk = try FaultDisk(release: release)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let read = Task {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 8, bufferLength: 8) {
            _, _ in
        }
    }
    await disk.started.wait()
    read.cancel()
    await release.signal()
    await #expect(throws: POSIXError(.ECANCELED)) { try await read.value }
    #expect(await disk.reads == 1)
}

@Test func invalidImageOffsetsFailBeforeReachingTheRemoteDisk() async throws {
    let disk = try FaultDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    await #expect(throws: POSIXError(.EINVAL)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: -1)
    }
    await #expect(throws: POSIXError(.EINVAL)) {
        try await volume.readChunks(from: volume.imageItem, at: -1, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    await #expect(throws: POSIXError(.ENOSPC)) {
        try await volume.write(contents: Data([1]), to: volume.imageItem, at: 4096)
    }
    #expect(
        try await volume.readChunks(from: volume.imageItem, at: 4096, length: 1, bufferLength: 1) {
            _, _ in
        } == 0)
    #expect(await disk.writes == 0)
    #expect(await disk.reads == 0)
}

@Test func stateAttributeIsLocalImmutableAndAvailableAfterShutdown() async throws {
    let disk = try FaultDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let name = FSFileName(string: ConnectionDescriptor.connectionStateAttributeName)
    #expect(
        try await volume.xattr(named: name, of: volume.rootItem)
            == DiskConnectionState.connected.encoded)
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.setXattr(named: name, to: nil, on: volume.rootItem, policy: .delete)
    }
    await volume.shutdown()
    #expect(
        try await volume.xattr(named: name, of: volume.imageItem)
            == DiskConnectionState.closed.encoded)
    #expect(await disk.reads == 0)
    #expect(await disk.writes == 0)
    #expect(await disk.flushes == 0)
}
