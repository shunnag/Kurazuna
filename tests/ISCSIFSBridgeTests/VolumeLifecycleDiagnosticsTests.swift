import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private final class LifecycleEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [VolumeLifecycleDiagnostics.Event] = []
    func record(_ event: VolumeLifecycleDiagnostics.Event) {
        lock.withLock { storage.append(event) }
    }
    var values: [VolumeLifecycleDiagnostics.Event] { lock.withLock { storage } }
}

private actor LifecycleDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = false
    private var failure: (any Error)?
    private let holdSync: Bool
    private let holdClose: Bool
    private var syncReply: CheckedContinuation<Void, Never>?
    private var closeReply: CheckedContinuation<Void, Never>?
    private(set) var flushes = 0
    private(set) var closes = 0
    var syncHeld: Bool { syncReply != nil }
    var closeHeld: Bool { closeReply != nil }

    init(failure: (any Error)? = nil, holdSync: Bool = false, holdClose: Bool = false) throws {
        var bytes = Array(repeating: UInt8(0), count: 8)
        bytes.put(UInt32(7), at: 0)
        bytes.put(UInt32(512), at: 4)
        capacity = try DiskCapacity(readCapacity10: Data(bytes))
        self.failure = failure
        self.holdSync = holdSync
        self.holdClose = holdClose
    }
    func read(offset: Int64, length: Int) async throws -> Data {
        Data(repeating: 0, count: length)
    }
    func write(offset: Int64, data: Data) async throws {}
    func synchronize() async throws {
        flushes += 1
        if holdSync && flushes == 1 {
            await withCheckedContinuation { syncReply = $0 }
        }
        if let failure {
            self.failure = nil
            throw failure
        }
    }
    func close() async {
        closes += 1
        if holdClose { await withCheckedContinuation { closeReply = $0 } }
    }
    func releaseSync() {
        syncReply?.resume()
        syncReply = nil
    }
    func releaseClose() {
        closeReply?.resume()
        closeReply = nil
    }
    func connectionState() async -> DiskConnectionState { closes == 0 ? .connected : .closed }
}

private func awaitLifecycle(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test(arguments: [FSSyncFlags.wait, .noWait, .dWait])
func lifecycleSynchronizationRetainsFlagsAndOneBackendCall(_ flags: FSSyncFlags) async throws {
    let disk = try LifecycleDisk()
    let events = LifecycleEvents()
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: events.record)
    try await volume.synchronize(flags: flags)
    let pair = events.values
    #expect(pair.count == 2)
    #expect(pair.map(\.phase) == [.begin, .finished])
    #expect(pair.map(\.operation) == [.synchronize, .synchronize])
    #expect(pair.map(\.outcome) == [.pending, .success])
    #expect(pair.allSatisfy { $0.flags == UInt64(flags.rawValue) && $0.errorCode == 0 })
    #expect(Set(pair.map(\.requestID)).count == 1)
    #expect(await disk.flushes == 1)
}

private struct LifecycleFailure: Sendable {
    let source: any Error
    let code: POSIXErrorCode
}

@Test(arguments: [
    LifecycleFailure(source: ProtocolError.connectionClosed, code: .EIO),
    LifecycleFailure(source: ProtocolError.timedOut, code: .ETIMEDOUT),
    LifecycleFailure(source: CancellationError(), code: .ECANCELED),
])
private func lifecycleSynchronizationReportsTheActualReturnedError(_ failure: LifecycleFailure)
    async throws
{
    let disk = try LifecycleDisk(failure: failure.source)
    let events = LifecycleEvents()
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: events.record)
    await #expect(throws: POSIXError(failure.code)) {
        try await volume.synchronize(flags: .wait)
    }
    let pair = events.values
    #expect(pair.count == 2)
    #expect(pair[0].phase == .begin && pair[0].outcome == .pending)
    #expect(pair[1].phase == .finished && pair[1].errorCode == Int(failure.code.rawValue))
    #expect(pair[1].outcome == (failure.code == .ECANCELED ? .cancelled : .posix))
    #expect(pair[0].requestID == pair[1].requestID)
    #expect(await disk.flushes == 1)
}

@Test func lifecycleCloseDoesNotFinishEarlyOrLetAnotherFlushOvertakeIt() async throws {
    let disk = try LifecycleDisk(holdSync: true)
    let events = LifecycleEvents()
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: events.record)
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    let close = Task { try await volume.closeItem(volume.imageItem, modes: .read) }
    do {
        try await awaitLifecycle { await disk.syncHeld }
        let sync = Task { try await volume.synchronize(flags: .wait) }
        try await awaitLifecycle { await volume.queuedIOCount == 1 }
        #expect(await disk.flushes == 1)
        #expect(!events.values.contains { $0.operation == .close && $0.phase == .finished })
        #expect(!events.values.contains { $0.operation == .synchronize && $0.phase == .finished })
        await disk.releaseSync()
        try await close.value
        try await sync.value
        #expect(await disk.flushes == 2)
        let finished = events.values.filter { $0.phase == .finished }
        #expect(finished.count == 3)
        // The I/O gate orders backend work. Finishing observers can run after
        // its release, so separate requests need not log in completion order.
        #expect(finished.filter { $0.operation == .open }.map(\.flags) == [3])
        #expect(finished.filter { $0.operation == .close }.map(\.flags) == [1])
        #expect(finished.filter { $0.operation == .synchronize }.map(\.flags) == [1])
        #expect(Set(events.values.map(\.volumeID)).count == 1)
        #expect(Set(finished.map(\.requestID)).count == 3)
        try await volume.closeItem(volume.imageItem, modes: [])
        #expect(await disk.flushes == 2)
    } catch {
        await disk.releaseSync()
        _ = try? await close.value
        throw error
    }
}

@Test func lifecycleFailedCloseKeepsItsErrorAndRequiresAnExplicitRetry() async throws {
    let disk = try LifecycleDisk(failure: ProtocolError.connectionClosed)
    let events = LifecycleEvents()
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: events.record)
    try await volume.openItem(volume.imageItem, modes: .write)
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.closeItem(volume.imageItem, modes: [])
    }
    #expect(await disk.flushes == 1)
    let failure = events.values.filter { $0.operation == .close }
    #expect(failure.count == 2 && failure[1].outcome == .posix && failure[1].errorCode == 5)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 2)
    let completed = events.values.filter { $0.operation == .close && $0.phase == .finished }
    #expect(completed.map(\.outcome) == [.posix, .success])
    #expect(Set(completed.map(\.requestID)).count == 2)
}

@Test func lifecycleUnmountAndDeactivationShareOnlyOneActualShutdown() async throws {
    let disk = try LifecycleDisk(holdClose: true)
    let events = LifecycleEvents()
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: events.record)
    let unmount = Task { await volume.unmount() }
    let deactivate = Task { try await volume.deactivate() }
    do {
        try await awaitLifecycle {
            await disk.closeHeld
                && events.values.contains { $0.operation == .unmount && $0.phase == .begin }
                && events.values.contains { $0.operation == .deactivate && $0.phase == .begin }
        }
        #expect(events.values.filter { $0.operation == .shutdown && $0.phase == .begin }.count == 1)
        #expect(!events.values.contains { $0.phase == .finished })
        await disk.releaseClose()
        await unmount.value
        try await deactivate.value
        await volume.shutdown()
        #expect(await disk.closes == 1)
        #expect(await disk.flushes == 0)
        let pair = events.values.filter { $0.operation == .shutdown }
        #expect(pair.map(\.phase) == [.begin, .finished])
        #expect(pair.allSatisfy { $0.outcome == ($0.phase == .begin ? .pending : .success) })
        #expect(Set(pair.map(\.requestID)).count == 1)
        #expect(Set(events.values.map(\.volumeID)).count == 1)
    } catch {
        await disk.releaseClose()
        await unmount.value
        _ = try? await deactivate.value
        throw error
    }
}

private struct LifecyclePrivateError: LocalizedError {
    let errorDescription: String?
}

@Test(arguments: [false, true])
func lifecycleDiagnosticsCannotSerializePrivateResourceOrErrorText(_ foundation: Bool) throws {
    let secret = "iscsi-fskit://private-user:private-password@private-host/PrivateDisk.img"
    let error: any Error =
        foundation
        ? NSError(domain: secret, code: 42, userInfo: [NSLocalizedDescriptionKey: secret])
        : LifecyclePrivateError(errorDescription: secret)
    let events = LifecycleEvents()
    let trace = VolumeLifecycleDiagnostics.Trace(
        volumeID: UUID(), operation: .close, flags: 0, observer: events.record)
    trace.record(.begin)
    trace.record(.finished, error: error)
    for event in events.values {
        let json = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
        for text in [event.fields, json] {
            for token in [
                "iscsi-fskit", "private-user", "private-password", "private-host", "PrivateDisk",
            ] {
                #expect(!text.contains(token))
            }
        }
    }
    #expect(events.values.last?.outcome == .other)
    #expect(events.values.last?.errorCode == 0)
}
