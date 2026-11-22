import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor BridgeIODisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly: Bool
    private let holdRead: Bool
    private let holdSync: Bool
    private let failingSyncs: Int
    private var readReply: CheckedContinuation<Void, Never>?
    private var syncReply: CheckedContinuation<Void, Never>?
    private(set) var reads = 0
    private(set) var writes = 0
    private(set) var flushes = 0
    private(set) var closes = 0
    var readHeld: Bool { readReply != nil }
    var syncHeld: Bool { syncReply != nil }

    init(
        readOnly: Bool = false, holdRead: Bool = false, holdSync: Bool = false,
        failingSyncs: Int = 0
    ) throws {
        var data = Array(repeating: UInt8(0), count: 8)
        data.put(UInt32(8191), at: 0)
        data.put(UInt32(512), at: 4)
        capacity = try DiskCapacity(readCapacity10: Data(data))
        isReadOnly = readOnly
        self.holdRead = holdRead
        self.holdSync = holdSync
        self.failingSyncs = failingSyncs
    }
    func read(offset: Int64, length: Int) async throws -> Data {
        reads += 1
        if holdRead && reads == 1 { await withCheckedContinuation { readReply = $0 } }
        return Data(repeating: 0xA5, count: length)
    }
    func write(offset: Int64, data: Data) async throws { writes += 1 }
    func synchronize() async throws {
        flushes += 1
        if holdSync && flushes == 1 { await withCheckedContinuation { syncReply = $0 } }
        if flushes <= failingSyncs { throw POSIXError(.EIO) }
    }
    func close() async { closes += 1 }
    func connectionState() async -> DiskConnectionState { closes == 0 ? .connected : .closed }
    func releaseRead() {
        readReply?.resume()
        readReply = nil
    }
    func releaseSync() {
        syncReply?.resume()
        syncReply = nil
    }
}

private func ioVolume(
    _ disk: any ImageDisk, recorder: IODiagnostics.Recorder?
) -> LUNImageVolume {
    LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: { _ in }, ioDiagnostics: recorder)
}

private func waitForBridgeIO(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test func ioBridgeLegacyCloseTracePreservesTheFailedBarrierAndPendingWriteAccess() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk(failingSyncs: 1)
    let volume = ioVolume(disk, recorder: recorder)
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.closeItem(volume.imageItem, modes: [])
    }
    #expect(await disk.flushes == 1)
    let failed = recorder.snapshot().events.filter { $0.operation.rawValue == "close" }
    #expect(failed.first?.stage == .entered)
    #expect(failed.last?.stage == .finished && failed.last?.result.code == EIO)
    #expect(failed.contains { $0.stage == .backendBegin && $0.detail == .synchronize })
    #expect(failed.contains { $0.stage == .backendEnd && $0.result.code == EIO })
    // The failed close must keep write access pending. Only a distinct explicit
    // close retries its barrier; the next already-closed callback must not do so.
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 2)
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(await disk.flushes == 2)
    #expect(recorder.snapshot().summary.activeOperations == 0)
}

@Test func ioBridgeLegacyCloseDirectoryAndForeignItemKeepTheirOriginalShortcuts() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: recorder)
    try await volume.closeItem(volume.rootItem, modes: [])
    let other = ioVolume(disk, recorder: recorder)
    await #expect(throws: POSIXError(.ESTALE)) {
        try await volume.closeItem(other.imageItem, modes: [])
    }
    #expect(await disk.flushes == 0)
    let events = recorder.snapshot().events.filter { $0.operation.rawValue == "close" }
    #expect(events.filter { $0.stage == .entered }.count == 2)
    #expect(events.filter { $0.stage == .finished }.count == 2)
    #expect(events.last?.result.code == ESTALE)
    #expect(!events.contains { $0.stage == .gateWaiting || $0.stage == .backendBegin })
}

@Test func ioBridgeDiagnosticBindingIsAbsentAndUnforgeableWithoutARecorder() async throws {
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: nil)
    let name = FSFileName(string: "dev.soba.iscsi.ioDiagnostics")
    #expect(!(try await volume.xattrs(of: volume.imageItem)).contains { $0.string == name.string })
    await #expect(throws: POSIXError(.ENOATTR)) {
        _ = try await volume.xattr(named: name, of: volume.imageItem)
    }
    for policy: FSVolume.SetXattrPolicy in [.alwaysSet, .mustCreate, .mustReplace, .delete] {
        await #expect(throws: POSIXError(.EPERM)) {
            try await volume.setXattr(
                named: name, to: policy == .delete ? nil : Data("forged".utf8),
                on: volume.imageItem, policy: policy)
        }
    }
}

@Test func ioBridgeDiagnosticBindingReportsImmutableRecorderAndDistinctVolumeOwnership()
    async throws
{
    let recorder = IODiagnostics.Recorder(layer: .volume, capacity: 17)
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: recorder)
    let other = ioVolume(disk, recorder: recorder)
    let name = FSFileName(string: "dev.soba.iscsi.ioDiagnostics")
    let bytes = try await volume.xattr(named: name, of: volume.imageItem)
    #expect(bytes.count <= 1024)
    let first = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    let second = try #require(
        JSONSerialization.jsonObject(
            with: try await other.xattr(named: name, of: other.imageItem)) as? [String: Any])
    #expect(first["version"] as? Int == 1)
    #expect(Set(first.keys) == ["version", "volumeID", "recorder"])
    #expect(first["volumeID"] as? String == volume.imageItem.owner.uuidString)
    #expect(first["volumeID"] as? String != second["volumeID"] as? String)
    let binding = try #require(first["recorder"] as? [String: Any])
    #expect(
        Set(binding.keys) == [
            "version", "processInstanceID", "processID", "recorderID", "scopeID", "layer",
            "capacity",
        ])
    #expect(binding["recorderID"] as? String == recorder.id.uuidString)
    #expect(binding["scopeID"] as? String == recorder.scopeID.uuidString)
    #expect(binding["layer"] as? String == "volume")
    #expect(binding["capacity"] as? Int == 17)
    #expect(binding["processID"] as? Int32 == ProcessInfo.processInfo.processIdentifier)
    #expect(try await volume.xattr(named: name, of: volume.imageItem) == bytes)
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.setXattr(
            named: name, to: Data(), on: volume.imageItem, policy: .alwaysSet)
    }
    // A shared test recorder never grants one volume ownership of another item.
    await #expect(throws: POSIXError(.ESTALE)) {
        _ = try await volume.xattr(named: name, of: other.imageItem)
    }
}

@Test func ioBridgeLiveDiagnosticBindingMatchesTheProductionOwnerOnlyWhenOptedIn() async throws {
    let disk = try BridgeIODisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let name = FSFileName(string: "dev.soba.iscsi.ioDiagnostics")
    if ProcessInfo.processInfo.environment["ISCSI_IO_DIAGNOSTICS"] == "1" {
        let bytes = try await volume.xattr(named: name, of: volume.imageItem)
        let value = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let recorder = try #require(value["recorder"] as? [String: Any])
        #expect(value["volumeID"] as? String == volume.imageItem.owner.uuidString)
        #expect(recorder["scopeID"] as? String == volume.imageItem.owner.uuidString)
        #expect(recorder["capacity"] as? Int == 4096)
    } else {
        await #expect(throws: POSIXError(.ENOATTR)) {
            _ = try await volume.xattr(named: name, of: volume.imageItem)
        }
    }
}

@Test func ioBridgeShutdownAfterBackendReadPreservesThePostReadEIO() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk(holdRead: true)
    let volume = ioVolume(disk, recorder: recorder)
    let reading = Task {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    do {
        try await waitForBridgeIO { await disk.readHeld }
        await volume.shutdown()
        await disk.releaseRead()
        await #expect(throws: POSIXError(.EIO)) { try await reading.value }
        #expect(await disk.reads == 1)
        #expect(await disk.closes == 1)
        let events = recorder.snapshot().events
        #expect(events.contains { $0.stage == .backendEnd && $0.result.outcome == .success })
        #expect(events.contains { $0.stage == .rejected && $0.detail == .closing })
        #expect(events.last?.stage == .finished && events.last?.result.code == EIO)
    } catch {
        await disk.releaseRead()
        _ = try? await reading.value
        throw error
    }
}

@Test func ioBridgeQueueSaturationNeverAddsAnExtraGateRelease() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume, capacity: 4096)
    let disk = try BridgeIODisk(holdRead: true)
    let volume = ioVolume(disk, recorder: recorder)
    let reading = Task {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    var waiters: [Task<Int, any Error>] = []
    do {
        try await waitForBridgeIO { await disk.readHeld }
        waiters = (0..<128).map { _ in
            Task { try await volume.write(contents: Data([7]), to: volume.imageItem, at: 0) }
        }
        try await waitForBridgeIO { await volume.queuedIOCount == 128 }
        await #expect(throws: POSIXError(.EBUSY)) { try await volume.synchronize(flags: .wait) }
        #expect(await disk.flushes == 0)
        for task in waiters { task.cancel() }
        for task in waiters {
            await #expect(throws: POSIXError(.ECANCELED)) { try await task.value }
        }
        #expect(await disk.writes == 0)
        await disk.releaseRead()
        #expect(try await reading.value == 1)
        try await volume.synchronize(flags: .wait)
        #expect(await disk.flushes == 1)
        #expect(recorder.snapshot().summary.activeOperations == 0)
    } catch {
        for task in waiters { task.cancel() }
        for task in waiters { _ = try? await task.value }
        await disk.releaseRead()
        _ = try? await reading.value
        throw error
    }
}

@Test(arguments: [false, true])
func ioBridgeReadFinalizationIsInsideTheCallbackTrace(_ copyFails: Bool) async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: recorder)
    await #expect(throws: POSIXError(.EFAULT)) {
        try await volume.readCallback(
            from: volume.imageItem, at: 0, length: 32, bufferLength: 32,
            consume: { _, _ in if copyFails { throw POSIXError(.EFAULT) } },
            finalize: { _ in if !copyFails { throw POSIXError(.EFAULT) } })
    }
    let events = recorder.snapshot().events
    let callback = try #require(
        events.first { $0.operation == .readCallback && $0.stage == .entered })
    let child = try #require(events.first { $0.operation == .read && $0.stage == .entered })
    #expect(child.parentOperationID == callback.operationID)
    let callbackEnd = try #require(
        events.first {
            $0.operationID == callback.operationID && $0.stage == .finished
        })
    let childEnd = try #require(
        events.first {
            $0.operationID == child.operationID && $0.stage == .finished
        })
    #expect(callbackEnd.result.code == EFAULT)
    #expect(childEnd.result.outcome == (copyFails ? .posix : .success))
    #expect(callbackEnd.sequence > childEnd.sequence)
    #expect(await disk.reads == 1)
    #expect(await disk.flushes == 0)
    #expect(recorder.snapshot().summary.activeOperations == 0)
}

@Test(arguments: [false, true])
func ioBridgeValidationAndReadOnlyErrorsDispatchNothing(_ enabled: Bool) async throws {
    let recorder = enabled ? IODiagnostics.Recorder(layer: .volume) : nil
    let disk = try BridgeIODisk(readOnly: true)
    let volume = ioVolume(disk, recorder: recorder)
    await #expect(throws: POSIXError(.EISDIR)) {
        try await volume.readChunks(from: volume.rootItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    await #expect(throws: POSIXError(.EINVAL)) {
        try await volume.readChunks(from: volume.imageItem, at: -1, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    await #expect(throws: POSIXError(.EFAULT)) {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 2, bufferLength: 1) {
            _, _ in
        }
    }
    await #expect(throws: POSIXError(.EROFS)) {
        try await volume.write(contents: Data(), to: volume.imageItem, at: 0)
    }
    #expect(await disk.reads == 0)
    #expect(await disk.writes == 0)
    #expect(await disk.flushes == 0)
    if let recorder {
        let snapshot = recorder.snapshot()
        #expect(!snapshot.events.contains { $0.stage == .gateWaiting || $0.stage == .backendBegin })
        #expect(snapshot.summary.activeOperations == 0 && snapshot.summary.integrityValid)
    }
}

@Test func ioBridgeRecorderSharingCannotWeakenItemOwnership() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk()
    let first = ioVolume(disk, recorder: recorder)
    let second = ioVolume(disk, recorder: recorder)
    await #expect(throws: POSIXError(.ESTALE)) {
        try await first.readChunks(from: second.imageItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    #expect(await disk.reads == 0)
}

@Test func ioBridgeChunkAttemptsAndFinalBarrierRemainSeparate() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: recorder)
    let count = 2_097_169
    #expect(
        try await volume.readChunks(
            from: volume.imageItem, at: 0, length: count, bufferLength: count
        ) { _, _ in } == count)
    #expect(
        try await volume.write(
            contents: Data(repeating: 7, count: count), to: volume.imageItem, at: 0) == count)
    #expect(await disk.reads == 3)
    #expect(await disk.writes == 3)
    #expect(await disk.flushes == 1)
    let events = recorder.snapshot().events
    let write = try #require(events.first { $0.operation == .write && $0.stage == .entered })
    let begins = events.filter { $0.operationID == write.operationID && $0.stage == .backendBegin }
    let ends = events.filter { $0.operationID == write.operationID && $0.stage == .backendEnd }
    #expect(begins.map(\.detail) == [.write, .write, .write, .synchronize])
    #expect(Set(begins.compactMap(\.backendAttemptID)).count == 4)
    #expect(begins.map(\.backendAttemptID) == ends.map(\.backendAttemptID))
    #expect(ends.allSatisfy { $0.result.outcome == .success })
}

@Test(arguments: [false, true])
func ioBridgeCancelledWaiterNeverReleasesAnotherOperationsGate(_ enabled: Bool) async throws {
    let recorder = enabled ? IODiagnostics.Recorder(layer: .volume) : nil
    let disk = try BridgeIODisk(holdRead: true)
    let volume = ioVolume(disk, recorder: recorder)
    let reading = Task {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 32, bufferLength: 32) {
            _, _ in
        }
    }
    do {
        try await waitForBridgeIO { await disk.readHeld }
        let writing = Task {
            try await volume.write(contents: Data([7]), to: volume.imageItem, at: 0)
        }
        try await waitForBridgeIO { await volume.queuedIOCount == 1 }
        writing.cancel()
        await #expect(throws: POSIXError(.ECANCELED)) { try await writing.value }
        #expect(await disk.writes == 0)
        #expect(await disk.flushes == 0)
        await disk.releaseRead()
        #expect(try await reading.value == 32)
        try await volume.synchronize(flags: .wait)
        #expect(await disk.flushes == 1)
        if let recorder {
            let write = recorder.snapshot().events.filter { $0.operation == .write }
            #expect(write.contains { $0.stage == .gateWaiting })
            #expect(!write.contains { $0.stage == .gateAcquired || $0.stage == .backendBegin })
            #expect(write.last?.result.outcome == .cancelled)
        }
    } catch {
        await disk.releaseRead()
        _ = try? await reading.value
        throw error
    }
}

@Test func ioBridgeWriteBarrierKeepsQueuedReadOutsideTheBackend() async throws {
    let recorder = IODiagnostics.Recorder(layer: .volume)
    let disk = try BridgeIODisk(holdSync: true)
    let volume = ioVolume(disk, recorder: recorder)
    let writing = Task { try await volume.write(contents: Data([7]), to: volume.imageItem, at: 0) }
    do {
        try await waitForBridgeIO { await disk.syncHeld }
        let reading = Task {
            try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
                _, _ in
            }
        }
        try await waitForBridgeIO { await volume.queuedIOCount == 1 }
        #expect(await disk.reads == 0)
        #expect(await disk.writes == 1)
        #expect(await disk.flushes == 1)
        let before = recorder.snapshot().events
        #expect(!before.contains { $0.operation == .write && $0.stage == .finished })
        #expect(!before.contains { $0.operation == .read && $0.stage == .backendBegin })
        await disk.releaseSync()
        #expect(try await writing.value == 1)
        #expect(try await reading.value == 1)
    } catch {
        await disk.releaseSync()
        _ = try? await writing.value
        throw error
    }
}

@Test(arguments: [false, true])
func ioBridgeClosingRejectionAndCancelledPrecedenceRemainVisible(_ enabled: Bool) async throws {
    let recorder = enabled ? IODiagnostics.Recorder(layer: .volume) : nil
    let disk = try BridgeIODisk()
    let volume = ioVolume(disk, recorder: recorder)
    await volume.shutdown()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
            _, _ in
        }
    }
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await volume.readChunks(
            from: volume.imageItem, at: 0, length: 1, bufferLength: 1
        ) { _, _ in }
    }
    await #expect(throws: POSIXError(.ECANCELED)) { try await cancelled.value }
    #expect(await disk.reads == 0)
    #expect(await disk.closes == 1)
    if let recorder {
        let reasons = recorder.snapshot().events.filter { $0.stage == .rejected }.map(\.detail)
        #expect(reasons == [.closing, .cancelled])
    }
}
