import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor OpenFailureDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly: Bool
    private var state: DiskConnectionState
    private var failWrite = false
    private var failSync = false
    private var holdSync = false
    private var syncContinuation: CheckedContinuation<Void, Never>?
    private var holdStateQuery = false
    private var stateContinuation: CheckedContinuation<Void, Never>?
    private(set) var writes = 0
    private(set) var flushes = 0
    private(set) var reads = 0
    var syncIsHeld: Bool { syncContinuation != nil }
    var stateQueryIsHeld: Bool { stateContinuation != nil }

    init(state: DiskConnectionState = .connected, readOnly: Bool = false) throws {
        var response = Array(repeating: UInt8(0), count: 8)
        response.put(UInt32(7), at: 0)
        response.put(UInt32(512), at: 4)
        capacity = try DiskCapacity(readCapacity10: Data(response))
        self.state = state
        isReadOnly = readOnly
    }

    func failNextWrite() { failWrite = true }
    func failNextSync(held: Bool = false) {
        failSync = true
        holdSync = held
    }
    func releaseSync() {
        syncContinuation?.resume()
        syncContinuation = nil
    }
    func holdNextStateQuery() { holdStateQuery = true }
    func releaseStateQuery() {
        stateContinuation?.resume()
        stateContinuation = nil
    }
    func read(offset: Int64, length: Int) async throws -> Data {
        reads += 1
        return Data(repeating: 0, count: length)
    }
    func write(offset: Int64, data: Data) async throws {
        writes += 1
        if failWrite {
            state = .interrupted
            throw ProtocolError.invalidState
        }
    }
    func synchronize() async throws {
        flushes += 1
        if holdSync { await withCheckedContinuation { syncContinuation = $0 } }
        if failSync {
            state = .interrupted
            throw ProtocolError.invalidState
        }
    }
    func connectionState() async -> DiskConnectionState {
        let snapshot = state
        if holdStateQuery {
            holdStateQuery = false
            await withCheckedContinuation { stateContinuation = $0 }
        }
        return snapshot
    }
    func close() async { state = .closed }
}

private func waitForOpenPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Suite struct ImageOpenFailureTests {
    @Test(arguments: [DiskConnectionState.unknown, .interrupted, .closed], [0, 1, 2])
    func unavailableDiskRejectsANewImageOpen(_ state: DiskConnectionState, _ access: Int)
        async throws
    {
        let modes: FSVolume.OpenModes =
            access == 0 ? .read : access == 1 ? .write : [.read, .write]
        let disk = try OpenFailureDisk(state: state)
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.openItem(volume.imageItem, modes: modes)
        }
        #expect(await disk.reads == 0)
        #expect(await disk.writes == 0)
        #expect(await disk.flushes == 0)
    }

    @Test(arguments: [false, true])
    func aWriteOrFinalCloseFailureCannotBeFollowedByASuccessfulNewOpen(_ atClose: Bool)
        async throws
    {
        let disk = try OpenFailureDisk()
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        try await volume.openItem(volume.imageItem, modes: [.read, .write])
        if atClose {
            _ = try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
            await disk.failNextSync()
            await #expect(throws: POSIXError(.EIO)) {
                try await volume.closeItem(volume.imageItem, modes: [])
            }
        } else {
            await disk.failNextWrite()
            await #expect(throws: POSIXError(.EIO)) {
                try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
            }
        }
        for modes: FSVolume.OpenModes in [.read, .write] {
            await #expect(throws: POSIXError(.EIO)) {
                try await volume.openItem(volume.imageItem, modes: modes)
            }
        }
        #expect(await disk.connectionState() == .interrupted)
        #expect(await disk.reads == 0)
        #expect(await disk.writes == 1)
        #expect(await disk.flushes == (atClose ? 2 : 0))
    }

    @Test func anOpenQueuedBehindAFailingWriteChecksTheResultingState() async throws {
        let disk = try OpenFailureDisk()
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        try await volume.openItem(volume.imageItem, modes: .write)
        await disk.failNextSync(held: true)
        let writer = Task {
            try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
        }
        do {
            try await waitForOpenPhase { await disk.syncIsHeld }
            let reader = Task { try await volume.openItem(volume.imageItem, modes: .read) }
            try await waitForOpenPhase { await volume.queuedIOCount == 1 }
            await disk.releaseSync()
            await #expect(throws: POSIXError(.EIO)) { try await writer.value }
            await #expect(throws: POSIXError(.EIO)) { try await reader.value }
            #expect(await disk.writes == 1)
            #expect(await disk.flushes == 1)
            #expect(await disk.reads == 0)
        } catch {
            await disk.releaseSync()
            _ = try? await writer.value
            throw error
        }
    }

    @Test(arguments: [false, true])
    func connectedDiskStillAllowsItsPermittedAccess(_ readOnly: Bool) async throws {
        let disk = try OpenFailureDisk(readOnly: readOnly)
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        try await volume.openItem(volume.imageItem, modes: readOnly ? .read : [.read, .write])
        try await volume.closeItem(volume.imageItem, modes: [])
        #expect(await disk.flushes == (readOnly ? 0 : 1))
        #expect(await disk.writes == 0)
    }

    @Test func cancellationDuringTheStateQueryDoesNotAcquireWriteAccess() async throws {
        let disk = try OpenFailureDisk()
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        await disk.holdNextStateQuery()
        let opening = Task { try await volume.openItem(volume.imageItem, modes: .write) }
        do {
            try await waitForOpenPhase { await disk.stateQueryIsHeld }
            opening.cancel()
            await disk.releaseStateQuery()
            await #expect(throws: POSIXError(.ECANCELED)) { try await opening.value }
            try await volume.closeItem(volume.imageItem, modes: [])
            #expect(await disk.flushes == 0)
            #expect(await disk.writes == 0)
            #expect(await disk.reads == 0)
        } catch {
            opening.cancel()
            await disk.releaseStateQuery()
            _ = try? await opening.value
            throw error
        }
    }

    @Test func faultedDiskRetainsRootDiagnosticsAndIdentityAndReadOnlyGuards() async throws {
        let disk = try OpenFailureDisk(state: .interrupted, readOnly: true)
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        let foreign = LUNImageVolume(disk: disk, identifier: UUID())
        try await volume.openItem(volume.rootItem, modes: .read)
        #expect(
            try await volume.xattr(
                named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
                of: volume.rootItem) == DiskConnectionState.interrupted.encoded)
        await #expect(throws: POSIXError(.EROFS)) {
            try await volume.openItem(volume.imageItem, modes: .write)
        }
        await #expect(throws: POSIXError(.ESTALE)) {
            try await volume.openItem(foreign.imageItem, modes: .read)
        }
        await #expect(throws: POSIXError(.EISDIR)) {
            try await volume.openItem(volume.rootItem, modes: .write)
        }
        #expect(await disk.reads == 0)
        #expect(await disk.writes == 0)
        #expect(await disk.flushes == 0)
    }
}
