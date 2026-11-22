import Foundation
import ISCSICore
import ISCSINetwork

/// The concrete owning adapter is deliberately limited to raw reserved disks.
final class ReservedVolumeDisk: ImageDisk, Sendable {
    let reserved: ReservedRemoteDisk
    var capacity: DiskCapacity { reserved.disk.capacity }
    var isReadOnly: Bool { reserved.disk.isReadOnly }

    init(_ reserved: ReservedRemoteDisk) { self.reserved = reserved }

    func read(offset: Int64, length: Int) async throws -> Data {
        try await reserved.disk.read(offset: offset, length: length)
    }

    func write(offset: Int64, data: Data) async throws {
        try await reserved.disk.write(offset: offset, data: data)
    }

    func synchronize() async throws { try await reserved.synchronizeForProducer() }
    func close() async { await reserved.close() }
    func connectionState() async -> DiskConnectionState {
        await reserved.disk.connectionState()
    }
}

/// Cache-close waits outside ioGate and itemLock until a recovery attempt finishes.
actor VolumeRecoveryCompletion {
    private var finished = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !finished else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func finish() {
        finished = true
        let waiting = waiters
        waiters.removeAll()
        for waiter in waiting { waiter.resume() }
    }
}
