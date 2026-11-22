import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor Latch {
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

private func resourceDescriptor() throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
}

@Test func unloadDuringLoadCannotPublishACancelledVolume() async throws {
    let started = Latch()
    let release = Latch()
    let cancelled = Latch()
    let controller = ResourceController { descriptor, readOnly in
        await started.signal()
        await withTaskCancellationHandler {
            await release.wait()
        } onCancel: {
            Task { await cancelled.signal() }
        }
        return LUNImageVolume(
            disk: try MemoryDisk(readOnly: readOnly),
            identifier: ISCSIFileSystem.identifier(for: descriptor))
    }
    let descriptor = try resourceDescriptor()
    let loading = Task { try await controller.load(descriptor, readOnly: true) }
    await started.wait()
    await #expect(throws: ProtocolError.busy) {
        try await controller.load(descriptor, readOnly: false)
    }
    let unloading = Task { try await controller.unload(descriptor) }
    await cancelled.wait()
    await release.signal()
    await #expect(throws: CancellationError.self) { try await loading.value }
    try await unloading.value
    _ = try await controller.load(descriptor, readOnly: false)
    try await controller.unload(descriptor)
}

@Test func resourceIdentityVariesWithTargetAndLogicalUnit() throws {
    let first = try resourceDescriptor()
    let second = try ConnectionDescriptor(
        profileID: first.profileID, portal: first.portal,
        initiatorName: first.initiatorName, targetName: first.targetName, lun: LogicalUnit(1),
        readOnly: false, isid: first.isid)
    #expect(ISCSIFileSystem.identifier(for: first) != ISCSIFileSystem.identifier(for: second))
    #expect(ISCSIFileSystem.identifier(for: first) == ISCSIFileSystem.identifier(for: first))
}
