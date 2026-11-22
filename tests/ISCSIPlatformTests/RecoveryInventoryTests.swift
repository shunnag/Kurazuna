import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

@Test func inventoryDoesNotHideUnexpectedResourcesUnderAKnownBridge() throws {
    let root = URL(fileURLWithPath: "/private/tmp/test-mounts", isDirectory: true)
    let known = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let other = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let results = try SystemAttachmentBackend.untrackedBridgeURLs(
        root: root,
        mountedPaths: [
            "/", "/Volumes/Other", root.path + "-unrelated/disk", known.path,
            other.path, known.path + "/unexpected",
        ],
        imagePaths: [
            known.path + "/Disk.img", known.path + "/Disk.sparsebundle/", other.path + "/Disk.img",
            known.path + "/unexpected/Other.img", "/Volumes/Other/Disk.img",
        ],
        trackedURLs: [known])
    #expect(Set(results.map(\.path)) == [other.path, known.path + "/unexpected", known.path])
    #expect(
        try SystemAttachmentBackend.untrackedBridgeURLs(
            root: root, mountedPaths: [root.path], imagePaths: [], trackedURLs: []
        ).map(\.path) == [root.path])
    #expect(throws: ProtocolError.self) {
        try SystemAttachmentBackend.untrackedBridgeURLs(
            root: root, mountedPaths: Array(repeating: "/", count: 4097), imagePaths: [],
            trackedURLs: [])
    }
}

@Test func realBackendCanInspectAnAbsentBridgeWithoutCreatingIt() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    let backend = SystemAttachmentBackend(root: root)
    let id = UUID()
    let descriptor = try recoveryDescriptor(mountID: id)
    let url = try await backend.bridgeURL(for: id)
    let inspection = try await backend.inspectBridge(descriptor, at: url)
    #expect(inspection.ownership == .absent)
    #expect(inspection.attachment == nil)
    let secondID = UUID()
    let secondURL = try await backend.bridgeURL(for: secondID)
    let entries = try [
        AttachmentJournalEntry(id: id, descriptor: descriptor, bridgeURL: url, phase: .connected),
        AttachmentJournalEntry(
            id: secondID, descriptor: recoveryDescriptor(mountID: secondID),
            bridgeURL: secondURL, phase: .connected),
    ]
    let batch = try await backend.inspectBridges(entries)
    #expect(batch.count == 2)
    for entry in entries {
        let result = try #require(batch[entry.id])
        let current = try result.get()
        #expect(current.ownership == .absent && current.attachment == nil)
        #expect(current.connectionState == .unknown)
    }
    #expect(try await backend.untrackedBridges(excluding: []).isEmpty)
    #expect(!FileManager.default.fileExists(atPath: root.path))
}

@Test func anEmptyJournalDoesNotAuthorizeConnectionsBeforeInventoryIsChecked() async throws {
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend)
    let descriptor = try recoveryDescriptor()
    await #expect(throws: AttachmentError.self) { try await coordinator.connect(descriptor) }
    #expect(await backend.events.isEmpty)
    let unknown = URL(fileURLWithPath: "/private/tmp/unknown-bridge")
    await backend.setUntracked([unknown])
    await #expect(throws: AttachmentError.self) { try await coordinator.restore() }
    #expect(await coordinator.untrackedBridgeURLs == [unknown])
    await #expect(throws: AttachmentError.self) { try await coordinator.connect(descriptor) }
    #expect(await backend.events.isEmpty)
    await backend.setUntracked([])
    try await coordinator.restore()
    #expect(await coordinator.recoveryReady)
    let record = try await coordinator.connect(descriptor)
    try await coordinator.eject(record.id)
}

@Test func inventoryFailureCannotBeMistakenForNoConnectedDisks() async throws {
    let backend = FakeBackend()
    await backend.setInventoryFailure(true)
    let coordinator = try AttachmentCoordinator(backend: backend)
    await #expect(throws: POSIXError.self) { try await coordinator.restore() }
    #expect(await coordinator.recoveryReady == false)
    await #expect(throws: AttachmentError.self) {
        try await coordinator.connect(recoveryDescriptor())
    }
    #expect(await backend.events.isEmpty)
    await backend.setInventoryFailure(false)
    try await coordinator.restore()
    #expect(await coordinator.recoveryReady)
}

@Test func anUntrackedBridgeDoesNotPreventEjectingAVerifiedDisk() async throws {
    let id = UUID()
    let entry = try AttachmentJournalEntry(
        id: id, descriptor: recoveryDescriptor(mountID: id),
        bridgeURL: URL(fileURLWithPath: "/private/tmp/\(id.uuidString)"), phase: .connected)
    let backend = FakeBackend()
    await backend.present(
        mounted: true, image: DiskAttachment(device: "/dev/disk7", volumeURLs: []))
    await backend.setUntracked([URL(fileURLWithPath: "/private/tmp/unknown-bridge")])
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: MemoryAttachmentJournal(entries: [entry]))
    await #expect(throws: AttachmentError.self) { try await coordinator.restore() }
    #expect(await coordinator.disks.first?.verificationFailed == false)
    try await coordinator.eject(id)
    #expect(await coordinator.disks.isEmpty)
    #expect(await backend.events == ["detach", "unmount"])
    #expect(await coordinator.recoveryReady == false)
}

private func recoveryDescriptor(mountID: UUID? = nil) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], mountID: mountID)
}
