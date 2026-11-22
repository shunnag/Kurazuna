import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private func descriptor(profileID: UUID = UUID()) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: profileID, portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
}

actor FakeBackend: AttachmentBackend {
    var failAttach = false
    var failDetach = false
    var failUnmount = false
    private var mountFailure: AttachmentError?
    var orphanImage = false
    var replaceImageDuringDetach = false
    var mounted = false
    var ownershipMatches = true
    var image: DiskAttachment?
    var connectionState = DiskConnectionState.connected
    private var inspectionPause: HealthInspectionPause?
    private var inspectionFails = false
    var untracked: [URL] = []
    var inventoryFails = false
    private(set) var events: [String] = []
    func set(
        attach: Bool = false, detach: Bool = false, unmount: Bool = false, orphan: Bool = false,
        replaceImageDuringDetach: Bool = false
    ) {
        failAttach = attach
        failDetach = detach
        failUnmount = unmount
        orphanImage = orphan
        self.replaceImageDuringDetach = replaceImageDuringDetach
    }
    func bridgeURL(for id: UUID) async throws -> URL {
        URL(fileURLWithPath: "/private/tmp/\(id.uuidString)", isDirectory: true)
    }
    func untrackedBridges(excluding trackedURLs: [URL]) async throws -> [URL] {
        if inventoryFails { throw POSIXError(.EIO) }
        return untracked
    }
    func setUntracked(_ urls: [URL]) { untracked = urls }
    func setInventoryFailure(_ fails: Bool) { inventoryFails = fails }
    func setConnectionState(_ state: DiskConnectionState) { connectionState = state }
    func pauseNextInspection(_ pause: HealthInspectionPause) { inspectionPause = pause }
    func setInspectionFailure(_ fails: Bool) { inspectionFails = fails }
    func setMountFailure(_ failure: AttachmentError?) { mountFailure = failure }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        events.append("mount")
        mounted = true
        if let mountFailure { throw mountFailure }
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> DiskAttachment
    {
        events.append("attach")
        if orphanImage { image = DiskAttachment(device: "/dev/disk99", volumeURLs: []) }
        if failAttach { throw POSIXError(.EIO) }
        let attachment = DiskAttachment(device: "/dev/disk99", volumeURLs: [])
        image = attachment
        return attachment
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        async throws
    {
        events.append("detach")
        if failDetach { throw POSIXError(.EBUSY) }
        if replaceImageDuringDetach {
            image = DiskAttachment(device: "/dev/disk7", volumeURLs: [])
        }
        guard image?.device == attachment.device else { throw AttachmentError.imageIdentityChanged }
        orphanImage = false
        image = nil
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        events.append("unmount")
        if failUnmount || image != nil { throw POSIXError(.EBUSY) }
        mounted = false
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    {
        if inspectionFails { throw POSIXError(.EIO) }
        let observation = AttachmentInspection(
            ownership: ownershipMatches ? (mounted ? .verified : .absent) : .conflicting,
            attachment: image, connectionState: connectionState)
        if let pause = inspectionPause {
            inspectionPause = nil
            await pause.started.signal()
            await pause.release.wait()
        }
        return observation
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        events.append("discard")
        guard !mounted, image == nil else { throw POSIXError(.EBUSY) }
    }
    func present(mounted: Bool, image: DiskAttachment? = nil, ownershipMatches: Bool = true) {
        self.mounted = mounted
        self.image = image
        self.ownershipMatches = ownershipMatches
    }
}

@Test(arguments: [false, true])
func unsupportedWritePolicyKeepsNormalCleanupAndRetryAvailable(_ failUnmount: Bool) async throws {
    let backend = FakeBackend()
    await backend.setMountFailure(.writeCompletionUnavailable)
    await backend.set(unmount: failUnmount)
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    await #expect(throws: AttachmentError.writeCompletionUnavailable) {
        try await coordinator.connect(descriptor())
    }
    #expect(await backend.image == nil)
    #expect(await backend.events == ["mount", "unmount"])
    if failUnmount {
        let record = try #require(await coordinator.disks.first)
        #expect(record.needsCleanup && record.attachment == nil)
        await backend.set()
        try await coordinator.eject(record.id)
    }
    #expect(await coordinator.disks.isEmpty)
    #expect(await backend.mounted == false)
    await backend.setMountFailure(nil)
    let disk = try await coordinator.connect(descriptor())
    try await coordinator.eject(disk.id)
    #expect(await coordinator.disks.isEmpty)
}

@Test func interruptedAttachCanRecoverTheImageBeforeUnmounting() async throws {
    let backend = FakeBackend()
    await backend.set(attach: true, detach: true, orphan: true)
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.connect(descriptor()) }
    let records = await coordinator.disks
    let record = try #require(records.first)
    await backend.set(orphan: true)
    try await coordinator.eject(record.id)
    #expect(await backend.events == ["mount", "attach", "detach", "detach", "unmount"])
    #expect(await coordinator.disks.isEmpty)
}

@Test func duplicatePhysicalDiskAcrossProfilesIsRejected() async throws {
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    let first = try await coordinator.connect(descriptor())
    await #expect(throws: AttachmentError.self) { try await coordinator.connect(descriptor()) }
    try await coordinator.eject(first.id)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
    #expect(await coordinator.disks.isEmpty)
}

@Test func busyDiskIsNotUnmountedOrForgotten() async throws {
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    let record = try await coordinator.connect(descriptor())
    await backend.set(detach: true)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(record.id) }
    #expect(await backend.events == ["mount", "attach", "detach"])
    #expect(await coordinator.disks.first?.attachment?.device == "/dev/disk99")
}

@Test func deviceReplacementDuringEjectionRequiresAnotherVerification() async throws {
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    let record = try await coordinator.connect(descriptor())
    await backend.set(replaceImageDuringDetach: true)
    await #expect(throws: AttachmentError.self) { try await coordinator.eject(record.id) }
    #expect(await coordinator.disks.first?.verificationFailed == true)
    #expect(await backend.events == ["mount", "attach", "detach"])
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.connect(descriptor())
    }
    await backend.set()
    try await coordinator.restore()
    #expect(await coordinator.disks.first?.attachment?.device == "/dev/disk7")
    try await coordinator.eject(record.id)
    #expect(await backend.events == ["mount", "attach", "detach", "detach", "unmount"])
    #expect(await coordinator.disks.isEmpty)
}

@Test func failedUnmountCanBeRetriedWithoutDetachingAnotherDevice() async throws {
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    let record = try await coordinator.connect(descriptor())
    await backend.set(unmount: true)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(record.id) }
    #expect(await coordinator.disks.first?.attachment == nil)
    #expect(await coordinator.disks.first?.needsCleanup == true)
    await backend.set()
    try await coordinator.eject(record.id)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount", "unmount"])
}

@Test func failedAttachPreservesCleanupRecordIfRollbackFails() async throws {
    let backend = FakeBackend()
    await backend.set(attach: true, unmount: true)
    let coordinator = try AttachmentCoordinator(backend: backend)
    try await coordinator.restore()
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.connect(descriptor()) }
    let records = await coordinator.disks
    let record = try #require(records.first)
    #expect(record.needsCleanup)
    #expect(record.attachment == nil)
    await backend.set()
    try await coordinator.eject(record.id)
    #expect(await coordinator.disks.isEmpty)
}

@Test func diskImageParserRequiresWholeDeviceAndFiltersMountPaths() throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: [
            "system-entities": [
                ["dev-entry": "/dev/disk99"],
                ["dev-entry": "/dev/disk99s1", "mount-point": "/Volumes/Archive"],
                ["mount-point": "/Users/other/path"],
            ]
        ], format: .binary, options: 0)
    let result = try SystemAttachmentBackend.parseAttachment(data)
    #expect(result.device == "/dev/disk99")
    #expect(result.volumeURLs.map(\.path) == ["/Volumes/Archive"])
    let partition = try PropertyListSerialization.data(
        fromPropertyList: [
            "system-entities": [
                ["dev-entry": "/dev/disk99s1"]
            ]
        ], format: .binary, options: 0)
    #expect(throws: AttachmentError.self) { try SystemAttachmentBackend.parseAttachment(partition) }
}

@Test func commandArgumentsAreNotInterpretedByAShell() async throws {
    let data = try await SystemCommand.run(
        "/bin/echo", arguments: ["literal; $(whoami)", "`id`"], timeout: 5)
    #expect(String(decoding: data, as: UTF8.self) == "literal; $(whoami) `id`\n")
}

@Test func commandDeadlineAndCancellationTerminateTheChild() async throws {
    await #expect(throws: SystemCommandError.timedOut(program: "sleep")) {
        try await SystemCommand.run("/bin/sleep", arguments: ["5"], timeout: 0.05)
    }
    let task = Task { try await SystemCommand.run("/bin/sleep", arguments: ["5"]) }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
}
