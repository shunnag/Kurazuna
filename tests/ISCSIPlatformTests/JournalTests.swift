import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private func journalEntry(
    phase: AttachmentPhase = .connected,
    root: URL = URL(fileURLWithPath: "/private/tmp", isDirectory: true), mutual: Bool = false
) throws -> AttachmentJournalEntry {
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(addressKey: "4001000000000000"), readOnly: false,
        chapUsername: mutual ? "Mac" : nil,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: id,
        targetCHAPUsername: mutual ? "Server" : nil)
    return try AttachmentJournalEntry(
        id: id, descriptor: descriptor,
        bridgeURL: root.appendingPathComponent(id.uuidString, isDirectory: true), phase: phase)
}

private final class FaultJournal: AttachmentJournal, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [AttachmentJournalEntry] = []
    private var calls = 0
    private var failureCall: Int?
    private let commitBeforeFailure: Bool
    init(failureCall: Int, commitBeforeFailure: Bool = false) {
        self.failureCall = failureCall
        self.commitBeforeFailure = commitBeforeFailure
    }
    func load() -> [AttachmentJournalEntry] { lock.withLock { entries } }
    func save(_ entries: [AttachmentJournalEntry]) throws {
        try lock.withLock {
            calls += 1
            if calls == failureCall {
                if commitBeforeFailure { self.entries = entries }
                throw POSIXError(.ENOSPC)
            }
            self.entries = entries
        }
    }
    func allowWrites() { lock.withLock { failureCall = nil } }
}

@Test(arguments: [false, true])
func journalFailureBeforeMountPreventsSideEffects(commitBeforeFailure: Bool) async throws {
    let backend = FakeBackend()
    let journal = FaultJournal(failureCall: 1, commitBeforeFailure: commitBeforeFailure)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let entry = try journalEntry()
    await #expect(throws: AttachmentError.self) { try await coordinator.connect(entry.descriptor) }
    #expect(await backend.events.isEmpty)
    #expect(await coordinator.recoveryReady == false)
    journal.allowWrites()
    try await coordinator.restore()
    #expect(await coordinator.disks.isEmpty)
    #expect(await coordinator.recoveryReady)
    #expect(await backend.events == (commitBeforeFailure ? ["discard"] : []))
}

@Test func journalFailureBetweenMountAndAttachStopsBeforeCreatingADevice() async throws {
    let backend = FakeBackend()
    let journal = FaultJournal(failureCall: 2)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    await #expect(throws: AttachmentError.self) {
        try await coordinator.connect(journalEntry().descriptor)
    }
    #expect(await backend.events == ["mount"])
    #expect(journal.load().first?.phase == .mountingBridge)
    journal.allowWrites()
    let restored = try AttachmentCoordinator(backend: backend, journal: journal)
    try await restored.restore()
    let records = await restored.disks
    let record = try #require(records.first)
    #expect(record.attachment == nil)
    #expect(record.needsCleanup)
    try await restored.eject(record.id)
    #expect(await backend.events == ["mount", "unmount"])
}

@Test func anImageCreatedBeforeTheFinalSaveIsRecoveredByCurrentIdentity() async throws {
    let backend = FakeBackend()
    let journal = FaultJournal(failureCall: 3)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    await #expect(throws: AttachmentError.self) {
        try await coordinator.connect(journalEntry().descriptor)
    }
    #expect(await backend.events == ["mount", "attach"])
    #expect(journal.load().first?.phase == .attachingImage)
    #expect(
        !String(decoding: try JSONEncoder().encode(journal.load()), as: UTF8.self).contains(
            "/dev/disk"))
    journal.allowWrites()
    await backend.present(
        mounted: true,
        image: DiskAttachment(
            device: "/dev/disk7", volumeURLs: [URL(fileURLWithPath: "/Volumes/Archive")]))
    let restored = try AttachmentCoordinator(backend: backend, journal: journal)
    try await restored.restore()
    let records = await restored.disks
    let record = try #require(records.first)
    #expect(record.attachment?.device == "/dev/disk7")
    #expect(!record.needsCleanup)
    try await restored.eject(record.id)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
}

@Test func saveFailureAfterDetachDoesNotProceedToUnmount() async throws {
    let backend = FakeBackend()
    let journal = FaultJournal(failureCall: 5)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let record = try await coordinator.connect(journalEntry().descriptor)
    await #expect(throws: AttachmentError.self) { try await coordinator.eject(record.id) }
    #expect(await backend.events == ["mount", "attach", "detach"])
    #expect(journal.load().first?.phase == .detachingImage)
    journal.allowWrites()
    try await coordinator.restore()
    try await coordinator.eject(record.id)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
}

@Test(arguments: [4, 6], [false, true])
func journalFailureAtEjectionBoundariesPreservesRecoverableIntent(
    failureCall: Int, commitBeforeFailure: Bool
) async throws {
    let backend = FakeBackend()
    let journal = FaultJournal(failureCall: failureCall, commitBeforeFailure: commitBeforeFailure)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let record = try await coordinator.connect(journalEntry().descriptor)
    await #expect(throws: AttachmentError.self) { try await coordinator.eject(record.id) }
    #expect(await coordinator.recoveryReady == false)
    let beforeRecovery = await backend.events
    #expect(
        beforeRecovery
            == (failureCall == 4 ? ["mount", "attach"] : ["mount", "attach", "detach", "unmount"]))
    journal.allowWrites()
    try await coordinator.restore()
    if failureCall == 4 {
        try await coordinator.eject(record.id)
        #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
    } else {
        #expect(await backend.events == beforeRecovery + ["discard"])
    }
    #expect(await coordinator.disks.isEmpty)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.recoveryReady)
}

@Test(arguments: [
    AttachmentPhase.mountingBridge, .attachingImage, .connected, .detachingImage, .unmountingBridge,
])
func disconnectedEntriesAreRemovedWithoutUnmountingAnyVolume(phase: AttachmentPhase) async throws {
    let entry = try journalEntry(phase: phase)
    let journal = MemoryAttachmentJournal(entries: [entry])
    let backend = FakeBackend()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    await #expect(throws: AttachmentError.self) {
        try await coordinator.connect(journalEntry().descriptor)
    }
    try await coordinator.restore()
    #expect(await coordinator.disks.isEmpty)
    #expect(journal.load().isEmpty)
    #expect(await backend.events == ["discard"])
}

@Test func conflictingOwnershipIsNeverDetachedOrForgotten() async throws {
    let entry = try journalEntry()
    let journal = MemoryAttachmentJournal(entries: [entry])
    let backend = FakeBackend()
    await backend.present(
        mounted: true, image: DiskAttachment(device: "/dev/disk99", volumeURLs: []),
        ownershipMatches: false)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    await #expect(throws: AttachmentError.self) { try await coordinator.restore() }
    await #expect(throws: AttachmentError.self) { try await coordinator.eject(entry.id) }
    #expect(await backend.events.isEmpty)
    #expect(journal.load() == [entry])
    #expect(await coordinator.disks.first?.verificationFailed == true)
    await backend.present(mounted: false)
    try await coordinator.restore()
    #expect(journal.load().isEmpty)
}

@Test func fileJournalRoundTripLeaseAndCorruptionHandling() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    let root = directory.appendingPathComponent("Mounts", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    var journal: FileAttachmentJournal? = try FileAttachmentJournal(
        directory: directory, bridgeRoot: root)
    #expect(try journal?.load().isEmpty == true)
    let entry = try journalEntry(root: root)
    try journal?.save([entry])
    #expect(try journal?.load() == [entry])
    #expect(throws: POSIXError.self) {
        try FileAttachmentJournal(directory: directory, bridgeRoot: root)
    }
    journal = nil
    let reopened = try FileAttachmentJournal(directory: directory, bridgeRoot: root)
    #expect(try reopened.load() == [entry])
    let attributes = try FileManager.default.attributesOfItem(
        atPath: directory.appendingPathComponent("Connections.json").path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    #expect(throws: ProtocolError.self) { try reopened.save([entry, entry]) }
    #expect(throws: ProtocolError.self) { try reopened.save([journalEntry()]) }
    let url = directory.appendingPathComponent("Connections.json")
    try Data("broken journal".utf8).write(to: url)
    #expect(throws: DecodingError.self) { try reopened.load() }
    #expect(try Data(contentsOf: url) == Data("broken journal".utf8))
}

@Test func mutualJournalUsesAVersionThatOlderAppsMustRejectAndRestoresTheIdentity() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: directory) }
    let root = directory.appendingPathComponent("Mounts", isDirectory: true)
    var journal: FileAttachmentJournal? = try FileAttachmentJournal(
        directory: directory, bridgeRoot: root)
    let entry = try journalEntry(root: root, mutual: true)
    try journal?.save([entry])
    let bytes = try Data(contentsOf: directory.appendingPathComponent("Connections.json"))
    let json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    #expect(json["version"] as? Int == 2)
    journal = nil
    let reopened = try FileAttachmentJournal(directory: directory, bridgeRoot: root)
    #expect(try reopened.load() == [entry])
    #expect(try reopened.load().first?.descriptor.targetCHAPUsername == "Server")
    try reopened.save([])
    let empty = try Data(contentsOf: directory.appendingPathComponent("Connections.json"))
    #expect(
        try (JSONSerialization.jsonObject(with: empty) as? [String: Any])?["version"] as? Int == 1)
}

@Test(arguments: ["symlink", "permissions", "size"])
func fileJournalRejectsUnsafeInputWithoutChangingIt(_ fault: String) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: directory) }
    let journal = try FileAttachmentJournal(
        directory: directory, bridgeRoot: directory.appendingPathComponent("Mounts"))
    let url = directory.appendingPathComponent("Connections.json")
    let target = directory.appendingPathComponent("untouched")
    let original = Data("preserve this file".utf8)
    try original.write(to: target)
    if fault == "symlink" {
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: target)
        #expect(throws: POSIXError.self) { try journal.load() }
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: url.path) == target.path)
    } else {
        try original.write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: fault == "permissions" ? 0o644 : 0o600], ofItemAtPath: url.path)
        if fault == "permissions" {
            #expect(throws: POSIXError(.EACCES)) { try journal.load() }
            #expect(try Data(contentsOf: url) == original)
        } else {
            let file = try FileHandle(forWritingTo: url)
            try file.truncate(atOffset: 1_048_577)
            try file.close()
            #expect(throws: ProtocolError.self) { try journal.load() }
            #expect(
                (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?
                    .intValue == 1_048_577)
        }
    }
    #expect(try Data(contentsOf: target) == original)
}

@Test func replacingTheJournalDirectoryInvalidatesItsLease() throws {
    let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    let directory = parent.appendingPathComponent("Journal", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: parent) }
    let journal = try FileAttachmentJournal(
        directory: directory, bridgeRoot: parent.appendingPathComponent("Mounts"))
    try FileManager.default.moveItem(
        at: directory, to: parent.appendingPathComponent("OldJournal", isDirectory: true))
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700])
    #expect(throws: POSIXError(.ESTALE)) { try journal.load() }
    #expect(throws: POSIXError(.ESTALE)) { try journal.save([]) }
    #expect(
        !FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("Connections.json").path))
}

@Test func aSerializedConnectionIsRecoveredWithoutAStoredDeviceNumber() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: directory) }
    let journal = try FileAttachmentJournal(
        directory: directory, bridgeRoot: URL(fileURLWithPath: "/private/tmp", isDirectory: true))
    let entry = try journalEntry(phase: .attachingImage)
    try journal.save([entry])
    let serialized = try String(
        contentsOf: directory.appendingPathComponent("Connections.json"), encoding: .utf8)
    #expect(!serialized.contains("/dev/disk"))
    let backend = FakeBackend()
    await backend.present(
        mounted: true, image: DiskAttachment(device: "/dev/disk7", volumeURLs: []))
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    #expect(await coordinator.disks.first?.descriptor.lun.addressKey == "4001000000000000")
    #expect(await coordinator.disks.first?.attachment?.device == "/dev/disk7")
    #expect(try journal.load().first?.phase == .connected)
    try await coordinator.eject(entry.id)
    #expect(try journal.load().isEmpty)
}
