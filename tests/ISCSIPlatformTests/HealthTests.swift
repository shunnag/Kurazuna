import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

actor HealthSignal {
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

struct HealthInspectionPause: Sendable {
    let started = HealthSignal()
    let release = HealthSignal()
}

private final class HealthJournal: AttachmentJournal, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [AttachmentJournalEntry] = []
    private var saves = 0
    var saveCount: Int { lock.withLock { saves } }
    func load() -> [AttachmentJournalEntry] { lock.withLock { entries } }
    func save(_ entries: [AttachmentJournalEntry]) {
        lock.withLock {
            self.entries = entries
            saves += 1
        }
    }
}

private func healthDescriptor() throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5])
}

private func healthConnection() async throws
    -> (FakeBackend, HealthJournal, AttachmentCoordinator, AttachedDisk)
{
    let backend = FakeBackend()
    let journal = HealthJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let record = try await coordinator.connect(healthDescriptor())
    return (backend, journal, coordinator, record)
}

@Test(arguments: [DiskConnectionState.interrupted, .closed, .unknown, .connected])
func healthRefreshDoesNotWriteOrForgetTheMountedDisk(state: DiskConnectionState) async throws {
    let (backend, journal, coordinator, record) = try await healthConnection()
    let entries = journal.load()
    let saves = journal.saveCount
    await backend.setConnectionState(state)
    await coordinator.refreshHealth()
    let disks = await coordinator.disks
    let updated = try #require(disks.first)
    #expect(updated.connectionState == state)
    #expect(updated.phase == .connected && !updated.verificationFailed)
    #expect(updated.attachment == record.attachment)
    #expect(journal.load() == entries && journal.saveCount == saves)
    #expect(await backend.events == ["mount", "attach"])
    try await coordinator.eject(record.id)
    #expect(await coordinator.disks.isEmpty)
}

@Test(arguments: [false, true])
func aFailedHealthInspectionRetainsTheRecordAndRequiresVerification(transportError: Bool)
    async throws
{
    let (backend, journal, coordinator, record) = try await healthConnection()
    let saved = journal.load()
    if transportError {
        await backend.setInspectionFailure(true)
    } else {
        await backend.present(mounted: true, image: record.attachment, ownershipMatches: false)
    }
    await coordinator.refreshHealth()
    #expect(await coordinator.disks.first?.verificationFailed == true)
    #expect(journal.load() == saved)
    #expect(await backend.events == ["mount", "attach"])
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.connect(record.descriptor)
    }
}

@Test func aHealthRefreshCannotResurrectAnEjectedConnection() async throws {
    let (backend, journal, coordinator, record) = try await healthConnection()
    let pause = HealthInspectionPause()
    await backend.pauseNextInspection(pause)
    let refresh = Task { await coordinator.refreshHealth() }
    await pause.started.wait()
    try await coordinator.eject(record.id)
    await pause.release.signal()
    await refresh.value
    #expect(await coordinator.disks.isEmpty)
    #expect(journal.load().isEmpty)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
}

@Test func aHealthRefreshCannotOverwriteNewerRecoveryInformation() async throws {
    let (backend, _, coordinator, _) = try await healthConnection()
    let pause = HealthInspectionPause()
    await backend.pauseNextInspection(pause)
    let refresh = Task { await coordinator.refreshHealth() }
    await pause.started.wait()
    await backend.present(
        mounted: true, image: DiskAttachment(device: "/dev/disk7", volumeURLs: []))
    await backend.setConnectionState(.interrupted)
    try await coordinator.restore()
    await pause.release.signal()
    await refresh.value
    let disks = await coordinator.disks
    let record = try #require(disks.first)
    #expect(record.attachment?.device == "/dev/disk7")
    #expect(record.connectionState == .interrupted && !record.verificationFailed)
}

@Test func aDeviceChangeDuringHealthRefreshDoesNotEjectEitherDevice() async throws {
    let (backend, journal, coordinator, _) = try await healthConnection()
    let saved = journal.load()
    await backend.present(
        mounted: true, image: DiskAttachment(device: "/dev/disk7", volumeURLs: []))
    await coordinator.refreshHealth()
    #expect(await coordinator.disks.first?.verificationFailed == true)
    #expect(journal.load() == saved)
    #expect(await backend.events == ["mount", "attach"])
}

@Test func cancelledHealthInspectionDoesNotPublishItsResult() async throws {
    let (backend, journal, coordinator, _) = try await healthConnection()
    let saves = journal.saveCount
    let pause = HealthInspectionPause()
    await backend.pauseNextInspection(pause)
    let refresh = Task { await coordinator.refreshHealth() }
    await pause.started.wait()
    refresh.cancel()
    await pause.release.signal()
    await refresh.value
    #expect(await coordinator.disks.first?.connectionState == .connected)
    #expect(journal.saveCount == saves)
    await backend.setConnectionState(.interrupted)
    await coordinator.refreshHealth()
    #expect(await coordinator.disks.first?.connectionState == .interrupted)
}

@Test func interruptedConnectionDuringAttachIsNotReportedAsReady() async throws {
    let backend = FakeBackend()
    let journal = HealthJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    await backend.setConnectionState(.interrupted)
    await #expect(throws: AttachmentError.connectionInterrupted) {
        try await coordinator.connect(healthDescriptor())
    }
    #expect(await coordinator.disks.isEmpty)
    #expect(journal.load().isEmpty)
    #expect(await backend.events == ["mount", "attach", "detach", "unmount"])
}
