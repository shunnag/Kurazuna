import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private enum ConnectionPause {
    case preparing, mounting, attaching, inspecting, detaching, unmounting, connected
}

private actor MultipleBackend: AttachmentBackend {
    enum Event: Equatable {
        case prepare(UUID)
        case mount(UUID)
        case attach(UUID)
        case detach(UUID)
        case unmount(UUID)
    }
    private var pause: ConnectionPause?
    private var preparationFails: Bool
    private var waiter: CheckedContinuation<Void, Never>?
    private var observations: [UUID: AttachmentInspection]
    private(set) var events: [Event] = []
    var isPaused: Bool { waiter != nil }

    init(
        pause: ConnectionPause? = nil, entries: [AttachmentJournalEntry] = [],
        preparationFails: Bool = false
    ) {
        self.pause = pause
        self.preparationFails = preparationFails
        observations = Dictionary(
            uniqueKeysWithValues: entries.enumerated().map { index, entry in
                (
                    entry.id,
                    AttachmentInspection(
                        ownership: .verified,
                        attachment: DiskAttachment(
                            device: "/dev/disk\(900000 + index)", volumeURLs: []),
                        connectionState: .connected)
                )
            })
    }
    private func suspend(at stage: ConnectionPause) async {
        guard pause == stage else { return }
        pause = nil
        await withCheckedContinuation { waiter = $0 }
    }
    func release() {
        waiter?.resume()
        waiter = nil
    }
    func bridgeURL(for id: UUID) async throws -> URL {
        events.append(.prepare(id))
        await suspend(at: .preparing)
        if preparationFails {
            preparationFails = false
            throw POSIXError(.EACCES)
        }
        return URL(fileURLWithPath: "/private/tmp/iSCSI-MultipleTests/\(id.uuidString)")
    }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        let id = try #require(descriptor.mountID)
        events.append(.mount(id))
        observations[id] = AttachmentInspection(ownership: .verified, attachment: nil)
        await suspend(at: .mounting)
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> DiskAttachment
    {
        let id = try #require(descriptor.mountID)
        events.append(.attach(id))
        let attachment = DiskAttachment(device: "/dev/disk\(900000 + events.count)", volumeURLs: [])
        observations[id] = AttachmentInspection(
            ownership: .verified, attachment: attachment, connectionState: .connected)
        await suspend(at: .attaching)
        return attachment
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        await suspend(at: .inspecting)
        return observations[id] ?? AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        async throws
    {
        let id = try #require(descriptor.mountID)
        guard observations[id]?.attachment == attachment else {
            throw AttachmentError.imageIdentityChanged
        }
        events.append(.detach(id))
        observations[id] = AttachmentInspection(ownership: .verified, attachment: nil)
        await suspend(at: .detaching)
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        let id = try #require(descriptor.mountID)
        guard observations[id]?.attachment == nil else { throw POSIXError(.EBUSY) }
        events.append(.unmount(id))
        observations[id] = nil
        await suspend(at: .unmounting)
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

private func multipleDescriptor(
    portal: String = "nas.local", target: String = "iqn.2026-10.test:disk", lun: UInt16 = 0,
    mountID: UUID? = nil
) throws -> ConnectionDescriptor {
    let identity = try InitiatorIdentity(
        name: "iqn.2026-10.test:initiator", seed: [0x80, 1, 2, 3, 4, 5])
    let unit = try LogicalUnit(lun)
    return try ConnectionDescriptor(
        profileID: UUID(), portal: Portal(portal), initiatorName: identity.name,
        targetName: target, lun: unit, readOnly: false,
        isid: identity.isid(targetName: target, lun: unit), mountID: mountID)
}

private func multipleEntry(portal: String = "nas.local", target: String = "iqn.2026-10.test:disk")
    throws -> AttachmentJournalEntry
{
    let id = UUID()
    return try AttachmentJournalEntry(
        id: id, descriptor: multipleDescriptor(portal: portal, target: target, mountID: id),
        bridgeURL: URL(fileURLWithPath: "/private/tmp/iSCSI-MultipleTests/\(id.uuidString)"),
        phase: .connected)
}

private func connectionPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test(
    arguments: [ConnectionPause.preparing, .mounting, .connected],
    ["192.0.2.10", "[2001:db8::10]", "nas.local:3261"])
private func oneLogicalDiskCannotBeConnectedAgainThroughAnotherPortal(
    _ stage: ConnectionPause, _ alias: String
) async throws {
    let backend = MultipleBackend(pause: stage)
    let journal = MemoryAttachmentJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let original = try multipleDescriptor()
    let alternate = try multipleDescriptor(portal: alias)
    #expect(original.profileID != alternate.profileID && original.isid == alternate.isid)
    let first: AttachedDisk
    if stage == .connected {
        first = try await coordinator.connect(original)
        let events = await backend.events
        await #expect(throws: AttachmentError.alreadyConnected) {
            try await coordinator.connect(alternate)
        }
        #expect(await backend.events == events)
    } else {
        let connecting = Task { try await coordinator.connect(original) }
        try await connectionPhase { await backend.isPaused }
        let events = await backend.events
        await #expect(throws: AttachmentError.alreadyConnected) {
            try await coordinator.connect(alternate)
        }
        #expect(await backend.events == events)
        await backend.release()
        first = try await connecting.value
    }
    #expect(await coordinator.disks.map(\.id) == [first.id])
    #expect(journal.load().map(\.id) == [first.id])
    try await coordinator.eject(first.id)
    #expect(await coordinator.disks.isEmpty)
}

@Test(arguments: [false, true])
private func distinctDisksCanFinishAndEjectWhileAnotherConnectionIsPreparing(_ differentLUN: Bool)
    async throws
{
    let backend = MultipleBackend(pause: .preparing)
    let journal = MemoryAttachmentJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let pending = Task { try await coordinator.connect(multipleDescriptor()) }
    try await connectionPhase { await backend.isPaused }
    let second = try await coordinator.connect(
        multipleDescriptor(
            target: differentLUN ? "iqn.2026-10.test:disk" : "iqn.2026-10.test:other",
            lun: differentLUN ? 1 : 0))
    #expect(await coordinator.disks.map(\.id) == [second.id])
    try await coordinator.eject(second.id)
    #expect(await coordinator.disks.isEmpty && journal.load().isEmpty)
    await backend.release()
    let first = try await pending.value
    #expect(await coordinator.disks.map(\.id) == [first.id])
    #expect(journal.load().map(\.id) == [first.id])
    let events = await backend.events
    #expect(events.suffix(2) == [.mount(first.id), .attach(first.id)])
    #expect(events.filter { $0 == .detach(first.id) || $0 == .unmount(first.id) }.isEmpty)
    try await coordinator.eject(first.id)
    #expect(await coordinator.disks.isEmpty && journal.load().isEmpty)
}

@Test private func aPreparingConnectionReservesSpaceInTheConnectionLimit() async throws {
    let entries = try (0..<127).map { try multipleEntry(target: "iqn.2026-10.test:disk-\($0)") }
    let backend = MultipleBackend(pause: .preparing, entries: entries)
    let journal = MemoryAttachmentJournal(entries: entries)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let pending = Task {
        try await coordinator.connect(multipleDescriptor(target: "iqn.2026-10.test:pending"))
    }
    try await connectionPhase { await backend.isPaused }
    let events = await backend.events
    await #expect(throws: ProtocolError.limitExceeded("connected disks")) {
        try await coordinator.connect(multipleDescriptor(target: "iqn.2026-10.test:over-limit"))
    }
    #expect(await backend.events == events)
    await backend.release()
    let last = try await pending.value
    #expect(await coordinator.disks.count == 128 && journal.load().count == 128)
    try await coordinator.eject(last.id)
    let replacement = try await coordinator.connect(
        multipleDescriptor(target: "iqn.2026-10.test:replacement"))
    #expect(await coordinator.disks.count == 128)
    try await coordinator.eject(replacement.id)
}

@Test private func restoringDuplicateLogicalDisksPreservesBothForExplicitEjection() async throws {
    let entries = try [multipleEntry(), multipleEntry(portal: "192.0.2.10")]
    let backend = MultipleBackend(entries: entries)
    let journal = MemoryAttachmentJournal(entries: entries)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    await #expect(throws: AttachmentError.duplicateConnections) { try await coordinator.restore() }
    let disks = await coordinator.disks
    #expect(disks.count == 2 && disks.allSatisfy(\.verificationFailed))
    #expect(await coordinator.recoveryReady == false)
    #expect(Set(journal.load().map(\.id)) == Set(entries.map(\.id)))
    #expect(await backend.events.isEmpty)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.connect(multipleDescriptor(target: "iqn.2026-10.test:other"))
    }
    try await coordinator.eject(entries[0].id)
    try await coordinator.restore()
    #expect(await coordinator.recoveryReady)
    #expect(await coordinator.disks.map(\.id) == [entries[1].id])
    #expect(await coordinator.disks.first?.verificationFailed == false)
    try await coordinator.eject(entries[1].id)
    #expect(journal.load().isEmpty)
}

@Test(arguments: [false, true])
private func failedOrCancelledPreparationReleasesItsReservedConnectionSlot(_ cancelled: Bool)
    async throws
{
    let entries = try (0..<127).map { try multipleEntry(target: "iqn.2026-10.test:disk-\($0)") }
    let backend = MultipleBackend(pause: .preparing, entries: entries, preparationFails: !cancelled)
    let journal = MemoryAttachmentJournal(entries: entries)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let descriptor = try multipleDescriptor(target: "iqn.2026-10.test:last")
    let pending = Task { try await coordinator.connect(descriptor) }
    try await connectionPhase { await backend.isPaused }
    if cancelled { pending.cancel() }
    await backend.release()
    if cancelled {
        await #expect(throws: CancellationError.self) { try await pending.value }
    } else {
        await #expect(throws: POSIXError(.EACCES)) { try await pending.value }
    }
    #expect(await backend.events.count == 1)
    #expect(journal.load().count == 127)
    #expect(await coordinator.recoveryReady)
    let replacement = try await coordinator.connect(descriptor)
    #expect(await coordinator.disks.count == 128)
    try await coordinator.eject(replacement.id)
}

@Test(arguments: [ConnectionPause.mounting, .attaching, .inspecting])
private func cancelledConnectionCannotCommitAnUncooperativeBackendResult(_ phase: ConnectionPause)
    async throws
{
    let backend = MultipleBackend(pause: phase)
    let journal = MemoryAttachmentJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let descriptor = try multipleDescriptor(target: "iqn.2026-10.test:cancelled")
    let pending = Task { try await coordinator.connect(descriptor) }
    try await connectionPhase { await backend.isPaused }
    pending.cancel()
    await backend.release()
    switch await pending.result {
    case .success(let connected):
        #expect(Bool(false), "A cancelled connection published a late backend success")
        try await coordinator.eject(connected.id)
    case .failure(let error):
        #expect(error is CancellationError)
    }
    #expect(await coordinator.disks.isEmpty)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.recoveryReady)
    let events = await backend.events
    let id = try #require(
        events.compactMap { event -> UUID? in
            if case .prepare(let id) = event { return id }
            return nil
        }.first)
    #expect(events.last == .unmount(id))
    if phase == .mounting {
        #expect(!events.contains { if case .attach = $0 { true } else { false } })
    } else {
        #expect(events.contains { if case .detach = $0 { true } else { false } })
    }
}

private final class ConcurrentFaultJournal: AttachmentJournal, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [AttachmentJournalEntry] = []
    private var failure: Bool?
    func failNextSave(commit: Bool) { lock.withLock { failure = commit } }
    func load() -> [AttachmentJournalEntry] { lock.withLock { entries } }
    func save(_ next: [AttachmentJournalEntry]) throws {
        try lock.withLock {
            if let commit = failure {
                failure = nil
                if commit { entries = next }
                throw POSIXError(.ENOSPC)
            }
            entries = next
        }
    }
}

@Test(arguments: [false, true])
private func aPreparingConnectionCannotClearAnotherOperationsJournalFailure(_ commit: Bool)
    async throws
{
    let backend = MultipleBackend(pause: .preparing)
    let journal = ConcurrentFaultJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let descriptor = try multipleDescriptor()
    let pending = Task { try await coordinator.connect(descriptor) }
    try await connectionPhase { await backend.isPaused }
    journal.failNextSave(commit: commit)
    await #expect(throws: AttachmentError.journalUnavailable) {
        try await coordinator.connect(multipleDescriptor(target: "iqn.2026-10.test:other"))
    }
    let events = await backend.events
    await backend.release()
    await #expect(throws: AttachmentError.recoveryRequired) { try await pending.value }
    #expect(await backend.events == events)
    #expect(await coordinator.recoveryReady == false)
    #expect(journal.load().count == (commit ? 1 : 0))
    try await coordinator.restore()
    #expect(await coordinator.recoveryReady)
    let replacement = try await coordinator.connect(descriptor)
    try await coordinator.eject(replacement.id)
    #expect(journal.load().isEmpty)
}

@Test(
    arguments: [ConnectionPause.mounting, .attaching, .inspecting, .detaching, .unmounting],
    [false, true])
private func aSuspendedOperationStopsWhenAnotherOperationCannotSaveItsIntent(
    _ stage: ConnectionPause, _ commit: Bool
) async throws {
    let ejecting = stage == .detaching || stage == .unmounting
    let entries = ejecting ? try [multipleEntry()] : []
    let backend = MultipleBackend(pause: stage, entries: entries)
    let journal = ConcurrentFaultJournal()
    try journal.save(entries)
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let work = Task {
        if ejecting {
            try await coordinator.eject(entries[0].id)
        } else {
            _ = try await coordinator.connect(multipleDescriptor())
        }
    }
    try await connectionPhase { await backend.isPaused }
    let original = try #require(await coordinator.disks.first)
    journal.failNextSave(commit: commit)
    await #expect(throws: AttachmentError.journalUnavailable) {
        try await coordinator.connect(multipleDescriptor(target: "iqn.2026-10.test:other"))
    }
    let events = await backend.events
    await backend.release()
    await #expect(throws: AttachmentError.journalUnavailable) { try await work.value }
    #expect(await backend.events == events)
    #expect(await coordinator.disks.contains { $0.id == original.id })
    #expect(await coordinator.recoveryReady == false)
    #expect(journal.load().count == (commit ? 2 : 1))
    try await coordinator.restore()
    #expect(await coordinator.recoveryReady)
    if await coordinator.disks.contains(where: { $0.id == original.id }) {
        try await coordinator.eject(original.id)
    }
    #expect(journal.load().isEmpty)
}

@Test(arguments: [false, true])
private func ejectingOneOfTwoConnectedDisksPreservesTheOtherMount(_ differentLUN: Bool) async throws
{
    let backend = MultipleBackend()
    let journal = MemoryAttachmentJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let first = try await coordinator.connect(multipleDescriptor())
    let second = try await coordinator.connect(
        multipleDescriptor(
            target: differentLUN ? "iqn.2026-10.test:disk" : "iqn.2026-10.test:other",
            lun: differentLUN ? 1 : 0))
    #expect(await coordinator.disks.count == 2)
    #expect(first.attachment?.device != second.attachment?.device)
    try await coordinator.eject(first.id)
    await coordinator.refreshHealth()
    let remaining = try #require(await coordinator.disks.first)
    #expect(remaining.id == second.id && remaining.attachment == second.attachment)
    #expect(remaining.connectionState == .connected && !remaining.verificationFailed)
    #expect(journal.load().map(\.id) == [second.id])
    #expect(await backend.events.suffix(2) == [.detach(first.id), .unmount(first.id)])
    try await coordinator.eject(second.id)
    #expect(journal.load().isEmpty)
}
