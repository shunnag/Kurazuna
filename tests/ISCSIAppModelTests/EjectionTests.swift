import AppKit
import Foundation
import ISCSICore
import ISCSIPlatform
import Security
import Testing

@testable import ISCSIAppModel

@Test(arguments: [Int(errSecInteractionNotAllowed), Int(errSecMissingEntitlement), -50])
@MainActor private func metadataCleanupIssuesNeverDescribeSavedPasswordsOrConnectedDisks(
    _ status: Int
) {
    let cause = NSError(domain: NSOSStatusErrorDomain, code: status)
    let issue = AppIssue(
        MountResourceCleanupError(underlying: cause), context: .ejectingDisk("Work"))
    #expect(issue.title == "Connection Information Couldn’t Be Removed")
    #expect(issue.message.contains("The disk is disconnected"))
    #expect(!issue.message.localizedCaseInsensitiveContains("password"))
    #expect(!issue.message.contains("Disk Utility"))
    #expect(issue.recoveryAction == nil && issue.forceEjectionDiskID == nil)
    #expect(issue.detail == cause.localizedDescription)
    if status == Int(errSecInteractionNotAllowed) {
        #expect(issue.message.contains("Unlock your Mac"))
        #expect(issue.message.contains("Check Connections"))
    } else {
        #expect(!issue.message.contains("Unlock"))
        #expect(issue.message.localizedCaseInsensitiveContains("contact the developer"))
    }
}

@Test @MainActor private func unavailableWriteCompletionExplainsTheReadOnlyAction() {
    let issue = AppIssue(AttachmentError.writeCompletionUnavailable, context: .connectingDisk)
    #expect(issue.title == String(localized: "Read-Only Connection Required"))
    #expect(
        issue.message
            == String(
                localized:
                    "This connection can’t confirm when writes are complete. To view and copy files, choose Connect Read-Only from the Connect menu."
            ))
    #expect(issue.recoveryAction == nil)
}

@Test @MainActor private func unsupportedWritableGeometryExplainsTheReadOnlyAction() {
    let issue = AppIssue(AttachmentError.readOnlyGeometryRequired)
    #expect(issue.title == String(localized: "Read-Only Connection Required"))
    #expect(
        issue.message
            == String(
                localized:
                    "Kurazuna can currently connect this disk only as read-only. To view and copy files, choose Connect Read-Only from the Connect menu."
            ))
    #expect(issue.recoveryAction == nil)
}

private enum EjectionFailure: String, CaseIterable {
    case busy, command, timeout

    var error: any Error {
        switch self {
        case .busy: POSIXError(.EBUSY)
        case .command: SystemCommandError.failed(program: "umount", status: 1, detail: "Failed")
        case .timeout: ProtocolError.timedOut
        }
    }
}

private enum EjectionStage: String, CaseIterable { case detach, unmount }

private actor EjectionBackend: AttachmentBackend {
    private var observations: [UUID: AttachmentInspection]
    var failure: EjectionFailure?
    private let stage: EjectionStage
    private(set) var detachAttempts: [UUID] = []
    private(set) var unmountAttempts: [UUID] = []
    private(set) var forceAttempts: [UUID] = []
    private(set) var forceObservations: [UUID] = []
    private var forceFailure: EjectionFailure?
    private var metadataFailure: (any Error)?
    private var pendingMetadata: Set<UUID> = []
    private var inspectionFailures: [UUID: any Error] = [:]
    private var inventoryFailure = false
    private var unknownBridge = false
    private(set) var metadataRemovalAttempts: [UUID] = []

    init(observations: [UUID: AttachmentInspection], failure: EjectionFailure, stage: EjectionStage)
    {
        self.observations = observations
        self.failure = failure
        self.stage = stage
    }

    func allowEjection() { failure = nil }
    func failInspection(_ error: (any Error)?, for id: UUID) { inspectionFailures[id] = error }
    func failInventory(_ value: Bool) { inventoryFailure = value }
    func showUnknownBridge(_ value: Bool) { unknownBridge = value }
    func failMetadataRemoval(_ error: any Error) { metadataFailure = error }
    func allowMetadataRemoval() { metadataFailure = nil }
    func failForceEjection(_ failure: EjectionFailure) { forceFailure = failure }
    func setConnectionState(_ state: DiskConnectionState, for id: UUID) {
        guard let old = observations[id] else { return }
        observations[id] = AttachmentInspection(
            ownership: old.ownership, attachment: old.attachment, connectionState: state)
    }
    func bridgeURL(for id: UUID) throws -> URL { throw ProtocolError.invalidState }
    func untrackedBridges(excluding trackedURLs: [URL]) throws -> [URL] {
        if inventoryFailure { throw POSIXError(.EIO) }
        return unknownBridge ? [URL(fileURLWithPath: "/private/tmp/iSCSI-Unknown")] : []
    }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        throw ProtocolError.invalidState
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        throw ProtocolError.invalidState
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        if let error = inspectionFailures[id] { throw error }
        return observations[id] ?? AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        let id = try #require(descriptor.mountID)
        detachAttempts.append(id)
        // Archive ejects before Work when quitting; Work is the disk that fails.
        if stage == .detach, descriptor.targetName.hasSuffix("disk-1"), let failure {
            throw failure.error
        }
        observations[id] = AttachmentInspection(ownership: .verified, attachment: nil)
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        let id = try #require(descriptor.mountID)
        unmountAttempts.append(id)
        if stage == .unmount, descriptor.targetName.hasSuffix("disk-1"), let failure {
            throw failure.error
        }
        observations.removeValue(forKey: id)
        pendingMetadata.insert(id)
        try discardEmptyBridge(descriptor, at: bridgeURL)
    }
    func forceEjectionIdentity(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws -> DiskAttachmentIdentity {
        let id = try #require(descriptor.mountID)
        forceObservations.append(id)
        return DiskAttachmentIdentity(
            imageURL: bridgeURL.appendingPathComponent("Disk.img"), device: attachment.device,
            unmountDevices: [attachment.device], mediaIdentifiers: [attachment.device: 41])
    }
    /// Like the system backend, the forced inspection doesn't depend on the extension's
    /// answers, so an ordinary inspection failure doesn't prevent it.
    func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        guard let observation = observations[id] else {
            return AttachmentInspection(ownership: .absent, attachment: nil)
        }
        return AttachmentInspection(
            ownership: observation.ownership, attachment: observation.attachment,
            connectionState: inspectionFailures[id] == nil ? observation.connectionState : .unknown)
    }
    func forceDetachImage(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws {
        let id = try #require(descriptor.mountID)
        forceAttempts.append(id)
        if let forceFailure { throw forceFailure.error }
        observations[id] = AttachmentInspection(ownership: .verified, attachment: nil)
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        let id = try #require(descriptor.mountID)
        guard pendingMetadata.contains(id) else { return }
        metadataRemovalAttempts.append(id)
        if let metadataFailure { throw MountResourceCleanupError(underlying: metadataFailure) }
        pendingMetadata.remove(id)
    }
}

private actor NoCredentials: CredentialStore {
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
}

private final class EjectionSettings: ProfileStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var document: ProfileDocument
    init(_ document: ProfileDocument) { self.document = document }
    func loadOrCreate() -> ProfileDocument { load() }
    func load() -> ProfileDocument { lock.withLock { document } }
    func save(_ value: ProfileDocument) { lock.withLock { document = value } }
}

/// A journal whose saves can be made to fail, as when the Mac runs out of space.
private final class ArmedJournal: AttachmentJournal, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [AttachmentJournalEntry] = []
    private var failing = false
    func replace(_ entries: [AttachmentJournalEntry]) { lock.withLock { self.entries = entries } }
    func arm() { lock.withLock { failing = true } }
    func load() -> [AttachmentJournalEntry] { lock.withLock { entries } }
    func save(_ entries: [AttachmentJournalEntry]) throws {
        try lock.withLock {
            if failing { throw POSIXError(.ENOSPC) }
            self.entries = entries
        }
    }
}

/// A manual clock for when a reconnecting disk's forced release is offered.
private final class OfferClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    func advance(_ duration: Duration) {
        lock.withLock { instant = instant.advanced(by: duration) }
    }
}

/// Stands in for sleeping until an instant of the offer clock: records each requested
/// instant and returns only when the test releases it, or throws when the wait is cancelled.
private final class OfferWaits: @unchecked Sendable {
    private let lock = NSLock()
    private var requested: [ContinuousClock.Instant] = []
    private var waiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private var cancelled: Set<UUID> = []
    var deadlines: [ContinuousClock.Instant] { lock.withLock { requested } }
    var pending: Int { lock.withLock { waiters.count } }
    var cancellations: Int { lock.withLock { cancelled.count } }

    func wait(until deadline: ContinuousClock.Instant) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let cancelledFirst = lock.withLock { () -> Bool in
                    requested.append(deadline)
                    if cancelled.contains(id) { return true }
                    waiters[id] = continuation
                    return false
                }
                if cancelledFirst { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            let waiter = lock.withLock { () -> CheckedContinuation<Void, any Error>? in
                cancelled.insert(id)
                return waiters.removeValue(forKey: id)
            }
            waiter?.resume(throwing: CancellationError())
        }
    }

    func release() {
        let released = lock.withLock { () -> [CheckedContinuation<Void, any Error>] in
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        for waiter in released { waiter.resume() }
    }
}

/// Stands in for the system's notifications that the screen was unlocked and that the
/// application became active, for one model only.
private struct UnlockSignals {
    let screen = NotificationCenter()
    let application = NotificationCenter()
    func unlock() { screen.post(name: AppModel.screenUnlockedNotification, object: nil) }
    func activate() {
        application.post(name: NSApplication.didBecomeActiveNotification, object: nil)
    }
    func post(_ event: LockedCleanupRetryEvent) {
        switch event {
        case .screenUnlocked: unlock()
        case .applicationActivated: activate()
        }
    }
}

/// Stands in for the wait before the second try after an unlock: records each requested
/// duration and returns only when the test releases it, or throws when the wait is cancelled.
private final class FollowUpDelays: @unchecked Sendable {
    private let lock = NSLock()
    private var durations: [Duration] = []
    private var waiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private var cancelled: Set<UUID> = []
    var requested: [Duration] { lock.withLock { durations } }
    var pending: Int { lock.withLock { waiters.count } }
    var cancellations: Int { lock.withLock { cancelled.count } }

    func wait(_ duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let cancelledFirst = lock.withLock { () -> Bool in
                    durations.append(duration)
                    if cancelled.contains(id) { return true }
                    waiters[id] = continuation
                    return false
                }
                if cancelledFirst { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            let waiter = lock.withLock { () -> CheckedContinuation<Void, any Error>? in
                cancelled.insert(id)
                return waiters.removeValue(forKey: id)
            }
            waiter?.resume(throwing: CancellationError())
        }
    }

    func release() {
        let released = lock.withLock { () -> [CheckedContinuation<Void, any Error>] in
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        for waiter in released { waiter.resume() }
    }
}

@MainActor private func fixture(
    _ failure: EjectionFailure, stage: EjectionStage = .detach, volumeNames: Bool = true,
    memoryConfiguration: Bool = false, journal armed: ArmedJournal? = nil,
    clock: OfferClock = OfferClock(), waits: OfferWaits? = nil,
    signals: UnlockSignals = UnlockSignals(), delays: FollowUpDelays = FollowUpDelays()
) async throws
    -> (AppModel, EjectionBackend, MemoryAttachmentJournal)
{
    let identity = try InitiatorIdentity.makeNew()
    let server = try ServerProfile(name: "Storage", portal: Portal("192.0.2.10"))
    var entries: [AttachmentJournalEntry] = []
    var observations: [UUID: AttachmentInspection] = [:]
    for (index, name) in ["Archive", "Work"].enumerated() {
        let id = try #require(UUID(uuidString: "00000000-0000-4000-8000-00000000000\(index + 1)"))
        let descriptor = try ConnectionDescriptor(
            profileID: server.id, portal: server.portal, initiatorName: identity.name,
            targetName: "iqn.2026-10.test:disk-\(index)", lun: LogicalUnit(UInt16(index)),
            readOnly: false, isid: identity.seed, mountID: id)
        entries.append(
            try AttachmentJournalEntry(
                id: id, descriptor: descriptor,
                bridgeURL: URL(fileURLWithPath: "/private/tmp/iSCSI-ModelTests/\(id.uuidString)"),
                phase: .connected))
        observations[id] = AttachmentInspection(
            ownership: .verified,
            attachment: DiskAttachment(
                device: "/dev/disk\(900000 + index)",
                volumeURLs: volumeNames ? [URL(fileURLWithPath: "/Volumes/\(name)")] : []),
            connectionState: .connected)
    }
    let backend = EjectionBackend(observations: observations, failure: failure, stage: stage)
    let journal = MemoryAttachmentJournal(entries: entries)
    armed?.replace(entries)
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: armed ?? journal as any AttachmentJournal,
        now: { clock.now })
    try await coordinator.restore()
    let document = try ProfileDocument(identity: identity, servers: [server])
    let configuration =
        memoryConfiguration
        ? try ServerConfiguration(storage: EjectionSettings(document), credentials: NoCredentials())
        : nil
    let model: AppModel
    if let waits {
        model = AppModel(
            coordinator: coordinator, configuration: configuration, credentials: NoCredentials(),
            sessionFactory: { _, _, _ in throw ProtocolError.invalidState },
            extensionCheck: { .ready }, waitUntil: { try await waits.wait(until: $0) },
            unlockNotifications: signals.screen, activationNotifications: signals.application,
            retryDelay: { try await delays.wait($0) })
    } else {
        model = AppModel(
            coordinator: coordinator, configuration: configuration, credentials: NoCredentials(),
            sessionFactory: { _, _, _ in throw ProtocolError.invalidState },
            extensionCheck: { .ready }, unlockNotifications: signals.screen,
            activationNotifications: signals.application,
            retryDelay: { try await delays.wait($0) })
    }
    model.document = document
    model.attached = await coordinator.disks
    model.recoveryComplete = true
    model.extensionState = .ready
    return (model, backend, journal)
}

@MainActor private func waitForOperation(_ model: AppModel) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@Test(arguments: [false, true])
@MainActor private func metadataCleanupFailureRetainsTheJournalUntilExplicitEjectionRetry(
    staleDisk: Bool
) async throws {
    let (model, backend, journal) = try await fixture(.command, stage: .unmount)
    await backend.allowEjection()
    await backend.failMetadataRemoval(
        NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed)))
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    let original = try #require(journal.load().first { $0.id == disk.id })
    model.eject(disk)
    #expect(model.activity == "Ejecting disk…")
    try await waitForOperation(model)
    let retained = try #require(model.attached.first { $0.id == disk.id })
    #expect(retained.attachment == nil && retained.needsCleanup)
    #expect(retained.phase == .unmountingBridge && retained.verificationFailed)
    #expect(retained.resourceCleanupError != nil)
    #expect(model.resourceCleanupOnly)
    #expect(model.diskStatus(retained) == "Disconnected")
    #expect(!model.connectionRecoveryNotice.showsDiskUtility)
    let entry = try #require(journal.load().first { $0.id == disk.id })
    #expect(entry.phase == .unmountingBridge)
    #expect(entry.descriptor == original.descriptor && entry.bridgeURL == original.bridgeURL)
    #expect(model.issue?.message.contains("The disk is disconnected") == true)
    #expect(model.issue?.forceEjectionDiskID == nil && model.issue?.recoveryAction == nil)
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.metadataRemovalAttempts == [disk.id])
    #expect(await backend.forceAttempts.isEmpty)
    #expect(await backend.forceObservations.isEmpty)
    #expect(model.attached.count == 2 && journal.load().count == 2)

    model.issue = nil
    await backend.allowMetadataRemoval()
    model.eject(staleDisk ? disk : retained)
    #expect(model.activity == "Removing connection information…")
    try await waitForOperation(model)
    #expect(model.issue == nil && model.attached.count == 1)
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.metadataRemovalAttempts == [disk.id, disk.id])
    #expect(await backend.forceAttempts.isEmpty)
    #expect(await backend.forceObservations.isEmpty)
}

@Test @MainActor private func metadataCleanupCanBeRecoveredByANewCoordinatorWithoutAnotherDetach()
    async throws
{
    let (model, backend, journal) = try await fixture(.command, stage: .unmount)
    await backend.allowEjection()
    await backend.failMetadataRemoval(
        NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed)))
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    let restarted = try AttachmentCoordinator(backend: backend, journal: journal)
    #expect(await restarted.disks.allSatisfy { $0.resourceCleanupError == nil })
    #expect(await restarted.recoveryState == .needsInspection)
    await #expect(throws: MountResourceCleanupError.self) { try await restarted.restore() }
    #expect(await restarted.recoveryState == .resourceCleanupPending)
    #expect(journal.load().contains { $0.id == disk.id && $0.phase == .unmountingBridge })
    #expect(await backend.detachAttempts == [disk.id])
    await backend.allowMetadataRemoval()
    try await restarted.restore()
    #expect(await restarted.recoveryState == .ready)
    #expect(await restarted.disks.count == 1)
    #expect(journal.load().count == 1 && !journal.load().contains { $0.id == disk.id })
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == [disk.id])
    #expect(await backend.forceAttempts.isEmpty)
    #expect(await backend.forceObservations.isEmpty)
}

@Test(arguments: [Int(errSecInteractionNotAllowed), Int(errSecMissingEntitlement), -50])
@MainActor private func metadataCleanupRecoveryNoticeUsesTheObservedCause(_ status: Int)
    async throws
{
    let (model, backend, journal) = try await fixture(
        .command, stage: .unmount, memoryConfiguration: true)
    await model.load()
    await backend.allowEjection()
    await backend.failMetadataRemoval(NSError(domain: NSOSStatusErrorDomain, code: status))
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    model.issue = nil
    let notice = model.connectionRecoveryNotice
    #expect(model.resourceCleanupOnly && model.connectionStatusNeedsAttention)
    #expect(notice.title == "Connection Information Remains")
    #expect(notice.actionTitle == "Check Connections" && !notice.showsDiskUtility)
    #expect(!notice.message.contains("Disk Utility") && !notice.message.contains("password"))
    if status == Int(errSecInteractionNotAllowed) {
        #expect(notice.message.contains("Unlock your Mac"))
    } else if status == Int(errSecMissingEntitlement) {
        #expect(notice.message.contains("Contact the developer"))
        #expect(!notice.message.contains("Unlock"))
    } else {
        #expect(notice.message.contains("try again"))
    }
    #expect(!model.canConnect && !model.canEditServers)
    #expect(journal.load().contains { $0.id == disk.id })
    await backend.allowMetadataRemoval()
    model.checkConnections()
    try await waitForOperation(model)
    #expect(model.recoveryComplete && !model.connectionStatusNeedsAttention)
    #expect(!model.resourceCleanupOnly && model.issue == nil)
    #expect(model.canConnect && model.canEditServers)
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == [disk.id])
    #expect(await backend.forceAttempts.isEmpty)
}

private enum MetadataRecoveryGuard: CaseIterable, Equatable {
    case inspection, otherDisk, inventory, untracked
}

@Test(arguments: MetadataRecoveryGuard.allCases)
@MainActor private func metadataCleanupDoesNotHideOtherUnverifiedResources(
    _ failure: MetadataRecoveryGuard
) async throws {
    let (model, backend, _) = try await fixture(
        .command, stage: .unmount, memoryConfiguration: true)
    await model.load()
    await backend.allowEjection()
    await backend.failMetadataRemoval(
        NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed)))
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    let other = try #require(model.attached.first { $0.id != disk.id })
    model.eject(disk)
    try await waitForOperation(model)
    #expect(model.resourceCleanupOnly)
    switch failure {
    case .inspection: await backend.failInspection(POSIXError(.EIO), for: disk.id)
    case .otherDisk: await backend.failInspection(POSIXError(.EIO), for: other.id)
    case .inventory: await backend.failInventory(true)
    case .untracked: await backend.showUnknownBridge(true)
    }
    model.issue = nil
    model.checkConnections()
    try await waitForOperation(model)
    #expect(!model.resourceCleanupOnly && model.connectionStatusNeedsAttention)
    #expect(model.connectionRecoveryNotice.showsDiskUtility)
    #expect(model.connectionRecoveryNotice.title == "Check Connected Disks")
    if failure == .inspection {
        let current = try #require(model.attached.first { $0.id == disk.id })
        #expect(current.resourceCleanupError == nil)
        #expect(model.diskStatus(current) == "Check this connection")
    }
    await backend.failInspection(nil, for: disk.id)
    await backend.failInspection(nil, for: other.id)
    await backend.failInventory(false)
    await backend.showUnknownBridge(false)
    model.checkConnections()
    try await waitForOperation(model)
    #expect(model.resourceCleanupOnly && !model.connectionRecoveryNotice.showsDiskUtility)
    #expect(await backend.forceAttempts.isEmpty)
}

/// Ejects Work while its connection information can't be removed for `status`, as when the
/// Mac is locked. Archive stays connected, unless `archiveFirst` ejects it first, while its
/// connection information can still be removed.
@MainActor private func cleanupFixture(
    status: Int = Int(errSecInteractionNotAllowed), signals: UnlockSignals = UnlockSignals(),
    delays: FollowUpDelays = FollowUpDelays(), archiveFirst: Bool = false
) async throws -> (AppModel, EjectionBackend, MemoryAttachmentJournal, AttachedDisk) {
    let (model, backend, journal) = try await fixture(
        .command, stage: .unmount, memoryConfiguration: true, signals: signals, delays: delays)
    await model.load()
    await backend.allowEjection()
    let work = try #require(model.attached.first { $0.displayName == "Work" })
    let archive = try #require(model.attached.first { $0.displayName == "Archive" })
    if archiveFirst {
        model.eject(archive)
        try await waitForOperation(model)
        #expect(model.issue == nil && model.attached.map(\.id) == [work.id])
    }
    await backend.failMetadataRemoval(NSError(domain: NSOSStatusErrorDomain, code: status))
    model.eject(work)
    try await waitForOperation(model)
    #expect(model.issue?.reportsResourceCleanup == true)
    #expect(model.resourceCleanupOnly && model.connectionStatusNeedsAttention)
    return (model, backend, journal, work)
}

/// Waits until the back end has tried to remove connection information `count` times in all,
/// and the operation that tried has ended.
@MainActor private func waitForMetadataRemoval(
    _ count: Int, _ backend: EjectionBackend, _ model: AppModel
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while await backend.metadataRemovalAttempts.count < count {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
    try await waitForOperation(model)
}

/// The eject finished while the Mac was locked, so its alert is still shown when the Mac is
/// unlocked. The check runs behind it as Check Connections would and, once the connection
/// information is gone, closes the alert that asked to remove it.
@Test(arguments: LockedCleanupRetryEvent.allCases)
@MainActor private func anUnlockRemovesLockedConnectionInformationOnceAndClosesItsAlert(
    _ event: LockedCleanupRetryEvent
) async throws {
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, journal, disk) = try await cleanupFixture(
        signals: signals, delays: delays)
    #expect(model.issue?.reportsResourceCleanup == true)
    #expect(model.lockedResourceCleanupPending)
    #expect(await backend.metadataRemovalAttempts == [disk.id])
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    await backend.allowMetadataRemoval()
    signals.post(event)
    try await waitForMetadataRemoval(2, backend, model)
    #expect(model.recoveryComplete && !model.connectionStatusNeedsAttention)
    #expect(!model.resourceCleanupOnly && !model.lockedResourceCleanupPending)
    #expect(model.notice == nil && model.canConnect && model.canEditServers)
    #expect(model.attached.map(\.displayName) == ["Archive"])
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(model.issue == nil)
    // Nothing is left to remove, so later events start nothing, and nothing was scheduled.
    signals.unlock()
    signals.activate()
    try await Task.sleep(for: .milliseconds(50))
    #expect(!model.busy && delays.requested.isEmpty)
    #expect(await backend.metadataRemovalAttempts == [disk.id, disk.id])
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == [disk.id])
    #expect(await backend.forceAttempts.isEmpty)
}

/// The Keychain is still locked for a moment after the screen is unlocked. The check that
/// follows the unlock fails, and is tried once more shortly after, without another event.
@Test @MainActor private func aFailedCheckAfterAnUnlockIsTriedOnceMoreShortlyAfter()
    async throws
{
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, journal, disk) = try await cleanupFixture(
        signals: signals, delays: delays)
    let alert = try #require(model.issue)
    let notice = model.connectionRecoveryNotice
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    signals.unlock()
    try await waitForMetadataRemoval(2, backend, model)
    try await eventually { delays.pending == 1 }
    #expect(delays.requested == [AppModel.lockedCleanupFollowUpDelay])
    // The failed check changed nothing that's shown.
    #expect(model.issue?.id == alert.id && model.lockedResourceCleanupPending)
    #expect(model.connectionRecoveryNotice.message == notice.message)
    #expect(!model.busy)
    // The Keychain opens; no activation or other event is needed.
    await backend.allowMetadataRemoval()
    delays.release()
    try await waitForMetadataRemoval(3, backend, model)
    #expect(model.issue == nil && model.notice == nil)
    #expect(!model.lockedResourceCleanupPending && model.recoveryComplete)
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(delays.requested.count == 1 && delays.pending == 0)
    #expect(await backend.metadataRemovalAttempts.count == 3)
}

@Test @MainActor private func theSecondTryAfterAnUnlockSchedulesNoThird() async throws {
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, _, _) = try await cleanupFixture(signals: signals, delays: delays)
    let alert = try #require(model.issue)
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    signals.unlock()
    try await waitForMetadataRemoval(2, backend, model)
    try await eventually { delays.pending == 1 }
    delays.release()
    try await waitForMetadataRemoval(3, backend, model)
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy && delays.requested.count == 1 && delays.pending == 0)
    #expect(await backend.metadataRemovalAttempts.count == 3)
    #expect(model.issue?.id == alert.id && model.lockedResourceCleanupPending)
    // Only the next event tries again. A failed check after an activation isn't tried again
    // later: the screen was already unlocked.
    signals.activate()
    try await waitForMetadataRemoval(4, backend, model)
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy && delays.requested.count == 1 && delays.pending == 0)
    #expect(await backend.metadataRemovalAttempts.count == 4)
}

/// The application becomes active while the second try after an unlock waits. Its check
/// takes the second try's place and, when it fails too, the second try is still made.
@Test @MainActor private func anActivationBeforeTheSecondTryKeepsIt() async throws {
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, journal, disk) = try await cleanupFixture(
        signals: signals, delays: delays)
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    signals.unlock()
    try await waitForMetadataRemoval(2, backend, model)
    try await eventually { delays.pending == 1 }
    signals.activate()
    try await waitForMetadataRemoval(3, backend, model)
    try await eventually { delays.pending == 1 && delays.cancellations == 1 }
    #expect(delays.requested.count == 2 && model.lockedResourceCleanupPending)
    await backend.allowMetadataRemoval()
    delays.release()
    try await waitForMetadataRemoval(4, backend, model)
    #expect(model.issue == nil && !model.lockedResourceCleanupPending)
    #expect(!journal.load().contains { $0.id == disk.id })
    // The second try schedules nothing more.
    try await Task.sleep(for: .milliseconds(100))
    #expect(delays.requested.count == 2 && delays.pending == 0)
    #expect(await backend.metadataRemovalAttempts.count == 4)
}

/// An unlock usually makes the application active too, in either order. The two events check
/// once, and that check counts as the one after the unlock.
@Test(arguments: [true, false])
@MainActor private func anUnlockAndAnActivationTogetherCheckOnceAndTryOnceMore(
    _ unlockFirst: Bool
) async throws {
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, _, _) = try await cleanupFixture(signals: signals, delays: delays)
    model.issue = nil
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    if unlockFirst {
        signals.unlock()
        signals.activate()
    } else {
        signals.activate()
        signals.unlock()
    }
    try await waitForMetadataRemoval(2, backend, model)
    try await eventually { delays.pending == 1 }
    #expect(await backend.metadataRemovalAttempts.count == 2)
    #expect(delays.requested == [AppModel.lockedCleanupFollowUpDelay])
    #expect(model.issue == nil && model.lockedResourceCleanupPending)
}

/// The second try gives way to anything that happened meanwhile, and stopping cancels it.
@Test @MainActor private func theSecondTryIsSkippedOrCancelledWhenOtherThingsHappen()
    async throws
{
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, _, _) = try await cleanupFixture(signals: signals, delays: delays)
    model.issue = nil
    model.startRetryingLockedCleanup()
    signals.unlock()
    try await waitForMetadataRemoval(2, backend, model)
    try await eventually { delays.pending == 1 }
    // Check Connections runs meanwhile, and fails too; it reports this in its alert.
    model.checkConnections()
    try await waitForMetadataRemoval(3, backend, model)
    #expect(model.issue?.reportsResourceCleanup == true)
    delays.release()
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy)
    #expect(await backend.metadataRemovalAttempts.count == 3)

    // The next unlock schedules a second try again; stopping cancels it.
    signals.unlock()
    try await waitForMetadataRemoval(4, backend, model)
    try await eventually { delays.pending == 1 }
    model.stopRetryingLockedCleanup()
    try await eventually { delays.pending == 0 && delays.cancellations == 1 }
    await backend.allowMetadataRemoval()
    signals.unlock()
    signals.activate()
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy && model.lockedResourceCleanupPending)
    #expect(await backend.metadataRemovalAttempts.count == 4)
}

/// The model, not a window, keeps the observation, so it goes on while the main window is
/// closed. Starting it again adds no second observation: after one stop, nothing observes.
@Test @MainActor private func theModelKeepsOneObservationUntilItStops() async throws {
    let signals = UnlockSignals()
    let (model, backend, _, _) = try await cleanupFixture(signals: signals)
    model.issue = nil
    model.startRetryingLockedCleanup()
    model.startRetryingLockedCleanup()
    model.stopRetryingLockedCleanup()
    await backend.allowMetadataRemoval()
    signals.unlock()
    signals.activate()
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy && model.lockedResourceCleanupPending)
    #expect(await backend.metadataRemovalAttempts.count == 1)
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    signals.activate()
    try await waitForMetadataRemoval(2, backend, model)
    #expect(!model.lockedResourceCleanupPending && model.recoveryComplete)
}

@Test @MainActor private func aFailedCheckAfterAnActivationWaitsForTheNextEvent() async throws {
    let signals = UnlockSignals()
    let delays = FollowUpDelays()
    let (model, backend, journal, disk) = try await cleanupFixture(
        signals: signals, delays: delays)
    model.issue = nil
    let notice = model.connectionRecoveryNotice
    model.startRetryingLockedCleanup()
    defer { model.stopRetryingLockedCleanup() }
    signals.activate()
    try await waitForMetadataRemoval(2, backend, model)
    #expect(model.issue == nil)
    #expect(model.lockedResourceCleanupPending && model.notice == .connectionRecovery)
    #expect(model.connectionRecoveryNotice.title == notice.title)
    #expect(model.connectionRecoveryNotice.message == notice.message)
    #expect(!model.canConnect && !model.canEditServers)
    // A failed check isn't repeated on its own.
    try await Task.sleep(for: .milliseconds(100))
    #expect(!model.busy && model.issue == nil && delays.requested.isEmpty)
    #expect(await backend.metadataRemovalAttempts.count == 2)
    // The next event tries once more, and succeeds.
    await backend.allowMetadataRemoval()
    signals.unlock()
    try await waitForMetadataRemoval(3, backend, model)
    #expect(model.issue == nil && model.notice == nil)
    #expect(!model.lockedResourceCleanupPending && model.recoveryComplete)
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(await backend.metadataRemovalAttempts.count == 3 && delays.requested.isEmpty)
}

@Test @MainActor private func lockedConnectionInformationWaitsWhileAnythingElseIsInProgress()
    async throws
{
    let (model, backend, _, _) = try await cleanupFixture()
    await backend.allowMetadataRemoval()
    model.busy = true
    model.retryLockedResourceCleanup()
    #expect(!model.canCancel)
    model.busy = false
    model.showingServerEditor = true
    model.retryLockedResourceCleanup()
    #expect(!model.busy && !model.canCancel)
    model.showingServerEditor = false
    // An unrelated alert waits for an answer.
    model.issue = AppIssue(ProtocolError.timedOut)
    model.retryLockedResourceCleanup()
    #expect(!model.busy && !model.canCancel)
    model.issue = nil
    #expect(await backend.metadataRemovalAttempts.count == 1)
    #expect(model.lockedResourceCleanupPending)

    // The check can be canceled like any other, and then nothing reports it.
    model.retryLockedResourceCleanup()
    #expect(model.busy && model.canCancel)
    #expect(model.activity == String(localized: "Checking connected disks…"))
    model.cancel()
    try await waitForOperation(model)
    #expect(model.issue == nil && model.lockedResourceCleanupPending)

    model.retryLockedResourceCleanup()
    #expect(model.busy)
    // Another event while it runs starts nothing more.
    model.retryLockedResourceCleanup()
    // An alert about something else that appears meanwhile stays when the check succeeds.
    let unrelated = AppIssue(ProtocolError.timedOut)
    model.issue = unrelated
    try await waitForOperation(model)
    #expect(await backend.metadataRemovalAttempts.count == 2)
    #expect(!model.lockedResourceCleanupPending && model.issue?.id == unrelated.id)
}

/// Unlocking doesn't help with another cause, so only Check Connections tries again.
@Test(arguments: [Int(errSecMissingEntitlement), -50])
@MainActor private func connectionInformationLeftForAnotherCauseIsNotRetriedOnUnlock(_ status: Int)
    async throws
{
    let (model, backend, _, _) = try await cleanupFixture(status: status)
    #expect(!model.lockedResourceCleanupPending)
    for event in LockedCleanupRetryEvent.allCases {
        model.retryLockedResourceCleanup(after: event)
        #expect(!model.busy && !model.canCancel)
    }
    model.issue = nil
    for event in LockedCleanupRetryEvent.allCases {
        model.retryLockedResourceCleanup(after: event)
        #expect(!model.busy && !model.canCancel)
    }
    #expect(await backend.metadataRemovalAttempts.count == 1)
}

private func genericQuitWarning() -> QuitWarning {
    QuitWarning(
        title: String(localized: "Connection Status Is Unavailable"),
        message: String(
            localized:
                "\(AppName.inSentence) couldn’t verify which disks are connected. Check the disks in Disk Utility before quitting."
        ))
}

@Test(arguments: [Int(errSecInteractionNotAllowed), Int(errSecMissingEntitlement), -50])
@MainActor private func quittingWithOnlyConnectionInformationLeftSaysTheDiskIsDisconnected(
    _ status: Int
) async throws {
    let (model, _, _, _) = try await cleanupFixture(status: status, archiveFirst: true)
    model.issue = nil
    let warning = model.quitWarning
    #expect(warning.title == "Connection Information Remains")
    #expect(!warning.message.contains("Disk Utility"))
    switch status {
    case Int(errSecInteractionNotAllowed):
        #expect(
            warning.message
                == "The disk is disconnected. Unlock your Mac, then click Check Connections to remove its connection information."
        )
    case Int(errSecMissingEntitlement):
        #expect(
            warning.message
                == "The disk is disconnected, but this copy of Kurazuna can’t remove its connection information. Contact the developer for assistance."
        )
    default:
        #expect(
            warning.message
                == "The disk is disconnected, but its connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
        )
    }
}

@Test(arguments: [Int(errSecInteractionNotAllowed), Int(errSecMissingEntitlement), -50])
@MainActor private func quittingWithAConnectedDiskBesideConnectionInformationAsksForACheck(
    _ status: Int
) async throws {
    let (model, backend, _, _) = try await cleanupFixture(status: status)
    model.issue = nil
    // Archive is still connected beside Work's connection information.
    #expect(model.attached.contains { $0.resourceCleanupError == nil })
    #expect(model.quitWarning == genericQuitWarning())
    // Once Archive is ejected too, only connection information is left, for both disks.
    let archive = try #require(model.attached.first { $0.displayName == "Archive" })
    model.eject(archive)
    try await waitForOperation(model)
    model.issue = nil
    #expect(model.attached.count == 2)
    #expect(model.attached.allSatisfy { $0.resourceCleanupError != nil })
    let warning = model.quitWarning
    #expect(warning.title == "Connection Information Remains")
    switch status {
    case Int(errSecInteractionNotAllowed):
        #expect(
            warning.message
                == "The disks are disconnected. Unlock your Mac, then click Check Connections to remove their connection information."
        )
    case Int(errSecMissingEntitlement):
        #expect(
            warning.message
                == "The disks are disconnected, but this copy of Kurazuna can’t remove their connection information. Contact the developer for assistance."
        )
    default:
        #expect(
            warning.message
                == "The disks are disconnected, but their connection information couldn’t be removed. Click Check Connections to try again. If the problem continues, contact the developer for assistance."
        )
    }
    // A disk that can't be verified means which disks are connected isn't known.
    await backend.failInspection(POSIXError(.EIO), for: archive.id)
    model.checkConnections()
    try await waitForOperation(model)
    model.issue = nil
    #expect(model.connectionStatusNeedsAttention && !model.resourceCleanupOnly)
    #expect(model.quitWarning == genericQuitWarning())
}

@Test(arguments: EjectionFailure.allCases, EjectionStage.allCases)
@MainActor private func failedEjectionRetainsTheDiskAndAllowsAnExplicitRetry(
    _ failure: EjectionFailure, _ stage: EjectionStage
)
    async throws
{
    let (model, backend, journal) = try await fixture(failure, stage: stage)
    let disk = try #require(
        model.attached.first { $0.attachment?.volumeURLs.first?.lastPathComponent == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    let issue = try #require(model.issue)
    #expect(issue.title.contains("Work"))
    #expect(!issue.message.contains("server address"))
    #expect(issue.recoveryAction == (failure == .busy ? nil : .openDiskUtility))
    // Every failed eject, busy or not, offers a confirmed forced release.
    #expect(issue.forceEjectionDiskID == disk.id)
    #expect(model.attached.count == 2)
    let phase: AttachmentPhase = stage == .detach ? .detachingImage : .unmountingBridge
    #expect(model.attached.first { $0.id == disk.id }?.phase == phase)
    #expect(journal.load().first { $0.id == disk.id }?.phase == phase)
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == (stage == .detach ? [] : [disk.id]))
    #expect(!model.busy && model.activity.isEmpty && !model.canCancel)

    model.issue = nil
    await backend.allowEjection()
    model.eject(try #require(model.attached.first { $0.id == disk.id }))
    try await waitForOperation(model)
    #expect(model.issue == nil)
    #expect(model.attached.count == 1 && model.attached.first?.id != disk.id)
    #expect(journal.load().count == 1)
    #expect(await backend.detachAttempts == (stage == .detach ? [disk.id, disk.id] : [disk.id]))
    #expect(await backend.unmountAttempts == (stage == .detach ? [disk.id] : [disk.id, disk.id]))
}

/// Another app (Parallels Desktop's OS detection, for example) still had the bridge's
/// Disk.img open after the inner image detached, beyond the backend's bounded wait.
@Test @MainActor private func aBusyBridgeAfterItsImageDetachedIsInUseAndStaysConnected()
    async throws
{
    let (model, backend, journal) = try await fixture(.busy, stage: .unmount)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "“\("Work")” Is in Use"))
    #expect(
        issue.message
            == String(
                localized: "Close any files or apps using this disk, then try ejecting it again."))
    #expect(issue.recoveryAction == nil)
    // As after any failed normal eject, the alert offers a confirmed forced release.
    #expect(issue.forceEjectionDiskID == disk.id)
    let retained = try #require(model.attached.first { $0.id == disk.id })
    #expect(retained.phase == .unmountingBridge && retained.attachment == nil)
    #expect(!retained.verificationFailed && retained.connectionState == .connected)
    // The row doesn't: the connection is healthy and only the bridge is left to unmount.
    #expect(!retained.offersForcedRelease && !model.offersForceEjection(retained))
    #expect(
        model.diskStatus(retained)
            == String(localized: "Not fully disconnected. Eject to finish."))
    #expect(model.recoveryComplete && !model.connectionStatusNeedsAttention)
    #expect(journal.load().first { $0.id == disk.id }?.phase == .unmountingBridge)

    model.issue = nil
    await backend.allowEjection()
    model.eject(retained)
    try await waitForOperation(model)
    #expect(model.issue == nil)
    #expect(model.attached.map(\.displayName) == ["Archive"])
    #expect(!journal.load().contains { $0.id == disk.id })
    // The image had already detached: the second eject only unmounts the bridge.
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == [disk.id, disk.id])
    #expect(await backend.forceAttempts.isEmpty)
}

@Test @MainActor private func aRelaunchAfterABusyBridgeShowsItAndFinishesTheEjection()
    async throws
{
    let (model, backend, journal) = try await fixture(.busy, stage: .unmount)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    #expect(journal.load().first { $0.id == disk.id }?.phase == .unmountingBridge)
    // The bridge is still mounted, connected, and now free.
    await backend.setConnectionState(.connected, for: disk.id)
    await backend.allowEjection()
    let restarted = try AttachmentCoordinator(backend: backend, journal: journal)
    try await restarted.restore()
    #expect(await restarted.recoveryState == .ready)
    let restored = try #require(await restarted.disks.first { $0.id == disk.id })
    #expect(restored.phase == .unmountingBridge && restored.attachment == nil)
    #expect(!restored.verificationFailed && restored.connectionState == .connected)
    #expect(!restored.offersForcedRelease)
    #expect(
        model.diskStatus(restored)
            == String(localized: "Not fully disconnected. Eject to finish."))
    try await restarted.eject(disk.id)
    #expect(await restarted.disks.map(\.displayName) == ["Archive"])
    #expect(!journal.load().contains { $0.id == disk.id })
    #expect(await backend.detachAttempts == [disk.id])
    #expect(await backend.unmountAttempts == [disk.id, disk.id])
    #expect(await backend.forceAttempts.isEmpty)
}

/// Unchanged: a bridge unmount that failed for another reason leaves the disk to be checked.
@Test @MainActor private func aBridgeUnmountFailureThatIsNotBusyStillAsksForACheck()
    async throws
{
    let (model, backend, journal) = try await fixture(.command, stage: .unmount)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    model.eject(disk)
    try await waitForOperation(model)
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "“\("Work")” Couldn’t Be Ejected"))
    #expect(
        issue.message
            == String(
                localized:
                    "The disk may still be connected. Check it in Disk Utility, then try again."))
    #expect(issue.recoveryAction == .openDiskUtility)
    #expect(issue.detail == "umount (1): Failed")
    let retained = try #require(model.attached.first { $0.id == disk.id })
    #expect(retained.phase == .unmountingBridge && retained.verificationFailed)
    #expect(retained.connectionState == .unknown && model.offersForceEjection(retained))
    #expect(model.diskStatus(retained) == String(localized: "Check this connection"))
    #expect(journal.load().first { $0.id == disk.id }?.phase == .unmountingBridge)
    #expect(await backend.unmountAttempts == [disk.id])
}

@Test @MainActor private func ejectAndQuitStopsAtTheFailedDiskAndNamesItInTheIssue() async throws {
    let (model, backend, journal) = try await fixture(.command)
    let ids = model.attached.map(\.id)
    #expect(!(await model.ejectAll()))
    #expect(model.issue?.title.contains("Work") == true)
    #expect(model.issue?.recoveryAction == .openDiskUtility)
    #expect(model.attached.map(\.id) == [ids[1]])
    #expect(journal.load().map(\.id) == [ids[1]])
    #expect(await backend.detachAttempts == ids)
    #expect(await backend.unmountAttempts == [ids[0]])
    #expect(!model.busy && model.activity.isEmpty)

    model.issue = nil
    await backend.allowEjection()
    #expect(await model.ejectAll())
    #expect(model.attached.isEmpty)
    #expect(journal.load().isEmpty)
}

private struct LostEjectionCase: Sendable {
    let state: DiskConnectionState
    let quitting: Bool
    let stage: EjectionStage

    static var all: [Self] {
        [DiskConnectionState.interrupted, .closed].flatMap { state in
            [false, true].flatMap { quitting in
                EjectionStage.allCases.map { Self(state: state, quitting: quitting, stage: $0) }
            }
        }
    }
}

@Test(arguments: LostEjectionCase.all)
@MainActor private func busyEjectionAfterConnectionLossUsesTheLatestStateAndRetainsRecovery(
    _ input: LostEjectionCase
) async throws {
    let (state, quitting, stage) = (input.state, input.quitting, input.stage)
    let (model, backend, journal) = try await fixture(.busy, stage: stage)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    #expect(disk.connectionState == .connected)
    // The row is stale: only the eject-time backend inspection sees the loss.
    await backend.setConnectionState(state, for: disk.id)
    if quitting {
        #expect(!(await model.ejectAll()))
    } else {
        model.eject(disk)
        try await waitForOperation(model)
    }
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "“\(disk.displayName)” Couldn’t Be Ejected"))
    #expect(issue.recoveryAction == .openDiskUtility)
    // Any failed eject offers force, including one that stopped at the outer bridge.
    #expect(issue.forceEjectionDiskID == disk.id)
    #expect(
        issue.message
            == String(
                localized:
                    "The connection was interrupted, and recent changes may not have been saved. Check the disk in Disk Utility, then try ejecting it again."
            ))
    let retained = try #require(model.attached.first { $0.id == disk.id })
    #expect(retained.connectionState == state)
    #expect(retained.needsCleanup && !retained.verificationFailed)
    #expect(journal.load().contains { $0.id == disk.id })
    #expect(model.attached.count == (quitting ? 1 : 2))
    #expect(!model.busy && !model.canCancel && model.activity.isEmpty)
    #expect(await backend.detachAttempts.filter { $0 == disk.id }.count == 1)
    #expect(
        await backend.unmountAttempts.filter { $0 == disk.id }.count == (stage == .detach ? 0 : 1))

    model.issue = nil
    await backend.allowEjection()
    await backend.setConnectionState(.connected, for: disk.id)
    #expect(await model.ejectAll())
    #expect(model.attached.isEmpty && journal.load().isEmpty)
}

@Test @MainActor private func forceEjectionCanBeCancelledAndOnlyConfirmsOneInterruptedDisk()
    async throws
{
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.interrupted, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    #expect(model.issue?.forceEjectionDiskID == disk.id)
    #expect(await backend.forceAttempts.isEmpty)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let first = try #require(model.forceEjectionRequest)
    #expect(first.displayName == "Work")
    #expect(await backend.forceAttempts.isEmpty)
    #expect(journal.load().count == 2)
    await model.cancelForceEjection(first)
    #expect(await backend.forceAttempts.isEmpty)
    #expect(model.attached.count == 2)
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let second = try #require(model.forceEjectionRequest)
    #expect(first.id != second.id)
    model.forceEject(second)
    try await waitForOperation(model)
    #expect(await backend.forceAttempts == [disk.id])
    #expect(model.attached.map(\.displayName) == ["Archive"])
    #expect(journal.load().map(\.id) == model.attached.map(\.id))
    #expect(model.forceEjectionRequest == nil && model.issue == nil)
    #expect(!model.busy && !model.canCancel)
}

@Test @MainActor private func failedForceEjectionKeepsTheInterruptedDiskWarningAndJournal()
    async throws
{
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.interrupted, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    let normalIssue = try #require(model.issue)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    await backend.failForceEjection(.busy)
    model.forceEject(request)
    try await waitForOperation(model)
    #expect(model.issue?.title == normalIssue.title)
    #expect(model.issue?.message == normalIssue.message)
    // A failed forced release can be tried again, with a new observation and confirmation.
    #expect(model.issue?.forceEjectionDiskID == disk.id)
    #expect(model.forceEjectionRequest == nil)
    #expect(model.attached.count == 2 && journal.load().count == 2)
    #expect(model.attached.first { $0.id == disk.id }?.connectionState == .interrupted)
    #expect(await backend.forceAttempts == [disk.id])
    #expect(!model.busy && !model.canCancel)
}

@Test(arguments: [false, true])
@MainActor private func aDismissedForceConfirmationCannotBeSubmittedLater(
    anotherOperation: Bool
) async throws {
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.interrupted, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    if anotherOperation {
        let other = try #require(model.attached.first { $0.id != disk.id })
        model.eject(other)
        try await waitForOperation(model)
    } else {
        // The original SwiftUI presentation binding only cleared the visible request.
        model.forceEjectionRequest = nil
    }
    #expect(model.forceEjectionRequest == nil)
    model.forceEject(request)
    try await waitForOperation(model)
    #expect(await backend.forceAttempts.isEmpty)
    #expect(model.attached.contains { $0.id == disk.id })
    #expect(journal.load().contains { $0.id == disk.id })
}

@Test(arguments: [false, true])
@MainActor private func cancellingAnOldForceConfirmationKeepsItsReplacement(
    synchronousDismissal: Bool
) async throws {
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.interrupted, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let first = try #require(model.forceEjectionRequest)
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let second = try #require(model.forceEjectionRequest)
    #expect(first != second)
    if synchronousDismissal {
        model.dismissForceEjection(first)
    } else {
        await model.cancelForceEjection(first)
    }
    #expect(model.forceEjectionRequest == second)
    model.forceEject(second)
    try await waitForOperation(model)
    #expect(await backend.forceAttempts == [disk.id])
    #expect(!model.attached.contains { $0.id == disk.id })
    #expect(!journal.load().contains { $0.id == disk.id })
}

@Test @MainActor private func forceDismissalInvalidatesTheRequestBeforeItsActorCancellation()
    async throws
{
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.interrupted, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    model.dismissForceEjection(request)
    #expect(model.forceEjectionRequest == nil)
    model.forceEject(request)
    #expect(!model.busy)
    await model.cancelForceEjection(request)
    #expect(await backend.forceAttempts.isEmpty)
    #expect(model.attached.contains { $0.id == disk.id })
    #expect(journal.load().contains { $0.id == disk.id })
}

/// A disk without a mounted volume is called by its LUN, as its row shows it, rather than by
/// the target's full name.
@Test @MainActor private func anUnnamedDiskUsesItsDisplayedNameInTheEjectionIssue()
    async throws
{
    let (model, _, journal) = try await fixture(.command, volumeNames: false)
    let disk = try #require(model.attached.last)
    let name = String(localized: "Disk \(disk.descriptor.lun.displayIdentifier)")
    #expect(disk.displayName == name)
    model.eject(disk)
    try await waitForOperation(model)
    // The title keeps the name on one line.
    #expect(
        model.issue?.title
            == String(localized: "“\(AppName.inSentence(name))” Couldn’t Be Ejected"))
    #expect(model.issue?.title.contains(disk.descriptor.targetName) == false)
    #expect(model.issue?.recoveryAction == .openDiskUtility)
    #expect(journal.load().count == 2)
}

@Test(
    arguments: [DiskConnectionState.connected, .interrupted, .closed, .unknown],
    [AttachmentPhase.connected, .unmountingBridge])
@MainActor private func availableDisksRecognizeAnExistingConnectionAcrossServerProfiles(
    _ state: DiskConnectionState, _ phase: AttachmentPhase
) async throws {
    let (model, _, _) = try await fixture(.busy)
    model.attached[0].connectionState = state
    model.attached[0].phase = phase
    let existing = model.attached[0]
    let alias = try ServerProfile(name: "Other Address", portal: Portal("[2001:db8::10]"))
    let candidate = FoundDisk(
        targetName: existing.descriptor.targetName,
        inspection: .init(lun: existing.descriptor.lun, result: .failure(.notReady)))
    model.choices[model.choiceKey(alias, candidate.targetName)] = [candidate]
    #expect(alias.id != existing.descriptor.profileID && alias.portal != existing.descriptor.portal)
    #expect(model.existingConnection(for: candidate)?.id == existing.id)
    let otherLUN = FoundDisk(
        targetName: candidate.targetName,
        inspection: .init(
            lun: try LogicalUnit(addressKey: "4000000000000000"), result: .failure(.notReady)))
    let otherTarget = FoundDisk(
        targetName: "iqn.2026-10.test:unconnected",
        inspection: .init(lun: existing.descriptor.lun, result: .failure(.notReady)))
    #expect(model.existingConnection(for: otherLUN) == nil)
    #expect(model.existingConnection(for: otherTarget) == nil)
}

@Test @MainActor private func restoredDuplicateConnectionsExplainHowToResolveThem() {
    let issue = AppIssue(AttachmentError.duplicateConnections)
    #expect(issue.recoveryAction == .openDiskUtility)
    #expect(issue.message.contains("more than one connection"))
    #expect(issue.message.contains("Eject"))
}

@Test(
    arguments: [DiskConnectionState.connected, .interrupted, .closed, .unknown],
    [AttachmentPhase.connected, .unmountingBridge])
@MainActor private func onlyAVerifiedConnectedDiskWithoutMountedVolumesOffersTheDiskUtilityHint(
    _ state: DiskConnectionState, _ phase: AttachmentPhase
) async throws {
    let (model, _, _) = try await fixture(.busy, volumeNames: false)
    var disk = model.attached[0]
    disk.connectionState = state
    disk.phase = phase
    #expect(disk.hasNoMountedVolumes == (state == .connected && phase == .connected))
    disk.verificationFailed = true
    #expect(!disk.hasNoMountedVolumes)
    disk.verificationFailed = false
    disk.attachment = DiskAttachment(
        device: "/dev/disk900000", volumeURLs: [URL(fileURLWithPath: "/Volumes/Archive")])
    #expect(!disk.hasNoMountedVolumes)
    disk.attachment = nil
    #expect(!disk.hasNoMountedVolumes)
}

@Test(arguments: [EjectionFailure.busy, .command], [DiskConnectionState.connected, .interrupted])
@MainActor private func theForceConfirmationExplainsALostConnectionOnlyWhenOneIsObserved(
    _ failure: EjectionFailure, _ state: DiskConnectionState
) async throws {
    let (model, backend, journal) = try await fixture(failure)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    #expect(!model.offersForceEjection(disk))
    await backend.setConnectionState(state, for: disk.id)
    model.eject(disk)
    try await waitForOperation(model)
    #expect(model.issue?.forceEjectionDiskID == disk.id)
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    #expect(request.reportsLostConnection == (state != .connected))
    #expect(
        model.forceEjectionMessage(request)
            == (state == .connected
                ? String(localized: "Unsaved changes on this disk may be lost.")
                : String(
                    localized:
                        "The connection to the server was lost. Changes that haven’t been saved to the disk will be lost."
                )))
    #expect(await backend.forceAttempts.isEmpty)
    model.forceEject(request)
    try await waitForOperation(model)
    #expect(await backend.forceAttempts == [disk.id])
    #expect(!journal.load().contains { $0.id == disk.id })
}

@Test @MainActor private func anUnverifiableDiskOffersForceEjectionFromItsRow() async throws {
    let (model, backend, journal) = try await fixture(.busy, memoryConfiguration: true)
    await model.load()
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    let other = try #require(model.attached.first { $0.id != disk.id })
    #expect(!model.offersForceEjection(disk) && !model.offersForceEjection(other))
    // The extension stopped answering: the ordinary inspection now fails.
    await backend.failInspection(POSIXError(.ENXIO), for: disk.id)
    model.checkConnections()
    try await waitForOperation(model)
    model.issue = nil
    let unverified = try #require(model.attached.first { $0.id == disk.id })
    #expect(
        unverified.verificationFailed && model.diskStatus(unverified) == "Check this connection")
    #expect(model.offersForceEjection(unverified))
    #expect(!model.offersForceEjection(try #require(model.attached.first { $0.id == other.id })))
    // Launch and Check Connections only inspect; nothing was released by force.
    #expect(await backend.forceAttempts.isEmpty && journal.load().count == 2)
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    #expect(request.reportsLostConnection)
    #expect(await backend.forceAttempts.isEmpty)
    model.forceEject(request)
    try await waitForOperation(model)
    #expect(await backend.forceAttempts == [disk.id])
    #expect(model.attached.map(\.id) == [other.id])
    #expect(journal.load().map(\.id) == [other.id])
}

@Test @MainActor private func aReconnectingDiskShowsItsStatusAndKeepsTheNormalEject() async throws {
    let (model, backend, journal) = try await fixture(.busy)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    let reconnecting = try #require(model.attached.first { $0.id == disk.id })
    #expect(reconnecting.connectionState == .reconnecting)
    #expect(model.diskStatus(reconnecting) == "Reconnecting…")
    // Eject stays available. Force Eject waits until the disk has kept reconnecting for a
    // while (see AttachedDisk.forcedReleaseReconnectingDelay), so a blip doesn't show it.
    #expect(!model.busy)
    #expect(!model.offersForceEjection(reconnecting))
    model.eject(reconnecting)
    try await waitForOperation(model)
    #expect(await backend.detachAttempts == [disk.id])
    // Once a normal eject has failed, Force Eject is offered and reports the lost connection.
    let issue = try #require(model.issue)
    #expect(issue.forceEjectionDiskID == disk.id)
    #expect(issue.message.contains("The connection was interrupted"))
    model.issue = nil
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    let request = try #require(model.forceEjectionRequest)
    #expect(request.reportsLostConnection)
    #expect(await backend.forceAttempts.isEmpty)
    #expect(journal.load().contains { $0.id == disk.id })
}

@Test @MainActor private func aRefusedEjectionOfANamedDiskIsNotAboutConnectingAnother() {
    // An earlier ejection of this disk is still pending; its own name and next step apply.
    let issue = AppIssue(
        AttachmentError.recoveryRequired,
        context: .ejectingDisk("Work", connectionState: .reconnecting))
    #expect(issue.title == String(localized: "“\("Work")” Couldn’t Be Ejected"))
    #expect(
        issue.message
            == String(
                localized:
                    "The disk may still be connected. Check it in Disk Utility, then try again."))
    #expect(issue.recoveryAction == .openDiskUtility)
    let general = AppIssue(AttachmentError.recoveryRequired)
    #expect(general.title == String(localized: "Check Connected Disks"))
}

@Test @MainActor private func anEjectionRefusedUntilConnectionsAreCheckedAgainSaysSo()
    async throws
{
    let journal = ArmedJournal()
    let (model, _, _) = try await fixture(.busy, journal: journal)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    journal.arm()
    model.eject(disk)
    try await waitForOperation(model)
    #expect(model.issue?.title == String(localized: "Connection Information Couldn’t Be Saved"))
    model.issue = nil
    // Every operation now waits for Check Again; that, not this disk, is what to report.
    model.eject(disk)
    try await waitForOperation(model)
    let issue = try #require(model.issue)
    #expect(issue.title == String(localized: "Check Connected Disks"))
    #expect(issue.forceEjectionDiskID == nil)
}

@Test @MainActor private func aDiskThatReconnectedBeforeItsForceEjectionStaysConnected()
    async throws
{
    let clock = OfferClock()
    let (model, backend, journal) = try await fixture(.busy, clock: clock)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    #expect(!model.offersForceEjection(try #require(model.attached.first { $0.id == disk.id })))
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    await model.refreshConnectionHealth()
    #expect(model.offersForceEjection(try #require(model.attached.first { $0.id == disk.id })))
    // The server came back before the click reached the disk.
    await backend.setConnectionState(.connected, for: disk.id)
    model.prepareForceEjection(disk.id)
    try await waitForOperation(model)
    #expect(model.forceEjectionRequest == nil)
    let issue = try #require(model.issue)
    // The disk is healthy, so the explanation says what happened and asks nothing more.
    #expect(issue.title == String(localized: "“\("Work")” Is Connected Again"))
    #expect(
        issue.message
            == String(
                localized:
                    "The connection to the server was restored, so the disk wasn’t force ejected."
            ))
    #expect(issue.forceEjectionDiskID == nil && issue.recoveryAction == nil)
    model.issue = nil
    // The disk stays as observed: connected, verified, and not offered a forced release.
    let current = try #require(model.attached.first { $0.id == disk.id })
    #expect(!current.verificationFailed && current.connectionState == .connected)
    #expect(model.diskStatus(current) != "Check this connection")
    #expect(!model.offersForceEjection(current) && model.recoveryComplete)
    #expect(await backend.forceAttempts.isEmpty)
    // Health checks and a normal eject continue as for any connected disk.
    await model.refreshConnectionHealth()
    #expect(model.attached.first { $0.id == disk.id }?.verificationFailed == false)
    model.eject(current)
    try await waitForOperation(model)
    #expect(await backend.detachAttempts == [disk.id])
    #expect(journal.load().contains { $0.id == disk.id })
}

/// Waits a short, bounded time for work that the model started on its own.
@MainActor private func eventually(_ condition: @MainActor () -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !condition() {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

@MainActor private func offered(_ model: AppModel, _ id: UUID) -> Bool {
    model.attached.first { $0.id == id }.map(model.offersForceEjection) == true
}

@Test @MainActor private func aReconnectingDiskIsOfferedForceEjectionWhenItsDelayEnds()
    async throws
{
    let clock = OfferClock()
    let waits = OfferWaits()
    let (model, backend, _) = try await fixture(.busy, clock: clock, waits: waits)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    let reconnecting = try #require(model.attached.first { $0.id == disk.id })
    #expect(!model.offersForceEjection(reconnecting))
    // One check is due exactly when the delay ends, by the coordinator's clock.
    try await eventually { waits.pending == 1 }
    let since = try #require(reconnecting.reconnectingSince)
    #expect(waits.deadlines == [since.advanced(by: AttachedDisk.forcedReleaseReconnectingDelay)])
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    waits.release()
    // Nothing here refreshes the disks: the model checks again on its own.
    try await eventually { offered(model, disk.id) }
    #expect(!model.busy && model.issue == nil)
    // The delay was checked once, and nothing else waits, so nothing polls.
    #expect(waits.deadlines.count == 1 && waits.pending == 0)
}

@Test @MainActor private func aDiskThatReconnectsBeforeItsDelayEndsIsNotOffered() async throws {
    let clock = OfferClock()
    let waits = OfferWaits()
    let (model, backend, _) = try await fixture(.busy, clock: clock, waits: waits)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    try await eventually { waits.pending == 1 }
    await backend.setConnectionState(.connected, for: disk.id)
    await model.refreshConnectionHealth()
    // The disk reconnected, so its pending check is withdrawn.
    try await eventually { waits.cancellations == 1 && waits.pending == 0 }
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    waits.release()
    let current = try #require(model.attached.first { $0.id == disk.id })
    #expect(current.connectionState == .connected && !model.offersForceEjection(current))
    #expect(waits.deadlines.count == 1)
}

@Test @MainActor private func aDelayEndingDuringAnOperationIsCheckedWhenItEnds() async throws {
    let clock = OfferClock()
    let waits = OfferWaits()
    let (model, backend, _) = try await fixture(.busy, clock: clock, waits: waits)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    try await eventually { waits.pending == 1 }
    // An operation keeps its own view of the disks until it ends.
    model.busy = true
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    waits.release()
    try await eventually { waits.pending == 0 }
    for _ in 0..<3 { await Task.yield() }
    #expect(!offered(model, disk.id))
    model.busy = false
    // The same instant is checked again, now that the operation has ended.
    try await eventually { waits.pending == 1 }
    #expect(waits.deadlines.count == 2 && waits.deadlines[0] == waits.deadlines[1])
    waits.release()
    try await eventually { offered(model, disk.id) }
}

@Test @MainActor private func eachDelayIsCheckedOnlyOnce() async throws {
    // The coordinator's clock stands still, so the disk never qualifies.
    let clock = OfferClock()
    let waits = OfferWaits()
    let (model, backend, _) = try await fixture(.busy, clock: clock, waits: waits)
    let disk = try #require(model.attached.first { $0.displayName == "Work" })
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    try await eventually { waits.pending == 1 }
    waits.release()
    try await eventually { waits.pending == 0 }
    for _ in 0..<3 {
        await model.refreshConnectionHealth()
        await Task.yield()
    }
    #expect(waits.deadlines.count == 1 && waits.pending == 0)
    #expect(!offered(model, disk.id))
    // A new reconnecting episode has a later delay, which is checked in turn.
    await backend.setConnectionState(.connected, for: disk.id)
    await model.refreshConnectionHealth()
    clock.advance(.seconds(1))
    await backend.setConnectionState(.reconnecting, for: disk.id)
    await model.refreshConnectionHealth()
    try await eventually { waits.pending == 1 }
    #expect(waits.deadlines.count == 2 && waits.deadlines[1] > waits.deadlines[0])
}
