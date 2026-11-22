import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private actor ForceBackend: AttachmentBackend {
    var state: DiskConnectionState
    var ownership = BridgeOwnership.verified
    var attachment: DiskAttachment? = DiskAttachment(
        device: "/dev/disk900000", volumeURLs: [URL(fileURLWithPath: "/Volumes/Work")])
    var mediaID: UInt64 = 41
    var forceFails = false
    var detachSucceeds = false
    var outerIOError = false
    var outerForceFails = false
    /// A normal detach failure other than EBUSY, for example a lost connection's EIO.
    var normalFailure: (any Error)?
    /// The extension can't answer, so the ordinary inspection fails. The forced inspection
    /// still proves ownership from local facts, which is what the system backend does.
    var extensionStopped = false
    /// The forced inspection finds an identity answer naming another resource.
    var forcedConflict = false
    /// Only the ordinary inspection fails, for example a transient DiskImages failure; the
    /// extension still answers and the forced inspection sees the disk's real state.
    var ordinaryInspectionFails = false
    private(set) var normalAttempts = 0
    private(set) var forceAttempts = 0
    private(set) var observations = 0
    private(set) var normalBridgeAttempts = 0
    private(set) var forcedBridgeAttempts = 0
    /// Forced release steps in order, including the request to stop reconnecting.
    private(set) var releaseSteps: [String] = []

    init(state: DiskConnectionState) { self.state = state }
    func change(_ name: String) {
        switch name {
        case "ownership": ownership = .conflicting
        case "state": state = .connected
        case "reconnecting": state = .reconnecting
        case "device": attachment = DiskAttachment(device: "/dev/disk900001", volumeURLs: [])
        case "media": mediaID = 42
        case "absent": attachment = nil
        case "force-failure": forceFails = true
        case "outer-busy": detachSucceeds = true
        case "outer-io-error": outerIOError = true
        case "outer-force-failure": outerForceFails = true
        case "outer-force-recovered": outerForceFails = false
        case "force-recovered": forceFails = false
        case "extension-stopped": extensionStopped = true
        case "forced-conflict": forcedConflict = true
        case "ordinary-inspection-failure": ordinaryInspectionFails = true
        default: break
        }
    }
    func failNormalDetach(_ error: any Error) { normalFailure = error }
    func bridgeURL(for id: UUID) throws -> URL { throw ProtocolError.invalidState }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
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
        if extensionStopped { throw POSIXError(.ENXIO) }
        if ordinaryInspectionFails { throw POSIXError(.EIO) }
        return AttachmentInspection(
            ownership: ownership, attachment: attachment, connectionState: state)
    }
    func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        -> AttachmentInspection
    {
        AttachmentInspection(
            ownership: forcedConflict ? .conflicting : ownership, attachment: attachment,
            connectionState: extensionStopped ? .unknown : state)
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        normalAttempts += 1
        if let normalFailure { throw normalFailure }
        if detachSucceeds {
            self.attachment = nil
        } else {
            throw POSIXError(.EBUSY)
        }
    }
    func forceEjectionIdentity(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) -> DiskAttachmentIdentity {
        observations += 1
        return DiskAttachmentIdentity(
            imageURL: bridgeURL.appendingPathComponent("Disk.img"), device: attachment.device,
            unmountDevices: [attachment.device], mediaIdentifiers: [attachment.device: mediaID])
    }
    func forceDetachImage(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws {
        try detachForcibly(identity)
    }
    // In an async context the protocol's async defaults would win overload resolution over
    // the synchronous witnesses, so the release variants call these directly.
    private func detachForcibly(_ identity: DiskAttachmentIdentity) throws {
        guard identity.mediaIdentifiers[identity.device] == mediaID else {
            throw AttachmentError.imageIdentityChanged
        }
        forceAttempts += 1
        releaseSteps.append("image")
        if forceFails { throw POSIXError(.EBUSY) }
        attachment = nil
    }
    func abandonConnectionRecovery(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {
        releaseSteps.append("abandon")
    }
    /// As the system backend does: its last check, of the media, comes before the release.
    func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        guard let image = identity.image, image.mediaIdentifiers[image.device] == mediaID else {
            throw AttachmentError.imageIdentityChanged
        }
        await beforeReleasing()
        try detachForcibly(image)
    }
    func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        await beforeReleasing()
        try releaseBridgeForcibly()
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        normalBridgeAttempts += 1
        if outerIOError { throw POSIXError(.EIO) }
        if detachSucceeds { throw POSIXError(.EBUSY) }
        ownership = .absent
    }
    func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) throws {
        try releaseBridgeForcibly()
    }
    private func releaseBridgeForcibly() throws {
        #expect(attachment == nil)
        forcedBridgeAttempts += 1
        releaseSteps.append("bridge")
        if outerForceFails { throw POSIXError(.EIO) }
        ownership = .absent
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
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

private func fixture(
    state: DiskConnectionState = .interrupted, phase: AttachmentPhase = .connected,
    clock: OfferClock = OfferClock(), prepare: (ForceBackend) async -> Void = { _ in }
) async throws
    -> (AttachmentCoordinator, ForceBackend, MemoryAttachmentJournal, UUID)
{
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("nas.local"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let journal = MemoryAttachmentJournal()
    journal.save([
        try AttachmentJournalEntry(
            id: id, descriptor: descriptor,
            bridgeURL: URL(fileURLWithPath: "/private/tmp/ForceTests/\(id.uuidString)"),
            phase: phase)
    ])
    let backend = ForceBackend(state: state)
    await prepare(backend)
    let coordinator = try AttachmentCoordinator(
        backend: backend, journal: journal, now: { clock.now })
    let stopped = await backend.extensionStopped
    let failing = await backend.ordinaryInspectionFails
    if stopped || failing {
        await #expect(throws: POSIXError.self) { try await coordinator.restore() }
    } else {
        try await coordinator.restore()
    }
    return (coordinator, backend, journal, id)
}

@Test private func forceEjectionNeedsAFailedNormalEjectAndPreviewDoesNotEject() async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.forceAttempts == 0)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.diskID == id && request.displayName == "Work")
    #expect(await backend.normalAttempts == 1)
    #expect(await backend.forceAttempts == 0)
    #expect(journal.load().count == 1)
    await coordinator.cancelForceEjection(request)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(request)
    }
    let confirmed = try await coordinator.prepareForceEjection(id)
    try await coordinator.forceEject(confirmed)
    #expect(await backend.forceAttempts == 1)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.disks.isEmpty)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(confirmed)
    }
    #expect(await backend.forceAttempts == 1)
}

// Any failed normal eject offers force, in every connection state. The confirmation
// reports a lost connection only when the observed state isn't connected.
@Test(arguments: [DiskConnectionState.connected, .unknown, .interrupted, .closed])
private func everyFailedNormalEjectOffersForceEjection(_ state: DiskConnectionState)
    async throws
{
    let (coordinator, backend, _, id) = try await fixture(state: state)
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    #expect(await coordinator.canPrepareForceEjection(id))
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.reportsLostConnection == (state != .connected))
    #expect(await backend.forceAttempts == 0)
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 1)
    #expect(await coordinator.disks.isEmpty)
}

// An image already detached after confirmation is skipped instead; see
// anImageDetachedAfterConfirmationIsSkippedAndTheReleaseContinues.
@Test(arguments: ["ownership", "state", "device", "media", "forced-conflict"])
private func aChangedDiskAfterConfirmationCannotBeForceEjected(_ change: String) async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    await backend.change(change)
    await #expect(throws: AttachmentError.self) { try await coordinator.forceEject(request) }
    #expect(await backend.forceAttempts == 0)
    #expect(journal.load().count == 1)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(request)
    }
}

@Test private func recoveryAndANewerPreviewInvalidateOldConfirmations() async throws {
    let (coordinator, backend, _, id) = try await fixture()
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let old = try await coordinator.prepareForceEjection(id)
    try await coordinator.restore()
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(old)
    }
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let first = try await coordinator.prepareForceEjection(id)
    let second = try await coordinator.prepareForceEjection(id)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(first)
    }
    try await coordinator.forceEject(second)
    #expect(await backend.forceAttempts == 1)
}

@Test private func aFailedForceEjectRetainsTheRecordAndNeedsFreshConsent() async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    await backend.change("force-failure")
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.forceEject(request) }
    #expect(journal.load().count == 1)
    #expect(journal.load().first?.phase == .detachingImage)
    // The failed release is offered again, but only with a new observation and consent.
    #expect(await coordinator.canPrepareForceEjection(id))
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(request)
    }
    #expect(await backend.forceAttempts == 1)
    await backend.change("force-recovered")
    let retry = try await coordinator.prepareForceEjection(id)
    try await coordinator.forceEject(retry)
    #expect(await backend.forceAttempts == 2)
    #expect(journal.load().isEmpty)
}

@Test private func aBusyOuterBridgeOffersAForcedReleaseOfOnlyTheBridge() async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await backend.change("outer-busy")
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    #expect(journal.load().first?.phase == .unmountingBridge)
    #expect(await coordinator.canPrepareForceEjection(id))
    #expect(await backend.observations == 0)
    #expect(await backend.forceAttempts == 0)
    let request = try await coordinator.prepareForceEjection(id)
    // The image was already detached normally; nothing about it is captured or forced.
    #expect(await backend.observations == 0)
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 0)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.disks.isEmpty)
}

@Test private func confirmedForceEjectionFinishesTheInterruptedOuterBridge() async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await backend.change("outer-io-error")
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(await backend.normalBridgeAttempts == 0)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.disks.isEmpty)
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(request)
    }
    #expect(await backend.forcedBridgeAttempts == 1)
}

@Test private func failedConfirmedBridgeEjectionKeepsTheJournalAndConsumesConsent() async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    await backend.change("outer-io-error")
    await backend.change("outer-force-failure")
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.forceEject(request) }
    #expect(journal.load().first?.phase == .unmountingBridge)
    #expect(await coordinator.disks.first?.attachment == nil)
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 1)
    // A record left unmounting its bridge stays offered, with new consent each time.
    #expect(await coordinator.canPrepareForceEjection(id))
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.forceEject(request)
    }
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.eject(id) }
    #expect(journal.load().count == 1)
    #expect(await backend.forcedBridgeAttempts == 1)
    await backend.change("outer-force-recovered")
    let resumed = try await coordinator.prepareForceEjection(id)
    try await coordinator.forceEject(resumed)
    // The image step was complete, so it isn't repeated.
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 2)
    #expect(journal.load().isEmpty)
}

@Test(arguments: ["io", "timeout", "command", "unverified"])
private func everyNonBusyNormalEjectFailureOffersForceEjection(_ failure: String) async throws {
    let (coordinator, backend, journal, id) = try await fixture()
    let error: any Error =
        switch failure {
        case "io": POSIXError(.EIO)
        case "timeout": ProtocolError.timedOut
        case "command": SystemCommandError.failed(program: "hdiutil", status: 1, detail: "")
        default: AttachmentError.ownershipUnverified
        }
    await backend.failNormalDetach(error)
    await #expect(throws: (any Error).self) { try await coordinator.eject(id) }
    #expect(await coordinator.canPrepareForceEjection(id))
    #expect(journal.load().first?.phase == .detachingImage)
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.reportsLostConnection)
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(journal.load().isEmpty)
}

@Test(arguments: [AttachmentPhase.connected, .detachingImage, .unmountingBridge])
private func aHealthyDiskIsOfferedForceEjectionOnlyAfterANormalEjectFails(
    _ phase: AttachmentPhase
) async throws {
    let (coordinator, backend, _, id) = try await fixture(state: .connected, phase: phase)
    let disk = try #require(await coordinator.disks.first)
    #expect(!disk.verificationFailed && !disk.offersForcedRelease)
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.observations == 0)
    #expect(await backend.forceAttempts == 0)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    #expect(await coordinator.canPrepareForceEjection(id))
    // A later restart forgets the failure; the healthy disk needs another failed eject.
    try await coordinator.restore()
    #expect(!(await coordinator.canPrepareForceEjection(id)))
}

@Test(arguments: [AttachmentPhase.connected, .attachingImage, .detachingImage, .unmountingBridge])
private func aDiskWhoseExtensionStoppedIsOfferedForceEjectionAtLaunch(_ phase: AttachmentPhase)
    async throws
{
    let (coordinator, backend, journal, id) = try await fixture(phase: phase) {
        await $0.change("extension-stopped")
    }
    let disk = try #require(await coordinator.disks.first)
    #expect(disk.verificationFailed && disk.offersForcedRelease)
    // Launch-time recovery inspected only; it never released anything by force.
    #expect(await backend.forceAttempts == 0)
    #expect(await backend.forcedBridgeAttempts == 0)
    #expect(await coordinator.canPrepareForceEjection(id))
    await #expect(throws: POSIXError(.ENXIO)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.reportsLostConnection && request.displayName == "Work")
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(journal.load().isEmpty)
    #expect(await coordinator.disks.isEmpty)
}

@Test private func aBridgeThatAnswersWithAnotherIdentityIsNeverForceEjected() async throws {
    let (coordinator, backend, journal, id) = try await fixture {
        await $0.change("extension-stopped")
        await $0.change("forced-conflict")
    }
    #expect(await coordinator.canPrepareForceEjection(id))
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.observations == 0)
    #expect(await backend.forceAttempts == 0)
    #expect(await backend.forcedBridgeAttempts == 0)
    #expect(journal.load().count == 1)
    // The refusal stands until an explicit recovery inspects the disk again.
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    #expect(await coordinator.disks.first?.offersForcedRelease == false)
    await #expect(throws: POSIXError(.ENXIO)) { try await coordinator.eject(id) }
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    await #expect(throws: POSIXError(.ENXIO)) { try await coordinator.restore() }
    #expect(await coordinator.canPrepareForceEjection(id))
    #expect(await coordinator.disks.first?.offersForcedRelease == true)
    await #expect(throws: AttachmentError.ownershipUnverified) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.forceAttempts == 0)
}

@Test private func anImageDetachedAfterConfirmationIsSkippedAndTheReleaseContinues()
    async throws
{
    let (coordinator, backend, journal, id) = try await fixture()
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.release.image?.device == "/dev/disk900000")
    await backend.change("absent")
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 0)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(journal.load().isEmpty)
}

/// The image step finished, but the app stopped before it saved the next phase.
@Test(arguments: [AttachmentPhase.detachingImage, .unmountingBridge])
private func aRestartAfterTheImageStepResumesWithTheBridge(_ phase: AttachmentPhase)
    async throws
{
    let (coordinator, backend, journal, id) = try await fixture(phase: phase) {
        await $0.change("absent")
    }
    let disk = try #require(await coordinator.disks.first)
    #expect(disk.phase == .unmountingBridge && disk.offersForcedRelease)
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.release.image == nil)
    try await coordinator.forceEject(request)
    #expect(await backend.observations == 0)
    #expect(await backend.forceAttempts == 0)
    #expect(await backend.forcedBridgeAttempts == 1)
    #expect(journal.load().isEmpty)
}

@Test private func aRestartAfterAFailedBridgeStepResumesWithoutRepeatingTheImageStep()
    async throws
{
    let (coordinator, backend, journal, id) = try await fixture()
    await backend.change("outer-force-failure")
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.forceEject(request) }
    #expect(journal.load().first?.phase == .unmountingBridge)
    // Relaunch while the extension can't answer; only local facts are available.
    await backend.change("extension-stopped")
    await backend.change("outer-force-recovered")
    let restarted = try AttachmentCoordinator(backend: backend, journal: journal)
    await #expect(throws: POSIXError(.ENXIO)) { try await restarted.restore() }
    #expect(await restarted.canPrepareForceEjection(id))
    let resumed = try await restarted.prepareForceEjection(id)
    #expect(resumed.release.image == nil)
    try await restarted.forceEject(resumed)
    #expect(await backend.forceAttempts == 1)
    #expect(await backend.forcedBridgeAttempts == 2)
    #expect(journal.load().isEmpty)
}

@Test private func aStaleFailedObservationNeverMakesAHealthyDiskEligible() async throws {
    let (coordinator, backend, journal, id) = try await fixture(state: .connected) {
        await $0.change("ordinary-inspection-failure")
    }
    let disk = try #require(await coordinator.disks.first)
    // The failed launch inspection can't say whether the disk is healthy, so it is offered...
    #expect(disk.verificationFailed && disk.offersForcedRelease)
    // ...but the forced observation sees a connected disk, which needs a failed eject first.
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.observations == 0)
    #expect(await backend.forceAttempts == 0)
    await #expect(throws: POSIXError(.EIO)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    #expect(!request.reportsLostConnection)
    try await coordinator.forceEject(request)
    #expect(await backend.forceAttempts == 1)
    #expect(journal.load().isEmpty)
}

// A disk with nothing to write reconnects for as long as its server is away, and its normal
// eject may have to wait for the server: once it has kept reconnecting for a while, a confirmed
// forced release is offered without a failed normal eject, and first asks the extension to
// stop reconnecting. An interrupted disk is offered one at once.
@Test(arguments: [DiskConnectionState.reconnecting, .interrupted])
private func aReconnectingDiskCanBeForceEjectedWithoutANormalEject(
    _ state: DiskConnectionState
) async throws {
    let clock = OfferClock()
    let (coordinator, backend, journal, id) = try await fixture(
        state: state, phase: .unmountingBridge, clock: clock)
    if state == .reconnecting {
        #expect(!(await coordinator.canPrepareForceEjection(id)))
        clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    }
    #expect(await coordinator.canPrepareForceEjection(id))
    #expect(await coordinator.disks.first?.offersForcedRelease == true)
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.reportsLostConnection)
    #expect(await backend.normalAttempts == 0)
    #expect(await backend.releaseSteps.isEmpty)
    try await coordinator.forceEject(request)
    #expect(await backend.releaseSteps == ["abandon", "image", "bridge"])
    #expect(journal.load().isEmpty)
}

/// During a short blip the offer neither appears nor flickers: it needs an uninterrupted
/// reconnecting episode of `forcedReleaseReconnectingDelay`. A failed eject still offers it
/// at once.
@Test private func aReconnectingDiskIsOfferedForceEjectionOnlyAfterItsDelay() async throws {
    let clock = OfferClock()
    let (coordinator, backend, _, id) = try await fixture(state: .reconnecting, clock: clock)
    let delay = AttachedDisk.forcedReleaseReconnectingDelay
    func offered() async -> Bool {
        let disk = await coordinator.disks.first
        let prepare = await coordinator.canPrepareForceEjection(id)
        #expect(disk?.offersForcedRelease == prepare)
        return prepare
    }
    #expect(!(await offered()))
    clock.advance(delay - .seconds(1))
    await coordinator.refreshHealth()
    #expect(!(await offered()))
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    // The server answered for a moment: a new episode starts at the next observation.
    await backend.change("state")
    await coordinator.refreshHealth()
    #expect(await coordinator.disks.first?.reconnectingSince == nil)
    await backend.change("reconnecting")
    await coordinator.refreshHealth()
    clock.advance(delay - .seconds(1))
    #expect(!(await offered()))
    clock.advance(.seconds(1))
    #expect(await offered())
    // Before the delay, a failed normal eject makes it eligible at once.
    let (other, otherBackend, _, otherID) = try await fixture(state: .reconnecting)
    #expect(!(await other.canPrepareForceEjection(otherID)))
    await #expect(throws: POSIXError(.EBUSY)) { try await other.eject(otherID) }
    #expect(await other.canPrepareForceEjection(otherID))
    #expect(await otherBackend.normalAttempts == 1)
}

@Test private func aHealthyConnectedDiskIsNotOfferedForceEjectionUntilANormalEjectFails()
    async throws
{
    let (coordinator, backend, _, id) = try await fixture(state: .connected)
    #expect(await coordinator.disks.first?.offersForcedRelease == false)
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    #expect(await backend.releaseSteps.isEmpty)
}

/// The server came back between the offer and the click: the refusal leaves the disk as
/// observed, connected and verified, so health checks and new connections continue.
@Test private func aRefusedForceEjectionLeavesAReconnectedDiskConnectedAndUsable() async throws {
    let clock = OfferClock()
    let (coordinator, backend, journal, id) = try await fixture(state: .reconnecting, clock: clock)
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    #expect(await coordinator.canPrepareForceEjection(id))
    await backend.change("state")
    await #expect(throws: AttachmentError.recoveryRequired) {
        try await coordinator.prepareForceEjection(id)
    }
    let disk = try #require(await coordinator.disks.first)
    #expect(!disk.verificationFailed && disk.connectionState == .connected)
    #expect(!disk.offersForcedRelease)
    #expect(!(await coordinator.canPrepareForceEjection(id)))
    #expect(await coordinator.recoveryState == .ready)
    #expect(await backend.releaseSteps.isEmpty && journal.load().count == 1)
    // Health refresh still observes it, and a normal eject reaches the disk.
    await coordinator.refreshHealth()
    #expect(await coordinator.disks.first?.verificationFailed == false)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    #expect(await backend.normalAttempts == 1)
}

@Test private func aReconnectingDiskThatReconnectsBeforeTheReleaseIsRefusedIt() async throws {
    let clock = OfferClock()
    let (coordinator, backend, journal, id) = try await fixture(state: .reconnecting, clock: clock)
    clock.advance(AttachedDisk.forcedReleaseReconnectingDelay)
    let request = try await coordinator.prepareForceEjection(id)
    #expect(request.reportsLostConnection)
    await backend.change("state")
    await #expect(throws: AttachmentError.imageIdentityChanged) {
        try await coordinator.forceEject(request)
    }
    // Nothing was stopped or released; the disk keeps working.
    #expect(await backend.releaseSteps.isEmpty)
    #expect(await backend.forceAttempts == 0)
    #expect(journal.load().count == 1)
}

// Stopping reconnection can't be undone. A release refused by any of its checks, including
// the last one inside the image step, leaves the disk able to recover by itself.
@Test(arguments: ["ownership", "state", "device", "media", "forced-conflict"])
private func aReleaseRefusedByItsChecksNeverStopsReconnecting(_ change: String) async throws {
    let (coordinator, backend, journal, id) = try await fixture(state: .reconnecting)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    await backend.change(change)
    await #expect(throws: AttachmentError.self) { try await coordinator.forceEject(request) }
    #expect(await backend.releaseSteps.isEmpty)
    #expect(await backend.forceAttempts == 0)
    #expect(journal.load().count == 1)
}

@Test private func aBridgeOnlyReleaseStopsReconnectingOnceBeforeItsRelease() async throws {
    let (coordinator, backend, _, id) = try await fixture(state: .reconnecting)
    await #expect(throws: POSIXError(.EBUSY)) { try await coordinator.eject(id) }
    let request = try await coordinator.prepareForceEjection(id)
    // The inner image went away after confirmation: only the bridge remains to release.
    await backend.change("absent")
    try await coordinator.forceEject(request)
    #expect(await backend.releaseSteps == ["abandon", "bridge"])
}
