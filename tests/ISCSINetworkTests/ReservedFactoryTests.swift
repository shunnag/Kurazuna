import FSKit
import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private actor FactoryCredentials: CredentialStore {
    private(set) var contexts: [CredentialContext] = []
    func save(password: String, context: CredentialContext) throws { throw POSIXError(.EACCES) }
    func remove(context: CredentialContext) throws { throw POSIXError(.EACCES) }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        contexts.append(context)
        throw POSIXError(.EACCES)
    }
}

private actor FactorySource: ReservedLUNSource {
    let preparation: ReservedLUNPreparation
    let pause: ReservationLeasePause?
    nonisolated let cancellation = FactoryCancellation()
    private(set) var descriptors: [ConnectionDescriptor] = []
    private(set) var deadlines: [ContinuousClock.Instant] = []
    init(_ preparation: ReservedLUNPreparation, pause: ReservationLeasePause? = nil) {
        self.preparation = preparation
        self.pause = pause
    }
    func prepare(for descriptor: ConnectionDescriptor, deadline: ContinuousClock.Instant)
        async throws -> ReservedLUNPreparation
    {
        descriptors.append(descriptor)
        deadlines.append(deadline)
        if let pause {
            await withTaskCancellationHandler {
                await pause.wait()
            } onCancel: {
                self.cancellation.record()
            }
        }
        return preparation
    }
}

private final class FactoryCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var observed: Bool { lock.withLock { value } }
    func record() { lock.withLock { value = true } }
}

private actor FactoryMetadata: MountResourceStore {
    let descriptor: ConnectionDescriptor
    init(_ descriptor: ConnectionDescriptor) { self.descriptor = descriptor }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        try ConnectionResourceReference(descriptor: descriptor)
    }
    func resolve(_ reference: ConnectionResourceReference) -> ConnectionDescriptor { descriptor }
    func remove(_ reference: ConnectionResourceReference) {}
}

private func factoryDescriptor(
    readOnly: Bool = false, presentation: LUNImagePresentation = .raw, group: UInt16? = 1,
    chap: Bool = false
) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(1), readOnly: readOnly, chapUsername: chap ? "fixture" : nil,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID(), credentialID: chap ? UUID() : nil,
        imagePresentation: presentation, targetCHAPUsername: chap ? "fixture-target" : nil,
        portalGroupTag: group)
}

private func factoryFixture(
    _ descriptor: ConnectionDescriptor, pause: ReservationLeasePause? = nil,
    store: IntentFixture = IntentFixture(), limit: UInt32 = 1, writeProtected: Bool = false,
    changeCapacity: Bool = false,
    makeRecoveryControl: ReservedLUNPreparation.RecoveryControlFactory? = nil
) -> (FactorySource, ReservationTarget, IntentFixture, ContinuousLeaseFixture) {
    let target = ReservationTarget(
        store: store, maximumTransferBlocks: limit, writeProtected: writeProtected,
        changeCapacity: changeCapacity)
    let lease = ContinuousLeaseFixture()
    let preparation = ReservedLUNPreparation(
        descriptor: descriptor, transport: target, lease: lease, store: store,
        makeRecoveryControl: makeRecoveryControl)
    return (FactorySource(preparation, pause: pause), target, store, lease)
}

private struct FactoryRecoveryControl: LUNRecoveryControl {
    let liveVolumeID: UUID
    let resourceIdentity: Data
    func status(for volume: LUNImageVolume) -> Data { Data([1]) }
    func submit(_ command: Data, to volume: LUNImageVolume) throws { throw POSIXError(.EPERM) }
}

@Test(arguments: [ReservedUnmountBehavior.abandon, .attemptTransportCompletion])
func reservedFactoryPassesExplicitUnmountChoice(_ behavior: ReservedUnmountBehavior) async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, store, lease) = factoryFixture(descriptor)
    let volume = try await LUNVolumeFactory.openReserved(
        descriptor, readOnly: false, credentials: FactoryCredentials(), source: source,
        unmountBehavior: behavior)
    let commands = await target.dataCommands
    await volume.unmount()
    #expect(await target.logoutRequests == (behavior == .abandon ? 0 : 1))
    #expect(await target.dataCommands.count == commands.count + (behavior == .abandon ? 0 : 1))
    #expect(await target.isClosed)
    #expect(store.load().map(\.phase) == [.reserved])
    #expect(!lease.externalWritersAdmitted)
}

private final class FactoryRecoveryOwners: @unchecked Sendable {
    private let lock = NSLock()
    private var owners: [UUID] = []
    func record(_ owner: UUID) { lock.withLock { owners.append(owner) } }
    var values: [UUID] { lock.withLock { owners } }
}

private struct FactoryCancelOnLoadStore: OwnedReservationIntentStore {
    func load() -> [OwnedReservationIntent] {
        withUnsafeCurrentTask { $0?.cancel() }
        return []
    }
    func insert(_ value: OwnedReservationIntent) throws { throw ProtocolError.invalidState }
    func advance(_ expected: OwnedReservationIntent, to next: OwnedReservationIntent) throws {
        throw ProtocolError.invalidState
    }
}

@Test func recoveryControlCancelledStoreLoadCannotBeginLoginOrReservation() async throws {
    let descriptor = try factoryDescriptor()
    let target = ReservationTarget(store: IntentFixture())
    let source = FactorySource(
        ReservedLUNPreparation(
            descriptor: descriptor, transport: target,
            lease: ContinuousLeaseFixture(), store: FactoryCancelOnLoadStore()))
    await #expect(throws: (any Error).self) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.loginRequests.isEmpty)
    #expect(await target.actions.isEmpty)
    #expect(await target.isClosed)
}

@Test(arguments: ["throw", "owner", "resource", "cancel"])
func recoveryControlFactoryRefusalClosesOnlyItsPreparationBeforeLogin(_ fault: String) async throws
{
    let descriptor = try factoryDescriptor()
    let identity = try descriptor.resourceIdentity
    let owners = FactoryRecoveryOwners()
    let (source, target, store, _) = factoryFixture(
        descriptor,
        makeRecoveryControl: { owner in
            owners.record(owner)
            if fault == "throw" { throw POSIXError(.EACCES) }
            if fault == "cancel" { withUnsafeCurrentTask { $0?.cancel() } }
            return FactoryRecoveryControl(
                liveVolumeID: fault == "owner" ? UUID() : owner,
                resourceIdentity: fault == "resource" ? Data(repeating: 1, count: 32) : identity)
        })
    await #expect(throws: (any Error).self) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(owners.values.count == 1)
    #expect(await target.loginRequests.isEmpty)
    #expect(await target.actions.isEmpty)
    #expect(await target.isClosed)
    #expect(store.load().isEmpty)
}

@Test func recoveryControlFactoryRunsOnceAndKeepsTheExactLiveOwnerThroughVolumeInit() async throws {
    let descriptor = try factoryDescriptor()
    let identity = try descriptor.resourceIdentity
    let owners = FactoryRecoveryOwners()
    let (source, target, _, _) = factoryFixture(
        descriptor,
        makeRecoveryControl: { owner in
            owners.record(owner)
            return FactoryRecoveryControl(liveVolumeID: owner, resourceIdentity: identity)
        })
    let first = try await LUNVolumeFactory.openReserved(
        descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    #expect(owners.values == [first.recoveryControlSnapshot.liveVolumeID])
    #expect(first.recoveryControlSnapshot.resourceIdentity == identity)
    #expect(try first.makeAttributes(of: first.rootItem).mode == 0o700)
    #expect(
        try await first.xattr(
            named: FSFileName(string: LUNRecoveryControlAttributes.status), of: first.rootItem)
            == Data([1]))
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(owners.values.count == 1)
    #expect(await target.isClosed == false)
    #expect(try await first.write(contents: Data([9]), to: first.imageItem, at: 7) == 1)
    await first.shutdown()
}

@Test(arguments: [0, 1, 2, 3])
func reservedPreflightModeSenseMustRemainMetadataBeforeReservation(_ variant: Int) async throws {
    let (session, _) = try await reservedSession(IntentFixture())
    let commands: [SCSICommand] = [
        .modeSense10(), .modeSense10(headerOnly: true), .modeSense6(),
        .modeSense6(headerOnly: true),
    ]
    _ = try await session.execute(commands[variant], lun: LogicalUnit(1))
    #expect(await session.storageContinuity?.hasAdmittedDataAccess == false)
    await session.close()
}

@Test(arguments: [UInt32(1), 2, 3, UInt32.max])
func reservedFactoryRecoveryReadbackHonorsTheSameSmallTargetLimitAsWrites(_ limit: UInt32)
    async throws
{
    let descriptor = try factoryDescriptor()
    let (source, target, store, _) = factoryFixture(descriptor, limit: limit)
    let volume = try await LUNVolumeFactory.openReserved(
        descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(
            contents: Data(repeating: 0xAB, count: 2049), to: volume.imageItem, at: 7)
    }
    let before = await target.blockTransfers.count
    try await volume.recoverSynchronizationFailure()
    let transfers = await target.blockTransfers
    #expect(transfers.allSatisfy { $0.blocks <= limit })
    #expect(
        transfers.dropFirst(before).map(\.blocks)
            == transfers.prefix(before).filter { $0.opcode == 0x2A || $0.opcode == 0x8A }.map(
                \.blocks))
    let count = try await volume.readChunks(
        from: volume.imageItem, at: 7, length: 2049, bufferLength: 2049
    ) { data, offset in
        #expect(offset == 0 && data == Data(repeating: 0xAB, count: 2049))
    }
    #expect(count == 2049)
    await volume.shutdown()
    #expect(await target.actions == [0, 1])
    #expect(store.load().map(\.phase) == [.reserved])
}

@Test(arguments: [false, true])
func reservedPreflightMetadataCannotEraseEarlierDataAdmission(_ synchronize: Bool) async throws {
    let (session, target) = try await reservedSession(IntentFixture())
    let command: SCSICommand =
        try synchronize
        ? .synchronizeCache10() : .read(lba: 0, blocks: 1, blockSize: 512)
    _ = try await session.execute(command, lun: LogicalUnit(1))
    _ = try await session.execute(.modeSense10(), lun: LogicalUnit(1))
    #expect(await session.storageContinuity?.hasAdmittedDataAccess == true)
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await UnexposedLUNReservation.acquire(
            session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(),
            store: IntentFixture())
    }
    #expect(await target.actions.isEmpty)
}

@Test func reservedPreflightMetadataStillRequiresTheActiveInspectionTicket() async throws {
    let (session, target) = try await reservedSession(IntentFixture())
    let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
    await #expect(throws: ProtocolError.busy) {
        _ = try await session.execute(.modeSense10(), lun: LogicalUnit(1))
    }
    #expect(await session.finishStorageInspection(ticket))
    #expect(await target.commandLUNs.isEmpty)
    await session.close()
}

@Test(arguments: [0, 1, 2])
func reservedFactoryRejectsUnsupportedPresentationBeforePreparingTransport(_ variant: Int)
    async throws
{
    let descriptor = try factoryDescriptor(
        readOnly: variant == 1, presentation: variant == 2 ? .udsp : .raw)
    let (source, target, store, _) = factoryFixture(descriptor)
    await #expect(throws: variant == 2 ? POSIXError(.ENOTSUP) : POSIXError(.EROFS)) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: variant == 0, credentials: FactoryCredentials(), source: source)
    }
    #expect(await source.descriptors.isEmpty)
    #expect(await target.loginRequests.isEmpty)
    #expect(store.load().isEmpty)
    await target.close()  // Never transferred to the factory.
}

@Test func reservedFactoryUsesTheOrdinaryMutualCredentialContextBeforePreparation() async throws {
    let descriptor = try factoryDescriptor(chap: true)
    let (source, target, _, _) = factoryFixture(descriptor)
    let credentials = FactoryCredentials()
    await #expect(throws: POSIXError(.EACCES)) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: credentials, source: source)
    }
    #expect(
        await credentials.contexts == [
            CredentialContext(
                profileID: descriptor.profileID, portal: descriptor.portal, username: "fixture",
                credentialID: descriptor.credentialID, targetUsername: "fixture-target")
        ])
    #expect(await source.descriptors.isEmpty)
    await target.close()
}

@Test func reservedFactoryPreparationCannotSubstituteTheDescriptor() async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, store, _) = factoryFixture(try descriptor.assigningMountID(UUID()))
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.loginRequests.isEmpty)
    #expect(store.load().isEmpty)
}

@Test func reservedFactoryChecksPortalGroupBeforeProbesOrReservation() async throws {
    let descriptor = try factoryDescriptor(group: 2)
    let (source, target, store, _) = factoryFixture(descriptor)
    await #expect(throws: ProtocolError.malformed("target portal group")) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.commandLUNs.isEmpty)
    #expect(store.load().isEmpty)
}

@Test func reservedFactoryRejectsChangedCapacityBeforeAnyReservationEffect() async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, store, _) = factoryFixture(descriptor, changeCapacity: true)
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.actions.isEmpty)
    #expect(await target.dataCommands.isEmpty)
    #expect(store.load().isEmpty)
}

@Test func reservedFactoryRejectsWriteProtectionBeforeAnyReservationEffect() async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, store, _) = factoryFixture(descriptor, writeProtected: true)
    await #expect(throws: POSIXError(.EROFS)) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.actions.isEmpty)
    #expect(store.load().isEmpty)
}

@Test func reservedFactoryRefusedReuseCannotCloseTheFirstLiveVolume() async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, _, _) = factoryFixture(descriptor)
    let first = try await LUNVolumeFactory.openReserved(
        descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed == false)
    #expect(try await first.write(contents: Data([9]), to: first.imageItem, at: 7) == 1)
    let login = await target.loginRequests.map { String(decoding: $0, as: UTF8.self) }.joined()
    #expect(login.contains("InitiatorName=" + descriptor.initiatorName + "\0"))
    #expect(login.contains("TargetName=" + descriptor.targetName + "\0"))
    #expect(await target.commandLUNs.allSatisfy { $0 == Data(descriptor.lun.wireBytes) })
    await first.shutdown()
    #expect(await target.actions == [0, 1])
}

@Test func reservedFactoryAcquisitionFailurePreservesItsDurablePhaseAndFence() async throws {
    let descriptor = try factoryDescriptor()
    let store = IntentFixture(failPhase: .reserved)
    let (source, target, _, lease) = factoryFixture(descriptor, store: store)
    await #expect(throws: POSIXError(.EIO)) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.actions == [0, 1])
    #expect(store.load().map(\.phase) == [.reserving])
    #expect(lease.externalWritersAdmitted == false)
    // The same preparation stays consumed after failure; no login or cleanup resubmission.
    let count = await target.loginRequests.count
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.loginRequests.count == count)
}

@Test func reservedFactoryCannotReacquireAnUnresolvedStoredIntent() async throws {
    let store = IntentFixture()
    let (session, _) = try await reservedSession(store)
    let owner = try await UnexposedLUNReservation.acquire(
        session: session, lun: LogicalUnit(1), lease: ContinuousLeaseFixture(), store: store)
    await owner.abandon()
    let original = store.load()
    let descriptor = try factoryDescriptor()
    let (source, target, _, _) = factoryFixture(descriptor, store: store)
    await #expect(throws: ProtocolError.invalidState) {
        _ = try await LUNVolumeFactory.openReserved(
            descriptor, readOnly: false, credentials: FactoryCredentials(), source: source)
    }
    #expect(await target.isClosed)
    #expect(await target.loginRequests.isEmpty)
    #expect(store.load() == original)
}

@Test(arguments: [false, true])
func reservedFileSystemCannotPublishLatePreparationAfterCancelOrUnload(_ unload: Bool)
    async throws
{
    let descriptor = try factoryDescriptor()
    let pause = ReservationLeasePause()
    let (source, target, store, _) = factoryFixture(descriptor, pause: pause)
    let fileSystem = ISCSIFileSystem(
        reservedSource: source, credentials: FactoryCredentials(),
        resources: FactoryMetadata(descriptor))
    let resourceURL = try ConnectionResourceReference(descriptor: descriptor).url
    let loading = Task {
        try await fileSystem.loadVolume(
            resource: FSGenericURLResource(url: resourceURL), readOnly: false)
    }
    while !(await pause.isWaiting) { await Task.yield() }
    let unloading: Task<Void, any Error>?
    if unload {
        unloading = Task {
            try await fileSystem.unloadVolume(resource: FSGenericURLResource(url: resourceURL))
        }
    } else {
        unloading = nil
        loading.cancel()
    }
    while !source.cancellation.observed { await Task.yield() }
    await pause.resume()
    await #expect(throws: CancellationError.self) { _ = try await loading.value }
    try await unloading?.value
    #expect(await target.isClosed)
    #expect(await target.loginRequests.isEmpty)
    #expect(store.load().isEmpty)
}

@Test func reservedFileSystemLoadsTheConcreteVolumeThroughItsResourceController() async throws {
    let descriptor = try factoryDescriptor()
    let (source, target, store, _) = factoryFixture(descriptor)
    let fileSystem = ISCSIFileSystem(
        reservedSource: source, credentials: FactoryCredentials(),
        resources: FactoryMetadata(descriptor))
    let resource = FSGenericURLResource(
        url: try ConnectionResourceReference(descriptor: descriptor).url)
    let volume = try await fileSystem.loadVolume(resource: resource, readOnly: false)
    await target.failNextSynchronization()
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(contents: Data([9]), to: volume.imageItem, at: 7)
    }
    try await volume.recoverSynchronizationFailure()
    #expect(try await volume.write(contents: Data([8]), to: volume.imageItem, at: 8) == 1)
    try await fileSystem.unloadVolume(resource: resource)
    #expect(await target.isClosed)
    #expect(await target.actions == [0, 1])
    #expect(store.load().map(\.phase) == [.reserved])
}
