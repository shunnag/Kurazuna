import Foundation
import ISCSICore
import Synchronization

/// A trusted control-plane fence held continuously, including administrative and backing-file
/// writers. Revocation must serialize with this synchronous callback; a cached boolean, PR
/// snapshot, expiring lease, or asynchronous check alone cannot implement this contract.
public protocol ContinuousStorageQuiescenceLease: StorageQuiescenceLease {
    /// Rejects before invocation, or invokes exactly once inline and propagates the body's
    /// exact return/throw. Never suppress errors or throw after a successful body. Revocation
    /// cannot overlap body.
    func whileHeld(for binding: OwnedReservationBinding, _ body: () throws -> Void) throws
    /// Pins the real external fence across queued sends and command completion. Revocation
    /// refuses new pins, but must not admit other writers while an outstanding pin remains.
    func pinCommand(for binding: OwnedReservationBinding) throws -> any StorageCommandFencePin
}

/// Explicit completion only. WRITE pins remain held through a successful synchronization,
/// including target-cache destaging. Neither dropping this object nor closing a socket proves
/// target drain. On an uncertain completion the adapter preserves its fence until independent
/// recovery. The adapter must not automatically expire an unresolved pin.
public protocol StorageCommandFencePin: Sendable {
    func complete()
}

struct ReservedMutationOrigin: Sendable, Equatable {
    let authorityID: UUID
    let diskID: UUID
    let intentID: UUID
    let binding: OwnedReservationBinding
}

/// Private live authority. No initializer, saved intent, or public receipt recreates it.
final class ReservedDiskAccess: Sendable {
    struct State: Sendable {
        var generation: UInt64 = 0
        var recovering: UUID?
        var revoked = false
        var terminalSignal: OwnedIOGate.Drain?
    }
    let origin: ReservedMutationOrigin
    let inspection: StorageInspectionTicket
    let lease: any ContinuousStorageQuiescenceLease
    let owner: UnexposedLUNReservation
    private let state = Mutex(State())

    init(
        origin: ReservedMutationOrigin, inspection: StorageInspectionTicket,
        lease: any ContinuousStorageQuiescenceLease, owner: UnexposedLUNReservation
    ) {
        self.origin = origin
        self.inspection = inspection
        self.lease = lease
        self.owner = owner
    }

    var generation: UInt64 { state.withLock { $0.generation } }

    func validate(generation: UInt64, recovery: UUID? = nil) throws {
        try state.withLock {
            guard !$0.revoked, $0.generation == generation, $0.recovering == recovery else {
                throw ProtocolError.invalidState
            }
            try $0.terminalSignal?.validateConsumed()
        }
    }

    func beginTerminal(generation: UInt64, signal: OwnedIOGate.Drain) throws {
        try state.withLock {
            guard !$0.revoked, $0.generation == generation, $0.recovering == nil,
                $0.terminalSignal == nil
            else { throw ProtocolError.invalidState }
            try signal.validateConsumed()
            $0.terminalSignal = signal
        }
    }

    func validateTerminal(generation: UInt64, signal: OwnedIOGate.Drain) throws {
        try state.withLock {
            guard !$0.revoked, $0.generation == generation, $0.recovering == nil,
                $0.terminalSignal === signal
            else { throw ProtocolError.invalidState }
            try signal.validateConsumed()
        }
    }

    func beginRecovery(generation: UInt64, attempt: UUID) throws {
        try state.withLock {
            guard !$0.revoked, $0.generation == generation, $0.recovering == nil else {
                throw ProtocolError.invalidState
            }
            $0.recovering = attempt
        }
    }

    func revoke() { state.withLock { $0.revoked = true } }

    /// Called only by the session actor, under the same live fence as command admission.
    func commit(generation: UInt64, attempt: UUID, _ transition: () throws -> Void) throws {
        try state.withLock {
            guard !$0.revoked, $0.generation == generation, $0.generation < .max,
                $0.recovering == attempt
            else { throw ProtocolError.invalidState }
            try transition()
            $0.generation += 1
            $0.recovering = nil
        }
    }
}

/// A disk acquired before its first data command. Closing preserves its durable reservation
/// record; mounted teardown needs a real producer/unmount permit and has no shortcut here.
public final class ReservedRemoteDisk: Sendable {
    public let disk: RemoteDisk
    private let access: ReservedDiskAccess

    init(disk: RemoteDisk, access: ReservedDiskAccess) {
        self.disk = disk
        self.access = access
    }

    public static func acquire(
        session: ISCSISession, lun: LogicalUnit,
        lease: any ContinuousStorageQuiescenceLease, store: any OwnedReservationIntentStore,
        expectedCapacity: DiskCapacity? = nil,
        maximumTransferBlocks: UInt32 = 0,
        diagnostics: IODiagnostics.Recorder? = IODiagnostics.live(layer: .remoteDisk)
    ) async throws -> ReservedRemoteDisk {
        let reserved = try await UnexposedLUNReservation.acquire(
            session: session, lun: lun, lease: lease, store: store,
            expectedCapacity: expectedCapacity)
        return try await reserved.transferToDisk(
            maximumTransferBlocks: maximumTransferBlocks, diagnostics: diagnostics)
    }

    /// Explicit same-live recovery of the narrow, fully acknowledged synchronization incident.
    /// This does not flush kernel-dirty filesystem data or establish successful unmount.
    public func recoverSynchronizationFailure() async throws {
        try await disk.recoverSynchronizationFailure(access: access)
    }

    /// Opt-in producer path. Ordinary RemoteDisk synchronization keeps its original errors.
    public func synchronizeForProducer() async throws {
        try await disk.synchronize(access: access)
    }

    /// Refuses stale, foreign and already recovered failures before issuing recovery I/O.
    public func recoverSynchronizationFailure(matching failure: ReservedSynchronizationFailure)
        async throws
    {
        try await disk.recoverSynchronizationFailure(access: access, matching: failure)
    }

    public func close() async {
        access.revoke()
        await disk.close()
    }

    /// A distinct terminal path for this disk's issued I/O. It does not establish
    /// filesystem-producer closure, release its reservation or retire its backing.
    public func transportCompletion() -> ReservedTransportCompletion {
        disk.transportCompletion(access: access)
    }

    func prepareIssuedIODrain() async throws -> ReservedIODrain {
        try await disk.prepareIssuedIODrain(access: access)
    }

    @discardableResult
    func consumeIssuedIODrain(_ proof: ReservedIODrain) async throws -> ReservedIOTerminal {
        try await disk.consumeIssuedIODrain(proof, access: access)
    }
}
