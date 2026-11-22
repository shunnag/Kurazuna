import Foundation
import ISCSICore

/// Trusted target control-plane adapter. Acquisition must have drained all prior writers and
/// excluded new ones through every alias of this LU. An administrative mutex, empty PR state,
/// or a caller-supplied boolean cannot implement this contract. Keep the lease held until the
/// lifecycle closes. The original LU/backing incarnation must remain unchanged: no replacement,
/// remapping or aliases that bypass the fence. Stable VPD/PR/geometry alone do not prove this.
/// No general NAS adapter is supplied by the product yet.
public protocol StorageQuiescenceLease: Sendable {
    var id: UUID { get }
    /// Actual target-port mapping from the control plane, not the iSCSI portal group tag.
    var relativeTargetPort: UInt16 { get }
    func assertHeld(for binding: OwnedReservationBinding) async throws
}

/// First, deliberately unexposed lifecycle: actual PR changes with durable ownership metadata,
/// but no data I/O, mount or recovery permission. Every terminal path closes the session and
/// keeps its ordinary execute gate closed. There is no automatic reacquisition or orphan cleanup.
public actor UnexposedLUNReservation {
    public enum State: Sendable, Equatable {
        case reserved, transferring, transferred, releasing, released, lost
    }
    public private(set) var state: State = .reserved
    public let id: UUID
    private let session: ISCSISession
    private let ticket: StorageInspectionTicket
    private let lease: any StorageQuiescenceLease
    private let store: any OwnedReservationIntentStore
    private var intent: OwnedReservationIntent
    private weak var dataAccess: ReservedDiskAccess?
    private var normalTransportClosing = false

    private init(
        session: ISCSISession, ticket: StorageInspectionTicket,
        lease: any StorageQuiescenceLease, store: any OwnedReservationIntentStore,
        intent: OwnedReservationIntent
    ) {
        self.session = session
        self.ticket = ticket
        self.lease = lease
        self.store = store
        self.intent = intent
        id = intent.id
    }

    public static func acquire(
        session: ISCSISession, lun: LogicalUnit, lease: any StorageQuiescenceLease,
        store: any OwnedReservationIntentStore, expectedCapacity: DiskCapacity? = nil
    ) async throws -> UnexposedLUNReservation {
        try Task.checkCancellation()
        let ticket = try await session.beginStorageInspection(lun: lun)
        do {
            try await session.ownUnexposedReservation(ticket)
            let initial = try await DiskProbe.storageBody(session: session, ticket: ticket)
            guard expectedCapacity == nil || expectedCapacity == initial.capacity else {
                throw ProtocolError.invalidState
            }
            guard initial.keys.keys.isEmpty, initial.reservation.holder == nil,
                initial.capabilities.supportedTypes?.contains(.writeExclusive) == true
            else { throw ProtocolError.unsupported("unoccupied holder-only reservation") }
            let context = initial.finalContinuity
            let binding = try OwnedReservationBinding(
                sessionID: context.instanceID, initiatorName: context.initiatorName,
                targetName: context.targetName, isid: context.initiatorSessionID,
                tsih: context.targetSessionHandle, portalGroup: context.targetPortalGroupTag,
                relativeTargetPort: lease.relativeTargetPort, lun: lun,
                logicalUnitNames: initial.identity.canonicalBytes,
                blockCount: initial.capacity.blockCount, blockSize: initial.capacity.blockSize,
                quiescenceID: lease.id)
            try await lease.assertHeld(for: binding)
            try await session.validateUnexposedReservation(ticket)
            var intent = try OwnedReservationIntent(
                key: UInt64.random(in: 1...UInt64.max), binding: binding)
            try store.insert(intent)  // A successful durable publication precedes REGISTER.
            try await session.validateUnexposedReservation(ticket)
            try await control(
                .register, key: 0, newKey: intent.key, session: session, ticket: ticket)
            try await verify(intent, holder: false, absent: false, session: session, ticket: ticket)
            try advance(&intent, to: .registered, store: store)
            try advance(&intent, to: .reserving, store: store)
            try await lease.assertHeld(for: binding)
            try await session.validateUnexposedReservation(ticket)
            try await control(.reserve, key: intent.key, session: session, ticket: ticket)
            try await verify(intent, holder: true, absent: false, session: session, ticket: ticket)
            try advance(&intent, to: .reserved, store: store)
            try await lease.assertHeld(for: binding)
            // Atomic final check after the last external suspension/publication. This does not
            // grant data admission; the retained ticket still excludes ordinary execute().
            try await session.validateUnexposedReservation(ticket)
            return UnexposedLUNReservation(
                session: session, ticket: ticket, lease: lease, store: store, intent: intent)
        } catch {
            // The last durable phase describes a possible orphan, never an unissued command.
            // Cancellation/store uncertainty must not trigger another mutating cleanup command.
            await session.close()
            throw error
        }
    }

    /// Valid only for this first component, which never admitted filesystem producers. A future
    /// mounted capability needs a separate, real producer/unmount permit and cannot call this.
    public func release() async throws {
        guard state == .reserved else { throw ProtocolError.invalidState }
        state = .releasing  // Prevent actor reentry from issuing a second release.
        do {
            try await lease.assertHeld(for: intent.binding)
            try await session.validateUnexposedReservation(ticket)
            try await Self.verify(
                intent, holder: true, absent: false, session: session, ticket: ticket)
            try Self.advance(&intent, to: .releasing, store: store)
            try await Self.control(.release, key: intent.key, session: session, ticket: ticket)
            try await Self.verify(
                intent, holder: false, absent: false, session: session, ticket: ticket)
            try Self.advance(&intent, to: .unregistering, store: store)
            try await lease.assertHeld(for: intent.binding)
            try await session.validateUnexposedReservation(ticket)
            try await Self.control(
                .register, key: intent.key, session: session, ticket: ticket)
            try await Self.verify(
                intent, holder: false, absent: true, session: session, ticket: ticket)
            try Self.advance(&intent, to: .released, store: store)
            try await session.validateUnexposedReservation(ticket)
            _ = await session.closeGracefully()
            guard state == .releasing else { throw ProtocolError.invalidState }
            state = .released
        } catch {
            state = .lost
            await session.close()
            throw error
        }
    }

    /// Explicit abandonment preserves the unresolved durable record; it never sends RELEASE.
    public func abandon() async {
        if normalTransportClosing {
            dataAccess?.revoke()
            await session.close()
            return
        }
        guard
            state == .reserved || state == .releasing || state == .transferring
                || state == .transferred
        else { return }
        state = .lost
        dataAccess?.revoke()
        await session.close()
    }

    /// Terminal transport closure retains the unresolved durable reservation.
    /// This ticket proves only our issued-I/O synchronization, never native unmount.
    func finishTransport(synchronization: ReservedTerminalSynchronization) async throws -> Bool {
        let access = synchronization.access
        guard state == .transferred, dataAccess === access, access.owner === self else {
            throw ProtocolError.invalidState
        }
        try await lease.assertHeld(for: intent.binding)
        guard state == .transferred, dataAccess === access else { throw ProtocolError.invalidState }
        try await session.validateReservedDisk(access, generation: synchronization.generation)
        try access.lease.whileHeld(for: intent.binding) {
            guard self.state == .transferred, self.dataAccess === access else {
                throw ProtocolError.invalidState
            }
            try access.validateTerminal(
                generation: synchronization.generation, signal: synchronization.signal)
            self.state = .lost
            access.revoke()
            self.normalTransportClosing = true
        }
        let result = await session.closeGracefully(terminalSignal: synchronization.signal)
        normalTransportClosing = false
        return result
    }

    func transferToDisk(maximumTransferBlocks: UInt32 = 0, diagnostics: IODiagnostics.Recorder?)
        async throws -> ReservedRemoteDisk
    {
        guard state == .reserved, let continuous = lease as? any ContinuousStorageQuiescenceLease
        else { throw ProtocolError.invalidState }
        state = .transferring
        do {
            try await lease.assertHeld(for: intent.binding)
            try await Self.verify(
                intent, holder: true, absent: false, session: session, ticket: ticket)
            guard state == .transferring else { throw ProtocolError.invalidState }
            let origin = ReservedMutationOrigin(
                authorityID: UUID(), diskID: UUID(), intentID: intent.id, binding: intent.binding)
            let access = ReservedDiskAccess(
                origin: origin, inspection: ticket, lease: continuous, owner: self)
            dataAccess = access
            try await session.promoteReservation(access)
            try await session.establishReservedBaseline(access)
            try await Self.verify(
                intent, holder: true, absent: false, session: session, ticket: ticket,
                access: access)
            guard state == .transferring else { throw ProtocolError.invalidState }
            var bytes = [UInt8](repeating: 0, count: 32)
            bytes.put(intent.binding.blockCount - 1, at: 0)
            bytes.put(intent.binding.blockSize, at: 8)
            let disk = RemoteDisk(
                session: session, lun: ticket.lun,
                capacity: try DiskCapacity(readCapacity16: Data(bytes)), readOnly: false,
                maximumTransferBlocks: maximumTransferBlocks, diagnostics: diagnostics,
                reservedAccess: access)
            state = .transferred
            return ReservedRemoteDisk(disk: disk, access: access)
        } catch {
            dataAccess?.revoke()
            state = .lost
            await session.close()
            throw error
        }
    }

    func verifyDataOwnership(_ access: ReservedDiskAccess, generation: UInt64, recovery: UUID?)
        async throws
    {
        guard state == .transferred, dataAccess === access else {
            throw ProtocolError.invalidState
        }
        try access.validate(generation: generation, recovery: recovery)
        try await lease.assertHeld(for: intent.binding)
        // Data ownership has its own validation; the unexposed predicate remains strict.
        try await Self.verify(
            intent, holder: true, absent: false, session: session, ticket: ticket,
            access: access, generation: generation, recovery: recovery)
        guard state == .transferred else { throw ProtocolError.invalidState }
        try access.validate(generation: generation, recovery: recovery)
    }

    private static func advance(
        _ intent: inout OwnedReservationIntent, to phase: OwnedReservationIntent.Phase,
        store: any OwnedReservationIntentStore
    ) throws {
        try Task.checkCancellation()
        let next = try intent.advancing(to: phase)
        try store.advance(intent, to: next)
        intent = next
    }

    private static func control(
        _ action: SCSIReservationAction, key: UInt64, newKey: UInt64 = 0,
        session: ISCSISession, ticket: StorageInspectionTicket
    ) async throws {
        let control = try SCSIReservationControl(action: action, key: key, newKey: newKey)
        let result = try await session.executeReservationControl(control, ticket: ticket)
        guard result.residualCount == 0, result.data.isEmpty else {
            throw ProtocolError.malformed("reservation control completion")
        }
        try await session.validateUnexposedReservation(ticket)
    }

    private static func verify(
        _ intent: OwnedReservationIntent, holder: Bool, absent: Bool,
        session: ISCSISession, ticket: StorageInspectionTicket,
        access: ReservedDiskAccess? = nil, generation: UInt64 = 0, recovery: UUID? = nil
    ) async throws {
        if let access {
            try await session.validateReservedDisk(
                access, generation: generation, recovery: recovery)
        } else {
            try await session.validateUnexposedReservation(ticket)
        }
        let snapshot = try await DiskProbe.storageBody(session: session, ticket: ticket)
        let binding = intent.binding
        guard snapshot.identity.canonicalBytes == binding.logicalUnitNames,
            snapshot.capacity.blockCount == binding.blockCount,
            snapshot.capacity.blockSize == binding.blockSize,
            snapshot.capabilities.supportedTypes?.contains(.writeExclusive) == true,
            snapshot.keys.keys == (absent ? [] : [intent.key]),
            snapshot.fullStatus.registrations.count == (absent ? 0 : 1)
        else { throw ProtocolError.invalidState }
        if holder {
            guard snapshot.reservation.holder?.key == intent.key,
                snapshot.reservation.holder?.type == .writeExclusive
            else { throw ProtocolError.invalidState }
        } else {
            guard snapshot.reservation.holder == nil else { throw ProtocolError.invalidState }
        }
        if let own = snapshot.fullStatus.registrations.first {
            let port = try ISCSIReservationPort(data: own.transportID)
            guard own.key == intent.key, own.isHolder == holder, !own.allTargetPorts,
                own.relativeTargetPort == binding.relativeTargetPort,
                own.type == (holder ? .writeExclusive : nil),
                port.initiatorName == binding.initiatorName, port.isid == binding.isid
            else { throw ProtocolError.invalidState }
        }
        if let access {
            try await session.validateReservedDisk(
                access, generation: generation, recovery: recovery)
        } else {
            try await session.validateUnexposedReservation(ticket)
        }
    }
}
