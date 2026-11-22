import Foundation
@_spi(StorageRecovery) import ISCSICore

public struct DiscoveredTarget: Sendable, Equatable, Identifiable {
    public let name: String
    public let addresses: [String]
    public var id: String { name }

    public init(name: String, addresses: [String] = []) {
        self.name = name
        self.addresses = addresses
    }

    /// No advertised addresses means this target uses the Discovery connection's endpoint.
    public func connectionAddresses(fallback: Portal) throws -> [TargetAddress] {
        guard addresses.count <= 16 else {
            throw ProtocolError.limitExceeded("discovery addresses")
        }
        if addresses.isEmpty { return [TargetAddress(portal: fallback)] }
        var result: [TargetAddress] = []
        for value in addresses {
            let address = try TargetAddress(value)
            guard address.portalGroupTag != nil else {
                throw ProtocolError.malformed("discovery portal group")
            }
            if let previous = result.first(where: { $0.portal.isSameEndpoint(as: address.portal) })
            {
                guard previous.portalGroupTag == address.portalGroupTag else {
                    throw ProtocolError.malformed("conflicting target portal group")
                }
            } else {
                result.append(address)
            }
        }
        return result
    }
}

/// Owns a single connection and serializes tasks across actor suspension points.
/// A protocol/transport failure closes the session. Uncertain writes are never replayed.
public actor ISCSISession {
    static let maximumDiscoveryTargets = 1024

    public enum State: Sendable, Equatable {
        case disconnected, loggingIn, ready, closing, failed, closed
    }
    private enum LogoutPhase { case inactive, waiting, responseReceived }
    public private(set) var state = State.disconnected
    public var targetPortalGroupTag: UInt16? { parameters?.targetPortalGroupTag }
    private let storageInstanceID = UUID()
    private var storageDisruptionEpoch: UInt64 = 0
    private var storageAdmittedCommands: UInt64 = 0
    private var storageCountersComplete = true
    private var storageDataAccessed = false
    private var storageInspection: StorageInspectionTicket?
    // Set before the first reservation effect; it never returns to ordinary command admission.
    private var ownedReservation: UUID?
    private weak var reservedDisk: ReservedDiskAccess?
    private var reservedCommand: (ReservedDiskAccess, UInt64, UUID?)?
    private var reservedBaselineReady = false
    private var unresolvedCommandFences: [any StorageCommandFencePin] = []
    private var dirtyWriteFence: (any StorageCommandFencePin)?
    private let transport: any ByteTransport
    private let configuration: LoginConfiguration
    private var parameters: SessionParameters?
    private var decoder: PDUDecoder
    private var pending: [PDU] = []
    private var inFlight = false
    private var nextTag: UInt32 = 2
    private let clock: SessionClock
    private let commandTimeout: Duration
    private let heartbeatInterval: Duration
    private let heartbeatTimeout: Duration
    private let responses = ResponseMailbox()
    private let sendGate = AsyncGate()
    private var receiverTask: Task<Void, Never>?
    private var maintenanceTask: Task<Void, Never>?
    private var activeTag: UInt32?
    private var lastActivity: ContinuousClock.Instant
    private var windowWaiter: CheckedContinuation<Void, any Error>?
    private var heartbeatWaiter: CheckedContinuation<Void, any Error>?
    private var heartbeat: (tag: UInt32, data: Data, acknowledged: Bool)?
    private var failureReason: (any Error)?
    private var writeLength: Int?
    private var writeRequiresExactTransfer = false
    private var writeSubmitted = 0
    private var sendingWriteData = false
    private var writeBurstComplete = false
    private var deadlines: [UUID: ContinuousClock.Instant] = [:]
    private var logoutPhase = LogoutPhase.inactive
    private var logoutSent = false
    private var terminalLogoutSignal: OwnedIOGate.Drain?
    private var closingTask: Task<Bool, Never>?
    private struct TargetLogout {
        let tag: UInt32
        let retiredTag: UInt32?
        let heartbeat: (tag: UInt32, data: Data)?
        var deadline: ContinuousClock.Instant
        let overallDeadline: ContinuousClock.Instant
        let reusesLogout: Bool
        var issued: Bool
    }
    private var targetLogout: TargetLogout?
    private let targetLogoutResponses = ResponseMailbox()
    private var targetLogoutTask: Task<Bool, Never>?
    private var targetLogoutResult: Bool?
    private var targetLogoutWatchdog: Task<Void, Never>?
    private struct Negotiation {
        let id: UUID
        let tag: UInt32
        var deadline: ContinuousClock.Instant
        let overallDeadline: ContinuousClock.Instant
        var issued = false
        var awaitingResponse = false
        var lastHeader: [UInt8]?
    }
    private var negotiation: Negotiation?
    private let negotiationResponses = ResponseMailbox()
    private var negotiationTask: Task<Void, Never>?
    private var negotiationWatchdog: Task<Void, Never>?
    private var negotiationWaiters: [CheckedContinuation<Void, any Error>] = []
    private var retiredNegotiationTag: UInt32?
    private var retiredNegotiationHeader: [UInt8]?
    private var discoveryTextPending = false
    private var terminationHandler: (@Sendable (any Error) -> Void)?
    private var targetRequestedTime2Wait: Duration?

    /// Internal observation for deterministic transport-backpressure tests; never takes a permit.
    var queuedSendCount: Int { get async { await sendGate.waitingCount } }
    var textNegotiationInProgress: Bool { negotiation != nil }
    /// Observe acknowledgement before releasing a deliberately delayed send callback.
    var expectedStatusSequenceNumber: UInt32? { parameters?.expectedStatusSequenceNumber }
    /// The first failure that ended this session. A deliberate close records none.
    var terminationReason: (any Error)? { failureReason }
    /// The minimum wait before a new login: the target's Time2Wait from a drop-connection
    /// event, otherwise the negotiated DefaultTime2Wait.
    var reconnectionDelay: Duration {
        targetRequestedTime2Wait ?? .seconds(parameters?.defaultTime2Wait ?? 2)
    }

    /// Called once, with the recorded reason, when this session fails. It is called at once
    /// if the session has already failed, and never for a deliberate close or logout.
    func setTerminationHandler(_ handler: @escaping @Sendable (any Error) -> Void) {
        if state == .failed, let failureReason {
            handler(failureReason)
        } else if state != .failed, state != .closed {
            terminationHandler = handler
        }
    }

    public init(
        transport: any ByteTransport, configuration: LoginConfiguration,
        commandTimeout: Duration = .seconds(30),
        heartbeatInterval: Duration = .seconds(10), heartbeatTimeout: Duration = .seconds(5)
    ) throws {
        try self.init(
            transport: transport, configuration: configuration, commandTimeout: commandTimeout,
            heartbeatInterval: heartbeatInterval, heartbeatTimeout: heartbeatTimeout,
            clock: .continuous)
    }

    init(
        transport: any ByteTransport, configuration: LoginConfiguration,
        commandTimeout: Duration = .seconds(30),
        heartbeatInterval: Duration = .seconds(10), heartbeatTimeout: Duration = .seconds(5),
        clock: SessionClock
    ) throws {
        guard commandTimeout > .zero, commandTimeout <= .seconds(300) else {
            throw ProtocolError.malformed("command timeout")
        }
        guard heartbeatInterval > .zero, heartbeatInterval <= .seconds(300),
            heartbeatTimeout > .zero, heartbeatTimeout <= .seconds(300)
        else { throw ProtocolError.malformed("heartbeat timing") }
        self.transport = transport
        self.configuration = configuration
        self.decoder = try PDUDecoder(maximumDataLength: 8192)
        self.commandTimeout = commandTimeout
        self.heartbeatInterval = heartbeatInterval
        self.heartbeatTimeout = heartbeatTimeout
        self.clock = clock
        self.lastActivity = clock.now
    }

    deinit {
        receiverTask?.cancel()
        maintenanceTask?.cancel()
        targetLogoutTask?.cancel()
        targetLogoutWatchdog?.cancel()
        negotiationTask?.cancel()
        negotiationWatchdog?.cancel()
        let transport = transport
        Task { await transport.close() }
    }

    public func login() async throws {
        try await login(timeout: commandTimeout)
    }

    func login(timeout: Duration) async throws {
        guard timeout > .zero, timeout <= .seconds(300) else {
            throw ProtocolError.malformed("login timeout")
        }
        guard state == .disconnected, !inFlight else { throw ProtocolError.invalidState }
        inFlight = true
        state = .loggingIn
        defer { inFlight = false }
        do {
            try await withDeadline(timeout: timeout) {
                var machine = LoginMachine(configuration: self.configuration)
                var request: PDU? = try machine.start()
                while let current = request {
                    try await self.send(current, login: true)
                    request = try machine.accept(await self.receive())
                }
                try await self.finishLogin(machine)
            }
            guard state == .ready else { throw ProtocolError.connectionClosed }
            startReceiving()
        } catch {
            await fail(error)
            throw error
        }
    }

    private func finishLogin(_ machine: LoginMachine) throws {
        guard state == .loggingIn, machine.isComplete, decoder.isAtFrameBoundary, pending.isEmpty
        else {
            throw ProtocolError.malformed("bytes following final login response")
        }
        parameters = machine.parameters
        decoder = try PDUDecoder(
            maximumDataLength: configuration.receiveSegmentLength,
            digests: machine.parameters.digests)
        state = .ready
        lastActivity = clock.now
    }

    public func execute(
        _ command: SCSICommand, lun: LogicalUnit, output: Data = Data()
    ) async throws -> SCSIResult {
        try await executeCommand(command, lun: lun, output: output, inspection: nil)
    }

    public var storageContinuity: SCSIStorageContinuity? {
        guard let parameters, let targetName = configuration.targetName,
            let group = parameters.targetPortalGroupTag
        else { return nil }
        return SCSIStorageContinuity(
            instanceID: storageInstanceID,
            initiatorName: configuration.initiatorName, targetName: targetName,
            initiatorSessionID: configuration.isid,
            targetSessionHandle: parameters.targetSessionHandle,
            targetPortalGroupTag: group, disruptionEpoch: storageDisruptionEpoch,
            admittedCommands: storageAdmittedCommands, hasAdmittedDataAccess: storageDataAccessed,
            countersComplete: storageCountersComplete, isReady: state == .ready)
    }

    func beginStorageInspection(lun: LogicalUnit) throws -> StorageInspectionTicket {
        guard state == .ready, let initial = storageContinuity, initial.countersComplete,
            !inFlight, storageInspection == nil, closingTask == nil,
            targetLogoutTask == nil, logoutPhase == .inactive, negotiation == nil
        else { throw ProtocolError.busy }
        let ticket = StorageInspectionTicket(id: UUID(), lun: lun, initial: initial)
        storageInspection = ticket
        return ticket
    }

    func finishStorageInspection(
        _ ticket: StorageInspectionTicket, validating expected: SCSIStorageContinuity? = nil
    ) -> Bool {
        guard storageInspection == ticket, ownedReservation == nil else { return false }
        defer { storageInspection = nil }
        if let expected {
            guard !Task.isCancelled, let current = storageContinuity, current == expected,
                current.continues(ticket.initial), !inFlight, closingTask == nil,
                targetLogoutTask == nil, logoutPhase == .inactive
            else { return false }
        }
        return true
    }

    func executeForStorageInspection(_ command: SCSICommand, ticket: StorageInspectionTicket)
        async throws -> SCSIResult
    {
        guard command.direction != .write,
            [UInt8(0x12), 0x9E, 0x25, 0x5E].contains(command.cdb[0])
        else { throw ProtocolError.invalidState }
        return try await executeCommand(
            command, lun: ticket.lun, output: Data(), inspection: ticket)
    }

    func ownUnexposedReservation(_ ticket: StorageInspectionTicket) throws {
        guard ownedReservation == nil, storageInspection == ticket, !inFlight,
            let current = storageContinuity, current.continues(ticket.initial),
            !current.hasAdmittedDataAccess, !Task.isCancelled
        else { throw ProtocolError.invalidState }
        ownedReservation = ticket.id
    }

    func validateUnexposedReservation(_ ticket: StorageInspectionTicket) throws {
        guard reservedDisk == nil, ownedReservation == ticket.id,
            storageInspection == ticket, !inFlight,
            let current = storageContinuity, current.continues(ticket.initial),
            !current.hasAdmittedDataAccess, !Task.isCancelled,
            closingTask == nil, targetLogoutTask == nil, logoutPhase == .inactive
        else { throw ProtocolError.invalidState }
    }

    func promoteReservation(_ access: ReservedDiskAccess) throws {
        try validateUnexposedReservation(access.inspection)
        try access.lease.whileHeld(for: access.origin.binding) {
            try self.validateUnexposedReservation(access.inspection)
            try access.validate(generation: 0)
            self.reservedDisk = access
        }
    }

    func validateReservedDisk(
        _ access: ReservedDiskAccess, generation: UInt64, recovery: UUID? = nil
    ) throws {
        try checkReservedDisk(access, generation: generation, recovery: recovery, idle: true)
    }

    private func checkReservedDisk(
        _ access: ReservedDiskAccess, generation: UInt64, recovery: UUID?, idle: Bool
    ) throws {
        guard reservedDisk === access, ownedReservation == access.inspection.id,
            storageInspection == access.inspection, !idle || !inFlight,
            let current = storageContinuity, current.continues(access.inspection.initial),
            current.instanceID == access.origin.binding.sessionID,
            closingTask == nil, targetLogoutTask == nil, logoutPhase == .inactive
        else { throw ProtocolError.invalidState }
        try Task.checkCancellation()
        try access.validate(generation: generation, recovery: recovery)
    }

    func executeReservedDisk(
        _ command: SCSICommand, output: Data = Data(), access: ReservedDiskAccess,
        generation: UInt64, recovery: UUID? = nil
    ) async throws -> SCSIResult {
        // Only the disk's concrete block commands enter this path; PR/control stays separate.
        guard [UInt8(0x28), 0x88, 0x2A, 0x8A, 0x35, 0x91].contains(command.cdb[0]),
            command.transferLength <= 1_048_576, reservedCommand == nil,
            reservedBaselineReady || [UInt8(0x35), 0x91].contains(command.cdb[0]),
            recovery == nil || command.direction != .write,
            unresolvedCommandFences.count < 128
        else { throw ProtocolError.invalidState }
        let fence = try access.lease.pinCommand(for: access.origin.binding)
        var completed = false
        var retainedForDirtyWrites = false
        defer {
            if !retainedForDirtyWrites {
                if completed { fence.complete() } else { unresolvedCommandFences.append(fence) }
            }
            reservedCommand = nil
        }
        try access.lease.whileHeld(for: access.origin.binding) {
            try self.validateReservedDisk(access, generation: generation, recovery: recovery)
            self.reservedCommand = (access, generation, recovery)
        }
        let result = try await executeCommand(
            command, lun: access.inspection.lun, output: output, inspection: access.inspection)
        // GOOD cached WRITE is terminal but can still destage after administrative revocation.
        // One shared dirty fence covers all such writes until an actual strict GOOD barrier.
        if command.direction == .write, dirtyWriteFence == nil {
            dirtyWriteFence = fence
            retainedForDirtyWrites = true
        }
        if [UInt8(0x35), 0x91].contains(command.cdb[0]),
            result.residualCount == 0, result.data.isEmpty
        {
            dirtyWriteFence?.complete()
            dirtyWriteFence = nil
        }
        // Successful sends plus validated GOOD establish the individual command completion.
        // Unknown/non-GOOD command pins remain independently retained, even after a flush.
        completed = true
        do {
            try access.lease.whileHeld(for: access.origin.binding) {
                try self.validateReservedDisk(access, generation: generation, recovery: recovery)
            }
        } catch {
            access.revoke()
            throw error
        }
        return result
    }

    func establishReservedBaseline(_ access: ReservedDiskAccess) async throws {
        guard !reservedBaselineReady else { throw ProtocolError.invalidState }
        let result: SCSIResult
        do {
            result = try await executeReservedDisk(
                .synchronizeCache10(), access: access, generation: 0)
        } catch let ProtocolError.scsiFailure(status, data) {
            guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred,
                sense.key == 5, sense.additionalSenseCode == 0x20, sense.qualifier == 0
            else { throw ProtocolError.scsiFailure(status: status, sense: data) }
            result = try await executeReservedDisk(
                .synchronizeCache16(), access: access, generation: 0)
        }
        guard result.residualCount == 0, result.data.isEmpty else {
            throw ProtocolError.malformed("initial reservation synchronization")
        }
        try access.lease.whileHeld(for: access.origin.binding) {
            try self.validateReservedDisk(access, generation: 0)
            self.reservedBaselineReady = true
        }
    }

    /// Owns readback, barrier and the commit point; no public proof/token can call commit.
    func recoverReservedDisk(
        _ access: ReservedDiskAccess, journal: MutationEvidenceJournal,
        diagnostics: IODiagnostics.Recorder?
    ) async throws {
        let evidence = journal.snapshot
        guard reservedBaselineReady, evidence.reservedOrigin == access.origin,
            evidence.serviceGeneration == access.generation
        else { throw MutationRecoveryIssue.wrongContext }
        let plan = try MutationRecoveryPlan(
            evidence: evidence, diskID: access.origin.diskID, generation: evidence.generation,
            byteCount: evidence.byteCount, blockSize: evidence.blockSize)
        let generation = access.generation
        let attempt = UUID()
        try access.lease.whileHeld(for: access.origin.binding) {
            try self.validateReservedDisk(access, generation: generation)
            try access.beginRecovery(generation: generation, attempt: attempt)
        }
        do {
            try await access.owner.verifyDataOwnership(
                access, generation: generation, recovery: attempt)
            var checked: UInt64 = 0
            for range in plan.ranges {
                var cursor = 0
                while cursor < range.expected.count {
                    let count = min(65_536, range.expected.count - cursor)
                    let command = try SCSICommand.read(
                        lba: (range.offset + UInt64(cursor)) / UInt64(plan.blockSize),
                        blocks: UInt32(count) / plan.blockSize, blockSize: plan.blockSize)
                    let result = try await executeReservedDisk(
                        command, access: access, generation: generation, recovery: attempt)
                    guard result.residualCount == 0, result.data.count == count,
                        result.data == Data(range.expected[cursor..<(cursor + count)])
                    else { throw MutationRecoveryIssue.readMismatch }
                    checked += UInt64(count)
                    cursor += count
                }
            }
            // Do not alter the failed synchronization history and do not retry a failed barrier.
            let barrierOpcode = evidence.synchronizationAttempts.last!.opcode
            let result = try await executeReservedDisk(
                barrierOpcode == 0x35 ? .synchronizeCache10() : .synchronizeCache16(),
                access: access, generation: generation, recovery: attempt)
            guard result.residualCount == 0, result.data.isEmpty else {
                throw ProtocolError.malformed("recovery synchronization completion")
            }
            try await access.owner.verifyDataOwnership(
                access, generation: generation, recovery: attempt)
            // Same session actor, no suspension from this final check through both transitions.
            try access.lease.whileHeld(for: access.origin.binding) {
                try self.validateReservedDisk(access, generation: generation, recovery: attempt)
                try access.commit(generation: generation, attempt: attempt) {
                    try journal.commitRecovery(
                        evidence: evidence, plan: plan, checkedBytes: checked,
                        serviceGeneration: generation, barrierOpcode: barrierOpcode)
                }
                diagnostics?.finishVerifiedMutationRecovery(incidentID: plan.incidentID)
            }
            // Cancellation after commit does not report failure after service reopened.
        } catch {
            access.revoke()
            throw error
        }
    }

    func executeReservationControl(
        _ control: SCSIReservationControl, ticket: StorageInspectionTicket
    )
        async throws -> SCSIResult
    {
        try validateUnexposedReservation(ticket)
        return try await executeCommand(
            control.command, lun: ticket.lun, output: control.parameters, inspection: ticket)
    }

    private func executeCommand(
        _ command: SCSICommand, lun: LogicalUnit, output: Data,
        inspection: StorageInspectionTicket?
    ) async throws -> SCSIResult {
        guard state == .ready, configuration.targetName != nil else {
            throw state == .closing ? ProtocolError.targetEvent(1) : ProtocolError.invalidState
        }
        if let active = storageInspection {
            guard inspection == active, lun == active.lun else { throw ProtocolError.busy }
        } else if inspection != nil {
            throw ProtocolError.invalidState
        }
        if command.cdb[0] == 0x5F {
            guard ownedReservation != nil, inspection?.id == ownedReservation else {
                throw ProtocolError.invalidState
            }
        }
        guard !inFlight else { throw ProtocolError.busy }
        inFlight = true
        defer { inFlight = false }
        if storageAdmittedCommands == .max {
            storageCountersComplete = false
        } else {
            storageAdmittedCommands += 1
        }
        // Positive allowlist: unknown/future commands (including SYNC) cannot establish that
        // no filesystem producer was admitted. Owned PR parameters are control data only.
        let metadata =
            [UInt8(0x12), 0x25, 0x5E].contains(command.cdb[0])
            || (command.cdb[0] == 0x9E && command.cdb[1] == 0x10)
            || ((command.cdb[0] == 0x5A || command.cdb[0] == 0x1A)
                && (command == .modeSense10() || command == .modeSense10(headerOnly: true)
                    || command == .modeSense6() || command == .modeSense6(headerOnly: true)))
        let ownedControl =
            command.cdb[0] == 0x5F && inspection?.id == ownedReservation
            && ownedReservation != nil
        if !metadata && !ownedControl { storageDataAccessed = true }
        do {
            return try await withDeadline {
                try await self.executeTask(command, lun: lun, output: output)
            }
        } catch let error as ProtocolError {
            if case .scsiFailure(let status, let data) = error {
                let sense = status == 2 ? try? SCSISense(data: data) : nil
                // Record before a probe can consume Unit Attention or retry the query.
                if status == 0x18 || (status == 2 && (sense == nil || sense?.key == 6)) {
                    noteStorageDisruption()
                }
                // The original failure may belong to a previously acknowledged write.
                // Surface it once and retire this session before admitting further I/O.
                if let sense, sense.isDeferred {
                    await failOperation(error)
                }
            } else {
                await failOperation(error)
            }
            throw error
        } catch {
            await failOperation(error)
            throw error
        }
    }

    private func executeTask(_ command: SCSICommand, lun: LogicalUnit, output: Data) async throws
        -> SCSIResult
    {
        guard let parameters else { throw ProtocolError.invalidState }
        let tag = allocateTag()
        var transfer = try CommandTransfer(
            command: command, lun: lun, taskTag: tag, output: output,
            maximumSegmentLength: parameters.targetReceiveSegmentLength,
            maximumBurstLength: parameters.maximumBurstLength)
        try await waitForCommandWindow()
        activeTag = tag
        writeLength = command.direction == .write ? Int(command.transferLength) : nil
        writeRequiresExactTransfer = command.requiresExactTransfer
        writeSubmitted = 0
        writeBurstComplete = false
        defer {
            activeTag = nil
            writeLength = nil
            writeRequiresExactTransfer = false
            writeSubmitted = 0
            writeBurstComplete = false
        }
        guard let current = self.parameters else { throw ProtocolError.invalidState }
        let request = try transfer.request(
            commandSequenceNumber: current.commandSequenceNumber,
            expectedStatusSequenceNumber: current.expectedStatusSequenceNumber)
        try await send(request)
        while true {
            let response = try await receive()
            switch try transfer.accept(
                response,
                expectedStatusSequenceNumber: self.parameters!.expectedStatusSequenceNumber)
            {
            case .waiting: continue
            case .send(let pdus): try await sendData(pdus)
            case .complete(let result): return result
            }
        }
    }

    private func sendData(_ pdus: [PDU]) async throws {
        sendingWriteData = true
        writeBurstComplete = false
        defer { sendingWriteData = false }
        // An R2T may already have been expanded using the previous receive limit.
        // Re-slice under the send permit, after any Text exchange has committed.
        // DataSN remains contiguous across the whole R2T, even when a limit shrinks.
        var sequence: UInt32 = 0
        for pdu in pdus {
            var offset = 0
            while offset < pdu.data.count {
                try await acquireSend(for: pdu)
                do {
                    guard let parameters else { throw ProtocolError.invalidState }
                    let count = min(parameters.targetReceiveSegmentLength, pdu.data.count - offset)
                    var header = pdu.header
                    header[1] = offset + count == pdu.data.count ? pdu.flags : 0
                    header.put(sequence, at: 36)
                    header.put(pdu.bufferOffset + UInt32(offset), at: 40)
                    let start = pdu.data.startIndex + offset
                    let frame = try PDU(
                        header: header, data: Data(pdu.data[start..<(start + count)]))
                    try await sendFrame(frame, login: false)
                    offset += count
                    sequence &+= 1
                    await sendGate.release()
                } catch {
                    await sendGate.release()
                    throw error
                }
            }
        }
    }

    public func discover() async throws -> [DiscoveredTarget] {
        guard state == .ready, configuration.targetName == nil else {
            throw state == .closing ? ProtocolError.targetEvent(1) : ProtocolError.invalidState
        }
        guard !inFlight else { throw ProtocolError.busy }
        inFlight = true
        defer { inFlight = false }
        do { return try await withDeadline { try await self.discoverTargets() } } catch {
            await failOperation(error)
            throw error
        }
    }

    private func discoverTargets() async throws -> [DiscoveredTarget] {
        let tag = allocateTag()
        var transferTag = UInt32.max
        var data = Data()
        var first = true
        try await waitForCommandWindow()
        activeTag = tag
        defer { activeTag = nil }
        for _ in 0..<256 {
            guard let parameters else { throw ProtocolError.invalidState }
            var header = Array(repeating: UInt8(0), count: 48)
            header[0] = 0x44  // Immediate Text Request: CmdSN does not advance.
            header[1] = 0x80
            header.put(tag, at: 16)
            header.put(transferTag, at: 20)
            header.put(parameters.commandSequenceNumber, at: 24)
            header.put(parameters.expectedStatusSequenceNumber, at: 28)
            let text = first ? try TextParameters([.init("SendTargets", "All")]).encoded() : Data()
            try await send(PDU(header: header, data: text))
            first = false
            let response = try await receive()
            guard response.opcode == 0x24, response.taskTag == tag,
                response.flags & 0xC0 != 0xC0
            else { throw ProtocolError.malformed("discovery response") }
            guard data.count + response.data.count <= 1_048_576 else {
                throw ProtocolError.limitExceeded("discovery data")
            }
            data.append(response.data)
            if response.flags & 0x80 != 0 {
                guard response.transferTag == UInt32.max else {
                    throw ProtocolError.malformed("final discovery transfer tag")
                }
                return try parseDiscovery(data)
            }
            guard response.transferTag != UInt32.max,
                transferTag == UInt32.max || transferTag == response.transferTag
            else { throw ProtocolError.malformed("discovery transfer tag") }
            transferTag = response.transferTag
        }
        throw ProtocolError.limitExceeded("discovery exchanges")
    }

    public func logout() async throws {
        guard state == .ready else {
            throw state == .closing ? ProtocolError.targetEvent(1) : ProtocolError.invalidState
        }
        guard !inFlight else { throw ProtocolError.busy }
        try reserveLogout()
        inFlight = true
        defer { inFlight = false }
        do {
            await stopNegotiating(ProtocolError.connectionClosed)
            try await withDeadline { try await self.logoutTask() }
            state = .closed
            await stopReceiving(ProtocolError.connectionClosed)
            if targetLogout?.reusesLogout == true { targetLogoutResult = true }
        } catch {
            await fail(error)
            throw error
        }
    }

    private func logoutTask() async throws {
        guard let parameters, logoutPhase == .waiting, let tag = activeTag else {
            throw ProtocolError.invalidState
        }
        defer { activeTag = nil }
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x46
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(parameters.commandSequenceNumber, at: 24)
        header.put(parameters.expectedStatusSequenceNumber, at: 28)
        try await send(PDU(header: header))
        while true {
            let response = try await receive()
            guard response.opcode == 0x26, response.taskTag == tag, response.header[2] == 0,
                response.flags & 0x80 != 0, response.data.isEmpty
            else {
                throw ProtocolError.malformed("logout response")
            }
            return
        }
    }

    public func close() async {
        if state != .closed { noteStorageDisruption() }
        terminationHandler = nil
        state = .closed
        await stopReceiving(ProtocolError.connectionClosed)
    }

    /// Best-effort orderly shutdown, bounded to five seconds (or the shorter command limit).
    /// Busy, failed or cancelled sessions are aborted without sending another request.
    /// Concurrent callers share the exchange; close() can still interrupt it immediately.
    @discardableResult
    public func closeGracefully() async -> Bool {
        await closeGracefully(terminalSignal: nil)
    }

    func closeGracefully(terminalSignal: OwnedIOGate.Drain?) async -> Bool {
        if Task.isCancelled {
            await close()
            return false
        }
        if let signal = terminalSignal {
            guard targetLogoutTask == nil, targetLogoutResult == nil,
                transport is any SendAdmissionTransport
            else {
                await close()
                return false
            }
            if let closingTask {
                guard terminalLogoutSignal === signal else {
                    await close()
                    return false
                }
                return await closingTask.value
            }
        } else {
            if let targetLogoutTask { return await targetLogoutTask.value }
            if let closingTask { return await closingTask.value }
            if let targetLogoutResult { return targetLogoutResult }
        }
        guard !Task.isCancelled, state == .ready, !inFlight else {
            await close()
            return false
        }
        do {
            if let signal = terminalSignal {
                try signal.whileConsumed {
                    try self.reserveLogout()
                    self.terminalLogoutSignal = signal
                }
            } else {
                try reserveLogout()
            }
        } catch {
            await close()
            return false
        }
        // Reserve admission before creating a task that can suspend or run later.
        inFlight = true
        let task = Task { await self.finishClosing() }
        closingTask = task
        return await task.value
    }

    private func finishClosing() async -> Bool {
        defer {
            inFlight = false
            closingTask = nil
            terminalLogoutSignal = nil
        }
        var completed = false
        if state == .ready || state == .closing {
            do {
                await stopNegotiating(ProtocolError.connectionClosed)
                try await withDeadline(timeout: min(commandTimeout, .seconds(5))) {
                    try await self.logoutTask()
                }
                completed = state == .ready || state == .closing
            } catch {
                // A lost Logout response cannot justify replaying I/O or leaving
                // the transport open. Disk synchronization is the caller's responsibility.
            }
        }
        await close()
        if targetLogout?.reusesLogout == true { targetLogoutResult = completed }
        return completed
    }

    private func reserveLogout() throws {
        guard state == .ready, parameters != nil, logoutPhase == .inactive, activeTag == nil else {
            throw ProtocolError.invalidState
        }
        noteStorageDisruption()
        logoutPhase = .waiting
        activeTag = allocateTag()
    }

    private func send(_ pdu: PDU, login: Bool = false) async throws {
        try await acquireSend(for: pdu)
        do {
            try await sendFrame(pdu, login: login)
            await sendGate.release()
        } catch {
            await sendGate.release()
            throw error
        }
    }

    private func waitsForNegotiation(_ pdu: PDU) -> Bool {
        guard let negotiation else { return false }
        return [0x01, 0x05, 0x04].contains(pdu.opcode) && pdu.taskTag != negotiation.tag
    }

    private func acquireSend(for pdu: PDU) async throws {
        while true {
            try checkDeadlines()
            while waitsForNegotiation(pdu) {
                guard negotiationWaiters.count < 128 else { throw ProtocolError.busy }
                try await withCheckedThrowingContinuation { negotiationWaiters.append($0) }
                try Task.checkCancellation()
                try checkDeadlines()
            }
            try await sendGate.acquire()
            if !waitsForNegotiation(pdu) { return }
            // The Async notification may have arrived while this sender was queued.
            await sendGate.release()
        }
    }

    private func sendFrame(_ pdu: PDU, login: Bool) async throws {
        try Task.checkCancellation()
        try checkDeadlines()
        if [UInt8(0x01), 0x05].contains(pdu.opcode),
            let (access, generation, recovery) = reservedCommand
        {
            try access.lease.whileHeld(for: access.origin.binding) {
                try self.checkReservedDisk(
                    access, generation: generation, recovery: recovery, idle: false)
            }
        }
        guard state == .ready || state == .closing || (login && state == .loggingIn) else {
            throw failureReason ?? ProtocolError.invalidState
        }
        if let targetLogout {
            let logout = pdu.opcode == 0x06 && pdu.taskTag == targetLogout.tag
            let pingReply =
                pdu.opcode == 0 && pdu.taskTag == UInt32.max
                && pdu.transferTag != UInt32.max
            guard logout || pingReply else { throw ProtocolError.targetEvent(1) }
        }
        if !login, logoutSent {
            // RFC 7143 §11.14 stops new requests. A reply to a target's existing
            // NOP-In is still required by §11.18 until Logout completes.
            guard pdu.opcode == 0x00 else { throw ProtocolError.invalidState }
            let targetReply = pdu.taskTag == UInt32.max && pdu.transferTag != UInt32.max
            if !targetReply || logoutPhase == .responseReceived { return }
        }
        var frame = pdu
        if !login {
            guard let parameters else { throw ProtocolError.invalidState }
            var header = pdu.header
            header.put(parameters.expectedStatusSequenceNumber, at: 28)
            switch pdu.opcode {
            case 0x00, 0x04, 0x06:
                // Immediate requests use the next CmdSN actually admitted to the transport.
                header.put(parameters.commandSequenceNumber, at: 24)
            case 0x01:
                guard header.uint32(at: 24) == parameters.commandSequenceNumber else {
                    throw ProtocolError.invalidState
                }
            case 0x05: break  // Data-Out has no CmdSN; preserve its reserved bytes.
            default: throw ProtocolError.invalidState
            }
            frame = try PDU(header: header, data: pdu.data)
        }
        let bytes = frame.encoded(digests: login ? DigestPolicy() : parameters!.digests)
        // Encoding and waiting for the send gate also consume the exchange's budget.
        try Task.checkCancellation()
        try checkDeadlines()
        if pdu.opcode == 0x05 {
            guard pdu.taskTag == activeTag, let writeLength,
                pdu.data.count <= writeLength - writeSubmitted
            else { throw ProtocolError.invalidState }
            // Count frames admitted to the transport, not all Data-Out PDUs built for an R2T.
            // A reply may legitimately arrive before the final send completion callback.
            writeSubmitted += pdu.data.count
            writeBurstComplete = pdu.flags & 0x80 != 0
        }
        if pdu.opcode == 0x01 {
            // A queued command is not yet sent. Advance only after the final admission checks,
            // before awaiting a callback that may follow a legitimate early peer response.
            parameters?.commandSequenceNumber &+= 1
        }
        if pdu.opcode == 0x06 {
            logoutSent = true
            if var requested = targetLogout, requested.tag == pdu.taskTag, !requested.issued {
                requested.issued = true
                requested.deadline = requested.overallDeadline
                targetLogout = requested
                armTargetLogoutWatchdog(requested.deadline)
            }
        }
        if pdu.opcode == 0x04 {
            if var negotiation, pdu.taskTag == negotiation.tag {
                guard !negotiation.awaitingResponse else {
                    throw ProtocolError.malformed("overlapping Text negotiation request")
                }
                negotiation.awaitingResponse = true
                negotiation.lastHeader = frame.header
                negotiation.issued = true
                negotiation.deadline = negotiation.overallDeadline
                self.negotiation = negotiation
                armNegotiationWatchdog(negotiation.deadline)
            } else {
                discoveryTextPending = true
            }
        }
        do {
            if pdu.opcode == 0x06, let signal = terminalLogoutSignal {
                guard let admitted = transport as? any SendAdmissionTransport else {
                    throw ProtocolError.invalidState
                }
                try await admitted.send(bytes) { submit in
                    try signal.whileConsumed { submit() }
                }
            } else {
                try await transport.send(bytes)
            }
        } catch { throw failureReason ?? error }
    }

    private func receive() async throws -> PDU {
        try checkDeadlines()
        if state == .ready || state == .closing {
            let response = try await responses.next()
            try checkDeadlines()
            return response
        }
        while pending.isEmpty {
            try Task.checkCancellation()
            guard state == .loggingIn else { throw ProtocolError.invalidState }
            let maximum = min(65_536, decoder.bytesNeeded)
            let bytes = try await transport.receive(maximumLength: maximum)
            try checkDeadlines()
            guard !bytes.isEmpty else { throw ProtocolError.connectionClosed }
            guard bytes.count <= maximum else {
                throw ProtocolError.malformed("transport receive length")
            }
            pending = try decoder.append(bytes)
        }
        return pending.removeFirst()
    }

    private func startReceiving() {
        let transport = transport
        let responses = responses
        receiverTask = Task.detached { [weak self] in
            do {
                while let context = await self?.readContext() {
                    let bytes = try await transport.receive(
                        maximumLength: context.maximum, waitingForActivity: context.idle)
                    guard let pdus = try await self?.decode(bytes, maximum: context.maximum) else {
                        return
                    }
                    for pdu in pdus {
                        if try await self?.route(pdu) == true { try await responses.put(pdu) }
                    }
                }
            } catch { await self?.fail(error) }
        }
        let clock = clock
        maintenanceTask = Task.detached { [weak self] in
            do {
                while let deadline = await self?.maintenanceDeadline() {
                    try await clock.sleep(until: deadline)
                    try await self?.probeIfIdle()
                }
            } catch { await self?.failOperation(error) }
        }
    }

    private func readContext() -> (maximum: Int, idle: Bool)? {
        guard state == .ready || state == .closing, logoutPhase != .responseReceived else {
            return nil
        }
        return (min(65_536, decoder.bytesNeeded), decoder.isAtFrameBoundary)
    }

    private func decode(_ bytes: Data, maximum: Int) throws -> [PDU] {
        do {
            try checkDeadlines()
            guard state == .ready || state == .closing else {
                throw failureReason ?? ProtocolError.connectionClosed
            }
            guard !bytes.isEmpty else { throw ProtocolError.connectionClosed }
            guard bytes.count <= maximum else {
                throw ProtocolError.malformed("transport receive length")
            }
            return try decoder.append(bytes)
        } catch {
            recordFailure(error)
            throw error
        }
    }

    /// Acknowledge all PDUs in wire order, before handing a response to the command consumer.
    /// Target pings and our ping replies are handled here even when no command is running.
    private func route(_ pdu: PDU) async throws -> Bool {
        do {
            try checkDeadlines()
            guard state == .ready || state == .closing else { throw ProtocolError.connectionClosed }
            if try await handleControl(pdu) {
                try checkDeadlines()
                lastActivity = clock.now
                return false
            }
            if let current = negotiation,
                (pdu.opcode == 0x24 && pdu.taskTag == current.tag) || pdu.opcode == 0x3F
            {
                guard current.awaitingResponse else {
                    throw ProtocolError.malformed("premature Text negotiation response")
                }
                if pdu.opcode == 0x3F {
                    guard pdu.flags & 0x80 != 0, pdu.taskTag == UInt32.max,
                        let header = current.lastHeader,
                        pdu.data.count >= 48, Array(pdu.data.prefix(48)) == header,
                        [0x04, 0x0A].contains(pdu.header[2])
                    else { throw ProtocolError.malformed("Text negotiation Reject") }
                }
                try acknowledge(pdu)
                negotiation?.awaitingResponse = false
                try await negotiationResponses.put(pdu)
                return false
            }
            if pdu.opcode == 0x3F, let retiredNegotiationHeader,
                pdu.data.count >= 48, Array(pdu.data.prefix(48)) == retiredNegotiationHeader,
                logoutPhase != .inactive || state == .closing
            {
                guard pdu.flags & 0x80 != 0, pdu.taskTag == UInt32.max else {
                    throw ProtocolError.malformed("retired Text Reject")
                }
                try acknowledge(pdu)
                return false
            }
            if pdu.opcode == 0x24, pdu.taskTag == retiredNegotiationTag,
                logoutPhase != .inactive || state == .closing
            {
                try acknowledge(pdu)
                return false
            }
            guard pdu.opcode != 0x26 || logoutSent else {
                throw ProtocolError.malformed("premature logout response")
            }
            if let targetLogout, !targetLogout.reusesLogout {
                if pdu.opcode == 0x26, pdu.taskTag == targetLogout.tag {
                    try acknowledge(pdu)
                    logoutPhase = .responseReceived
                    try await targetLogoutResponses.put(pdu)
                    return false
                }
                guard pdu.taskTag == targetLogout.retiredTag,
                    [0x21, 0x25, 0x31, 0x24].contains(pdu.opcode)
                else {
                    throw ProtocolError.malformed("response during requested logout")
                }
                try acknowledge(pdu)
                return false
            }
            guard let activeTag, pdu.taskTag == activeTag else {
                throw ProtocolError.malformed("unsolicited task response")
            }
            if pdu.opcode == 0x21, let writeLength {
                if pdu.header[3] == 0 {
                    let residual = pdu.flags & 0x02 == 0 ? 0 : Int(pdu.residualCount)
                    // Reject a short block write here, before handing it to a consumer that
                    // may still be suspended in Data-Out. No remaining frames may be admitted.
                    guard !writeRequiresExactTransfer || residual == 0 else {
                        throw ProtocolError.malformed("short block transfer")
                    }
                    guard residual <= writeLength, writeSubmitted == writeLength - residual else {
                        throw ProtocolError.malformed("premature write status")
                    }
                } else if sendingWriteData && !writeBurstComplete {
                    // An error may end a command after the last requested R2T burst,
                    // even when the target never solicited the rest of the command.
                    // Its F PDU can reach the target before our send callback returns.
                    throw ProtocolError.malformed("write status during Data-Out")
                }
            }
            try acknowledge(pdu)
            if pdu.opcode == 0x24, pdu.flags & 0x80 != 0 { discoveryTextPending = false }
            if logoutPhase == .waiting, pdu.opcode == 0x26 {
                // This is the final response on this connection. A following TCP FIN must
                // not race the consumer's validation and deadline-watchdog cleanup.
                logoutPhase = .responseReceived
            }
            lastActivity = clock.now
            return true
        } catch {
            // Fail admission in this actor turn. Cleanup may suspend, but a resumed sender
            // must already see a failed state before attempting another Data-Out frame.
            recordFailure(error)
            throw error
        }
    }

    private func maintenanceDeadline() -> ContinuousClock.Instant? {
        guard state == .ready else { return nil }
        // probeIfIdle() declines while a command or a Text negotiation is pending, so check
        // again later instead of polling an idle deadline that has already passed. The
        // negotiation's own watchdog bounds it; completion restarts from lastActivity.
        let busy = inFlight || negotiation != nil
        return (busy ? clock.now : lastActivity).advanced(by: heartbeatInterval)
    }

    private func probeIfIdle() async throws {
        guard state == .ready, !inFlight, negotiation == nil,
            clock.now >= lastActivity.advanced(by: heartbeatInterval)
        else { return }
        guard let parameters, heartbeat == nil else { throw ProtocolError.invalidState }
        let tag = allocateTag()
        let data = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        heartbeat = (tag, data, false)
        defer { heartbeat = nil }
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x40  // Immediate; a ping never consumes CmdSN or a SCSI task slot.
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(parameters.commandSequenceNumber, at: 24)
        header.put(parameters.expectedStatusSequenceNumber, at: 28)
        let request = try PDU(header: header, data: data)
        try await withDeadline(timeout: heartbeatTimeout) {
            try await self.send(request)
            try await self.waitForHeartbeat()
        }
    }

    private func waitForHeartbeat() async throws {
        guard state == .ready, let heartbeat else { throw ProtocolError.connectionClosed }
        if heartbeat.acknowledged { return }
        try await withCheckedThrowingContinuation { heartbeatWaiter = $0 }
    }

    private func acknowledge(_ pdu: PDU) throws {
        guard var parameters else { throw ProtocolError.invalidState }
        // R2T and Data-In without S carry StatSN without consuming it.
        let carriesStatus = pdu.opcode != 0x25 || pdu.flags & 1 != 0
        if carriesStatus {
            guard pdu.statusSequenceNumber == parameters.expectedStatusSequenceNumber else {
                throw ProtocolError.malformed("StatSN")
            }
            if pdu.opcode != 0x31 && !(pdu.opcode == 0x20 && pdu.taskTag == UInt32.max) {
                parameters.expectedStatusSequenceNumber &+= 1
            }
        }
        try parameters.updateCommandWindow(
            expected: pdu.expectedCommandSequenceNumber,
            maximum: pdu.maximumCommandSequenceNumber)
        self.parameters = parameters
        resumeCommandWindowIfOpen()
    }

    private func waitForCommandWindow() async throws {
        while let parameters,
            !SerialNumber.isWithin(
                parameters.commandSequenceNumber, first: parameters.expectedCommandSequenceNumber,
                last: parameters.maximumCommandSequenceNumber)
        {
            try await withCheckedThrowingContinuation { windowWaiter = $0 }
        }
        guard state == .ready else { throw ProtocolError.connectionClosed }
    }

    private func resumeCommandWindowIfOpen() {
        guard let parameters,
            SerialNumber.isWithin(
                parameters.commandSequenceNumber, first: parameters.expectedCommandSequenceNumber,
                last: parameters.maximumCommandSequenceNumber)
        else { return }
        let waiter = windowWaiter
        windowWaiter = nil
        waiter?.resume()
    }

    private func handleControl(_ pdu: PDU) async throws -> Bool {
        if pdu.opcode == 0x32 {
            let message = try AsynchronousMessage(pdu)
            try acknowledge(pdu)
            switch message.event {
            case 1:
                try await requestTargetLogout(after: .seconds(message.parameter3))
            case 2 where message.parameter1 != 0: break
            case 2, 3:
                // Parameter2 is the Time2Wait before reconnecting (RFC 7143 §11.9.1).
                targetRequestedTime2Wait = .seconds(message.parameter2)
                throw ProtocolError.targetEvent(message.event)
            case 0: throw ProtocolError.targetEvent(message.event)
            case 248...255: break
            case 4:
                if !logoutSent, targetLogout != nil || logoutPhase == .waiting {
                    // A queued Logout satisfies the request only once admitted. Honor
                    // Parameter3 even when its send is behind an earlier callback.
                    try await requestTargetLogout(after: .seconds(message.parameter3))
                } else {
                    try requestNegotiation(after: .seconds(message.parameter3))
                }
            default: throw ProtocolError.unsupported("asynchronous event")
            }
            return true
        }
        guard pdu.opcode == 0x20 else { return false }
        guard pdu.flags & 0x80 != 0 else {
            throw ProtocolError.malformed("NOP-In flags")
        }
        if pdu.taskTag != UInt32.max {
            if let retired = targetLogout?.heartbeat,
                pdu.taskTag == retired.tag, pdu.transferTag == UInt32.max,
                pdu.data == retired.data
            {
                try acknowledge(pdu)
                if heartbeat?.tag == retired.tag {
                    heartbeat?.acknowledged = true
                    let waiter = heartbeatWaiter
                    heartbeatWaiter = nil
                    waiter?.resume()
                }
                return true
            }
            guard let heartbeat, !heartbeat.acknowledged, pdu.taskTag == heartbeat.tag,
                pdu.transferTag == UInt32.max, pdu.data == heartbeat.data
            else { throw ProtocolError.malformed("NOP-In echo") }
            try acknowledge(pdu)
            self.heartbeat?.acknowledged = true
            let waiter = heartbeatWaiter
            heartbeatWaiter = nil
            waiter?.resume()
            return true
        }
        guard pdu.data.isEmpty else { throw ProtocolError.malformed("unsolicited NOP-In data") }
        try acknowledge(pdu)
        guard let parameters else { throw ProtocolError.invalidState }
        if pdu.transferTag != UInt32.max {
            var header = Array(repeating: UInt8(0), count: 48)
            header[0] = 0x40
            header[1] = 0x80
            header.replaceSubrange(8..<16, with: pdu.header[8..<16])
            header.put(UInt32.max, at: 16)
            header.put(pdu.transferTag, at: 20)
            header.put(parameters.commandSequenceNumber, at: 24)
            header.put(parameters.expectedStatusSequenceNumber, at: 28)
            try await send(PDU(header: header, data: pdu.data))
        }
        return true
    }

    private func allocateTag() -> UInt32 {
        while true {
            let tag = nextTag
            nextTag &+= 1
            if nextTag == UInt32.max { nextTag = 2 }
            if tag != activeTag, tag != heartbeat?.tag, tag != negotiation?.tag { return tag }
        }
    }

    private func recordFailure(_ error: any Error) {
        if state != .closed {
            noteStorageDisruption()
            state = .failed
            if failureReason == nil { failureReason = error }
            if let handler = terminationHandler, let failureReason {
                terminationHandler = nil
                handler(failureReason)
            }
        }
    }

    private func noteStorageDisruption() {
        if storageDisruptionEpoch == .max {
            storageCountersComplete = false
        } else {
            storageDisruptionEpoch += 1
        }
    }

    private func failOperation(_ error: any Error) async {
        // The target's Logout owns shutdown now. Failing the retiring command must not
        // cancel that independent exchange before its Logout Response arrives.
        guard state != .closing else { return }
        await fail(error)
    }

    private func fail(_ error: any Error = ProtocolError.connectionClosed) async {
        // close() and logout() mark the session closed and then stop receiving themselves.
        // The background tasks that stop ends (the cancelled heartbeat wait, a receive the
        // close interrupted) must not repeat that teardown once the session reported closed.
        guard state != .closed else { return }
        recordFailure(error)
        await stopReceiving(failureReason ?? error)
    }

    private func stopReceiving(_ error: any Error) async {
        let window = windowWaiter
        let heartbeat = heartbeatWaiter
        windowWaiter = nil
        heartbeatWaiter = nil
        window?.resume(throwing: error)
        heartbeat?.resume(throwing: error)
        await responses.close(error)
        await targetLogoutResponses.close(error)
        await stopNegotiating(error)
        targetLogoutWatchdog?.cancel()
        targetLogoutTask?.cancel()
        receiverTask?.cancel()
        maintenanceTask?.cancel()
        await transport.close()
        // Exchanges still draining cancel their own deadline waits; then the timer stops.
        clock.releaseWhenIdle()
    }

    /// Admission must not depend on a watchdog being scheduled before a transport callback.
    /// Commands and an outstanding idle probe have independent, overlapping deadlines.
    private func checkDeadlines(including deadline: ContinuousClock.Instant? = nil) throws {
        if let failureReason { throw failureReason }
        guard state != .closed else { throw ProtocolError.connectionClosed }
        let now = clock.now
        if deadline.map({ now >= $0 }) == true || deadlines.values.contains(where: { now >= $0 })
            || targetLogout.map({ now >= $0.deadline }) == true
            || negotiation.map({ now >= $0.deadline }) == true
        {
            recordFailure(ProtocolError.timedOut)
            throw ProtocolError.timedOut
        }
    }

    private func requestNegotiation(after grace: Duration) throws {
        // An existing Text Request or Logout already satisfies RFC 7143 §11.9.1.
        guard state == .ready, logoutPhase == .inactive, !discoveryTextPending else { return }
        let now = clock.now
        let overall = now.advanced(by: commandTimeout)
        let issueBy = now.advanced(by: grace == .zero ? commandTimeout : min(grace, commandTimeout))
        if var current = negotiation {
            if !current.issued, issueBy < current.deadline {
                current.deadline = issueBy
                negotiation = current
                armNegotiationWatchdog(issueBy)
            }
            return
        }
        let current = Negotiation(
            id: UUID(), tag: allocateTag(), deadline: issueBy, overallDeadline: overall)
        negotiation = current
        armNegotiationWatchdog(issueBy)
        negotiationTask = Task { await self.finishNegotiation(current) }
    }

    private func armNegotiationWatchdog(_ deadline: ContinuousClock.Instant) {
        negotiationWatchdog?.cancel()
        let clock = clock
        negotiationWatchdog = Task { [weak self] in
            do {
                try await clock.sleep(until: deadline)
                try Task.checkCancellation()
                await self?.negotiationExpired(deadline)
            } catch {
                if !Task.isCancelled { await self?.fail(error) }
            }
        }
    }

    private func negotiationExpired(_ deadline: ContinuousClock.Instant) async {
        guard negotiation?.deadline == deadline else { return }
        if clock.now < deadline {
            armNegotiationWatchdog(deadline)
        } else {
            await fail(ProtocolError.timedOut)
        }
    }

    private func finishNegotiation(_ context: Negotiation) async {
        do {
            guard let parameters else { throw ProtocolError.invalidState }
            var machine = try FullFeatureNegotiation(
                taskTag: context.tag, maximumSegmentLength: parameters.targetReceiveSegmentLength)
            var request: PDU? = try machine.start()
            while let frame = request {
                try await send(frame)
                let response = try await negotiationResponses.next()
                try Task.checkCancellation()
                try checkDeadlines()
                guard negotiation?.id == context.id, state == .ready else {
                    throw ProtocolError.connectionClosed
                }
                request = try response.opcode == 0x3F ? machine.reset() : machine.accept(response)
            }
            guard machine.isComplete, negotiation?.id == context.id, state == .ready else {
                throw ProtocolError.invalidState
            }
            // Preserve StatSN, CmdSN, the command window and digests updated by the reader.
            if let length = machine.changes.targetReceiveSegmentLength {
                self.parameters?.targetReceiveSegmentLength = length
            }
            if let alias = machine.changes.targetAlias { self.parameters?.targetAlias = alias }
            negotiation = nil
            negotiationTask = nil
            negotiationWatchdog?.cancel()
            negotiationWatchdog = nil
            lastActivity = clock.now
            let waiters = negotiationWaiters
            negotiationWaiters.removeAll()
            for waiter in waiters { waiter.resume() }
        } catch {
            // A user/target Logout may supersede Text. Its own deadline and response
            // processing now own the connection; this cancelled worker must not abort it.
            if negotiation?.id == context.id { await failOperation(error) }
        }
    }

    private func stopNegotiating(_ error: any Error) async {
        if let negotiation {
            retiredNegotiationTag = negotiation.tag
            retiredNegotiationHeader = negotiation.lastHeader
        }
        negotiation = nil
        negotiationTask?.cancel()
        negotiationTask = nil
        negotiationWatchdog?.cancel()
        negotiationWatchdog = nil
        let waiters = negotiationWaiters
        negotiationWaiters.removeAll()
        for waiter in waiters { waiter.resume(throwing: error) }
        await negotiationResponses.close(error)
    }

    private func requestTargetLogout(after grace: Duration) async throws {
        // Parameter3 limits issuing the request, not receiving its response. Zero asks
        // for immediate issuance; no work is drained before attempting the Logout.
        let limit = min(commandTimeout, .seconds(5))
        let received = clock.now
        let overallDeadline = received.advanced(by: limit)
        let deadline = received.advanced(
            by: grace == .zero || logoutSent ? limit : min(grace, limit))
        if var existing = targetLogout {
            if !existing.issued, deadline < existing.deadline {
                existing.deadline = deadline
                targetLogout = existing
                armTargetLogoutWatchdog(deadline)
            }
            return
        }
        let reuse = logoutPhase == .waiting
        let tag: UInt32
        if reuse {
            guard let activeTag else { throw ProtocolError.invalidState }
            tag = activeTag
        } else {
            tag = allocateTag()
        }
        targetLogout = TargetLogout(
            tag: tag, retiredTag: activeTag,
            heartbeat: heartbeat.map { ($0.tag, $0.data) },
            deadline: min(deadline, overallDeadline),
            overallDeadline: overallDeadline, reusesLogout: reuse,
            issued: logoutSent)
        state = .closing
        armTargetLogoutWatchdog(min(deadline, overallDeadline))
        if reuse {
            await stopNegotiating(ProtocolError.targetEvent(1))
            return
        }
        targetLogoutTask = Task { await self.finishTargetLogout(tag: tag) }
        let window = windowWaiter
        let ping = heartbeatWaiter
        windowWaiter = nil
        heartbeatWaiter = nil
        window?.resume(throwing: ProtocolError.targetEvent(1))
        ping?.resume(throwing: ProtocolError.targetEvent(1))
        await stopNegotiating(ProtocolError.targetEvent(1))
        await responses.close(ProtocolError.targetEvent(1))
    }

    private func armTargetLogoutWatchdog(_ deadline: ContinuousClock.Instant) {
        targetLogoutWatchdog?.cancel()
        let clock = clock
        targetLogoutWatchdog = Task { [weak self] in
            do {
                try await clock.sleep(until: deadline)
                try Task.checkCancellation()
                await self?.targetLogoutExpired(deadline)
            } catch {
                if !Task.isCancelled { await self?.fail(error) }
            }
        }
    }

    private func targetLogoutExpired(_ deadline: ContinuousClock.Instant) async {
        guard targetLogout?.deadline == deadline, state == .closing else { return }
        if clock.now < deadline {
            armTargetLogoutWatchdog(deadline)
        } else {
            await fail(ProtocolError.timedOut)
        }
    }

    private func finishTargetLogout(tag: UInt32) async -> Bool {
        var completed = false
        defer {
            targetLogoutResult = completed
            targetLogoutTask = nil
        }
        do {
            var header = [UInt8](repeating: 0, count: 48)
            header[0] = 0x46
            header[1] = 0x80
            header.put(tag, at: 16)
            try await send(PDU(header: header))
            let reply = try await targetLogoutResponses.next()
            try checkDeadlines()
            guard reply.opcode == 0x26, reply.taskTag == tag, reply.header[2] == 0,
                reply.flags & 0x80 != 0, reply.data.isEmpty
            else {
                throw ProtocolError.malformed("logout response")
            }
            await fail(ProtocolError.targetEvent(1))
            completed = true
            return true
        } catch {
            await fail(error)
            return false
        }
    }

    private func expireDeadline(_ id: UUID) async throws -> Bool {
        try Task.checkCancellation()
        // A completed exchange removes its token before cancelling/draining its watchdog.
        guard let deadline = deadlines[id] else { throw CancellationError() }
        guard clock.now >= deadline else { return false }
        await fail(ProtocolError.timedOut)
        return true
    }

    /// Deadline covers the entire exchange, including a peer sending endless NOPs or fragments.
    private func withDeadline<Value: Sendable>(
        timeout: Duration? = nil,
        _ work: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        let deadline = clock.now.advanced(by: timeout ?? commandTimeout)
        let id = UUID()
        deadlines[id] = deadline
        defer { deadlines.removeValue(forKey: id) }
        let result = try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: Value.self) { group in
                group.addTask { try await work() }
                group.addTask { [clock] in
                    while true {
                        try await clock.sleep(until: deadline)
                        if try await self.expireDeadline(id) { throw ProtocolError.timedOut }
                    }
                }
                defer {
                    deadlines.removeValue(forKey: id)
                    group.cancelAll()
                }
                do {
                    guard let result = try await group.next() else {
                        throw ProtocolError.connectionClosed
                    }
                    try checkDeadlines()
                    try Task.checkCancellation()
                    return result
                } catch {
                    // Even a device error cannot keep an already expired session usable.
                    try checkDeadlines()
                    throw error
                }
            }
        } onCancel: {
            Task { await self.fail(CancellationError()) }
        }
        // Draining cancelled children can suspend; check again before publishing success.
        try checkDeadlines(including: deadline)
        try Task.checkCancellation()
        return result
    }

    private func parseDiscovery(_ data: Data) throws -> [DiscoveredTarget] {
        var targets: [DiscoveredTarget] = []
        var targetCount = 0
        var name: String?
        var addresses: [String] = []
        var groups: [TargetAddress] = []
        for entry in try TextParameters(data: data).entries {
            switch entry.key {
            case "TargetName":
                guard targetCount < Self.maximumDiscoveryTargets else {
                    throw ProtocolError.limitExceeded("discovery targets")
                }
                targetCount += 1
                if let name { targets.append(DiscoveredTarget(name: name, addresses: addresses)) }
                _ = try LoginConfiguration(
                    initiatorName: configuration.initiatorName, targetName: entry.value)
                name = entry.value
                addresses = []
                groups = []
            case "TargetAddress":
                guard name != nil else { throw ProtocolError.malformed("orphan target address") }
                let address = try TargetAddress(entry.value)
                guard let group = address.portalGroupTag else {
                    throw ProtocolError.malformed("discovery portal group")
                }
                if let previous = groups.first(where: {
                    $0.portal.isSameEndpoint(as: address.portal)
                }),
                    previous.portalGroupTag != group
                {
                    throw ProtocolError.malformed("conflicting target portal group")
                }
                groups.append(address)
                guard addresses.count < 16 else {
                    throw ProtocolError.limitExceeded("discovery addresses")
                }
                addresses.append(entry.value)
            default: throw ProtocolError.unsupported("discovery key \(entry.key)")
            }
        }
        if let name { targets.append(DiscoveredTarget(name: name, addresses: addresses)) }
        return targets
    }
}
