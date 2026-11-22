import Foundation
import ISCSICore
import Synchronization

/// A live observation of this exact disk's issued-I/O boundary. No public initializer,
/// durable representation, synchronization success or producer/unmount authority.
final class ReservedIODrain: Sendable {
    let disk: RemoteDisk
    let access: ReservedDiskAccess
    let generation: UInt64
    let drain: OwnedIOGate.Drain

    fileprivate init(
        disk: RemoteDisk, access: ReservedDiskAccess, generation: UInt64,
        drain: OwnedIOGate.Drain
    ) {
        self.disk = disk
        self.access = access
        self.generation = generation
        self.drain = drain
    }
}

final class ReservedIOTerminal: Sendable {
    let disk: RemoteDisk
    let access: ReservedDiskAccess
    let generation: UInt64
    let lease: OwnedIOGate.TerminalLease
    fileprivate init(
        disk: RemoteDisk, access: ReservedDiskAccess, generation: UInt64,
        lease: OwnedIOGate.TerminalLease
    ) {
        self.disk = disk
        self.access = access
        self.generation = generation
        self.lease = lease
    }
}

/// Minted only after the controlled terminal synchronization returned GOOD.
final class ReservedTerminalSynchronization: Sendable {
    let access: ReservedDiskAccess
    let generation: UInt64
    let signal: OwnedIOGate.Drain
    fileprivate init(terminal: ReservedIOTerminal) {
        access = terminal.access
        generation = terminal.generation
        signal = terminal.lease.signal
    }
}

/// Which commands that may change the medium a GOOD SYNCHRONIZE CACHE is known to cover.
/// Each such command takes the next generation before it is sent, including every redo of
/// one, together with the connection epoch it is sent in. A synchronization covers only the
/// generations that had completed when it was sent, only if the connection wasn't
/// reestablished while it ran, and only those sent in its own epoch: a target that restarted
/// may have lost what it had acknowledged before. An earlier epoch's generation stays dirty
/// until the write callback that sent it has sent everything again and flushed it within one
/// epoch (`supersede`). Any doubt leaves the disk dirty, which costs one SYNCHRONIZE CACHE. A
/// disk that has sent nothing since opening holds nothing of ours in the target's cache, so
/// it starts clean.
final class SynchronizationCoverage: Sendable {
    private struct Pending: Sendable {
        let generation: UInt64
        let epoch: UInt64
        var superseded = false
    }
    private struct State: Sendable {
        var issued: UInt64 = 0
        var inFlight: Set<UInt64> = []
        var clean: UInt64 = 0
        /// Every issued generation above `clean`, oldest first.
        var pending: [Pending] = []
        /// More were pending than are tracked: the disk stays dirty, every flush is sent.
        var overflowed = false
        /// The newest GOOD synchronization: the generation it covered and its epoch.
        var good: (captured: UInt64, epoch: UInt64)?

        mutating func advance() {
            guard let good, !overflowed else { return }
            var mark = clean
            for entry in pending {
                guard entry.generation <= good.captured,
                    entry.superseded || entry.epoch == good.epoch
                else { break }
                mark = entry.generation
            }
            clean = max(clean, mark)
            pending.removeAll { $0.generation <= clean }
        }
    }
    private static let pendingLimit = 65_536
    private let state = Mutex(State())

    /// Every issued generation completed and a GOOD synchronization covered it.
    var isClean: Bool { state.withLock { $0.inFlight.isEmpty && $0.clean == $0.issued } }
    var issuedGeneration: UInt64 { state.withLock { $0.issued } }
    var cleanGeneration: UInt64 { state.withLock { $0.clean } }

    /// Before a command that may change the medium is sent, in connection epoch `epoch`.
    func beginMutation(epoch: UInt64) -> UInt64 {
        state.withLock { value in
            value.issued &+= 1
            value.inFlight.insert(value.issued)
            if value.pending.count < Self.pendingLimit {
                value.pending.append(Pending(generation: value.issued, epoch: epoch))
            } else {
                value.overflowed = true
            }
            return value.issued
        }
    }

    /// After that command ended, whatever its outcome: a failed one stays dirty.
    func endMutation(_ generation: UInt64) {
        _ = state.withLock { $0.inFlight.remove(generation) }
    }

    /// When a synchronization is sent: the newest generation below every one still in flight.
    func capture() -> UInt64 {
        state.withLock { value in value.inFlight.min().map { $0 - 1 } ?? value.issued }
    }

    /// After a GOOD synchronization sent at `captured` in `epoch`, with no reconnection while
    /// it ran. Never covers a later generation, or one sent in another epoch.
    func synchronized(through captured: UInt64, epoch: UInt64) {
        state.withLock { value in
            guard captured <= value.issued else { return }
            if value.good.map({ captured >= $0.captured }) ?? true {
                value.good = (captured, epoch)
            }
            value.advance()
        }
    }

    /// `generations` were sent again, all of them, and flushed within one epoch by the write
    /// callback that sent them first: what they wrote is covered by the later flush.
    func supersede(_ generations: [UInt64]) {
        guard !generations.isEmpty else { return }
        let replaced = Set(generations)
        state.withLock { value in
            for index in value.pending.indices
            where replaced.contains(value.pending[index].generation) {
                value.pending[index].superseded = true
            }
            value.advance()
        }
    }
}

/// Byte-addressed access for the FSKit image file. Read-modify-write holds the same gate as
/// all reads, writes and flushes, preventing concurrent partial-sector updates from being lost.
public final class RemoteDisk: Sendable {
    public let capacity: DiskCapacity
    public let isReadOnly: Bool
    /// The opening session. Only the reserved path uses it directly; every shipping command
    /// goes through `connection`, which owns the current session after any reconnection.
    private let session: ISCSISession
    private let connection: RecoveringSession
    private let lun: LogicalUnit
    private let gate = OwnedIOGate()
    private let evidenceJournal: MutationEvidenceJournal
    private let useSync16 = Mutex(false)
    private let maximumTransferLength: Int
    private let diagnostics: IODiagnostics.Recorder?
    private let reservedAccess: ReservedDiskAccess?
    private let transportCloser = Mutex<ReservedTransportCompletion?>(nil)
    /// Awake time for retrying unexecuted commands: by default the connection's own clock.
    private let retryClock: RecoveryClock
    let coverage = SynchronizationCoverage()
    var queuedIOCount: Int { get async { await gate.waitingCount } }
    var mutationEvidence: MutationEvidence { evidenceJournal.snapshot }
    var recoveryHistory: [MutationEvidenceJournal.Recovery] { evidenceJournal.recoveryHistory }
    var isIssuedIOSealed: Bool { get async { await gate.isSealed } }
    var waitingIssuedIODrainCount: Int { get async { await gate.waitingDrainCount } }

    /// - Parameter writeProtection: The write-protection state observed when the disk was
    ///   probed for opening, or nil if the device didn't report one. A unit attention that
    ///   may follow a device change is retried only while this and the capacity still match.
    public convenience init(
        session: ISCSISession, lun: LogicalUnit, capacity: DiskCapacity, readOnly: Bool,
        maximumTransferBlocks: UInt32 = 0, writeProtection: Bool? = nil,
        diagnostics: IODiagnostics.Recorder? = IODiagnostics.live(layer: .remoteDisk)
    ) {
        self.init(
            session: session, lun: lun, capacity: capacity, readOnly: readOnly,
            maximumTransferBlocks: maximumTransferBlocks, diagnostics: diagnostics,
            reservedAccess: nil, writeProtection: writeProtection)
    }

    /// A disk whose connection is reestablished after it is lost. Its capacity and the state
    /// compared after each reconnection are the ones observed when it was opened.
    public convenience init(
        connection: RecoveringSession, readOnly: Bool, maximumTransferBlocks: UInt32 = 0,
        diagnostics: IODiagnostics.Recorder? = IODiagnostics.live(layer: .remoteDisk)
    ) {
        self.init(
            session: connection.initialSession, lun: connection.lun,
            capacity: connection.fingerprint.capacity, readOnly: readOnly,
            maximumTransferBlocks: maximumTransferBlocks, diagnostics: diagnostics,
            reservedAccess: nil, writeProtection: connection.fingerprint.writeProtection,
            connection: connection)
    }

    /// `retainedMutationBytes` overrides how many submitted write payload bytes the mutation
    /// evidence may copy. By default only a reserved disk, whose recovery consumes them,
    /// retains payloads; the shipping path keeps the incident latch without any copies.
    /// `retryClock` overrides the connection's clock for retrying unexecuted commands.
    init(
        session: ISCSISession, lun: LogicalUnit, capacity: DiskCapacity, readOnly: Bool,
        maximumTransferBlocks: UInt32 = 0, diagnostics: IODiagnostics.Recorder?,
        reservedAccess: ReservedDiskAccess?, writeProtection: Bool? = nil,
        retainedMutationBytes: Int? = nil, retryClock: RecoveryClock? = nil,
        connection: RecoveringSession? = nil
    ) {
        self.session = session
        // Without a connector, the one session is never replaced, exactly as before.
        self.connection =
            connection
            ?? RecoveringSession(
                session: session, lun: lun,
                fingerprint: LogicalUnitFingerprint(
                    capacity: capacity, writeProtection: writeProtection))
        self.lun = lun
        self.capacity = capacity
        self.isReadOnly = readOnly
        self.diagnostics = diagnostics
        self.reservedAccess = reservedAccess
        self.retryClock = retryClock ?? self.connection.clock
        evidenceJournal = MutationEvidenceJournal(
            byteCount: capacity.byteCount, blockSize: capacity.blockSize,
            maximumBytes: retainedMutationBytes ?? (reservedAccess == nil ? 0 : 4_194_304),
            reservedOrigin: reservedAccess?.origin)
        let localLimit = UInt32(1_048_576) / capacity.blockSize
        let blocks =
            maximumTransferBlocks == 0 ? localLimit : min(localLimit, maximumTransferBlocks)
        // Clamp in blocks before multiplying, including a target's UInt32.max report.
        maximumTransferLength = Int(blocks * capacity.blockSize)
    }

    public func read(offset: Int64, length: Int) async throws -> Data {
        try await IODiagnostics.withOperation(.read, recorder: diagnostics) { trace in
            try self.validate(offset: offset, length: length)
            trace?.record(.validated)
            guard length > 0 else { return Data() }
            return try await self.serialized(trace: trace) {
                try await self.readBytes(offset: UInt64(offset), length: length, trace: trace)
            }
        }
    }

    public func write(offset: Int64, data: Data) async throws {
        // A write callback, or part of one: once it sent data, it can't be undone.
        try await WriteProgress.within { try await self.writeAligning(offset: offset, data: data) }
    }

    private func writeAligning(offset: Int64, data: Data) async throws {
        try await IODiagnostics.withOperation(.write, recorder: diagnostics) { trace in
            guard !isReadOnly else { throw POSIXError(.EROFS) }
            try validate(offset: offset, length: data.count)
            trace?.record(.validated)
            guard !data.isEmpty else { return }
            try await serialized(trace: trace) {
                let blockSize = UInt64(self.capacity.blockSize)
                let start = UInt64(offset) / blockSize * blockSize
                let end =
                    (UInt64(offset) + UInt64(data.count) + blockSize - 1) / blockSize * blockSize
                var aligned: Data
                if start == UInt64(offset), end - start == UInt64(data.count) {
                    aligned = data
                } else {
                    // This read serves the write: if its window expires, the disk latches
                    // as for the write itself (see RecoveringSession.admittedSession).
                    aligned = try await self.readBytes(
                        offset: start, length: Int(end - start), trace: trace)
                    let displacement = Int(UInt64(offset) - start)
                    aligned.replaceSubrange(displacement..<(displacement + data.count), with: data)
                }
                var cursor = 0
                while cursor < aligned.count {
                    let count = min(self.maximumTransferLength, aligned.count - cursor)
                    let command = try SCSICommand.write(
                        lba: (start + UInt64(cursor)) / blockSize,
                        blocks: UInt32(count) / self.capacity.blockSize,
                        blockSize: self.capacity.blockSize)
                    let output = Data(
                        aligned[
                            (aligned.startIndex + cursor)..<(aligned.startIndex + cursor + count)])
                    let sequence = self.evidenceJournal.beginWrite(
                        offset: start + UInt64(cursor), payload: output)
                    _ = try await self.executeMutation(
                        command, output: output, evidenceSequence: sequence, trace: trace)
                    cursor += count
                }
            }
        }
    }

    public func synchronize() async throws {
        try await synchronize(reporting: nil)
    }

    func synchronize(access: ReservedDiskAccess) async throws {
        guard access === reservedAccess else { throw MutationRecoveryIssue.wrongContext }
        try await synchronize(reporting: access)
    }

    private func synchronize(reporting access: ReservedDiskAccess?) async throws {
        try await IODiagnostics.withOperation(.synchronize, recorder: diagnostics) { trace in
            trace?.record(.validated)
            guard !self.isReadOnly else { return }
            try await self.serialized(trace: trace) {
                if access == nil, try await self.skipsCleanSynchronization() { return }
                try await self.synchronizeAdmitted(reporting: access, trace: trace)
            }
        }
    }

    /// Called under the gate. FSKit asks for a flush about every 30 seconds even when nothing
    /// was written; during an outage such a flush would wait like a write and stop the disk
    /// when its window ends. A flush of a disk with nothing unsynchronized has nothing to make
    /// durable, so it isn't sent. A stopped disk still reports why: a skipped command never
    /// executes, so the connection's own failure is thrown here. The reserved path, and a
    /// single session that is no longer usable, always send it.
    private func skipsCleanSynchronization() async throws -> Bool {
        guard reservedAccess == nil, coverage.isClean else { return false }
        try await connection.checkAdmission()
        return await connection.admitsCommands
    }

    private func synchronizeAdmitted(
        reporting access: ReservedDiskAccess?, trace: IODiagnostics.Trace?
    ) async throws {
        let origin = trace == nil ? nil : DiagnosticOrigin()
        evidenceJournal.beginSynchronization()
        // Writes are serialized with flushes under the gate, so none is in flight here; the
        // capture still excludes one, and a reconnection while flushing proves nothing.
        let covered = coverage.capture()
        let epoch = await connectionEpoch()
        do {
            if useSync16.withLock({ $0 }) {
                _ = try await executeSynchronization(
                    .synchronizeCache16(), kind: .synchronize16, trace: trace, origin: origin)
            } else {
                do {
                    _ = try await executeSynchronization(
                        .synchronizeCache10(), kind: .synchronize10, trace: trace, origin: origin)
                } catch let ProtocolError.scsiFailure(status, data) {
                    // Only a current invalid-opcode response establishes that this
                    // format was not implemented. Invalid fields and deferred errors
                    // do not establish that, and must never trigger another command.
                    guard status == 2, let sense = try? SCSISense(data: data),
                        !sense.isDeferred, sense.key == 5,
                        sense.additionalSenseCode == 0x20, sense.qualifier == 0,
                        await self.admitsCommands
                    else { throw ProtocolError.scsiFailure(status: status, sense: data) }
                    _ = try await executeSynchronization(
                        .synchronizeCache16(), kind: .synchronize16, trace: trace, origin: origin)
                    useSync16.withLock { $0 = true }
                }
            }
            evidenceJournal.completeSynchronization()
            if await connectionEpoch() == epoch {
                coverage.synchronized(through: covered, epoch: epoch)
            }
        } catch {
            let incident = recordMutationFailure(
                error, trace: trace, originatingAttempt: origin?.attempt,
                operation: .synchronize, sequence: nil)
            if let access, let incident {
                throw ReservedSynchronizationFailure(
                    access: access, incident: incident,
                    evidence: evidenceJournal.snapshot, error: error)
            }
            throw error
        }
    }

    public func close() async {
        if let access = reservedAccess {
            // This public view cannot establish producer drain, even after a GOOD barrier.
            // Preserve the owning reserved disk's immediate-abandonment semantics and pins.
            access.revoke()
            let closer = transportCloser.withLock { $0 }
            closer?.cancel()
            gate.terminalHandle.invalidate()
            await gate.abort()
            await access.owner.abandon()
            await closer?.waitForAbort()
            return
        }
        // Abandons any reconnection first, so waiting I/O fails at once.
        await connection.close()
    }

    /// Increases each time the connection is reestablished, or the target reports a reset.
    public func connectionEpoch() async -> UInt64 {
        reservedAccess == nil ? await connection.epoch : 0
    }

    /// Stops reconnecting: waiting I/O fails at once and no further login is attempted.
    public func abandonConnectionRecovery() async {
        guard reservedAccess == nil else { return }
        await connection.abandon()
    }

    /// Runs `pass`, which writes and then synchronizes, again until one whole pass ran within
    /// a single connection epoch. A target that restarted with a volatile cache can lose
    /// acknowledged writes; a GOOD synchronization in a later epoch doesn't cover them. A write
    /// that can't complete within one epoch latches the disk, as a lost write would.
    public func repeatingWithinOneEpoch<Value: Sendable>(
        _ pass: @Sendable () async throws -> Value
    ) async throws -> Value {
        guard reservedAccess == nil else { return try await pass() }
        return try await WriteProgress.within { try await self.repeatingPasses(pass) }
    }

    private func repeatingPasses<Value: Sendable>(_ pass: @Sendable () async throws -> Value)
        async throws -> Value
    {
        var epoch = await connection.epoch
        var firstChange: Duration?
        var redone = 0
        let progress = WriteProgress.current
        // How many generations this callback's earlier passes sent.
        var earlier = 0
        while true {
            let value: Value
            do {
                value = try await pass()
            } catch {
                // A partial-sector pre-read can fail on a redo, after the old session
                // accepted data. The callback can no longer prove the whole write durable.
                if progress?.sent == true, !evidenceJournal.hasIncident {
                    await connection.failStop(error)
                }
                throw error
            }
            let after = await connection.epoch
            guard after != epoch else {
                // This pass sent everything again and flushed it within one epoch.
                if earlier > 0, let progress {
                    coverage.supersede(Array(progress.generations.prefix(earlier)))
                }
                return value
            }
            earlier = progress?.generations.count ?? 0
            let now = connection.clock.elapsed
            let start = firstChange ?? now
            firstChange = start
            redone += 1
            guard redone <= SessionRecovery.maximumRedoPasses,
                now - start < connection.recoveryWindow
            else {
                await connection.failStop(SessionRecoveryError.writeRedoLimitExceeded)
                throw SessionRecoveryError.writeRedoLimitExceeded
            }
            epoch = after
        }
    }

    private var admitsCommands: Bool {
        get async {
            reservedAccess == nil ? await connection.admitsCommands : await session.state == .ready
        }
    }

    func recoverSynchronizationFailure(
        access: ReservedDiskAccess, matching failure: ReservedSynchronizationFailure? = nil
    ) async throws {
        guard access === reservedAccess else { throw MutationRecoveryIssue.wrongContext }
        try await withOwnedGate {
            try Task.checkCancellation()
            try failure?.validate(access: access, evidence: evidenceJournal.snapshot)
            try await session.recoverReservedDisk(
                access, journal: evidenceJournal, diagnostics: diagnostics)
        }
    }

    /// Only the owning reserved lifecycle can request this lower-level drain.
    /// It leaves final synchronization, producer closure and session completion unproved.
    func prepareIssuedIODrain(access: ReservedDiskAccess) async throws -> ReservedIODrain {
        guard access === reservedAccess else { throw MutationRecoveryIssue.wrongContext }
        let terminal = gate.terminalHandle
        return try await withTaskCancellationHandler {
            do {
                let drain = try await gate.sealAndDrain()
                let generation = access.generation
                try Task.checkCancellation()
                try await session.validateReservedDisk(access, generation: generation)
                try Task.checkCancellation()
                try access.validate(generation: generation)
                guard !evidenceJournal.hasIncident else { throw ProtocolError.invalidState }
                try drain.validate()
                return ReservedIODrain(
                    disk: self, access: access, generation: generation, drain: drain)
            } catch {
                terminal.invalidate()
                await gate.abort()
                throw error
            }
        } onCancel: {
            terminal.invalidate()
        }
    }

    @discardableResult
    func consumeIssuedIODrain(
        _ proof: ReservedIODrain, access: ReservedDiskAccess
    ) async throws -> ReservedIOTerminal {
        guard proof.disk === self, proof.access === access, access === reservedAccess else {
            throw MutationRecoveryIssue.wrongContext
        }
        return try await withTaskCancellationHandler {
            do {
                try access.validate(generation: proof.generation)
                let lease = try await gate.consume(proof.drain)
                try Task.checkCancellation()
                try access.validate(generation: proof.generation)
                try access.beginTerminal(generation: proof.generation, signal: proof.drain)
                return ReservedIOTerminal(
                    disk: self, access: access, generation: proof.generation, lease: lease)
            } catch {
                proof.drain.invalidate()
                await gate.abort()
                throw error
            }
        } onCancel: {
            proof.drain.invalidate()
        }
    }

    func transportCompletion(access: ReservedDiskAccess) -> ReservedTransportCompletion {
        precondition(access === reservedAccess)
        return transportCloser.withLock { value in
            if let existing = value { return existing }
            let session = session
            let signal = gate.terminalHandle
            let operation = ReservedTransportCompletion(
                perform: { [weak self] in
                    guard let self else {
                        await session.close()
                        await access.owner.abandon()
                        return .abandoned
                    }
                    return await self.completeReservedTransport(access: access)
                },
                invalidate: {
                    access.revoke()
                    signal.invalidate()
                },
                abortTransport: {
                    await session.close()
                    await access.owner.abandon()
                })
            value = operation
            return operation
        }
    }

    private func completeReservedTransport(access: ReservedDiskAccess) async
        -> ReservedTransportCloseResult
    {
        guard let operation = transportCloser.withLock({ $0 }) else { return .abandoned }
        do {
            try operation.check()
            let drain = try await prepareIssuedIODrain(access: access)
            try operation.check()
            let terminal = try await consumeIssuedIODrain(drain, access: access)
            try operation.check()
            let synchronization = try await synchronizeTerminal(terminal)
            try operation.check()
            let accepted = try await access.owner.finishTransport(synchronization: synchronization)
            try operation.check()
            return accepted ? .synchronizedAndLoggedOut : .abandoned
        } catch {
            gate.terminalHandle.invalidate()
            access.revoke()
            await gate.abort()
            await session.close()
            await access.owner.abandon()
            return .abandoned
        }
    }

    private func synchronizeTerminal(
        _ terminal: ReservedIOTerminal
    ) async throws -> ReservedTerminalSynchronization {
        guard terminal.disk === self, terminal.access === reservedAccess else {
            throw MutationRecoveryIssue.wrongContext
        }
        // Spend the opportunity before the first suspension, including failed attempts.
        try terminal.lease.beginSynchronization()
        try await gate.validateTerminal(terminal.lease)
        try terminal.access.validate(generation: terminal.generation)
        try await IODiagnostics.withOperation(.synchronize, recorder: diagnostics) { trace in
            trace?.record(.validated)
            try await self.synchronizeAdmitted(reporting: terminal.access, trace: trace)
        }
        try terminal.access.validateTerminal(
            generation: terminal.generation, signal: terminal.lease.signal)
        return ReservedTerminalSynchronization(terminal: terminal)
    }

    func abortIssuedIODrain() async {
        gate.terminalHandle.invalidate()
        await gate.abort()
    }

    private func withOwnedGate<Value: Sendable>(
        _ operation: @Sendable () async throws -> Value
    ) async throws -> Value {
        let lease = try await gate.acquire()
        let result: Result<Value, any Error>
        do { result = .success(try await operation()) } catch { result = .failure(error) }
        guard await gate.release(lease) else { throw ProtocolError.invalidState }
        return try result.get()
    }

    public func connectionState() async -> DiskConnectionState {
        guard reservedAccess == nil else {
            switch await session.state {
            case .ready: return evidenceJournal.hasIncident ? .interrupted : .connected
            case .closing, .failed: return .interrupted
            case .closed: return .closed
            case .disconnected, .loggingIn: return .unknown
            }
        }
        switch await connection.health() {
        case .ready: return evidenceJournal.hasIncident ? .interrupted : .connected
        case .reconnecting: return evidenceJournal.hasIncident ? .interrupted : .reconnecting
        case .failed: return .interrupted
        case .closed: return .closed
        case .unknown: return .unknown
        }
    }

    private func readBytes(offset: UInt64, length: Int, trace: IODiagnostics.Trace?) async throws
        -> Data
    {
        let blockSize = UInt64(capacity.blockSize)
        let alignedStart = offset / blockSize * blockSize
        let alignedEnd = (offset + UInt64(length) + blockSize - 1) / blockSize * blockSize
        var position = alignedStart
        var data = Data()
        while position < alignedEnd {
            let count = min(UInt64(maximumTransferLength), alignedEnd - position)
            let command = try SCSICommand.read(
                lba: position / blockSize,
                blocks: UInt32(count / blockSize), blockSize: capacity.blockSize)
            let result = try await IODiagnostics.backend(.read, trace: trace) { attempt in
                // A read failure alone leaves the disk usable, but a changed device must not.
                try await self.executeBlock(command) { error in
                    self.recordMutationFailure(
                        error, trace: trace, originatingAttempt: attempt, operation: .read,
                        sequence: nil)
                }
            }
            guard result.residualCount == 0, result.data.count == Int(count) else {
                throw ProtocolError.malformed("short disk read")
            }
            data.append(result.data)
            position += count
        }
        let displacement = Int(offset - alignedStart)
        return Data(data[displacement..<(displacement + length)])
    }

    private func validate(offset: Int64, length: Int) throws {
        guard offset >= 0, length >= 0, length <= 16_777_216,
            UInt64(offset) <= capacity.byteCount,
            UInt64(length) <= capacity.byteCount - UInt64(offset)
        else { throw POSIXError(.EINVAL) }
    }

    private func executeMutation(
        _ command: SCSICommand, output: Data, evidenceSequence: UInt64?,
        trace: IODiagnostics.Trace?
    ) async throws -> SCSIResult {
        try await IODiagnostics.backend(.write, trace: trace) { attempt in
            do {
                let result = try await self.executeBlock(command, output: output)
                guard result.residualCount == 0 else {
                    throw ProtocolError.malformed("short disk write")
                }
                self.evidenceJournal.finishWrite(evidenceSequence, outcome: .fullyAcknowledged)
                return result
            } catch {
                let outcome: MutationWriteOutcome
                if case ProtocolError.scsiFailure(let status, _) = error {
                    outcome = .failedResponse(status)
                } else {
                    outcome = .indeterminate
                }
                self.evidenceJournal.finishWrite(evidenceSequence, outcome: outcome)
                // Retain the same failure before releasing the existing disk gate.
                self.recordMutationFailure(
                    error, trace: trace, originatingAttempt: attempt,
                    operation: .write, sequence: evidenceSequence)
                throw error
            }
        }
    }

    private final class DiagnosticOrigin: Sendable {
        private let storage = Mutex<IODiagnostics.BackendAttempt?>(nil)
        var attempt: IODiagnostics.BackendAttempt? { storage.withLock { $0 } }
        func failed(_ attempt: IODiagnostics.BackendAttempt?) { storage.withLock { $0 = attempt } }
    }

    private func executeSynchronization(
        _ command: SCSICommand, kind: IODiagnostics.Detail, trace: IODiagnostics.Trace?,
        origin: DiagnosticOrigin?
    ) async throws -> SCSIResult {
        try await IODiagnostics.backend(kind, trace: trace) { attempt in
            do {
                let result = try await self.executeBlock(command)
                guard result.residualCount == 0, result.data.isEmpty else {
                    throw ProtocolError.malformed("synchronization completion")
                }
                self.evidenceJournal.noteSynchronization(
                    opcode: command.cdb[0],
                    outcome: .fullyAcknowledged, sense: nil)
                return result
            } catch {
                if case ProtocolError.scsiFailure(let status, let data) = error {
                    self.evidenceJournal.noteSynchronization(
                        opcode: command.cdb[0], outcome: .failedResponse(status),
                        sense: try? SCSISense(data: data))
                } else {
                    self.evidenceJournal.noteSynchronization(
                        opcode: command.cdb[0], outcome: .indeterminate, sense: nil)
                }
                // A handled SYNC10 rejection must not latch the disk. Only the original
                // outer catch decides retention; remember the actual last failed attempt.
                origin?.failed(attempt)
                throw error
            }
        }
    }

    @discardableResult
    private func recordMutationFailure(
        _ error: any Error, trace: IODiagnostics.Trace?,
        originatingAttempt: IODiagnostics.BackendAttempt?,
        operation: MutationIncident.Operation, sequence: UInt64?
    ) -> MutationIncident? {
        if case ProtocolError.scsiFailure(let status, let data) = error {
            let incident = evidenceJournal.retainFailure(
                operation: operation, sequence: sequence, status: status,
                sense: try? SCSISense(data: data))
            // No recorder call under the product mutex, and no gate release before cause.
            if let incident {
                trace?.retainMutationFailure(
                    id: incident.id, error: error, originatingAttempt: originatingAttempt)
            }
            return incident
        }
        return nil
    }

    private func serialized<Value: Sendable>(
        trace: IODiagnostics.Trace?, _ operation: @Sendable () async throws -> Value
    ) async throws -> Value {
        let generation = reservedAccess?.generation
        trace?.record(.gateWaiting)
        return try await withOwnedGate {
            trace?.record(.gateAcquired)
            try Task.checkCancellation()
            if let access = reservedAccess, let generation {
                try await session.validateReservedDisk(access, generation: generation)
            }
            guard !evidenceJournal.hasIncident else {
                trace?.record(
                    .retainedMutationRejected, causeID: evidenceJournal.incidentID,
                    error: ProtocolError.invalidState)
                throw ProtocolError.invalidState
            }
            return try await operation()
        }
    }

    /// `deviceChanged` receives the original failure when a retry is refused because the
    /// device no longer matches the one opened. A write or synchronization caller already
    /// retains every failure it receives; a read caller must retain this one itself.
    private func executeBlock(
        _ command: SCSICommand, output: Data = Data(),
        deviceChanged: (any Error) -> Void = { _ in }
    ) async throws -> SCSIResult {
        let tracking = Self.leavesMediumUnchanged(command) ? nil : coverage
        if let access = reservedAccess {
            // The reserved path has its own recovery; never retry beneath it.
            let generation = tracking?.beginMutation(epoch: 0)
            defer { if let generation { coverage.endMutation(generation) } }
            return try await session.executeReservedDisk(
                command, output: output, access: access, generation: access.generation)
        }
        return try await executeRetryingUnexecuted(
            command, output: output, tracking: tracking, deviceChanged: deviceChanged)
    }

    /// READ (10, 16) and SYNCHRONIZE CACHE (10, 16).
    static func leavesMediumUnchanged(_ command: SCSICommand) -> Bool {
        [UInt8(0x28), 0x88, 0x35, 0x91].contains(command.cdb[0])
    }

    private enum UnexecutedCommand {
        case unitAttention(SCSISense)
        case busy
        /// Not unexecuted, but safe to send again: see `resendsAfterLogicalUnitFailure`.
        case failedRead
    }

    /// A current unit attention, BUSY, or TASK SET FULL reports that the device didn't
    /// execute the command. Deferred errors and every other status describe an outcome; only
    /// a READ's logical unit failure is sent again all the same.
    private static func unexecuted(_ error: any Error, command: SCSICommand) -> UnexecutedCommand? {
        guard case ProtocolError.scsiFailure(let status, let data) = error else { return nil }
        if status == 0x08 || status == 0x28 { return .busy }
        guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred else {
            return nil
        }
        if sense.isUnitAttention { return .unitAttention(sense) }
        return resendsAfterLogicalUnitFailure(command, sense: sense) ? .failedRead : nil
    }

    /// A READ (10, 16) that the logical unit failed: a current HARDWARE ERROR, LOGICAL UNIT
    /// FAILURE (3Eh/01h). A Windows Server 2025 target answers the READ in flight with it when
    /// its service stops, then drops the connection (asynchronous event 3). A READ leaves the
    /// medium unchanged, so it is sent again. Nothing else is: a write or synchronization that
    /// failed this way stops the disk, and other hardware errors describe the outcome.
    static func resendsAfterLogicalUnitFailure(_ command: SCSICommand, sense: SCSISense) -> Bool {
        [UInt8(0x28), 0x88].contains(command.cdb[0]) && !sense.isDeferred && sense.key == 4
            && sense.additionalSenseCode == 0x3E && sense.qualifier == 0x01
    }

    /// Unit attentions after which the logical unit may not be the one that was opened:
    /// medium change (28h), reset or power on (29h), changed parameters or capacity (2Ah),
    /// and changed operating conditions, including reported LUNs (3Fh).
    private static func mayHaveChangedDevice(_ sense: SCSISense) -> Bool {
        [0x28, 0x29, 0x2A, 0x3F].contains(sense.additionalSenseCode)
    }

    static let unexecutedAttemptLimit = 3
    static let unexecutedRetryWindow = Duration.seconds(10)
    static let busyBackoff: [Duration] = [.milliseconds(500), .seconds(2)]

    /// Retry a command that the device reported as not executed, or a READ that its logical
    /// unit failed, at most three attempts within a bounded window. Every refusal keeps the
    /// original failure, so a caller that retains failures does so exactly as it would have
    /// without a retry. The window begins at the first refusal, not when the command was
    /// submitted: submission may have waited for a reconnection, or across sleep. It begins
    /// again after a revalidation or a reconnection, so asking a busy device whether it changed
    /// doesn't use it up. The attempts are counted across reconnections.
    ///
    /// The window and the pauses count awake time, as the recovery window does. A Mac that
    /// sleeps during a pause sends the command again when it wakes, waiting for the
    /// reconnection if the connection was lost, instead of finding the window over.
    ///
    /// A failed READ waits like BUSY before it is sent again. The connection a target drops
    /// right after failing it is lost by then, so the READ waits for the reconnection, as any
    /// command does, instead of reaching the old connection again.
    private func executeRetryingUnexecuted(
        _ command: SCSICommand, output: Data, tracking coverage: SynchronizationCoverage?,
        deviceChanged: (any Error) -> Void
    ) async throws -> SCSIResult {
        var window: (end: Duration, epoch: UInt64)?
        var attempt = 1
        while true {
            do {
                return try await connection.execute(command, output: output, tracking: coverage)
            } catch {
                guard attempt < Self.unexecutedAttemptLimit,
                    let condition = Self.unexecuted(error, command: command),
                    !Task.isCancelled, await connection.admitsCommands
                else { throw error }
                let epoch = await connection.epoch
                if window == nil || window?.epoch != epoch {
                    window = (retryClock.elapsed + Self.unexecutedRetryWindow, epoch)
                }
                switch condition {
                case .unitAttention(let sense):
                    if Self.mayHaveChangedDevice(sense) {
                        // Shared with every reconnection: the opening's own queries. A lost
                        // connection here is recovered, and the next login revalidates.
                        switch await connection.revalidateAfterAttention(sense, for: command) {
                        case .unchanged, .connectionLost: window = nil
                        case .changed:
                            deviceChanged(error)
                            throw error
                        case .unconfirmed: throw SessionRecoveryError.recoveryWindowExpired
                        }
                    }
                case .busy, .failedRead:
                    let end = window?.end ?? retryClock.elapsed
                    let wake = retryClock.elapsed + Self.busyBackoff[attempt - 1]
                    guard wake < end else { throw error }
                    do { try await retryClock.sleep(until: wake) } catch { throw error }
                }
                if let end = window?.end, retryClock.elapsed >= end { throw error }
                guard !Task.isCancelled, await connection.admitsCommands else { throw error }
                attempt += 1
            }
        }
    }
}
