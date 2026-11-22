import Foundation
import ISCSICore
import Network
import Synchronization

/// Awake time for the recovery window. Time spent asleep isn't counted, so an outage while
/// the Mac sleeps doesn't use up the window of I/O that resumes after it wakes.
public struct RecoveryClock: Sendable {
    private let readElapsed: @Sendable () -> Duration
    private let waitUntil: @Sendable (Duration) async throws -> Void

    init(
        elapsed: @escaping @Sendable () -> Duration,
        sleepUntil: @escaping @Sendable (Duration) async throws -> Void
    ) {
        readElapsed = elapsed
        waitUntil = sleepUntil
    }

    var elapsed: Duration { readElapsed() }

    func sleep(until instant: Duration) async throws { try await waitUntil(instant) }

    /// The system's awake time (`SuspendingClock`).
    public static var awake: Self {
        let clock = SuspendingClock()
        let origin = clock.now
        return Self(
            elapsed: { origin.duration(to: clock.now) },
            sleepUntil: { try await clock.sleep(until: origin.advanced(by: $0)) })
    }
}

/// Session recovery after a lost connection, modeled on ERL 0 initiators such as open-iscsi:
/// block I/O, log in again, revalidate the logical unit, then redo the outstanding command.
public enum SessionRecovery {
    /// How long one blocked command waits for a new session, in awake time, before it fails.
    /// This is the one tunable; `LUNVolumeFactory.open` accepts another value.
    public static let defaultRecoveryWindow = Duration.seconds(120)
    /// Waits between failed login attempts; the last value repeats without limit.
    static let backoff: [Duration] = [.seconds(2), .seconds(4), .seconds(8), .seconds(15)]
    /// A target can ask for a long Time2Wait. Waiting longer can't help blocked I/O.
    static let maximumInitialDelay = Duration.seconds(60)
    /// Each login attempt's deadline, clamped to the earliest blocked command's remaining window.
    static let connectionTimeout = Duration.seconds(45)
    static let minimumAttemptTimeout = Duration.seconds(1)
    /// A write callback is redone at most this many times when the epoch keeps changing.
    static let maximumRedoPasses = 8
    /// Waits before asking a busy or not-ready device again whether it is the one opened. The
    /// last value repeats until the asking command's recovery window ends.
    static let revalidationBackoff: [Duration] = [
        .milliseconds(500), .seconds(1), .seconds(2), .seconds(4),
    ]
    /// How long, in awake time since the first such rejection in an outage, a new login keeps
    /// retrying an authentication (0201h) or authorization (0202h) failure. The same credentials
    /// opened this disk; a target restoring its configuration (LIO restores a portal group
    /// before its ACLs and CHAP secrets) may reject them for a while. Then the disk stops.
    static let authorizationRetryLimit = Duration.seconds(30)
}

/// The write callback a command serves, if any, and whether it already sent data. A callback
/// that sent part of its data can't be reported as not having happened: if it fails now, the
/// medium may hold some of it.
final class WriteProgress: Sendable {
    private let state = Mutex(false)
    private let issued = Mutex<[UInt64]>([])
    var sent: Bool { state.withLock { $0 } }
    func markSent() { state.withLock { $0 = true } }
    /// The disk's generations (see `SynchronizationCoverage`) this callback sent, in order.
    var generations: [UInt64] { issued.withLock { $0 } }
    func note(_ generation: UInt64) { issued.withLock { $0.append(generation) } }

    @TaskLocal static var current: WriteProgress?

    /// Runs `body` as one write callback; a nested call joins the enclosing one.
    static func within<Value: Sendable>(_ body: () async throws -> Value) async throws -> Value {
        if current != nil { return try await body() }
        return try await $current.withValue(WriteProgress()) { try await body() }
    }
}

public enum SessionRecoveryError: Error, Sendable, Equatable {
    /// A blocked command waited for the whole recovery window.
    case recoveryWindowExpired
    /// Recovery was abandoned by an unmount, an unload, or an explicit request.
    case abandoned
    /// After logging in again, the logical unit no longer matched the one opened.
    case deviceChanged
    /// After logging in again, the target answered from another portal group.
    case portalGroupChanged
    /// A write kept spanning new connection epochs and couldn't be completed within one.
    case writeRedoLimitExceeded
    /// A write or synchronization was cancelled after it was sent, so whether the target
    /// applied it is unknown.
    case mutationInterrupted
}

extension SessionRecoveryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .recoveryWindowExpired: "The connection to the server couldn’t be restored in time."
        case .abandoned: "Reconnecting to the server was stopped."
        case .deviceChanged: "The disk on the server changed while reconnecting."
        case .portalGroupChanged: "The server answered from a different portal group."
        case .writeRedoLimitExceeded: "The connection kept dropping while saving changes."
        case .mutationInterrupted: "Saving changes to the server was interrupted."
        }
    }
}

/// What was observed when the logical unit was opened. After a new login, or a reset, I/O
/// resumes only while every captured field still matches.
public struct LogicalUnitFingerprint: Sendable, Equatable {
    public enum Designator: Sendable, Equatable {
        /// Not observed when opening; never compared.
        case notCaptured
        /// The device reported no usable logical-unit name; it must still report none.
        case absent
        /// Canonical VPD page 83h logical-unit names.
        case present(Data)
    }
    /// Nil when not observed when opening; never compared then.
    public let peripheralDeviceType: UInt8?
    public let capacity: DiskCapacity
    /// Nil when the device didn't report write protection; it must still report none.
    public let writeProtection: Bool?
    public let designator: Designator

    public init(information: DiskInformation, designator: Data?) {
        self.init(information: information, designator: designator.map { .present($0) } ?? .absent)
    }

    public init(information: DiskInformation, designator: Designator) {
        peripheralDeviceType = information.device.peripheralDeviceType
        capacity = information.capacity
        writeProtection = information.isWriteProtected
        self.designator = designator
    }

    /// Only the capacity and write protection, as a disk opened without the other fields.
    init(capacity: DiskCapacity, writeProtection: Bool?) {
        peripheralDeviceType = nil
        self.capacity = capacity
        self.writeProtection = writeProtection
        designator = .notCaptured
    }
}

/// Stands between RemoteDisk and single-use sessions. A session never reconnects; when one
/// fails with a lost connection, this actor logs in again with the same ISID (reinstating the
/// session), revalidates the logical unit, publishes the new session and its epoch together,
/// and only then lets the waiting command run again. Without a connector it simply forwards
/// to its one session, and a lost connection fails the disk as before.
public actor RecoveringSession {
    public enum Health: Sendable, Equatable { case unknown, ready, reconnecting, failed, closed }
    typealias Connect = @Sendable (_ timeout: Duration) async throws -> ISCSISession

    private enum Phase {
        case ready, reconnecting, closed
        case failed(any Error)
    }
    /// `unavailable` is a device that is busy, not ready yet, or briefly not presenting the
    /// logical unit, or a lost connection: ask again. `failed` is any other error, which stops
    /// the disk with that error. Only a mismatch is `changed`.
    enum Revalidation: Sendable {
        case matches, changed, unavailable
        case failed(any Error)
    }
    /// `unconfirmed`: the device kept answering busy or not ready for the whole recovery window.
    enum AttentionOutcome: Sendable, Equatable {
        case unchanged, changed, connectionLost, unconfirmed
    }
    private enum Attempt {
        case adopted, retry
        case failStop(any Error)
    }
    private struct Waiter {
        let continuation: CheckedContinuation<Void, any Error>
        let deadline: Duration
    }

    public nonisolated let lun: LogicalUnit
    public nonisolated let fingerprint: LogicalUnitFingerprint
    nonisolated let initialSession: ISCSISession
    nonisolated let clock: RecoveryClock
    nonisolated let recoveryWindow: Duration
    private let connect: Connect?
    private var portalGroupTag: UInt16?
    private var current: ISCSISession
    private var currentToken = UUID()
    private var pending: UUID?
    private var pendingFailed = false
    private var phase = Phase.ready
    private var recovery: Task<Void, Never>?
    private var waiters: [UUID: Waiter] = [:]
    private var abandoned = false
    /// The pause between attempts to revalidate after a unit attention, so a close wakes it.
    private var attentionPause: Task<Void, any Error>?
    /// A unit attention's revalidation is running: the device isn't confirmed yet.
    private var revalidatingAttention = false
    /// One outage, from a lost connection until a session is adopted again.
    private struct Outage {
        /// When its recovery window began: when its first command started to wait.
        var windowStart: Duration?
        /// A command waited for the whole window. Later commands fail at once, until a
        /// session is adopted again, instead of each waiting a window of its own.
        var windowExpired = false
        /// The first authentication or authorization rejection while logging in again.
        var firstAuthorizationRejection: Duration?
    }
    private var outage = Outage()
    /// Increases after every adopted login and every reset unit attention (29h). Data that
    /// wasn't synchronized within one epoch may have been lost with the target's cache.
    public private(set) var epoch: UInt64 = 0
    private(set) var loginAttempts = 0
    private var runningRecoveries = 0
    var waitingCount: Int { waiters.count }
    var isRecovering: Bool { recovery != nil }
    /// A cancelled recovery task may still be finishing an attempt.
    var isRecoveryTaskRunning: Bool { runningRecoveries > 0 }

    /// A single session that is never replaced. A lost connection fails the disk.
    init(session: ISCSISession, lun: LogicalUnit, fingerprint: LogicalUnitFingerprint) {
        initialSession = session
        current = session
        self.lun = lun
        self.fingerprint = fingerprint
        clock = .awake
        recoveryWindow = SessionRecovery.defaultRecoveryWindow
        connect = nil
    }

    init(
        session: ISCSISession, lun: LogicalUnit, fingerprint: LogicalUnitFingerprint,
        recoveryWindow: Duration, clock: RecoveryClock, connect: @escaping Connect
    ) {
        initialSession = session
        current = session
        self.lun = lun
        self.fingerprint = fingerprint
        self.clock = clock
        self.recoveryWindow = recoveryWindow
        self.connect = connect
    }

    /// Recovers `session` after a lost connection. `connect` logs in again with the opening
    /// configuration and returns a ready session; its argument is that attempt's deadline.
    public static func recovering(
        session: ISCSISession, lun: LogicalUnit, fingerprint: LogicalUnitFingerprint,
        recoveryWindow: Duration = SessionRecovery.defaultRecoveryWindow,
        connect: @escaping @Sendable (_ timeout: Duration) async throws -> ISCSISession
    ) async throws -> RecoveringSession {
        try await recovering(
            session: session, lun: lun, fingerprint: fingerprint,
            recoveryWindow: recoveryWindow, clock: .awake, connect: connect)
    }

    static func recovering(
        session: ISCSISession, lun: LogicalUnit, fingerprint: LogicalUnitFingerprint,
        recoveryWindow: Duration, clock: RecoveryClock, connect: @escaping Connect
    ) async throws -> RecoveringSession {
        guard recoveryWindow > .zero, recoveryWindow <= .seconds(3600) else {
            throw ProtocolError.malformed("recovery window")
        }
        let recovering = RecoveringSession(
            session: session, lun: lun, fingerprint: fingerprint,
            recoveryWindow: recoveryWindow, clock: clock, connect: connect)
        await recovering.start()
        return recovering
    }

    private func start() async {
        portalGroupTag = await current.targetPortalGroupTag
        await watch(current, token: currentToken)
    }

    // MARK: Commands

    var admitsCommands: Bool {
        get async {
            guard connect != nil else {
                if case .failed = phase { return false }
                return await current.state == .ready
            }
            switch phase {
            case .ready, .reconnecting: return true
            case .failed, .closed: return false
            }
        }
    }

    /// Throws what a command would fail with at once without sending it: the failure that
    /// stopped the disk, or `abandoned` once closed, exactly as `execute` would. A disk that
    /// is reconnecting admits it. Without a connector, `admitsCommands` alone decides.
    func checkAdmission() throws {
        guard connect != nil else { return }
        switch phase {
        case .ready, .reconnecting: return
        case .failed(let error): throw error
        case .closed: throw SessionRecoveryError.abandoned
        }
    }

    /// Runs the command on the current session. After a lost connection the same command
    /// waits, up to the recovery window, for a revalidated session and is then issued again.
    func execute(
        _ command: SCSICommand, output: Data = Data(),
        tracking coverage: SynchronizationCoverage? = nil
    ) async throws -> SCSIResult {
        guard connect != nil else {
            if case .failed(let error) = phase { throw error }
            return try await executeAdmitted(
                command, output: output, on: current, epoch: epoch, tracking: coverage)
        }
        let mutating = command.direction == .write || [UInt8(0x35), 0x91].contains(command.cdb[0])
        let progress = WriteProgress.current
        while true {
            let (session, admittedEpoch) = try await admittedSession(
                mutating: mutating, progress: progress)
            // From here the target may receive the data, whatever this call reports.
            if command.direction == .write { progress?.markSent() }
            do {
                return try await executeAdmitted(
                    command, output: output, on: session, epoch: admittedEpoch, tracking: coverage)
            } catch {
                if Task.isCancelled {
                    // A cancelled write or synchronization, or any command of a write callback
                    // that already sent data, may have changed the medium in part. Its caller
                    // is told that it failed; never resume silently. Later I/O sees the latch.
                    if mutating || progress?.sent == true {
                        let ended = await session.state != .ready
                        if error is CancellationError || ended {
                            failStop(SessionRecoveryError.mutationInterrupted)
                        }
                    }
                    throw error
                }
                if case ProtocolError.scsiFailure(let status, let data) = error {
                    // A status describes this command, even when the session ended just after
                    // it, such as with a target's request to log out. Deliver it and never
                    // send the command again blindly. A deferred error may report data
                    // already lost; a session ending that way would not retire itself.
                    if status == 2, let sense = try? SCSISense(data: data), sense.isDeferred {
                        failStop(error)
                    } else if await session.state != .ready {
                        await noteTermination(of: session)
                    }
                    throw error
                }
                // Anything else on a usable session is reported as before.
                guard await session.state != .ready else { throw error }
                await noteTermination(of: session)
                switch phase {
                case .failed, .closed: throw error
                case .ready, .reconnecting: continue
                }
            }
        }
    }

    private func executeAdmitted(
        _ command: SCSICommand, output: Data, on session: ISCSISession, epoch: UInt64,
        tracking coverage: SynchronizationCoverage?
    ) async throws -> SCSIResult {
        // Admission may wait across a reconnect, or be cancelled without issuing a command.
        // Attribute each attempt to the session that can actually receive it.
        let generation = coverage?.beginMutation(epoch: epoch)
        if let generation { WriteProgress.current?.note(generation) }
        defer { if let generation { coverage?.endMutation(generation) } }
        return try await session.execute(command, lun: lun, output: output)
    }

    private func admittedSession(mutating: Bool, progress: WriteProgress?) async throws
        -> (ISCSISession, UInt64)
    {
        while true {
            if Task.isCancelled {
                if progress?.sent == true { failStop(SessionRecoveryError.mutationInterrupted) }
                throw CancellationError()
            }
            switch phase {
            case .ready: return (current, epoch)
            case .failed(let error): throw error
            case .closed: throw SessionRecoveryError.abandoned
            case .reconnecting:
                do {
                    try await waitForSession()
                } catch SessionRecoveryError.recoveryWindowExpired {
                    // The inner file system is told a write failed. Its data may be gone, so
                    // no later write may be admitted. A read just fails; recovery continues.
                    if mutating || progress != nil {
                        failStop(SessionRecoveryError.recoveryWindowExpired)
                    }
                    throw SessionRecoveryError.recoveryWindowExpired
                } catch is CancellationError {
                    // Like a cancelled write in flight: part of this callback was sent.
                    if progress?.sent == true {
                        failStop(SessionRecoveryError.mutationInterrupted)
                    }
                    throw CancellationError()
                }
            }
        }
    }

    /// Waits until the outage's window ends, which began when its first command waited.
    private func waitForSession() async throws {
        guard !outage.windowExpired else { throw SessionRecoveryError.recoveryWindowExpired }
        let start = outage.windowStart ?? clock.elapsed
        outage.windowStart = start
        let deadline = start + recoveryWindow
        guard clock.elapsed < deadline else {
            outage.windowExpired = true
            throw SessionRecoveryError.recoveryWindowExpired
        }
        let id = UUID()
        let clock = clock
        let timer = Task { [weak self] in
            do { try await clock.sleep(until: deadline) } catch { return }
            await self?.expireWaiter(id)
        }
        defer { timer.cancel() }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiters[id] = Waiter(continuation: continuation, deadline: deadline)
                }
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    private func expireWaiter(_ id: UUID) {
        guard let waiter = waiters.removeValue(forKey: id) else { return }
        outage.windowExpired = true
        waiter.continuation.resume(throwing: SessionRecoveryError.recoveryWindowExpired)
    }

    private func cancelWaiter(_ id: UUID) {
        waiters.removeValue(forKey: id)?.continuation.resume(throwing: CancellationError())
    }

    private func resumeWaiters(throwing error: (any Error)?) {
        let resumed = waiters.values
        waiters.removeAll()
        for waiter in resumed {
            if let error {
                waiter.continuation.resume(throwing: error)
            } else {
                waiter.continuation.resume()
            }
        }
    }

    // MARK: State

    public func health() async -> Health {
        guard connect != nil else {
            switch phase {
            case .closed: return .closed
            case .failed: return .failed
            case .ready, .reconnecting: break
            }
            switch await current.state {
            case .ready: return .ready
            case .closing, .failed: return .failed
            case .closed: return .closed
            case .disconnected, .loggingIn: return .unknown
            }
        }
        if case .ready = phase {
            let session = current
            // A termination may not have been reported yet.
            if await session.state != .ready { await noteTermination(of: session) }
        }
        switch phase {
        case .ready: return .ready
        case .reconnecting: return .reconnecting
        case .failed: return .failed
        case .closed: return .closed
        }
    }

    /// Stops all I/O: waiting and later commands fail with `error`, and no login is attempted.
    func failStop(_ error: any Error) {
        switch phase {
        case .failed, .closed: return
        case .ready, .reconnecting: break
        }
        phase = .failed(error)
        recovery?.cancel()
        recovery = nil
        attentionPause?.cancel()
        resumeWaiters(throwing: error)
    }

    /// Stops reconnecting, now and after any later lost connection. Waiting I/O fails at once.
    /// A healthy session keeps working until it fails.
    public func abandon() {
        abandoned = true
        if case .reconnecting = phase { failStop(SessionRecoveryError.abandoned) }
        // A device still being asked whether it is the one opened mustn't receive the waiting
        // command after all; it would have to be confirmed first.
        if revalidatingAttention { failStop(SessionRecoveryError.abandoned) }
    }

    /// Abandons recovery, fails waiting I/O, and ends the current session, gracefully if ready.
    public func close() async {
        if case .closed = phase { return }
        phase = .closed
        abandoned = true
        recovery?.cancel()
        recovery = nil
        attentionPause?.cancel()
        resumeWaiters(throwing: SessionRecoveryError.abandoned)
        _ = await current.closeGracefully()
    }

    // MARK: Revalidation

    /// Compares the logical unit with the one opened, using the opening's own queries. The
    /// raw device statuses are classified here, not the opening's own diagnosis of them.
    static func revalidate(
        _ session: ISCSISession, lun: LogicalUnit, against expected: LogicalUnitFingerprint
    ) async -> Revalidation {
        do {
            if let type = expected.peripheralDeviceType {
                let inquiry = try SCSIInquiry(
                    data: try await DiskProbe.readOnly(.inquiry(), session: session, lun: lun).data)
                // A target restoring its configuration may not present the logical unit yet.
                guard inquiry.peripheralQualifier == 0 else { return .unavailable }
                guard inquiry.peripheralDeviceType == type, inquiry.responseDataFormat == 2 else {
                    return .changed
                }
            }
            guard try await DiskProbe.capacity(session: session, lun: lun) == expected.capacity,
                try await DiskProbe.writeProtection(session: session, lun: lun)
                    == expected.writeProtection
            else { return .changed }
            let names: Data?
            switch expected.designator {
            case .notCaptured: return .matches
            case .absent: names = nil
            case .present(let expected): names = expected
            }
            do {
                guard try await DiskProbe.logicalUnitDesignator(session: session, lun: lun) == names
                else { return .changed }
            } catch is DiskProbeIssue {
                // The device matched; only its names are unknown for now. Ask again later.
                return .unavailable
            }
            return .matches
        } catch {
            guard await session.state == .ready else { return .unavailable }
            return isTransient(error) ? .unavailable : .failed(error)
        }
    }

    /// A device that is busy, not ready yet, reporting another unit attention, or aborting
    /// the query, or a logical unit briefly not supported, while a target restores its
    /// configuration. None of these shows that the device changed.
    static func isTransient(_ error: any Error) -> Bool {
        if let issue = error as? DiskProbeIssue {
            switch issue {
            case .notReady, .unavailable: return true
            case .commandFailed(let status): return status == 0x08 || status == 0x28
            default: return false
            }
        }
        guard case ProtocolError.scsiFailure(let status, let data) = error else { return false }
        if status == 0x08 || status == 0x28 { return true }
        guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred else {
            return false
        }
        switch sense.key {
        case 2, 6, 0x0B: return true
        case 5: return sense.additionalSenseCode == 0x25
        default: return false
        }
    }

    /// Called under RemoteDisk's gate after a unit attention reporting that the device may
    /// have changed, before `command` is sent again. A busy or not-ready device is asked again
    /// until the recovery window ends. Every match begins a new epoch: a reset's own 29h may
    /// have been consumed by these queries after another attention, and the cache with it.
    func revalidateAfterAttention(_ sense: SCSISense, for command: SCSICommand) async
        -> AttentionOutcome
    {
        let mutating = command.direction == .write || [UInt8(0x35), 0x91].contains(command.cdb[0])
        let started = clock.elapsed
        var attempts = 0
        revalidatingAttention = true
        defer { revalidatingAttention = false }
        // A stop or close while asking again ends in a phase that admits no command, so
        // RemoteDisk reports `connectionLost` as the original failure; it never sends again.
        while true {
            guard case .ready = phase else { return .connectionLost }
            let session = current
            let outcome = await Self.revalidate(session, lun: lun, against: fingerprint)
            guard case .ready = phase, session === current else { return .connectionLost }
            switch outcome {
            case .matches:
                epoch &+= 1
                return .unchanged
            case .changed:
                // RemoteDisk latches its incident; never log in again to another device.
                if connect != nil { failStop(SessionRecoveryError.deviceChanged) }
                return .changed
            case .failed(let error):
                if connect != nil { failStop(error) }
                return .changed
            case .unavailable:
                guard await session.state == .ready else {
                    // A lost connection is recovered, and the next login revalidates.
                    guard connect != nil else { return .changed }
                    await noteTermination(of: session)
                    return .connectionLost
                }
                let wait = SessionRecovery.revalidationBackoff[
                    min(attempts, SessionRecovery.revalidationBackoff.count - 1)]
                guard clock.elapsed + wait < started + recoveryWindow else {
                    return unconfirmed(session, mutating: mutating)
                }
                do {
                    try await pause(until: clock.elapsed + wait)
                } catch {
                    return .connectionLost
                }
                attempts += 1
            }
        }
    }

    /// The device couldn't be confirmed within the window. No command may reach it unchecked:
    /// a write or synchronization latches the disk, as when a reconnection takes too long; a
    /// read fails, and the session is replaced through a new, revalidated login.
    private func unconfirmed(_ session: ISCSISession, mutating: Bool) -> AttentionOutcome {
        guard connect != nil, !abandoned, !mutating, WriteProgress.current == nil else {
            failStop(SessionRecoveryError.recoveryWindowExpired)
            return .unconfirmed
        }
        handleTermination(of: session, reason: ProtocolError.connectionClosed)
        return .unconfirmed
    }

    /// Sleeps until `instant`. A close or a stop wakes it with an error, as does cancellation.
    private func pause(until instant: Duration) async throws {
        let clock = clock
        let pause = Task { try await clock.sleep(until: instant) }
        attentionPause = pause
        defer { if attentionPause == pause { attentionPause = nil } }
        try await withTaskCancellationHandler {
            try await pause.value
        } onCancel: {
            pause.cancel()
        }
    }

    // MARK: Recovery

    private enum Disposition { case reconnect, failStop }

    /// Only a lost connection is recovered. Device statuses (including a deferred error, which
    /// may report data already lost), protocol violations and other events stop the disk.
    private static func disposition(ofTermination reason: any Error) -> Disposition {
        switch reason {
        case is CancellationError: return .reconnect
        case let error as ProtocolError:
            switch error {
            case .connectionClosed, .timedOut, .digestMismatch: return .reconnect
            // Requested logout, dropped connection, dropped connections.
            case .targetEvent(let event): return (1...3).contains(event) ? .reconnect : .failStop
            default: return .failStop
            }
        case let error as NWError:
            if case .tls = error { return .failStop }
            return .reconnect
        default:
            // Only a transport produces errors outside the protocol's own types.
            return .reconnect
        }
    }

    private static func disposition(ofLogin error: any Error) -> Attempt {
        switch error {
        case let error as ProtocolError:
            switch error {
            case .connectionClosed, .timedOut, .localNetworkAccessRequired, .digestMismatch,
                .targetEvent:
                return .retry
            case .loginRejected(let statusClass, let detail):
                // Class 3: target error, service unavailable, out of resources. 0203, target
                // not found, is common while a target service restores its configuration.
                // Every other initiator error won't change by retrying. 0201 and 0202 are
                // retried for a limited time before reaching here; see `attempt`.
                return statusClass == 3 || (statusClass == 2 && detail == 3)
                    ? .retry : .failStop(error)
            default:
                // A failed mutual proof, a different portal group, malformed or unsupported
                // responses, and redirect limits.
                return .failStop(error)
            }
        case let error as NWError:
            if case .tls = error { return .failStop(error) }
            return .retry
        default:
            // Refused or unreachable connections, DNS and network-down errors after a wake.
            return .retry
        }
    }

    private func watch(_ session: ISCSISession, token: UUID) async {
        await session.setTerminationHandler { [weak self] reason in
            Task { await self?.sessionTerminated(token: token, reason: reason) }
        }
    }

    private func sessionTerminated(token: UUID, reason: any Error) {
        if token == pending {
            pendingFailed = true
            return
        }
        guard token == currentToken else { return }
        handleTermination(of: current, reason: reason)
    }

    private func noteTermination(of session: ISCSISession) async {
        guard case .ready = phase, session === current else { return }
        let state = await session.state
        let recorded = await session.terminationReason
        switch state {
        case .ready, .disconnected, .loggingIn: return
        case .closing: handleTermination(of: session, reason: ProtocolError.targetEvent(1))
        case .failed, .closed:
            handleTermination(of: session, reason: recorded ?? ProtocolError.connectionClosed)
        }
    }

    private func handleTermination(of session: ISCSISession, reason: any Error) {
        guard case .ready = phase, session === current else { return }
        guard !abandoned, let connect, Self.disposition(ofTermination: reason) == .reconnect
        else {
            failStop(reason)
            return
        }
        phase = .reconnecting
        outage = Outage()
        recovery = Task { [weak self] in
            await self?.recover(from: session, connect: connect)
        }
    }

    private var isReconnecting: Bool {
        if case .reconnecting = phase { return !Task.isCancelled }
        return false
    }

    private func recover(from old: ISCSISession, connect: Connect) async {
        runningRecoveries += 1
        defer { runningRecoveries -= 1 }
        // No task management function (LOGICAL UNIT RESET, ABORT TASK SET) is sent for a
        // command that timed out or was cut off. This relies on RFC 7143 session reinstatement
        // (section 6.3.5): the new login reuses this ISID with a TSIH of 0, so the target
        // implicitly logs out the old session and terminates its tasks before the new session
        // runs any command. A command of the old session therefore can't complete after one
        // sent again on the new session.
        // Wait out a target-requested Logout; otherwise this just closes the old transport.
        _ = await old.closeGracefully()
        var delay = min(await old.reconnectionDelay, SessionRecovery.maximumInitialDelay)
        var failures = 0
        while isReconnecting {
            if delay > .zero {
                do { try await clock.sleep(until: clock.elapsed + delay) } catch { return }
                guard isReconnecting else { return }
            }
            loginAttempts += 1
            switch await attempt(connect) {
            case .adopted: return
            case .retry: break
            case .failStop(let error):
                failStop(error)
                return
            }
            delay = SessionRecovery.backoff[min(failures, SessionRecovery.backoff.count - 1)]
            failures += 1
        }
    }

    private func attemptTimeout() -> Duration {
        guard let earliest = waiters.values.map(\.deadline).min() else {
            return SessionRecovery.connectionTimeout
        }
        let remaining = earliest - clock.elapsed
        return min(
            SessionRecovery.connectionTimeout, max(SessionRecovery.minimumAttemptTimeout, remaining)
        )
    }

    private func attempt(_ connect: Connect) async -> Attempt {
        let session: ISCSISession
        do {
            session = try await connect(attemptTimeout())
        } catch {
            if case ProtocolError.loginRejected(let statusClass, let detail) = error,
                statusClass == 2, detail == 1 || detail == 2
            {
                // The credentials that opened this disk, during a configuration restore.
                let now = clock.elapsed
                let first = outage.firstAuthorizationRejection ?? now
                outage.firstAuthorizationRejection = first
                return now - first < SessionRecovery.authorizationRetryLimit
                    ? .retry : .failStop(error)
            }
            return Self.disposition(ofLogin: error)
        }
        guard isReconnecting else {
            await session.close()
            return .retry
        }
        let token = UUID()
        pending = token
        pendingFailed = false
        defer { if pending == token { pending = nil } }
        await watch(session, token: token)
        // Redirect destinations carry no expected tag; compare with the first login here.
        if let portalGroupTag, await session.targetPortalGroupTag != portalGroupTag {
            _ = await session.closeGracefully()
            return .failStop(SessionRecoveryError.portalGroupChanged)
        }
        let revalidation = await Self.revalidate(session, lun: lun, against: fingerprint)
        guard isReconnecting else {
            await session.close()
            return .retry
        }
        switch revalidation {
        case .matches: break
        case .changed:
            _ = await session.closeGracefully()
            return .failStop(SessionRecoveryError.deviceChanged)
        case .unavailable:
            _ = await session.closeGracefully()
            return .retry
        case .failed(let error):
            _ = await session.closeGracefully()
            return .failStop(error)
        }
        let ready = await session.state == .ready
        guard isReconnecting, ready, !pendingFailed else {
            await session.close()
            return .retry
        }
        // Publish the revalidated session and its new epoch in one actor turn, then release
        // the waiting commands. No command reaches the new session before this point.
        current = session
        currentToken = token
        pending = nil
        epoch &+= 1
        phase = .ready
        outage = Outage()
        recovery = nil
        resumeWaiters(throwing: nil)
        return .adopted
    }
}
