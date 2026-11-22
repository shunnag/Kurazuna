import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSINetwork

private func timerPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(5))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(1))
    }
}

private func manualTimer(_ time: ManualSessionTime) -> DeadlineTimer {
    let source = time.source
    return DeadlineTimer(now: { source.now }, sleep: { try await source.sleep(until: $0) })
}

private enum WaitOutcome: Equatable { case expired, cancelled }

private func outcome(of wait: Task<Void, any Error>) async -> WaitOutcome? {
    do {
        try await wait.value
        return .expired
    } catch is CancellationError {
        return .cancelled
    } catch {
        return nil
    }
}

@Test func cancelledWaitsLeaveNoEntriesAndShareOneUnderlyingSleep() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    for step in 0..<2_000 {
        let deadline = time.now.advanced(by: .seconds(30))
        let wait = Task { try await timer.sleep(until: deadline) }
        var spins = 0
        while timer.pendingCount == 0 {
            spins += 1
            try #require(spins < 1_000_000)
            await Task.yield()
        }
        wait.cancel()
        #expect(await outcome(of: wait) == .cancelled)
        #expect(timer.pendingCount == 0)
        // Each later wait has a later deadline, like successive commands.
        if step % 100 == 0 { time.advance(by: .milliseconds(1)) }
    }
    #expect(timer.underlyingSleeps == 1)
    // The driver registers its underlying sleep from its own task.
    try await timerPhase { time.pendingCount == 1 }
    timer.releaseWhenIdle()
    #expect(!timer.isArmed)
    try await timerPhase { time.pendingCount == 0 }
}

@Test func dueWaitsResumeAtTheirDeadlinesAndTheDriverRearms() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let first = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(10))) }
    try await timerPhase { timer.pendingCount == 1 }
    let second = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(20))) }
    try await timerPhase { timer.pendingCount == 2 && time.hasSleeper(after: .seconds(10)) }
    #expect(!time.hasSleeper(after: .seconds(20)))
    time.advance(by: .seconds(10), wakeTimers: true)
    #expect(await outcome(of: first) == .expired)
    try await timerPhase { time.hasSleeper(after: .seconds(20)) }
    #expect(timer.pendingCount == 1)
    time.advance(by: .milliseconds(9_999), wakeTimers: true)
    #expect(timer.pendingCount == 1)
    time.advance(by: .milliseconds(1), wakeTimers: true)
    #expect(await outcome(of: second) == .expired)
    try await timerPhase { !timer.isArmed }
    #expect(timer.pendingCount == 0)
    #expect(time.pendingCount == 0)
    #expect(timer.underlyingSleeps == 2)
}

@Test func onlyAnEarlierDeadlineReplacesTheUnderlyingSleep() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let late = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(30))) }
    try await timerPhase { time.hasSleeper(after: .seconds(30)) }
    let later = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(31))) }
    try await timerPhase { timer.pendingCount == 2 }
    #expect(timer.underlyingSleeps == 1)
    let early = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(5))) }
    try await timerPhase {
        time.hasSleeper(after: .seconds(5)) && !time.hasSleeper(after: .seconds(30))
    }
    time.advance(by: .seconds(5), wakeTimers: true)
    #expect(await outcome(of: early) == .expired)
    try await timerPhase { time.hasSleeper(after: .seconds(30)) }
    time.advance(by: .seconds(26), wakeTimers: true)
    #expect(await outcome(of: late) == .expired)
    #expect(await outcome(of: later) == .expired)
    try await timerPhase { !timer.isArmed && time.pendingCount == 0 }
    #expect(timer.underlyingSleeps == 3)
}

@Test func dueAndCancelledWaitsReturnWithoutArming() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    try await timer.sleep(until: time.now)
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await timer.sleep(until: time.now.advanced(by: .seconds(30)))
    }
    #expect(await outcome(of: cancelled) == .cancelled)
    // Cancellation still wins over a deadline that has already passed.
    let late = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await timer.sleep(until: time.initial)
    }
    #expect(await outcome(of: late) == .cancelled)
    #expect(timer.underlyingSleeps == 0)
    #expect(!timer.isArmed)
    #expect(time.pendingCount == 0)
}

@Test func racingCancellationAndExpiryResumeEachWaitExactlyOnce() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    for _ in 0..<200 {
        let deadline = time.now.advanced(by: .seconds(1))
        let waits = (0..<8).map { _ in Task { try await timer.sleep(until: deadline) } }
        try await timerPhase { timer.pendingCount == 8 && time.pendingCount == 1 }
        // Expiry and completion (cancellation of the wait) arrive together.
        async let expiry: Void = time.advance(by: .seconds(1), wakeTimers: true)
        for (index, wait) in waits.enumerated() where index % 2 == 0 { wait.cancel() }
        await expiry
        var outcomes: [WaitOutcome] = []
        for (index, wait) in waits.enumerated() {
            let result = try #require(await outcome(of: wait))
            // A wait that was not cancelled can only have expired.
            if index % 2 == 1 { #expect(result == .expired) }
            outcomes.append(result)
        }
        #expect(outcomes.count == 8)
        #expect(timer.pendingCount == 0)
    }
    try await timerPhase { !timer.isArmed && time.pendingCount == 0 }
}

@Test func releasingTheTimerWaitsForPendingWaitsAndAllowsLaterOnes() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let wait = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(30))) }
    try await timerPhase { timer.pendingCount == 1 && time.pendingCount == 1 }
    timer.releaseWhenIdle()
    #expect(timer.isArmed)
    #expect(time.pendingCount == 1)
    wait.cancel()
    #expect(await outcome(of: wait) == .cancelled)
    #expect(!timer.isArmed)
    try await timerPhase { time.pendingCount == 0 }
    let next = Task { try await timer.sleep(until: time.initial.advanced(by: .seconds(5))) }
    try await timerPhase { time.hasSleeper(after: .seconds(5)) }
    time.advance(by: .seconds(5), wakeTimers: true)
    #expect(await outcome(of: next) == .expired)
}

/// How each wait ended and the measured instant it ended at. Waiting on `count` with a bound
/// turns a lost wake-up into a failure instead of a hang; resuming one continuation twice
/// traps in `CheckedContinuation`.
private final class WaitLog: Sendable {
    struct Entry {
        let index: Int
        let outcome: WaitOutcome?
        let instant: ContinuousClock.Instant
    }
    private let recorded = Mutex<[Entry]>([])
    var count: Int { recorded.withLock { $0.count } }
    var entries: [Entry] { recorded.withLock { $0 } }

    func record(_ entry: Entry) { recorded.withLock { $0.append(entry) } }
}

/// `timerPhase` for many short phases in a row: it yields between checks instead of sleeping.
private func spinPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(5))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

/// Starts one wait per offset from `time.initial`. The first offset must be the earliest:
/// the others start only once its driver sleeps, so none of them replaces that driver.
private func startWaits(
    _ offsets: [Duration], on timer: DeadlineTimer, _ time: ManualSessionTime, log: WaitLog
) async throws -> [Task<Void, Never>] {
    let earliest = try #require(offsets.first)
    try #require(offsets.dropFirst().allSatisfy { $0 > earliest })
    func start(_ index: Int) -> Task<Void, Never> {
        let deadline = time.initial.advanced(by: offsets[index])
        return Task {
            var outcome: WaitOutcome?
            do {
                try await timer.sleep(until: deadline)
                outcome = .expired
            } catch is CancellationError {
                outcome = .cancelled
            } catch {}
            log.record(WaitLog.Entry(index: index, outcome: outcome, instant: timer.now))
        }
    }
    // Task creation alone does not order registration, so the earliest wait registers alone.
    let first = start(0)
    try await spinPhase { timer.pendingCount == 1 && time.hasSleeper(after: earliest) }
    let waits = [first] + offsets.indices.dropFirst().map(start)
    try await spinPhase { timer.pendingCount == offsets.count }
    return waits
}

/// A system sleep: on wake the continuous clock has passed every pending deadline at once.
@Test func aSleepPastManyDeadlinesResumesEveryWaitOnceFromOneUnderlyingSleep() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let log = WaitLog()
    // 1,000 deadlines spread over the first minute.
    let offsets = (1...1_000).map { Duration.milliseconds(60 * $0) }
    let waits = try await startWaits(offsets, on: timer, time, log: log)
    #expect(timer.underlyingSleeps == 1)
    #expect(log.count == 0)
    time.advance(by: .seconds(3_600), wakeTimers: true)
    try await timerPhase { log.count == offsets.count }
    for wait in waits { await wait.value }
    let entries = log.entries
    #expect(entries.count == offsets.count)
    #expect(Set(entries.map(\.index)) == Set(offsets.indices))
    let woke = time.initial.advanced(by: .seconds(3_600))
    #expect(entries.allSatisfy { $0.outcome == .expired && $0.instant == woke })
    #expect(timer.pendingCount == 0)
    #expect(!timer.isArmed)
    #expect(time.pendingCount == 0)
    // The driver resumed the whole batch from its one sleep and had nothing left to re-arm.
    #expect(timer.underlyingSleeps == 1)
}

@Test func waitsStillAheadAfterASleepResumeLaterAtTheirOwnDeadlines() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let log = WaitLog()
    let overdue = (1...300).map { Duration.milliseconds(200 * $0) }
    let groupA = Array(repeating: Duration.seconds(3_630), count: 100)
    let groupB = Array(repeating: Duration.seconds(3_660), count: 100)
    // Exactly at the instant the sleep ends (due) and one millisecond after it (not due).
    let atWake = Duration.seconds(3_600)
    let afterWake = atWake + .milliseconds(1)
    let offsets = overdue + [atWake, afterWake] + groupA + groupB
    let waits = try await startWaits(offsets, on: timer, time, log: log)
    #expect(timer.underlyingSleeps == 1)

    time.advance(by: atWake, wakeTimers: true)
    let due = overdue.count + 1
    // The driver re-arms for the earliest remaining deadline under the lock it resumes from.
    try await timerPhase { log.count == due && time.hasSleeper(after: afterWake) }
    #expect(time.pendingCount == 1)
    #expect(timer.isArmed)
    #expect(timer.pendingCount == offsets.count - due)
    #expect(timer.underlyingSleeps == 2)

    time.advance(by: .milliseconds(1), wakeTimers: true)
    try await timerPhase { log.count == due + 1 && time.hasSleeper(after: .seconds(3_630)) }
    #expect(timer.pendingCount == groupA.count + groupB.count)
    // Short of the next deadline nothing more is delivered.
    time.advance(by: .milliseconds(29_998), wakeTimers: true)
    #expect(time.hasSleeper(after: .seconds(3_630)))
    #expect(timer.pendingCount == groupA.count + groupB.count)
    time.advance(by: .milliseconds(1), wakeTimers: true)
    try await timerPhase {
        log.count == due + 1 + groupA.count && time.hasSleeper(after: .seconds(3_660))
    }
    #expect(timer.pendingCount == groupB.count)
    time.advance(by: .seconds(30), wakeTimers: true)
    try await timerPhase { log.count == offsets.count }
    for wait in waits { await wait.value }

    let entries = log.entries
    #expect(Set(entries.map(\.index)) == Set(offsets.indices))
    for entry in entries {
        // Overdue waits end when the sleep ends; the others exactly at their own deadlines.
        let expected = time.initial.advanced(by: max(offsets[entry.index], atWake))
        #expect(entry.outcome == .expired, "wait \(entry.index)")
        #expect(entry.instant == expected, "wait \(entry.index)")
    }
    #expect(timer.pendingCount == 0)
    #expect(!timer.isArmed)
    #expect(time.pendingCount == 0)
    #expect(timer.underlyingSleeps == 4)
}

@Test func cancellingWaitsWhileASleepIsDeliveredResumesEachWaitOnce() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let rounds = 200
    for round in 0..<rounds {
        let log = WaitLog()
        let base = time.initial.duration(to: time.now)
        let offsets = (0..<32).map { base + .milliseconds(1 + 1_875 * $0) }
        let waits = try await startWaits(offsets, on: timer, time, log: log)
        // A different two thirds each round, the earliest wait included in some rounds.
        let cancelled = offsets.indices.filter { ($0 + round) % 3 != 0 }
        func cancelSubset() { for index in cancelled { waits[index].cancel() } }
        // The jump and the cancellations run on separate tasks, each side starting first in
        // turn; otherwise the cancellations mostly end before the driver's batch begins.
        if round % 2 == 0 {
            async let expiry: Void = time.advance(by: .seconds(3_600), wakeTimers: true)
            cancelSubset()
            await expiry
        } else {
            async let cancelling: Void = cancelSubset()
            time.advance(by: .seconds(3_600), wakeTimers: true)
            await cancelling
        }
        try await spinPhase { log.count == offsets.count }
        for wait in waits { await wait.value }
        let entries = log.entries
        #expect(Set(entries.map(\.index)) == Set(offsets.indices), "round \(round)")
        for entry in entries {
            let outcome = try #require(entry.outcome, "round \(round) wait \(entry.index)")
            // A wait that was not cancelled can only have expired.
            if !cancelled.contains(entry.index) {
                #expect(outcome == .expired, "round \(round) wait \(entry.index)")
            }
        }
        #expect(timer.pendingCount == 0)
        #expect(!timer.isArmed)
        #expect(time.pendingCount == 0)
    }
    // One underlying sleep per round: neither the batch nor a cancellation re-armed.
    #expect(timer.underlyingSleeps == rounds)
}

/// An underlying sleep that ends only when the test fails it.
private final class FailingSleep: Sendable {
    private let pending = Mutex<CheckedContinuation<Void, any Error>?>(nil)
    var isWaiting: Bool { pending.withLock { $0 != nil } }

    func sleep() async throws {
        try await withCheckedThrowingContinuation { continuation in
            pending.withLock { $0 = continuation }
        }
    }

    func fail(_ error: any Error) {
        pending.withLock { pending in
            defer { pending = nil }
            return pending
        }?.resume(throwing: error)
    }
}

@Test func anUnderlyingClockFailureReachesEveryPendingWait() async throws {
    let underlying = FailingSleep()
    let clock = ContinuousClock()
    let timer = DeadlineTimer(now: { clock.now }, sleep: { _ in try await underlying.sleep() })
    let deadline = clock.now.advanced(by: .seconds(30))
    let waits = (0..<2).map { _ in Task { try await timer.sleep(until: deadline) } }
    try await timerPhase { timer.pendingCount == 2 && underlying.isWaiting }
    underlying.fail(ProtocolError.connectionClosed)
    for wait in waits {
        await #expect(throws: ProtocolError.connectionClosed) { try await wait.value }
    }
    #expect(timer.pendingCount == 0)
    #expect(!timer.isArmed)
}

/// Answers login, TEST UNIT READY and idle probes; holds commands or probes unanswered when
/// asked to.
private actor CommandTarget: ByteTransport {
    private let logins: [Data]
    private let answersCommands: Bool
    private let answersPings: Bool
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var status: UInt32 = 2
    private var expectedCommand: UInt32 = 1
    private(set) var commands = 0
    private(set) var pings = 0
    private(set) var isClosed = false

    init(answersCommands: Bool = true, answersPings: Bool = true) throws {
        logins = try loginFixtures(normal: true)
        self.answersCommands = answersCommands
        self.answersPings = answersPings
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 1_048_576)
        for pdu in try decoder.append(data) {
            switch pdu.opcode {
            case 0x03: enqueue(logins[Int((pdu.flags >> 2) & 3)])
            case 0x01:
                commands += 1
                expectedCommand &+= 1
                guard answersCommands else { continue }
                enqueue(try PDU(header: header(0x21, tag: pdu.taskTag)).encoded())
                status &+= 1
            case 0x00 where pdu.taskTag != UInt32.max:
                pings += 1
                guard answersPings else { continue }
                var reply = header(0x20, tag: pdu.taskTag)
                reply.put(UInt32.max, at: 20)
                enqueue(try PDU(header: reply, data: pdu.data).encoded())
                status &+= 1
            default: break
            }
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !isClosed { await withCheckedContinuation { reader = $0 } }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let count = min(maximumLength, input.count)
        let result = Data(input.prefix(count))
        if count == input.count { input = Data() } else { input.removeFirst(count) }
        return result
    }

    func close() async {
        isClosed = true
        reader?.resume()
        reader = nil
    }

    private func header(_ opcode: UInt8, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(status, at: 24)
        header.put(expectedCommand, at: 28)
        header.put(expectedCommand &+ 31, at: 32)
        return header
    }

    private func enqueue(_ data: Data) {
        input.append(data)
        reader?.resume()
        reader = nil
    }
}

@Test func completedCommandsLeaveOnlyTheWaitsStillInFlight() async throws {
    let timer = DeadlineTimer()
    let target = try CommandTarget()
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        clock: SessionClock(timer: timer))
    try await session.login()
    for batch in 0..<20 {
        for _ in 0..<1_000 {
            _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
        }
        // Only the idle-probe wait remains; each command removed its own deadline wait.
        #expect(timer.pendingCount <= 1, "batch \(batch)")
    }
    #expect(await target.commands == 20_000)
    // The previous design started one runtime sleep per command; this one a handful in all.
    #expect(timer.underlyingSleeps < 50)
    #expect(await session.state == .ready)
    await session.close()
    try await timerPhase { timer.pendingCount == 0 && !timer.isArmed }
}

@Test func aCommandStillTimesOutAtItsDeadlineThroughTheSharedTimer() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let target = try CommandTarget(answersCommands: false)
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        clock: SessionClock(timer: timer))
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    // The idle-probe wait and the command's own deadline wait share the probe's +10 s sleep.
    try await timerPhase {
        await target.commands == 1 && timer.pendingCount == 2
            && time.hasSleeper(after: .seconds(10))
    }
    time.advance(by: .seconds(29), wakeTimers: true)
    try await timerPhase { time.hasSleeper(after: .seconds(30)) }
    #expect(await session.state == .ready)
    time.advance(by: .seconds(1), wakeTimers: true)
    await #expect(throws: ProtocolError.timedOut) { try await command.value }
    #expect(await session.state == .failed)
    #expect((await session.terminationReason as? ProtocolError) == .timedOut)
    #expect(await target.isClosed)
    try await timerPhase {
        timer.pendingCount == 0 && !timer.isArmed && time.pendingCount == 0
    }
}

@Test func aShortCommandTimeoutStillFiresOnTheProductionClock() async throws {
    let target = try CommandTarget(answersCommands: false)
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        commandTimeout: .milliseconds(100))
    try await session.login()
    let clock = ContinuousClock()
    let started = clock.now
    await #expect(throws: ProtocolError.timedOut) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    #expect(started.duration(to: clock.now) >= .milliseconds(100))
    #expect(await session.state == .failed)
    #expect(await target.isClosed)
}

@Test func closingDuringAPendingCommandLeavesNothingArmed() async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let target = try CommandTarget(answersCommands: false)
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        clock: SessionClock(timer: timer))
    try await session.login()
    let command = Task { try await session.execute(.testUnitReady(), lun: LogicalUnit(0)) }
    try await timerPhase { await target.commands == 1 && timer.pendingCount == 2 }
    #expect(timer.isArmed)
    await session.close()
    await #expect(throws: (any Error).self) { try await command.value }
    try await timerPhase {
        timer.pendingCount == 0 && !timer.isArmed && time.pendingCount == 0
    }
    #expect(await session.state == .closed)
}

/// A system sleep passes a pending command's deadline and the heartbeat's: either the idle
/// probe's next check (+10 s) or, with an unanswered probe outstanding, its own +5 s deadline.
/// The shared timer delivers both in one batch; the per-sleep clock, as before the shared
/// timer, wakes one sleeper per wait. Both end the same way.
@Test(arguments: [false, true], [false, true])
func aSleepPastACommandAndTheHeartbeatTimesOutTheCommandAsBefore(
    _ sharedTimer: Bool, _ probeOutstanding: Bool
) async throws {
    let time = ManualSessionTime()
    let timer = manualTimer(time)
    let target = try CommandTarget(answersCommands: false, answersPings: false)
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        clock: sharedTimer ? SessionClock(timer: timer) : time.source)
    try await session.login()
    let reasons = Mutex<[ProtocolError?]>([])
    await session.setTerminationHandler { error in
        reasons.withLock { $0.append(error as? ProtocolError) }
    }
    if probeOutstanding {
        try await timerPhase { time.hasSleeper(after: .seconds(10)) }
        time.advance(by: .seconds(10), wakeTimers: true)
        try await timerPhase { await target.pings == 1 && time.hasSleeper(after: .seconds(15)) }
    }
    let heartbeatDeadline: Duration = probeOutstanding ? .seconds(15) : .seconds(10)
    let commandDeadline: Duration = probeOutstanding ? .seconds(40) : .seconds(30)
    let ended = Mutex(false)
    let command = Task {
        defer { ended.withLock { $0 = true } }
        return try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    try await timerPhase {
        guard await target.commands == 1, time.hasSleeper(after: heartbeatDeadline) else {
            return false
        }
        // The shared timer sleeps once, until the heartbeat's earlier deadline.
        return sharedTimer
            ? timer.pendingCount == 2 && time.pendingCount == 1
            : time.hasSleeper(after: commandDeadline) && time.pendingCount == 2
    }
    #expect(await session.state == .ready)

    time.advance(by: .seconds(3_600), wakeTimers: true)
    // A lost wake-up fails here instead of hanging on the command.
    try await timerPhase { ended.withLock { $0 } }
    await #expect(throws: ProtocolError.timedOut) { try await command.value }
    #expect(await session.state == .failed)
    #expect((await session.terminationReason as? ProtocolError) == .timedOut)
    #expect(await target.isClosed)
    #expect(await target.commands == 1)
    // A probe never starts behind a command in flight, nor a second one after the first.
    #expect(await target.pings == (probeOutstanding ? 1 : 0))
    try await timerPhase {
        timer.pendingCount == 0 && !timer.isArmed && time.pendingCount == 0
    }
    // One failure, reported once, and still once after every deadline wait has ended.
    #expect(reasons.withLock { $0 } == [.timedOut])
}
