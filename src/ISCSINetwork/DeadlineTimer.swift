import Foundation
import Synchronization

/// Serves every pending deadline wait with one sleep on the underlying clock.
///
/// A cancelled `Clock.sleep` keeps its runtime timer and sleep task allocated until the
/// original deadline, so arming one per command or per transport operation keeps
/// rate × timeout timers alive. Here a wait is an entry in `waiters` that completion or
/// cancellation removes at once, and a single driver task sleeps on the underlying clock
/// until the earliest pending deadline. Deadlines that only move later (one timeout per
/// owner) never replace the driver; it wakes, resumes the due waits and re-arms.
///
/// Invariants, all under `state`:
/// - Each waiter is resumed exactly once: by the current driver once the clock reads at or
///   after its deadline, by its own cancellation, or with the underlying clock's error.
/// - While a waiter is pending, the current driver wakes no later than its deadline.
/// - Only the driver of the current generation resumes waiters. A strictly earlier deadline,
///   `releaseWhenIdle()` or deinit cancels the previous driver; drivers never hold the owner.
final class DeadlineTimer: Sendable {
    typealias Instant = ContinuousClock.Instant

    private struct Waiter {
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }
    private struct State {
        var waiters: [UInt64: Waiter] = [:]
        var nextWaiter: UInt64 = 0
        var armed: (deadline: Instant, generation: UInt64)?
        var generation: UInt64 = 0
        var driver: Task<Void, Never>?
        var releaseWhenIdle = false
        var underlyingSleeps = 0
    }
    private let state = Mutex(State())
    private let readInstant: @Sendable () -> Instant
    private let underlying: @Sendable (Instant) async throws -> Void

    init(
        now: @escaping @Sendable () -> Instant,
        sleep: @escaping @Sendable (Instant) async throws -> Void
    ) {
        readInstant = now
        underlying = sleep
    }

    convenience init(clock: ContinuousClock = ContinuousClock()) {
        self.init(now: { clock.now }, sleep: { try await clock.sleep(until: $0) })
    }

    deinit { state.withLock { $0.driver }?.cancel() }

    var now: Instant { readInstant() }
    /// Waits in progress; internal observation for tests.
    var pendingCount: Int { state.withLock { $0.waiters.count } }
    /// Whether a driver currently sleeps on the underlying clock.
    var isArmed: Bool { state.withLock { $0.armed != nil } }
    /// Underlying sleeps started over this timer's lifetime.
    var underlyingSleeps: Int { state.withLock { $0.underlyingSleeps } }

    /// Same contract as `Clock.sleep(until:)`: returns at or after `deadline`, or throws
    /// `CancellationError` when the calling task is cancelled first.
    func sleep(until deadline: Instant) async throws {
        if readInstant() >= deadline {
            // Like an already-due `Clock.sleep`: still one suspension point, but no timer.
            await Task.yield()
            try Task.checkCancellation()
            return
        }
        let id = state.withLock { state in
            state.nextWaiter &+= 1
            return state.nextWaiter
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                let (immediate, superseded) = state.withLock {
                    state -> (Result<Void, any Error>?, Task<Void, Never>?) in
                    if Task.isCancelled { return (.failure(CancellationError()), nil) }
                    if readInstant() >= deadline { return (.success(()), nil) }
                    state.waiters[id] = Waiter(deadline: deadline, continuation: continuation)
                    // A wait that starts after a release request still needs the driver.
                    state.releaseWhenIdle = false
                    guard state.armed.map({ deadline < $0.deadline }) ?? true else {
                        return (nil, nil)
                    }
                    return (nil, arm(&state, until: deadline))
                }
                superseded?.cancel()
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            let (waiter, released) = state.withLock { state in
                let waiter = state.waiters.removeValue(forKey: id)
                return (waiter, waiter == nil ? nil : releaseIfIdle(&state))
            }
            released?.cancel()
            waiter?.continuation.resume(throwing: CancellationError())
        }
    }

    /// The owner is closing: stop the driver now, or as soon as the pending waits end.
    /// A wait that starts later re-arms as usual.
    func releaseWhenIdle() {
        state.withLock { state in
            state.releaseWhenIdle = true
            return releaseIfIdle(&state)
        }?.cancel()
    }

    /// Returns the superseded driver; the caller cancels it after unlocking.
    private func arm(_ state: inout State, until deadline: Instant) -> Task<Void, Never>? {
        let superseded = state.driver
        state.generation &+= 1
        let generation = state.generation
        state.armed = (deadline, generation)
        state.underlyingSleeps += 1
        let underlying = underlying
        // Fixed priority: one driver serves the waits of every caller.
        state.driver = Task.detached(priority: .userInitiated) { [weak self] in
            let result: Result<Void, any Error>
            do {
                try await underlying(deadline)
                result = .success(())
            } catch {
                result = .failure(error)
            }
            self?.wake(generation, result)
        }
        return superseded
    }

    private func releaseIfIdle(_ state: inout State) -> Task<Void, Never>? {
        guard state.releaseWhenIdle, state.waiters.isEmpty else { return nil }
        state.releaseWhenIdle = false
        state.armed = nil
        defer { state.driver = nil }
        return state.driver
    }

    private func wake(_ generation: UInt64, _ result: Result<Void, any Error>) {
        let due = state.withLock { state -> [Waiter] in
            guard state.armed?.generation == generation else { return [] }
            state.armed = nil
            state.driver = nil
            if case .failure = result {
                // Each wait would have seen this error from its own underlying sleep.
                defer { state.waiters.removeAll() }
                return Array(state.waiters.values)
            }
            let now = readInstant()
            let due = state.waiters.filter { $0.value.deadline <= now }
            for id in due.keys { state.waiters.removeValue(forKey: id) }
            if let next = state.waiters.values.map(\.deadline).min() {
                _ = arm(&state, until: next)
            }
            return Array(due.values)
        }
        for waiter in due { waiter.continuation.resume(with: result) }
    }
}
