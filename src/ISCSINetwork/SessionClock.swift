import Foundation

/// Internal time source so deadline checks and delayed timer delivery can be tested separately.
struct SessionClock: Sendable {
    private let readInstant: @Sendable () -> ContinuousClock.Instant
    private let waitUntil: @Sendable (ContinuousClock.Instant) async throws -> Void
    private let release: @Sendable () -> Void

    init(
        now: @escaping @Sendable () -> ContinuousClock.Instant,
        sleep: @escaping @Sendable (ContinuousClock.Instant) async throws -> Void,
        releaseWhenIdle: @escaping @Sendable () -> Void = {}
    ) {
        readInstant = now
        waitUntil = sleep
        release = releaseWhenIdle
    }

    /// Every sleep on this clock shares the timer's single underlying sleep.
    init(timer: DeadlineTimer) {
        self.init(
            now: { timer.now }, sleep: { try await timer.sleep(until: $0) },
            releaseWhenIdle: { timer.releaseWhenIdle() })
    }

    var now: ContinuousClock.Instant { readInstant() }

    func sleep(until deadline: ContinuousClock.Instant) async throws {
        try await waitUntil(deadline)
    }

    /// The owner closed: the shared timer may stop once no sleep on it is pending.
    func releaseWhenIdle() { release() }

    /// The continuous clock. Per-command and per-exchange deadlines are cancelled far more
    /// often than they expire; a `DeadlineTimer` keeps those cancellations from leaving one
    /// runtime timer each alive until its original deadline.
    static var continuous: Self { Self(timer: DeadlineTimer()) }
}
