import Foundation

/// A bounded, per-operation allowance for a person's local-network permission choice.
/// Only an explicit denied local-network path may enter this wait. Network I/O
/// and login keep their existing budgets; elapsed permission time is counted once.
public final class LocalNetworkAccessWait: @unchecked Sendable {
    private let lock = NSLock()
    private let clock: SessionClock
    private let maximum: Duration
    private let changed: @Sendable () -> Void
    private var tokens: Set<UUID> = []
    private var began: ContinuousClock.Instant?
    private var accumulated: Duration = .zero

    public convenience init(changed: @escaping @Sendable () -> Void = {}) {
        self.init(clock: .continuous, maximum: .seconds(120), changed: changed)
    }

    init(
        clock: SessionClock, maximum: Duration,
        changed: @escaping @Sendable () -> Void = {}
    ) {
        precondition(maximum > .zero && maximum <= .seconds(300))
        self.clock = clock
        self.maximum = maximum
        self.changed = changed
    }

    public var isWaiting: Bool { lock.withLock { !tokens.isEmpty } }

    var elapsed: Duration {
        lock.withLock {
            min(maximum, accumulated + (began.map { $0.duration(to: clock.now) } ?? .zero))
        }
    }

    func update(_ token: UUID, waiting: Bool) {
        let notify = lock.withLock {
            let wasWaiting = !tokens.isEmpty
            if waiting {
                tokens.insert(token)
                if !wasWaiting { began = clock.now }
            } else {
                tokens.remove(token)
                if tokens.isEmpty, let began {
                    accumulated = min(maximum, accumulated + began.duration(to: clock.now))
                    self.began = nil
                }
            }
            return wasWaiting != !tokens.isEmpty
        }
        // Observers read the latest status; delayed callbacks cannot restore an old state.
        if notify { changed() }
    }

    func additionalTime(since earlier: Duration) -> Duration {
        max(.zero, elapsed - earlier)
    }
}
