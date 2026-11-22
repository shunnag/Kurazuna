import Foundation
import Synchronization

/// Describes only the original disk transport. Neither result grants filesystem
/// unmount, reservation release, external-writer admission or backing retirement.
public enum ReservedTransportCloseResult: Sendable, Equatable {
    case synchronizedAndLoggedOut
    case abandoned
}

/// One live, terminal completion owned by a reserved disk. Construction is internal;
/// callers may join or cancel this original operation, never recreate its authority.
public final class ReservedTransportCompletion: Sendable {
    private struct State: Sendable {
        var main: Task<ReservedTransportCloseResult, Never>?
        var abort: Task<Void, Never>?
        var cancelled = false
        var finished = false
    }
    private enum Observation {
        case join(Task<Void, Never>)
        case finished(ReservedTransportCloseResult)
    }
    private let state = Mutex(State())
    private let perform: @Sendable () async -> ReservedTransportCloseResult
    private let invalidate: @Sendable () -> Void
    private let abortTransport: @Sendable () async -> Void

    init(
        perform: @escaping @Sendable () async -> ReservedTransportCloseResult,
        invalidate: @escaping @Sendable () -> Void,
        abortTransport: @escaping @Sendable () async -> Void
    ) {
        self.perform = perform
        self.invalidate = invalidate
        self.abortTransport = abortTransport
    }

    public var isCancelled: Bool { state.withLock { $0.cancelled } }

    func check() throws {
        if isCancelled { throw CancellationError() }
    }

    /// Installs cancellation handling before starting a task. An already-cancelled
    /// caller cannot start normal completion on an uncancelled unstructured task.
    public func wait() async -> ReservedTransportCloseResult {
        await withTaskCancellationHandler {
            if Task.isCancelled { cancel() }
            let original = state.withLock { value in
                if let existing = value.main { return existing }
                let task = Task {
                    self.state.withLock { _ in }  // Publication precedes work.
                    if self.isCancelled { return ReservedTransportCloseResult.abandoned }
                    return await self.perform()
                }
                value.main = task
                return task
            }
            let result = await original.value
            var joinedAbort = false
            while true {
                let observation = state.withLock { value -> Observation in
                    if !joinedAbort, let abort = value.abort { return .join(abort) }
                    // This commit and abort-owner reservation share the same lock.
                    // Late cancellation cannot create an unjoined cleanup task.
                    value.finished = true
                    return .finished(value.cancelled ? .abandoned : result)
                }
                switch observation {
                case .join(let task):
                    await task.value
                    joinedAbort = true
                case .finished(let result): return result
                }
            }
        } onCancel: {
            self.cancel()
        }
    }

    /// Sticky cancellation; original normal work is observed rather than cancelled.
    /// The sole abort owner is published before normal finalization may observe it.
    public func cancel() {
        state.withLock { value in
            guard !value.finished else { return }
            value.cancelled = true
            // This internal callback only revokes the bound access and signal.
            // It must not reenter this controller. Finalization cannot overtake it.
            invalidate()
            guard value.abort == nil else { return }
            let task = Task {
                self.state.withLock { _ in }  // Wait until the owner is published.
                await self.abortTransport()
            }
            value.abort = task
        }
    }

    /// Generic close interrupts immediately and does not wait for the I/O drain it
    /// may need to unblock. Normal waiters separately join both original owners.
    func waitForAbort() async {
        let task = state.withLock { $0.abort }
        await task?.value
    }
}
