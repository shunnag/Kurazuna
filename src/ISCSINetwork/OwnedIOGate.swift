import Foundation
import ISCSICore
import Synchronization

/// Ownership for the disk's issued operations. Terminal drain is not a storage barrier,
/// producer unmount, Logout permit, reservation release, or target-retirement authority.
actor OwnedIOGate {
    final class Lease: Sendable {
        fileprivate init() {}
    }

    final class Drain: Sendable {
        private struct State: Sendable {
            var invalid = false
            var consumed = false
        }
        private let state = Mutex(State())
        fileprivate init() {}

        func invalidate() { state.withLock { $0.invalid = true } }

        func validate() throws {
            try state.withLock {
                guard !$0.invalid, !$0.consumed else { throw ProtocolError.invalidState }
            }
        }

        func validateConsumed() throws {
            try state.withLock {
                guard !$0.invalid, $0.consumed else { throw ProtocolError.invalidState }
            }
        }

        func whileConsumed(_ body: () throws -> Void) throws {
            try state.withLock {
                guard !$0.invalid, $0.consumed else { throw ProtocolError.invalidState }
                try body()
            }
        }

        fileprivate func consume() throws {
            try state.withLock {
                guard !$0.invalid, !$0.consumed else { throw ProtocolError.invalidState }
                $0.consumed = true
            }
        }
    }

    final class TerminalLease: Sendable {
        let signal: Drain
        private let synchronizationStarted = Mutex(false)
        fileprivate init(signal: Drain) { self.signal = signal }

        func beginSynchronization() throws {
            try synchronizationStarted.withLock {
                guard !$0 else { throw ProtocolError.invalidState }
                $0 = true
                try signal.validateConsumed()
            }
        }
    }

    private var current: Lease?
    /// Available before an actor hop so an enclosing operation can synchronously
    /// record cancellation. Possession alone supplies no seal or drain authority.
    nonisolated let terminalHandle = Drain()
    private var waiters: [(UUID, CheckedContinuation<Lease, any Error>)] = []
    private var terminal: Drain?
    private var terminalOwner: TerminalLease?
    private var drainWaiters: [(UUID, CheckedContinuation<Drain, any Error>)] = []

    var waitingCount: Int { waiters.count }
    var waitingDrainCount: Int { drainWaiters.count }
    var isSealed: Bool { terminal != nil }

    func acquire() async throws -> Lease {
        try Task.checkCancellation()
        guard terminal == nil else { throw ProtocolError.invalidState }
        if current == nil {
            let lease = Lease()
            current = lease
            return lease
        }
        guard waiters.count < 128 else { throw ProtocolError.busy }
        let id = UUID()
        // A continuation granted before seal remains the current owner even if its
        // task has not resumed yet. Its caller must release that exact lease.
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiters.append((id, continuation))
                }
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    @discardableResult
    func release(_ lease: Lease) -> Bool {
        guard current === lease else { return false }
        if terminal != nil {
            current = nil
            completeDrain()
        } else if waiters.isEmpty {
            current = nil
        } else {
            let next = waiters.removeFirst().1
            let lease = Lease()
            current = lease
            next.resume(returning: lease)
        }
        return true
    }

    /// Seal linearizes in this actor turn. Queued work is rejected; the already
    /// granted operation retains ownership until it releases its original lease.
    func sealAndDrain() async throws -> Drain {
        let drain = seal()
        if Task.isCancelled {
            drain.invalidate()
            throw CancellationError()
        }
        if current == nil { return drain }
        guard drainWaiters.count < 128 else {
            drain.invalidate()
            throw ProtocolError.busy
        }
        let id = UUID()
        do {
            let result: Drain = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    if Task.isCancelled {
                        drain.invalidate()
                        continuation.resume(throwing: CancellationError())
                    } else {
                        drainWaiters.append((id, continuation))
                    }
                }
            } onCancel: {
                // Do not defer authorization revocation behind another actor turn.
                drain.invalidate()
                Task { await self.cancelDrainWaiter(id) }
            }
            try Task.checkCancellation()
            return result
        } catch {
            drain.invalidate()
            throw error
        }
    }

    /// Repeated observation never creates additional terminal owners.
    @discardableResult
    func consume(_ drain: Drain) throws -> TerminalLease {
        guard terminal === drain else { throw ProtocolError.invalidState }
        if Task.isCancelled {
            drain.invalidate()
            throw CancellationError()
        }
        guard current == nil else {
            throw ProtocolError.invalidState
        }
        try drain.consume()
        let lease = TerminalLease(signal: drain)
        terminalOwner = lease
        return lease
    }

    func validateTerminal(_ lease: TerminalLease) throws {
        guard terminalOwner === lease, terminal === lease.signal, current == nil else {
            throw ProtocolError.invalidState
        }
        try lease.signal.validateConsumed()
    }

    /// Invalidation never waits for the operation it must allow generic close to interrupt.
    func abort() {
        seal().invalidate()
    }

    func seal() -> Drain {
        if let terminal { return terminal }
        let drain = terminalHandle
        terminal = drain
        let rejected = waiters
        waiters.removeAll()
        for (_, waiter) in rejected { waiter.resume(throwing: ProtocolError.invalidState) }
        if current == nil { completeDrain() }
        return drain
    }

    private func completeDrain() {
        guard current == nil, let terminal else { return }
        let observers = drainWaiters
        drainWaiters.removeAll()
        for (_, waiter) in observers { waiter.resume(returning: terminal) }
    }

    private func cancelWaiter(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        waiters.remove(at: index).1.resume(throwing: CancellationError())
    }

    private func cancelDrainWaiter(_ id: UUID) {
        terminal?.invalidate()
        guard let index = drainWaiters.firstIndex(where: { $0.0 == id }) else { return }
        drainWaiters.remove(at: index).1.resume(throwing: CancellationError())
    }
}
