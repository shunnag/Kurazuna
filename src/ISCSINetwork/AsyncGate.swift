import Foundation
import ISCSICore

/// FIFO admission for disk operations. Queueing is bounded; cancelled waiters release no permit.
public actor AsyncGate {
    private var held = false
    private var waiters: [(UUID, CheckedContinuation<Void, any Error>)] = []
    public var waitingCount: Int { waiters.count }

    public init() {}

    public func acquire() async throws {
        try Task.checkCancellation()
        if !held {
            held = true
            return
        }
        guard waiters.count < 128 else { throw ProtocolError.busy }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiters.append((id, continuation))
                }
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
    }

    public func release() {
        if waiters.isEmpty { held = false } else { waiters.removeFirst().1.resume() }
    }

    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        waiters.remove(at: index).1.resume(throwing: CancellationError())
    }
}
