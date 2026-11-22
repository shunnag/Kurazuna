import Foundation
import ISCSICore

/// One response slot with backpressure. The single reader never accumulates an unbounded queue
/// while the command consumer is sending Data-Out or processing a previous response.
actor ResponseMailbox {
    private var response: PDU?
    private var consumer: CheckedContinuation<PDU, any Error>?
    private var producer: CheckedContinuation<Void, any Error>?
    private var failure: (any Error)?

    func put(_ pdu: PDU) async throws {
        try Task.checkCancellation()
        if let failure { throw failure }
        guard response == nil, producer == nil else { throw ProtocolError.busy }
        if let consumer {
            self.consumer = nil
            consumer.resume(returning: pdu)
            return
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                response = pdu
                producer = continuation
            }
        } onCancel: {
            Task { await self.close(CancellationError()) }
        }
    }

    func next() async throws -> PDU {
        try Task.checkCancellation()
        if let failure { throw failure }
        guard consumer == nil else { throw ProtocolError.busy }
        if let response {
            self.response = nil
            let producer = self.producer
            self.producer = nil
            producer?.resume()
            return response
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { consumer = $0 }
        } onCancel: {
            Task { await self.close(CancellationError()) }
        }
    }

    func close(_ error: any Error) {
        guard failure == nil else { return }
        failure = error
        response = nil
        let consumer = self.consumer
        let producer = self.producer
        self.consumer = nil
        self.producer = nil
        consumer?.resume(throwing: error)
        producer?.resume(throwing: error)
    }
}
