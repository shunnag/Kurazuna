import Foundation
import ISCSICore
import Network
import Synchronization
import Testing

@testable import ISCSINetwork

/// A loopback peer that accepts one connection and neither reads nor writes unless asked.
private final class LoopbackPeer: Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.soba.iscsi.test.loopback-peer")
    private let accepted = Mutex<NWConnection?>(nil)

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() async throws -> Portal {
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            let resumed = Mutex(false)
            let once: @Sendable (Result<UInt16, any Error>) -> Void = { result in
                let first = resumed.withLock { done in
                    defer { done = true }
                    return !done
                }
                if first { continuation.resume(with: result) }
            }
            listener.stateUpdateHandler = { [listener] state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue {
                        once(.success(port))
                    } else {
                        once(.failure(ProtocolError.invalidState))
                    }
                case .failed(let error): once(.failure(error))
                case .cancelled: once(.failure(ProtocolError.connectionClosed))
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                guard let self else { return connection.cancel() }
                self.accepted.withLock { $0 = connection }
                connection.start(queue: self.queue)
            }
            listener.start(queue: queue)
        }
        return try Portal(host: "127.0.0.1", port: port)
    }

    var hasConnection: Bool { accepted.withLock { $0 != nil } }

    func write(_ data: Data) {
        accepted.withLock { $0 }?.send(content: data, completion: .idempotent)
    }

    func stop() {
        accepted.withLock { $0 }?.cancel()
        listener.cancel()
    }
}

private func transportPhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let limit = clock.now.advanced(by: .seconds(5))
    while !(await predicate()) {
        guard clock.now < limit else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
}

private func connectedTransport(_ peer: LoopbackPeer, timeout: TimeInterval) async throws
    -> TCPTransport
{
    let transport = try TCPTransport(
        portal: try await peer.start(), timeout: timeout, waitForConnectivity: false)
    try await transport.connect()
    try await transportPhase { peer.hasConnection }
    return transport
}

@Test func aSilentPeerTimesOutAPendingReceive() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 0.2)
    let clock = ContinuousClock()
    let started = clock.now
    await #expect(throws: ProtocolError.timedOut) {
        _ = try await transport.receive(maximumLength: 48)
    }
    #expect(started.duration(to: clock.now) >= .milliseconds(200))
    #expect(transport.deadlines.pendingCount == 0)
    // The timeout cancels the connection; later operations cannot use it.
    await #expect(throws: (any Error).self) { try await transport.send(Data([1])) }
    await transport.close()
    try await transportPhase { !transport.deadlines.isArmed }
}

@Test func manyExchangesShareOneUnderlyingSleep() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 30)
    for _ in 0..<2_000 {
        try await transport.send(Data(repeating: 0x5A, count: 48))
        // Each completed send removed its own deadline wait.
        #expect(transport.deadlines.pendingCount == 0)
    }
    peer.write(Data(repeating: 0xA5, count: 2_000))
    var received = 0
    while received < 2_000 {
        received += try await transport.receive(maximumLength: 2_000 - received).count
        #expect(transport.deadlines.pendingCount == 0)
    }
    // The connect deadline armed the only sleep; later deadlines never come earlier.
    #expect(transport.deadlines.underlyingSleeps == 1)
    await transport.close()
    try await transportPhase { !transport.deadlines.isArmed }
}

@Test func aPeerThatStopsReadingTimesOutASend() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 0.3)
    let chunk = Data(repeating: 0xA5, count: 1_048_576)
    var outcome: (any Error)?
    for _ in 0..<256 {
        do { try await transport.send(chunk) } catch {
            outcome = error
            break
        }
    }
    #expect((outcome as? ProtocolError) == .timedOut)
    await transport.close()
}

@Test func anIdleReceiveWaitsBeyondTheOperationTimeout() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 0.1)
    let receive = Task {
        try await transport.receive(maximumLength: 48, waitingForActivity: true)
    }
    try await ContinuousClock().sleep(for: .milliseconds(400))
    // An idle receive arms no deadline; the connect deadline's sleep has run out.
    #expect(transport.deadlines.pendingCount == 0)
    #expect(!transport.deadlines.isArmed)
    peer.write(Data([7, 8, 9]))
    #expect(try await receive.value == Data([7, 8, 9]))
    // A completed exchange leaves the next timed operation its whole budget.
    try await transport.send(Data([1, 2, 3]))
    await transport.close()
}

@Test func aReceiveThatCompletesBeforeItsDeadlineIsNotFailedLater() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 0.2)
    peer.write(Data([1]))
    #expect(try await transport.receive(maximumLength: 1) == Data([1]))
    try await ContinuousClock().sleep(for: .milliseconds(400))
    peer.write(Data([2]))
    #expect(try await transport.receive(maximumLength: 1) == Data([2]))
    await transport.close()
}

@Test func closingInterruptsAPendingReceive() async throws {
    let peer = try LoopbackPeer()
    defer { peer.stop() }
    let transport = try await connectedTransport(peer, timeout: 30)
    let receive = Task { try await transport.receive(maximumLength: 48) }
    try await transportPhase { transport.deadlines.pendingCount == 1 }
    #expect(transport.deadlines.isArmed)
    await transport.close()
    await #expect(throws: (any Error).self) { _ = try await receive.value }
    try await transportPhase {
        transport.deadlines.pendingCount == 0 && !transport.deadlines.isArmed
    }
}
