import Foundation
import ISCSICore
import Network
import OSLog

public protocol ByteTransport: Sendable {
    func send(_ data: Data) async throws
    func receive(maximumLength: Int) async throws -> Data
    func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data
    func close() async
}

public protocol ConnectableByteTransport: ByteTransport {
    func connect() async throws
}

/// The trusted transport invokes submission inline inside the caller's synchronous admission
/// boundary. This closes the gap between an asynchronous caller check and actual socket enqueue.
/// Already submitted bytes and an uncertain completion still require the external fence.
/// Admission must invoke submit exactly once inline, or throw before invoking it. It must
/// never retain submit, suppress its invocation, or throw after successful submission.
public protocol SendAdmissionTransport: ByteTransport {
    func send(
        _ data: Data,
        whileAdmitted: @escaping @Sendable (_ submit: () -> Void) throws -> Void
    ) async throws
}

/// Validation-only observation of one ready connection, not peer authentication.
@_spi(Validation)
public struct TCPIPv4EndpointPair: Equatable, Sendable {
    public let localAddress: Data
    public let localPort: UInt16
    public let remoteAddress: Data
    public let remotePort: UInt16

    init?(local: NWEndpoint?, remote: NWEndpoint?) {
        guard let local, let remote,
            case .hostPort(let localHost, let localPort) = local,
            case .hostPort(let remoteHost, let remotePort) = remote,
            case .ipv4(let localAddress) = localHost,
            case .ipv4(let remoteAddress) = remoteHost,
            localPort.rawValue != 0, remotePort.rawValue != 0,
            localAddress.rawValue.count == 4, remoteAddress.rawValue.count == 4,
            localAddress.rawValue.contains(where: { $0 != 0 }),
            remoteAddress.rawValue.contains(where: { $0 != 0 })
        else { return nil }
        self.localAddress = localAddress.rawValue
        self.localPort = localPort.rawValue
        self.remoteAddress = remoteAddress.rawValue
        self.remotePort = remotePort.rawValue
    }
}

@_spi(Validation)
public enum TCPConnectionObservationError: Error, Equatable {
    case unavailable, timedOut
}

extension ByteTransport {
    public func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data {
        try await receive(maximumLength: maximumLength)
    }
}

/// Resumes a continuation exactly once across completion, deadline and cancellation races.
private final class Completion<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, any Error>?
    private var result: Result<Value, any Error>?

    func install(_ continuation: CheckedContinuation<Value, any Error>) {
        lock.lock()
        if let result {
            lock.unlock()
            continuation.resume(with: result)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    @discardableResult
    func finish(_ result: Result<Value, any Error>) -> Bool {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return false
        }
        self.result = result
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
        return true
    }
}

public final class TCPTransport: ConnectableByteTransport, SendAdmissionTransport, Sendable {
    private static let logger = Logger(subsystem: "dev.soba.iscsi.network", category: "connection")
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.soba.iscsi.tcp", qos: .userInitiated)
    private let timeout: TimeInterval
    private let waitForConnectivity: Bool
    private let localNetworkAccessWait: LocalNetworkAccessWait?
    private let readyCheck: (@Sendable (NWConnection) throws -> Void)?
    /// One underlying sleep serves the deadlines of every send and receive in flight.
    let deadlines = DeadlineTimer()

    public convenience init(
        portal: Portal, timeout: TimeInterval = 15, waitForConnectivity: Bool = true,
        localNetworkAccessWait: LocalNetworkAccessWait? = nil
    ) throws {
        let options = NWProtocolTCP.Options()
        options.noDelay = true
        try self.init(
            portal: portal, timeout: timeout, waitForConnectivity: waitForConnectivity,
            localNetworkAccessWait: localNetworkAccessWait,
            parameters: NWParameters(tls: nil, tcp: options), readyCheck: nil)
    }

    /// Internal TLS construction is owned by PinnedBrokerTransport; ordinary TCP stays plaintext.
    init(
        portal: Portal, timeout: TimeInterval, waitForConnectivity: Bool = false,
        localNetworkAccessWait: LocalNetworkAccessWait? = nil, parameters: NWParameters,
        readyCheck: (@Sendable (NWConnection) throws -> Void)?
    ) throws {
        guard timeout.isFinite, (0.1...300).contains(timeout),
            let port = NWEndpoint.Port(rawValue: portal.port)
        else { throw ProtocolError.malformed("connection timeout or port") }
        self.connection = NWConnection(
            host: NWEndpoint.Host(portal.host), port: port, using: parameters)
        self.timeout = timeout
        self.waitForConnectivity = waitForConnectivity
        self.localNetworkAccessWait = localNetworkAccessWait
        self.readyCheck = readyCheck
    }

    public func connect() async throws {
        let token = UUID()
        let initialWait = localNetworkAccessWait?.elapsed ?? .zero
        let deadlineExtension: @Sendable () -> Duration = { [localNetworkAccessWait] in
            localNetworkAccessWait?.additionalTime(since: initialWait) ?? .zero
        }
        defer {
            connection.stateUpdateHandler = nil
            localNetworkAccessWait?.update(token, waiting: false)
        }
        let timeoutError: @Sendable () -> any Error = { [connection] in
            if case .localNetworkDenied? = connection.currentPath?.unsatisfiedReason {
                return ProtocolError.localNetworkAccessRequired
            }
            return ProtocolError.timedOut
        }
        try await operation(timeoutError: timeoutError, deadlineExtension: deadlineExtension) {
            (completion: Completion<Void>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.localNetworkAccessWait?.update(token, waiting: false)
                    do {
                        try self.readyCheck?(self.connection)
                        completion.finish(.success(()))
                    } catch {
                        completion.finish(.failure(error))
                        self.connection.cancel()
                    }
                case .failed(let error):
                    self.localNetworkAccessWait?.update(token, waiting: false)
                    completion.finish(.failure(error))
                case .waiting(let error):
                    let reason = self.connection.currentPath?.unsatisfiedReason
                    Self.logger.notice(
                        "Connection waiting: \(String(describing: error), privacy: .private); path reason: \(String(describing: reason), privacy: .private)"
                    )
                    // The first privacy alert can put the connection in waiting
                    // before the person has made a choice. Let Network resume
                    // this same TCP attempt if access is allowed before its deadline.
                    if case .localNetworkDenied? = reason {
                        self.localNetworkAccessWait?.update(token, waiting: true)
                        break
                    }
                    self.localNetworkAccessWait?.update(token, waiting: false)
                    if !self.waitForConnectivity,
                        completion.finish(.failure(error))
                    {
                        self.connection.cancel()
                    }
                case .preparing:
                    self.localNetworkAccessWait?.update(token, waiting: false)
                case .cancelled:
                    self.localNetworkAccessWait?.update(token, waiting: false)
                    completion.finish(.failure(ProtocolError.connectionClosed))
                default: break
                }
            }
            connection.start(queue: queue)
        }
    }

    public func send(_ data: Data) async throws {
        try await send(data, whileAdmitted: { submit in submit() })
    }

    public func send(
        _ data: Data,
        whileAdmitted: @escaping @Sendable (_ submit: () -> Void) throws -> Void
    ) async throws {
        try await operation { (completion: Completion<Void>) in
            do {
                try whileAdmitted {
                    connection.send(
                        content: data,
                        completion: .contentProcessed { error in
                            if let error {
                                completion.finish(.failure(error))
                            } else {
                                completion.finish(.success(()))
                            }
                        })
                }
            } catch { completion.finish(.failure(error)) }
        }
    }

    public func receive(maximumLength: Int) async throws -> Data {
        try await receive(maximumLength: maximumLength, waitingForActivity: false)
    }

    public func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data {
        guard (1...1_048_576).contains(maximumLength) else {
            throw ProtocolError.limitExceeded("TCP receive length")
        }
        return try await operation(waitingForActivity: waitingForActivity) { completion in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximumLength) {
                data, _, _, error in
                if let error {
                    completion.finish(.failure(error))
                } else if let data, !data.isEmpty {
                    completion.finish(.success(data))
                } else {
                    completion.finish(.failure(ProtocolError.connectionClosed))
                }
            }
        }
    }

    public func close() async {
        connection.cancel()
        deadlines.releaseWhenIdle()
    }

    func cancellationObserved() async -> Bool {
        await withCheckedContinuation { continuation in
            queue.async {
                if case .cancelled = self.connection.state {
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(returning: false)
                }
            }
        }
    }

    /// Reads the actual connection's path on its serial queue. Failure or cancellation
    /// of this bounded diagnostic never cancels or reconfigures the connection.
    @_spi(Validation)
    public func validationIPv4Endpoints() async throws -> TCPIPv4EndpointPair {
        let completion = Completion<TCPIPv4EndpointPair>()
        let timer = Task {
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
            completion.finish(.failure(TCPConnectionObservationError.timedOut))
        }
        defer { timer.cancel() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
                queue.async { [weak connection = self.connection] in
                    guard let connection, case .ready = connection.state,
                        let path = connection.currentPath,
                        let endpoints = TCPIPv4EndpointPair(
                            local: path.localEndpoint, remote: path.remoteEndpoint),
                        case .ready = connection.state
                    else {
                        completion.finish(.failure(TCPConnectionObservationError.unavailable))
                        return
                    }
                    completion.finish(.success(endpoints))
                }
            }
        } onCancel: {
            completion.finish(.failure(CancellationError()))
        }
    }

    private func operation<Value: Sendable>(
        waitingForActivity: Bool = false,
        timeoutError: @escaping @Sendable () -> any Error = { ProtocolError.timedOut },
        deadlineExtension: @escaping @Sendable () -> Duration = { .zero },
        _ start: (Completion<Value>) -> Void
    ) async throws -> Value {
        let completion = Completion<Value>()
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(timeout))
        let timer: Task<Void, Never>? =
            waitingForActivity
            ? nil
            : Task { [connection, deadlines] in
                while !Task.isCancelled {
                    do {
                        try await deadlines.sleep(until: deadline.advanced(by: deadlineExtension()))
                    } catch { return }
                    guard clock.now >= deadline.advanced(by: deadlineExtension()) else { continue }
                    if completion.finish(.failure(timeoutError())) { connection.cancel() }
                    return
                }
            }
        defer { timer?.cancel() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
                start(completion)
            }
        } onCancel: { [connection] in
            completion.finish(.failure(CancellationError()))
            connection.cancel()
        }
    }
}
