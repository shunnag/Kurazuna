import Foundation
import ISCSICore

protocol DiskEjectionHandle: Sendable {
    func unmount() async throws
    func eject() async throws
}

protocol DiskEjectionService: Sendable {
    func eject(
        device: String, image: URL, unmountDevices: [String],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws
    func ejectConfirmed(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws
    func forceEject(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws
    func pendingImagePaths() async -> Set<String>
    /// Whether no ejection of the image is pending any longer, waiting at most `timeout` for
    /// the OS to answer one that is.
    func waitForPendingEjection(of image: URL, timeout: Duration) async -> Bool
}

extension DiskEjectionService {
    func ejectConfirmed(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        // A backend that cannot enforce the supplied identity must not discard it.
        throw AttachmentError.ownershipUnverified
    }

    func forceEject(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        throw AttachmentError.recoveryRequired
    }

    /// A service that never keeps a request pending past its reply.
    func waitForPendingEjection(of image: URL, timeout: Duration) async -> Bool {
        !(await pendingImagePaths()).contains(image.standardizedFileURL.path)
    }
}

struct DiskEjectionRequest: Sendable {
    let device: String
    let unmountDevices: [String]
    let deadline: ContinuousClock.Instant
    let force: Bool
    let mediaIdentifiers: [String: UInt64]
    let trace: DiskEjectionDiagnostics.Trace

    init(
        device: String, unmountDevices: [String], deadline: ContinuousClock.Instant,
        force: Bool = false, mediaIdentifiers: [String: UInt64] = [:],
        trace: DiskEjectionDiagnostics.Trace? = nil
    ) {
        self.device = device
        self.unmountDevices = unmountDevices
        self.deadline = deadline
        self.force = force
        self.mediaIdentifiers = mediaIdentifiers
        self.trace = trace ?? .init(force: force, targetCount: unmountDevices.count)
    }
}

/// A timed-out OS request remains pending until its callback drains. A late
/// unmount must never start ejection, nor allow recovery to release its bridge.
actor DiskEjection: DiskEjectionService {
    static let shared = DiskEjection()
    typealias Factory = @Sendable (DiskEjectionRequest) async throws -> any DiskEjectionHandle
    private struct Entry {
        let id: UUID
        let path: String
        let operation: Task<Void, Never>
        let timer: Task<Void, Never>
        let trace: DiskEjectionDiagnostics.Trace
        var reply: CheckedContinuation<Void, any Error>?
    }
    private let factory: Factory
    private let timeout: Duration
    private let now: @Sendable () -> ContinuousClock.Instant
    private let waitUntil: @Sendable (ContinuousClock.Instant) async throws -> Void
    private let diagnostics: DiskEjectionDiagnostics.Observer
    private var entries: [String: Entry] = [:]
    private var drainWaiters: [UUID: (path: String, reply: CheckedContinuation<Bool, Never>)] = [:]

    init(
        timeout: Duration = .seconds(30),
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        waitUntil: @escaping @Sendable (ContinuousClock.Instant) async throws -> Void = {
            try await Task.sleep(until: $0, clock: .continuous)
        }, diagnostics: @escaping DiskEjectionDiagnostics.Observer = DiskEjectionDiagnostics.log,
        factory: @escaping Factory = { try DiskArbitrationEjectionHandle(request: $0) }
    ) {
        self.timeout = timeout
        self.now = now
        self.waitUntil = waitUntil
        self.factory = factory
        self.diagnostics = diagnostics
    }

    func pendingImagePaths() -> Set<String> { Set(entries.values.map(\.path)) }

    func waitForPendingEjection(of image: URL, timeout: Duration) async -> Bool {
        let path = image.standardizedFileURL.path
        guard entries.values.contains(where: { $0.path == path }) else { return true }
        guard timeout > .zero, drainWaiters.count < 128 else { return false }
        let id = UUID()
        let deadline = now().advanced(by: timeout)
        let waitUntil = self.waitUntil
        let timer = Task { [self] in
            do { try await waitUntil(deadline) } catch { return }
            resolveDrain(id, ended: false)
        }
        defer { timer.cancel() }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { reply in
                if Task.isCancelled {
                    reply.resume(returning: false)
                } else {
                    drainWaiters[id] = (path, reply)
                }
            }
        } onCancel: {
            Task { await self.resolveDrain(id, ended: false) }
        }
    }

    private func resolveDrain(_ id: UUID, ended: Bool) {
        drainWaiters.removeValue(forKey: id)?.reply.resume(returning: ended)
    }

    func eject(
        device: String, image: URL, unmountDevices: [String] = [],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        try await performEjection(
            device: device, image: image, unmountDevices: unmountDevices,
            force: false, mediaIdentifiers: [:], validate: validate)
    }

    func ejectConfirmed(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        guard !mediaIdentifiers.isEmpty else { throw AttachmentError.imageIdentityChanged }
        try await performEjection(
            device: device, image: image, unmountDevices: unmountDevices,
            force: false, mediaIdentifiers: mediaIdentifiers, validate: validate)
    }

    func forceEject(
        device: String, image: URL, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        try await performEjection(
            device: device, image: image, unmountDevices: unmountDevices,
            force: true, mediaIdentifiers: mediaIdentifiers, validate: validate)
    }

    private func performEjection(
        device: String, image: URL, unmountDevices: [String], force: Bool,
        mediaIdentifiers: [String: UInt64],
        validate: @escaping @Sendable () async throws -> Void
    ) async throws {
        let unmountDevices = unmountDevices.isEmpty ? [device] : unmountDevices
        guard device.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil,
            unmountDevices.last == device, Set(unmountDevices).count == unmountDevices.count,
            unmountDevices.count <= 128,
            unmountDevices.allSatisfy({
                $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil
            }),
            image.isFileURL, timeout > .zero, timeout <= .seconds(120)
        else { throw ProtocolError.invalidState }
        guard
            (!force && mediaIdentifiers.isEmpty)
                || (Set(mediaIdentifiers.keys) == Set(unmountDevices)
                    && mediaIdentifiers.values.allSatisfy { $0 != 0 })
        else { throw AttachmentError.imageIdentityChanged }
        try Task.checkCancellation()
        let path = image.standardizedFileURL.path
        guard entries[device] == nil, !entries.values.contains(where: { $0.path == path }) else {
            throw AttachmentError.recoveryRequired
        }
        guard entries.count < 128 else { throw ProtocolError.limitExceeded("disk ejections") }
        let id = UUID()
        let trace = DiskEjectionDiagnostics.Trace(
            id: id, force: force, targetCount: unmountDevices.count, observer: diagnostics)
        let deadline = now().advanced(by: timeout)
        let request = DiskEjectionRequest(
            device: device, unmountDevices: unmountDevices, deadline: deadline,
            force: force, mediaIdentifiers: mediaIdentifiers, trace: trace)
        let factory = self.factory
        let now = self.now
        let waitUntil = self.waitUntil
        try await withCheckedThrowingContinuation { reply in
            trace.record(.begin, awaitingReply: true)
            // Once requested, finish the bounded ejection even if the caller cancels.
            let operation = Task.detached { [self] in
                do {
                    func check() throws {
                        try Task.checkCancellation()
                        guard now() < deadline else { throw ProtocolError.timedOut }
                    }
                    try check()
                    let handle = try await factory(request)
                    try check()
                    try await handle.unmount()
                    try check()
                    try await validate()
                    try check()
                    try await handle.eject()
                    try check()
                    await finish(device, id: id, result: .success(()))
                } catch {
                    await finish(device, id: id, result: .failure(error))
                }
            }
            let timer = Task { [self] in
                do {
                    try await waitUntil(deadline)
                    try Task.checkCancellation()
                    expire(device, id: id)
                } catch {}
            }
            entries[device] = Entry(
                id: id, path: path, operation: operation, timer: timer, trace: trace, reply: reply)
        }
    }

    private func expire(_ device: String, id: UUID) {
        guard var entry = entries[device], entry.id == id, let reply = entry.reply else { return }
        entry.reply = nil
        entries[device] = entry
        entry.operation.cancel()
        entry.trace.record(.deadline, outcome: .timedOut, awaitingReply: false)
        reply.resume(throwing: ProtocolError.timedOut)
    }

    private func finish(_ device: String, id: UUID, result: Result<Void, any Error>) {
        guard let entry = entries[device], entry.id == id else { return }
        entries.removeValue(forKey: device)
        entry.timer.cancel()
        let outcome: DiskEjectionDiagnostics.Outcome
        let code: Int
        switch result {
        case .success: (outcome, code) = (.success, 0)
        case .failure(let error): (outcome, code) = DiskEjectionDiagnostics.failure(error)
        }
        entry.trace.record(
            .finished, outcome: outcome, errorCode: code, awaitingReply: entry.reply != nil)
        entry.reply?.resume(with: result)
        guard !entries.values.contains(where: { $0.path == entry.path }) else { return }
        for (id, waiter) in drainWaiters where waiter.path == entry.path {
            resolveDrain(id, ended: true)
        }
    }
}
