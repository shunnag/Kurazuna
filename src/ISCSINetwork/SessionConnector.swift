import Foundation
import ISCSICore

public struct SessionConnection: Sendable {
    public let session: ISCSISession
    public let portal: Portal
    public let redirects: [LoginRedirect]
    public let permanentRedirects: [PermanentPortalRedirect]
    public let invalidatedRedirectSources: [Portal]
    public let contactedPortals: [Portal]

    public init(
        session: ISCSISession, portal: Portal, redirects: [LoginRedirect] = [],
        permanentRedirects: [PermanentPortalRedirect] = [],
        invalidatedRedirectSources: [Portal] = [], contactedPortals: [Portal]? = nil
    ) {
        self.session = session
        self.portal = portal
        self.redirects = redirects
        self.permanentRedirects = permanentRedirects
        self.invalidatedRedirectSources = invalidatedRedirectSources
        self.contactedPortals = contactedPortals ?? [portal]
    }
}

/// Follows login redirects only. A ready session is never reconnected or replayed here.
public enum SessionConnector {
    public static func connect(
        portal: Portal, configuration: LoginConfiguration, timeout: Duration = .seconds(45),
        cachedRedirects: [PermanentPortalRedirect] = [],
        localNetworkAccessWait: LocalNetworkAccessWait? = nil
    ) async throws -> SessionConnection {
        try await connect(
            addresses: [TargetAddress(portal: portal)], configuration: configuration,
            timeout: timeout, cachedRedirects: cachedRedirects,
            localNetworkAccessWait: localNetworkAccessWait)
    }

    public static func connect(
        addresses: [TargetAddress], configuration: LoginConfiguration,
        timeout: Duration = .seconds(45), cachedRedirects: [PermanentPortalRedirect] = [],
        localNetworkAccessWait: LocalNetworkAccessWait? = nil
    ) async throws -> SessionConnection {
        try await connect(
            addresses: addresses, configuration: configuration, timeout: timeout,
            cachedRedirects: cachedRedirects, clock: .continuous,
            localNetworkAccessWait: localNetworkAccessWait,
            factory: {
                try TCPTransport(
                    portal: $0, timeout: $1, waitForConnectivity: false,
                    localNetworkAccessWait: localNetworkAccessWait)
            })
    }

    static func connect(
        portal: Portal, configuration: LoginConfiguration, timeout: Duration = .seconds(45),
        maximumRedirects: Int = 4, maximumAttempts: Int = 16,
        cachedRedirects: [PermanentPortalRedirect] = [], clock: SessionClock,
        localNetworkAccessWait: LocalNetworkAccessWait? = nil,
        factory: @escaping @Sendable (Portal, TimeInterval) throws -> any ConnectableByteTransport
    ) async throws -> SessionConnection {
        try await connect(
            addresses: [TargetAddress(portal: portal)], configuration: configuration,
            timeout: timeout,
            maximumRedirects: maximumRedirects, maximumAttempts: maximumAttempts,
            cachedRedirects: cachedRedirects, clock: clock,
            localNetworkAccessWait: localNetworkAccessWait,
            factory: factory)
    }

    static func connect(
        addresses: [TargetAddress], configuration: LoginConfiguration,
        timeout: Duration = .seconds(45),
        maximumRedirects: Int = 4, maximumAttempts: Int = 16,
        cachedRedirects: [PermanentPortalRedirect] = [], clock: SessionClock,
        localNetworkAccessWait: LocalNetworkAccessWait? = nil,
        factory: @escaping @Sendable (Portal, TimeInterval) throws -> any ConnectableByteTransport
    ) async throws -> SessionConnection {
        guard timeout > .zero, timeout <= .seconds(300),
            (0...8).contains(maximumRedirects), (1...32).contains(maximumAttempts),
            !addresses.isEmpty, addresses.count <= 16, cachedRedirects.count <= 128,
            Set(cachedRedirects.map { RedirectingLogin.key($0.source) }).count
                == cachedRedirects.count
        else { throw ProtocolError.malformed("login connection limits") }
        var unique: [TargetAddress] = []
        for address in addresses {
            if let previous = unique.first(where: { $0.portal.isSameEndpoint(as: address.portal) })
            {
                guard previous.portalGroupTag == address.portalGroupTag else {
                    throw ProtocolError.malformed("conflicting target portal group")
                }
            } else {
                unique.append(address)
            }
        }
        let baseDeadline = clock.now.advanced(by: timeout)
        let initialWait = localNetworkAccessWait?.elapsed ?? .zero
        let deadline: @Sendable () -> ContinuousClock.Instant = {
            baseDeadline.advanced(
                by: localNetworkAccessWait?.additionalTime(since: initialWait) ?? .zero)
        }
        let attempt = RedirectingLogin(
            addresses: unique, configuration: configuration, deadline: deadline,
            maximumRedirects: maximumRedirects, maximumAttempts: maximumAttempts,
            cachedRedirects: cachedRedirects, clock: clock,
            localNetworkAccessWait: localNetworkAccessWait, factory: factory)
        return try await withTaskCancellationHandler {
            do {
                let result = try await withThrowingTaskGroup(of: SessionConnection.self) { group in
                    group.addTask { try await attempt.open() }
                    group.addTask {
                        while true {
                            try await clock.sleep(until: deadline())
                            try Task.checkCancellation()
                            if clock.now >= deadline() {
                                let error: ProtocolError =
                                    localNetworkAccessWait?.isWaiting == true
                                    ? .localNetworkAccessRequired : .timedOut
                                await attempt.abort(error)
                                throw error
                            }
                        }
                    }
                    defer { group.cancelAll() }
                    do {
                        guard let result = try await group.next() else {
                            throw ProtocolError.connectionClosed
                        }
                        try await attempt.validate()
                        return result
                    } catch {
                        try await attempt.validate()
                        throw error
                    }
                }
                // Cancellation/draining can suspend after the login itself completed.
                try await attempt.validate()
                return result
            } catch {
                await attempt.abort(error)
                throw error
            }
        } onCancel: {
            Task { await attempt.abort(CancellationError()) }
        }
    }
}

private actor RedirectingLogin {
    private let configuration: LoginConfiguration
    private let deadline: @Sendable () -> ContinuousClock.Instant
    private let localNetworkAccessWait: LocalNetworkAccessWait?
    private let maximumRedirects: Int
    private let maximumAttempts: Int
    private let clock: SessionClock
    private let factory: @Sendable (Portal, TimeInterval) throws -> any ConnectableByteTransport
    private struct Candidate {
        let address: TargetAddress
        let depth: Int
        var permanent: [PermanentPortalRedirect] = []
        var invalidated: [Portal] = []
        var useCache = true
        var contacted: [Portal] = []

        mutating func invalidate(_ portal: Portal) {
            permanent.removeAll { $0.source.isSameEndpoint(as: portal) }
            if !invalidated.contains(where: { $0.isSameEndpoint(as: portal) }) {
                invalidated.append(portal)
            }
        }
    }
    private var candidates: [Candidate]
    private let cachedRedirects: [PermanentPortalRedirect]
    private var expandedCaches: Set<String> = []
    private var visited: Set<String> = []
    private var redirects: [LoginRedirect] = []
    private var currentSession: ISCSISession?
    private var currentTransport: (any ConnectableByteTransport)?
    private var failure: (any Error)?

    init(
        addresses: [TargetAddress], configuration: LoginConfiguration,
        deadline: @escaping @Sendable () -> ContinuousClock.Instant,
        maximumRedirects: Int, maximumAttempts: Int, cachedRedirects: [PermanentPortalRedirect],
        clock: SessionClock, localNetworkAccessWait: LocalNetworkAccessWait?,
        factory: @escaping @Sendable (Portal, TimeInterval) throws -> any ConnectableByteTransport
    ) {
        self.configuration = configuration
        self.deadline = deadline
        self.maximumRedirects = maximumRedirects
        self.maximumAttempts = maximumAttempts
        self.cachedRedirects = cachedRedirects
        self.clock = clock
        self.localNetworkAccessWait = localNetworkAccessWait
        self.factory = factory
        var queued: Set<String> = []
        candidates = addresses.filter { queued.insert(Self.key($0.portal)).inserted }.map {
            Candidate(address: $0, depth: 0)
        }
    }

    func validate() throws {
        if let failure { throw failure }
        guard clock.now < deadline() else {
            throw localNetworkAccessWait?.isWaiting == true
                ? ProtocolError.localNetworkAccessRequired : ProtocolError.timedOut
        }
        try Task.checkCancellation()
    }

    func abort(_ error: any Error) async {
        if failure == nil { failure = error }
        let session = currentSession
        let transport = currentTransport
        currentSession = nil
        currentTransport = nil
        if let session { await session.close() } else if let transport { await transport.close() }
    }

    func open() async throws -> SessionConnection {
        var lastError: (any Error)?
        while !candidates.isEmpty {
            try validate()
            var candidate = candidates.removeFirst()
            if candidate.useCache,
                let cached = cachedRedirects.first(where: {
                    $0.source.isSameEndpoint(as: candidate.address.portal)
                })
            {
                if candidate.depth < maximumRedirects,
                    expandedCaches.insert(Self.key(cached.source)).inserted
                {
                    var fallback = candidate
                    fallback.useCache = false
                    fallback.invalidate(cached.source)
                    candidates.insert(fallback, at: 0)
                    try enqueue(cached.destinations, after: candidate, permanent: cached)
                    continue
                }
                // A stale/cyclic hint may not prevent consulting its original endpoint.
                candidate.invalidate(cached.source)
            }
            guard visited.insert(Self.key(candidate.address.portal)).inserted else { continue }
            guard visited.count <= maximumAttempts else {
                throw ProtocolError.limitExceeded("login connection attempts")
            }
            let now = clock.now
            let budget = now.duration(to: deadline()) / (candidates.count + 1)
            let attemptDeadline = now.advanced(by: budget)
            let initialWait = localNetworkAccessWait?.elapsed ?? .zero
            let components = budget.components
            let seconds = Double(components.seconds) + Double(components.attoseconds) / 1e18
            let transport = try factory(candidate.address.portal, max(0.1, min(15, seconds)))
            currentTransport = transport
            let session = try ISCSISession(
                transport: transport, configuration: configuration, clock: clock)
            currentSession = session
            do {
                try validate()
                try await transport.connect()
                try validate()
                let adjustedDeadline = attemptDeadline.advanced(
                    by: localNetworkAccessWait?.additionalTime(since: initialWait) ?? .zero)
                let loginBudget = min(
                    Duration.seconds(30), clock.now.duration(to: adjustedDeadline))
                guard loginBudget > .zero else { throw ProtocolError.timedOut }
                try await session.login(timeout: loginBudget)
                try validate()
                if let expected = candidate.address.portalGroupTag,
                    await session.targetPortalGroupTag != expected
                {
                    throw ProtocolError.malformed("target portal group")
                }
                return SessionConnection(
                    session: session, portal: candidate.address.portal, redirects: redirects,
                    permanentRedirects: candidate.permanent,
                    invalidatedRedirectSources: candidate.invalidated,
                    contactedPortals: candidate.contacted + [candidate.address.portal])
            } catch {
                // Login rejection, including redirection, ends the old TCP connection.
                await session.close()
                currentSession = nil
                currentTransport = nil
                try validate()
                if case ProtocolError.loginRedirect(let redirect) = error {
                    guard candidate.depth < maximumRedirects else {
                        throw ProtocolError.limitExceeded("login redirects")
                    }
                    redirects.append(redirect)
                    let permanent =
                        redirect.kind == .permanent
                        ? try PermanentPortalRedirect(
                            source: candidate.address.portal, destinations: redirect.addresses)
                        : nil
                    try enqueue(
                        redirect.addresses, after: candidate, permanent: permanent,
                        contactedSource: true)
                    guard !candidates.isEmpty else {
                        throw ProtocolError.limitExceeded("login redirect loop")
                    }
                } else {
                    if error is CancellationError { throw error }
                    if let protocolError = error as? ProtocolError {
                        switch protocolError {
                        case .connectionClosed, .timedOut: break
                        default: throw error
                        }
                    }
                    guard !candidates.isEmpty else { throw error }
                    lastError = error
                }
            }
        }
        throw lastError ?? ProtocolError.limitExceeded("login redirect loop")
    }

    private func enqueue(
        _ portals: [Portal], after candidate: Candidate, permanent: PermanentPortalRedirect?,
        contactedSource: Bool = false
    ) throws {
        var unique: Set<String> = []
        let next = portals.filter {
            let key = Self.key($0)
            return !visited.contains(key) && unique.insert(key).inserted
                && !$0.isSameEndpoint(as: candidate.address.portal)
        }
        // Prefer the newly observed route when the same endpoint is already queued.
        // Otherwise a successful alternate would lose the redirect that led to it.
        candidates.removeAll { unique.contains(Self.key($0.address.portal)) }
        let children = try next.map { portal in
            var child = Candidate(
                address: TargetAddress(portal: portal), depth: candidate.depth + 1,
                permanent: candidate.permanent, invalidated: candidate.invalidated,
                contacted: candidate.contacted + (contactedSource ? [candidate.address.portal] : [])
            )
            if let permanent {
                child.permanent.removeAll { $0.source.isSameEndpoint(as: permanent.source) }
                child.permanent.append(try permanent.preferring(portal))
            }
            return child
        }
        candidates.insert(contentsOf: children, at: 0)
    }

    static func key(_ portal: Portal) -> String {
        let parts = portal.host.split(
            separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        let host = parts[0].lowercased() + (parts.count == 2 ? "%" + String(parts[1]) : "")
        return "\(host)\0\(portal.port)"
    }
}
