import Dispatch
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform

/// The production login, probe and volume factory, shared by the FSKit resource
/// controller and process-isolated protocol tests. Credential ownership stays explicit.
public enum LUNVolumeFactory {
    /// - Parameter recoveryWindow: How long a blocked command waits, in awake time, for a
    ///   lost connection to be reestablished before it fails. See `SessionRecovery`.
    public static func open(
        _ descriptor: ConnectionDescriptor, readOnly: Bool, credentials: any CredentialStore,
        recoveryWindow: Duration = SessionRecovery.defaultRecoveryWindow
    ) async throws -> LUNImageVolume {
        try await withInitializationDeadline(timeout: .seconds(45)) {
            try await openSession(
                descriptor, readOnly: readOnly || descriptor.readOnly, credentials: credentials,
                recoveryWindow: recoveryWindow)
        }
    }

    /// Explicitly selected raw writable route. The trusted source supplies the real continuous
    /// fence and transport; absence or failure never falls back to an ordinary connection.
    public static func openReserved(
        _ descriptor: ConnectionDescriptor, readOnly: Bool, credentials: any CredentialStore,
        source: any ReservedLUNSource, unmountBehavior: ReservedUnmountBehavior = .abandon
    ) async throws -> LUNImageVolume {
        guard !readOnly, !descriptor.readOnly else { throw POSIXError(.EROFS) }
        guard descriptor.imagePresentation == .raw else { throw POSIXError(.ENOTSUP) }
        let deadline = ContinuousClock.now.advanced(by: .seconds(45))
        return try await withInitializationDeadline(deadline: deadline) {
            let configuration = try await loginConfiguration(descriptor, credentials: credentials)
            let identity = try descriptor.resourceIdentity
            let preparation = try await source.prepare(for: descriptor, deadline: deadline)
            // Own a late return before checking cancellation. A rejected second claimant must
            // never close the first claimant's still-live transport.
            try preparation.claim()
            var session: ISCSISession?
            var reserved: ReservedRemoteDisk?
            do {
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                guard preparation.descriptor == descriptor else { throw ProtocolError.invalidState }
                let liveOwner = UUID()
                let recoveryControl = try preparation.makeRecoveryControl?(liveOwner)
                if let recoveryControl {
                    guard recoveryControl.liveVolumeID == liveOwner,
                        recoveryControl.resourceIdentity == identity
                    else { throw ProtocolError.invalidState }
                }
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                // Existing ownership is not permission to reacquire or clean up an orphan.
                guard try preparation.store.load().isEmpty else { throw ProtocolError.invalidState }
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                let opened = try ISCSISession(
                    transport: preparation.transport, configuration: configuration)
                session = opened
                try await opened.login()
                if let group = descriptor.portalGroupTag,
                    await opened.targetPortalGroupTag != group
                {
                    throw ProtocolError.malformed("target portal group")
                }
                let information = try await DiskProbe.diskInformation(
                    session: opened, lun: descriptor.lun)
                guard information.isWriteProtected != true else { throw POSIXError(.EROFS) }
                let limits = try await DiskProbe.blockLimits(session: opened, lun: descriptor.lun)
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                let acquired = try await ReservedRemoteDisk.acquire(
                    session: opened, lun: descriptor.lun, lease: preparation.lease,
                    store: preparation.store, expectedCapacity: information.capacity,
                    maximumTransferBlocks: limits?.maximumTransferBlocks ?? 0)
                reserved = acquired
                guard acquired.disk.capacity == information.capacity else {
                    throw ProtocolError.invalidState
                }
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                // This is the source's descriptor-bound logical portal, including when its
                // trusted transport is a tunnel. It is not independent endpoint observation.
                let route = try ConnectionRouteReport(
                    resourceIdentity: identity, connectedPortal: descriptor.portal,
                    contactedPortals: [descriptor.portal], permanentRedirects: [],
                    creationOrder: DispatchTime.now().uptimeNanoseconds)
                return LUNImageVolume(
                    reservedDisk: acquired, identifier: ISCSIFileSystem.identifier(for: descriptor),
                    resourceIdentity: identity, connectionRoute: route,
                    owner: liveOwner, recoveryControl: recoveryControl,
                    unmountBehavior: unmountBehavior)
            } catch {
                if let reserved {
                    await reserved.close()
                } else if let session {
                    await session.close()
                } else {
                    await preparation.transport.close()
                }
                throw error
            }
        }
    }

    static func withInitializationDeadline(
        timeout: Duration,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        sleepUntil: @escaping @Sendable (ContinuousClock.Instant) async throws -> Void = {
            try await Task.sleep(until: $0, clock: .continuous)
        }, operation: @escaping @Sendable () async throws -> LUNImageVolume
    ) async throws -> LUNImageVolume {
        guard timeout > .zero, timeout <= .seconds(300) else { throw ProtocolError.invalidState }
        let deadline = now().advanced(by: timeout)
        return try await withInitializationDeadline(
            deadline: deadline, now: now, sleepUntil: sleepUntil, operation: operation)
    }

    private static func withInitializationDeadline(
        deadline: ContinuousClock.Instant,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        sleepUntil: @escaping @Sendable (ContinuousClock.Instant) async throws -> Void = {
            try await Task.sleep(until: $0, clock: .continuous)
        }, operation: @escaping @Sendable () async throws -> LUNImageVolume
    ) async throws -> LUNImageVolume {
        try Task.checkCancellation()
        let volume = try await withThrowingTaskGroup(of: LUNImageVolume.self) { group in
            group.addTask {
                let volume = try await operation()
                if Task.isCancelled {
                    await volume.shutdown()
                    throw CancellationError()
                }
                guard now() < deadline else {
                    await volume.shutdown()
                    throw ProtocolError.timedOut
                }
                return volume
            }
            group.addTask {
                try await sleepUntil(deadline)
                throw ProtocolError.timedOut
            }
            defer { group.cancelAll() }
            guard let volume = try await group.next() else { throw ProtocolError.invalidState }
            return volume
        }
        // Draining the cancelled timer can suspend after the opener completed.
        if Task.isCancelled {
            await volume.shutdown()
            throw CancellationError()
        }
        guard now() < deadline else {
            await volume.shutdown()
            throw ProtocolError.timedOut
        }
        return volume
    }

    private static func loginConfiguration(
        _ descriptor: ConnectionDescriptor, credentials: any CredentialStore
    ) async throws -> LoginConfiguration {
        var chap: CHAPCredentials?
        if let username = descriptor.chapUsername {
            chap = try await credentials.credentials(
                context: CredentialContext(
                    profileID: descriptor.profileID, portal: descriptor.portal,
                    username: username, credentialID: descriptor.credentialID,
                    targetUsername: descriptor.targetCHAPUsername))
        }
        try Task.checkCancellation()
        return try LoginConfiguration(
            initiatorName: descriptor.initiatorName,
            targetName: descriptor.targetName, credentials: chap, isid: descriptor.isid)
    }

    private static func openSession(
        _ descriptor: ConnectionDescriptor, readOnly: Bool, credentials: any CredentialStore,
        recoveryWindow: Duration
    ) async throws -> LUNImageVolume {
        // The configuration, including any CHAP secrets, stays in memory for logging in again.
        // The Keychain item may be unavailable later, for example while the screen is locked.
        let configuration = try await loginConfiguration(descriptor, credentials: credentials)
        let addresses = [
            TargetAddress(portal: descriptor.portal, portalGroupTag: descriptor.portalGroupTag)
        ]
        let connection = try await SessionConnector.connect(
            addresses: addresses, configuration: configuration)
        let session = connection.session
        var recovering: RecoveringSession?
        do {
            let information = try await DiskProbe.diskInformation(
                session: session, lun: descriptor.lun)
            guard readOnly || information.isWriteProtected != true else {
                throw POSIXError(.EROFS)
            }
            let limits = try await DiskProbe.blockLimits(session: session, lun: descriptor.lun)
            // Compared after every reconnection. A device without usable names must keep
            // reporting none. A device error here leaves the names unknown and uncompared; it
            // never prevents opening the disk.
            let designator: LogicalUnitFingerprint.Designator
            do {
                designator =
                    try await DiskProbe.logicalUnitDesignator(
                        session: session, lun: descriptor.lun
                    ).map { .present($0) } ?? .absent
            } catch is DiskProbeIssue {
                designator = .notCaptured
            }
            try Task.checkCancellation()
            let route = try ConnectionRouteReport(
                resourceIdentity: descriptor.resourceIdentity,
                connectedPortal: connection.portal,
                contactedPortals: connection.contactedPortals,
                permanentRedirects: connection.permanentRedirects,
                creationOrder: DispatchTime.now().uptimeNanoseconds)
            // Reconnect to the same address with the same ISID (session reinstatement), using
            // the permanent redirects learned now. The first login's portal group must answer.
            let redirects = connection.permanentRedirects
            let opened = try await RecoveringSession.recovering(
                session: session, lun: descriptor.lun,
                fingerprint: LogicalUnitFingerprint(
                    information: information, designator: designator),
                recoveryWindow: recoveryWindow,
                connect: { timeout in
                    try await SessionConnector.connect(
                        addresses: addresses, configuration: configuration, timeout: timeout,
                        cachedRedirects: redirects
                    ).session
                })
            recovering = opened
            let disk = RemoteDisk(
                connection: opened, readOnly: readOnly,
                maximumTransferBlocks: limits?.maximumTransferBlocks ?? 0)
            let image: any ImageDisk
            switch descriptor.imagePresentation {
            case .raw: image = disk
            case .udsp: image = try SparseImageDisk(disk)
            }
            return LUNImageVolume(
                disk: image, identifier: ISCSIFileSystem.identifier(for: descriptor),
                resourceIdentity: try descriptor.resourceIdentity,
                sourceCapacity: information.capacity, connectionRoute: route)
        } catch {
            // Closing the recovering session also stops it from reconnecting.
            if let recovering { await recovering.close() } else { await session.closeGracefully() }
            throw error
        }
    }
}
