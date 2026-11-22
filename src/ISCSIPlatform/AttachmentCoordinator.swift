import Foundation
import ISCSICore
import Synchronization

/// Persist intent before each external side effect. Recover by inspecting current resources;
/// persisted device names are intentionally absent from the journal.
public actor AttachmentCoordinator {
    private let backend: any AttachmentBackend
    private let journal: any AttachmentJournal
    private var records: [UUID: AttachedDisk]
    private var busyKeys: Set<String> = []
    private var preparingConnections: Set<UUID> = []
    private var restored: Bool
    private var restoring = false
    private var journalUnavailable = false
    private var inventoryVerified = false
    private var refreshing = false
    private var generation = UUID()
    private var forceEjectionCandidates: Set<UUID> = []
    private var forceEjectionRequests: [UUID: ForceEjectionRequest] = [:]
    /// When a reconnecting disk's forced release is offered; see `AttachedDisk`.
    private let now: @Sendable () -> ContinuousClock.Instant
    public private(set) var untrackedBridgeURLs: [URL] = []

    public init(
        backend: any AttachmentBackend, journal: any AttachmentJournal = MemoryAttachmentJournal(),
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) throws {
        self.backend = backend
        self.journal = journal
        self.now = now
        let entries: [AttachmentJournalEntry]
        do { entries = try journal.load() } catch { throw AttachmentError.journalUnreadable }
        guard entries.count <= 128, Set(entries.map(\.id)).count == entries.count else {
            throw ProtocolError.malformed("connection journal entries")
        }
        records = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, AttachedDisk(entry: $0)) })
        restored = false
    }

    public var disks: [AttachedDisk] {
        let instant = now()
        return records.values.sorted { $0.id.uuidString < $1.id.uuidString }.map {
            var disk = $0
            disk.evaluateReconnecting(at: instant)
            return disk
        }
    }

    /// Records an observed connection state. A disk first seen reconnecting is stamped then;
    /// any other state ends that episode (see `AttachedDisk.connectionState`).
    private func observe(_ state: DiskConnectionState, on record: inout AttachedDisk) {
        record.connectionState = state
        record.evaluateReconnecting(at: now())
    }
    private var operationReady: Bool { restored && !restoring && !journalUnavailable }
    /// False while the journal must be read again, or is being restored: every operation is
    /// refused (`recoveryRequired`) until an explicit recovery.
    public var isOperationReady: Bool { operationReady }
    public var recoveryReady: Bool {
        recoveryState == .ready
    }
    public var recoveryState: AttachmentRecoveryState {
        guard operationReady, inventoryVerified, untrackedBridgeURLs.isEmpty else {
            return .needsInspection
        }
        let pending = records.values.filter(\.verificationFailed)
        guard !pending.isEmpty else { return .ready }
        guard
            pending.allSatisfy({
                $0.resourceCleanupError != nil && $0.phase == .unmountingBridge
                    && $0.attachment == nil
            }), Set(records.values.map { identity($0.descriptor) }).count == records.count
        else {
            return .needsInspection
        }
        return .resourceCleanupPending
    }

    public func restore() async throws {
        guard !restoring, busyKeys.isEmpty else { throw ProtocolError.busy }
        restoring = true
        forceEjectionCandidates.removeAll()
        forceEjectionRequests.removeAll()
        generation = UUID()
        restored = false
        inventoryVerified = false
        for id in records.keys {
            records[id]?.resourceCleanupError = nil
            records[id]?.forcedReleaseRefused = false
        }
        defer { restoring = false }
        let entries: [AttachmentJournalEntry]
        do { entries = try journal.load() } catch {
            journalUnavailable = true
            throw AttachmentError.journalUnreadable
        }
        guard entries.count <= 128, Set(entries.map(\.id)).count == entries.count else {
            throw ProtocolError.malformed("connection journal entries")
        }
        for entry in entries {
            if var known = records[entry.id] {
                guard known.descriptor == entry.descriptor, known.bridgeURL == entry.bridgeURL
                else {
                    throw AttachmentError.ownershipUnverified
                }
                known.phase = entry.phase
                records[entry.id] = known
            } else {
                records[entry.id] = AttachedDisk(entry: entry)
            }
        }
        var firstError: (any Error)?
        for id in records.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard var record = records[id] else { continue }
            do {
                let inspection = try await backend.inspectBridge(
                    record.descriptor, at: record.bridgeURL)
                switch inspection.ownership {
                case .absent:
                    guard inspection.attachment == nil else {
                        throw AttachmentError.ownershipUnverified
                    }
                    // rmdir refuses a late mount. Recovery never forcibly unmounts a resource.
                    try await backend.discardEmptyBridge(record.descriptor, at: record.bridgeURL)
                    try remove(id)
                case .verified:
                    record.attachment = inspection.attachment
                    observe(inspection.connectionState, on: &record)
                    record.connectionRoute = verifiedRoute(
                        inspection, descriptor: record.descriptor)
                    record.verificationFailed = false
                    record.resourceCleanupError = nil
                    if inspection.attachment == nil {
                        record.phase = .unmountingBridge
                    } else if record.phase == .mountingBridge || record.phase == .attachingImage {
                        record.phase = .connected
                    }
                    try checkpoint(record)
                case .conflicting: throw AttachmentError.ownershipUnverified
                }
            } catch {
                recordFailure(id, error)
                if firstError == nil { firstError = error }
            }
        }
        // Older records may contain the same logical disk under different portal addresses.
        // Keep every mount for explicit ejection; do not silently pick one or reconnect it.
        let duplicates = Dictionary(grouping: records.values, by: { identity($0.descriptor) })
            .values.filter { $0.count > 1 }
        for group in duplicates {
            for record in group {
                records[record.id]?.verificationFailed = true
                records[record.id]?.resourceCleanupError = nil
            }
        }
        if !duplicates.isEmpty, firstError == nil {
            firstError = AttachmentError.duplicateConnections
        }
        do {
            untrackedBridgeURLs = try await backend.untrackedBridges(
                excluding: records.values.map(\.bridgeURL))
            inventoryVerified = true
            if !untrackedBridgeURLs.isEmpty, firstError == nil {
                firstError = AttachmentError.ownershipUnverified
            }
        } catch {
            if firstError == nil { firstError = error }
        }
        restored = true
        if let firstError { throw firstError }
        journalUnavailable = false
    }

    public func connect(_ descriptor: ConnectionDescriptor) async throws -> AttachedDisk {
        guard recoveryReady else {
            throw AttachmentError.recoveryRequired
        }
        guard records.count + preparingConnections.count < 128 else {
            throw ProtocolError.limitExceeded("connected disks")
        }
        let key = identity(descriptor)
        guard !busyKeys.contains(key),
            !records.values.contains(where: { identity($0.descriptor) == key })
        else {
            throw AttachmentError.alreadyConnected
        }
        busyKeys.insert(key)
        defer { busyKeys.remove(key) }
        let id = UUID()
        preparingConnections.insert(id)
        defer { preparingConnections.remove(id) }
        let descriptor = try descriptor.assigningMountID(id)
        let bridge = try await backend.bridgeURL(for: id)
        try Task.checkCancellation()
        // Another operation may have failed to save while this preparation was suspended.
        guard recoveryReady else { throw AttachmentError.recoveryRequired }
        let entry = try AttachmentJournalEntry(
            id: id, descriptor: descriptor, bridgeURL: bridge, phase: .mountingBridge)
        var record = AttachedDisk(entry: entry)
        record.verificationFailed = false
        try checkpoint(record)
        preparingConnections.remove(id)  // The durable record now occupies the reserved slot.
        do {
            try await backend.mountBridge(descriptor, at: bridge)
            try requireAvailableJournal()
            try Task.checkCancellation()
            record.phase = .attachingImage
            try checkpoint(record)
            record.attachment = try await backend.attachImage(descriptor, at: bridge)
            try requireAvailableJournal()
            try Task.checkCancellation()
            let inspection = try await backend.inspectBridge(descriptor, at: bridge)
            try requireAvailableJournal()
            try Task.checkCancellation()
            guard inspection.ownership == .verified,
                inspection.attachment?.device == record.attachment?.device
            else { throw AttachmentError.ownershipUnverified }
            observe(inspection.connectionState, on: &record)
            record.connectionRoute = verifiedRoute(inspection, descriptor: descriptor)
            guard record.connectionState != .interrupted, record.connectionState != .closed else {
                throw AttachmentError.connectionInterrupted
            }
            record.phase = .connected
            try checkpoint(record)
            return record
        } catch {
            // If a save may have partially committed, retain the durable intent and stop I/O.
            if !journalUnavailable {
                do { try await Task.detached { try await self.disconnectRecord(id) }.value } catch {
                    // The durable record remains available for retry.
                }
            }
            throw error
        }
    }

    public func eject(_ id: UUID) async throws {
        guard operationReady else { throw AttachmentError.recoveryRequired }
        guard let record = records[id] else { throw ProtocolError.invalidState }
        let key = identity(record.descriptor)
        guard busyKeys.insert(key).inserted else { throw ProtocolError.busy }
        defer { busyKeys.remove(key) }
        forceEjectionCandidates.remove(id)
        forceEjectionRequests[id] = nil
        do {
            try await disconnectRecord(id)
        } catch {
            offerForcedRelease(id, after: error)
            throw error
        }
    }

    /// Any failed or timed-out ejection of a disk may be followed by a forced release, which
    /// still needs its own observation and the user's explicit confirmation. Cancellation
    /// isn't a failure, and once only connection information remains there's nothing to
    /// force.
    private func offerForcedRelease(_ id: UUID, after error: any Error) {
        guard records[id] != nil, !(error is CancellationError),
            !(error is MountResourceCleanupError)
        else { return }
        forceEjectionCandidates.insert(id)
    }

    public func canPrepareForceEjection(_ id: UUID) -> Bool {
        guard operationReady, var record = records[id], record.resourceCleanupError == nil,
            !record.forcedReleaseRefused
        else { return false }
        record.evaluateReconnecting(at: now())
        return forceEjectionCandidates.contains(id) || record.offersForcedRelease
    }

    /// A forced release that no longer applies: the disk was observed connected again. Its
    /// refusal leaves the disk as observed, connected and usable, never unverified.
    private struct ConnectedAgain: Error {}

    public func cancelForceEjection(_ request: ForceEjectionRequest) {
        if forceEjectionRequests[request.diskID] == request {
            forceEjectionRequests[request.diskID] = nil
        }
    }

    /// Observe the exact resources for a user confirmation. This never ejects anything.
    public func prepareForceEjection(_ id: UUID) async throws -> ForceEjectionRequest {
        guard canPrepareForceEjection(id), let record = records[id] else {
            throw AttachmentError.recoveryRequired
        }
        let key = identity(record.descriptor)
        guard busyKeys.insert(key).inserted else { throw ProtocolError.busy }
        defer { busyKeys.remove(key) }
        do {
            let inspection = try await forcedReleaseInspection(record)
            // Without a failed normal eject, only a disk observed not to be connected qualifies,
            // including one still reconnecting; a stale or failed earlier observation never
            // makes a healthy disk eligible. A disk that reconnects before the release is
            // refused it (see `forceEject`).
            guard forceEjectionCandidates.contains(id) || inspection.connectionState != .connected
            else {
                // Connected again since the offer, for example a server back before the click.
                throw ConnectedAgain()
            }
            let release = try await backend.forcedReleaseIdentity(
                inspection.attachment, descriptor: record.descriptor,
                bridgeURL: record.bridgeURL)
            try requireAvailableJournal()
            guard release.image?.device == inspection.attachment?.device,
                release.image.map({
                    $0.imageURL == record.bridgeURL.appendingPathComponent("Disk.img")
                }) ?? true
            else { throw AttachmentError.imageIdentityChanged }
            let confirmed = try await forcedReleaseInspection(record)
            guard confirmed.ownership == inspection.ownership,
                confirmed.attachment?.device == inspection.attachment?.device
            else { throw AttachmentError.imageIdentityChanged }
            guard
                (confirmed.connectionState == .connected)
                    == (inspection.connectionState == .connected)
            else {
                if confirmed.connectionState == .connected, !forceEjectionCandidates.contains(id) {
                    throw ConnectedAgain()
                }
                throw AttachmentError.imageIdentityChanged
            }
            let request = ForceEjectionRequest(
                id: UUID(), diskID: id,
                displayName: (inspection.attachment ?? record.attachment)?.volumeURLs.first?
                    .lastPathComponent ?? record.descriptor.targetName,
                reportsLostConnection: inspection.connectionState != .connected,
                descriptor: record.descriptor, bridgeURL: record.bridgeURL, release: release)
            forceEjectionRequests[id] = request
            return request
        } catch is ConnectedAgain {
            // Withdraw the offer that the earlier, reconnecting observation made. The forced
            // observation proved ownership from local facts only, so it doesn't replace the
            // ordinary inspection's route; the next health refresh observes the disk again.
            forceEjectionRequests[id] = nil
            if var current = records[id] {
                observe(.connected, on: &current)
                records[id] = current
            }
            throw AttachmentError.recoveryRequired
        } catch {
            // A pending earlier ejection or a transient failure can be observed again later;
            // only a resource proven not to belong to this record withdraws the offer.
            if (error as? AttachmentError) == .ownershipUnverified {
                records[id]?.forcedReleaseRefused = true
            }
            forceEjectionRequests[id] = nil
            records[id]?.verificationFailed = true
            throw error
        }
    }

    /// Consume only this confirmation. Each step re-observes its resource: an unchanged one
    /// is released, an absent one is skipped, and a changed one stops the release. The phase
    /// is saved before each step, so a later confirmed attempt continues where this one
    /// stopped, after a failure or a restart.
    public func forceEject(_ request: ForceEjectionRequest) async throws {
        let id = request.diskID
        guard operationReady, forceEjectionRequests[id] == request,
            canPrepareForceEjection(id), var record = records[id],
            record.descriptor == request.descriptor, record.bridgeURL == request.bridgeURL
        else { throw AttachmentError.recoveryRequired }
        let key = identity(record.descriptor)
        guard busyKeys.insert(key).inserted else { throw ProtocolError.busy }
        defer { busyKeys.remove(key) }
        forceEjectionRequests[id] = nil
        forceEjectionCandidates.remove(id)
        do {
            let inspection = try await forcedReleaseInspection(record)
            guard (inspection.connectionState != .connected) == request.reportsLostConnection
            else { throw AttachmentError.imageIdentityChanged }
            observe(inspection.connectionState, on: &record)
            record.connectionRoute = nil
            // A reconnecting extension would otherwise hold the release while its I/O waits
            // for the server. Ask it to stop, but only once every check on what is released
            // has passed, just before the first step that can't be undone: stopping is
            // irreversible, and a release refused before that leaves the disk able to recover.
            // The release doesn't depend on an answer.
            let stopReconnecting = StopReconnectingOnce(
                backend: backend, descriptor: record.descriptor, bridgeURL: record.bridgeURL,
                enabled: inspection.ownership == .verified)
            if let attachment = inspection.attachment {
                guard attachment.device == request.release.image?.device else {
                    throw AttachmentError.imageIdentityChanged
                }
                record.attachment = attachment
                record.phase = .detachingImage
                try checkpoint(record)
                try await backend.forceReleaseImage(
                    request.release, descriptor: record.descriptor, bridgeURL: record.bridgeURL,
                    beforeReleasing: stopReconnecting.send)
                try requireAvailableJournal()
            }
            record.attachment = nil
            record.phase = .unmountingBridge
            try checkpoint(record)
            try await backend.forceReleaseBridge(
                request.release, descriptor: record.descriptor, bridgeURL: record.bridgeURL,
                beforeReleasing: stopReconnecting.send)
            try requireAvailableJournal()
            try remove(id)
        } catch {
            recordFailure(id, error, preservingBusyVerification: true)
            if (error as? AttachmentError) == .ownershipUnverified {
                records[id]?.forcedReleaseRefused = true
            } else {
                offerForcedRelease(id, after: error)
            }
            throw error
        }
    }

    /// A disk image without its bridge mount, or a bridge that answers with another identity,
    /// doesn't belong to this record and must never be released by force.
    private func forcedReleaseInspection(_ record: AttachedDisk) async throws
        -> AttachmentInspection
    {
        let inspection = try await backend.forcedReleaseInspection(
            record.descriptor, at: record.bridgeURL)
        try requireAvailableJournal()
        guard inspection.ownership != .conflicting,
            inspection.ownership == .verified || inspection.attachment == nil
        else { throw AttachmentError.ownershipUnverified }
        if let known = record.attachment?.device, let observed = inspection.attachment?.device,
            known != observed
        {
            throw AttachmentError.imageIdentityChanged
        }
        return inspection
    }

    /// Read-only observation. Health is never persisted, and stale observations cannot replace
    /// records changed by a connect, eject, or explicit recovery while the backend was suspended.
    public func refreshHealth() async {
        guard operationReady, !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        let epoch = generation
        let candidates = disks.filter {
            $0.phase == .connected && !$0.verificationFailed
                && !busyKeys.contains(identity($0.descriptor))
        }
        guard !candidates.isEmpty else { return }
        let results: [UUID: Result<AttachmentInspection, any Error>]
        do {
            results = try await backend.inspectBridges(candidates.map { try $0.journalEntry() })
        } catch {
            if Task.isCancelled { return }
            results = Dictionary(uniqueKeysWithValues: candidates.map { ($0.id, .failure(error)) })
        }
        guard operationReady, generation == epoch, !Task.isCancelled else { return }
        for snapshot in candidates {
            guard var current = records[snapshot.id], current.phase == .connected,
                !busyKeys.contains(identity(current.descriptor))
            else { continue }
            current.resourceCleanupError = nil
            if case .success(let observation) = results[snapshot.id],
                observation.ownership == .verified,
                observation.attachment?.device == current.attachment?.device,
                observation.attachment != nil
            {
                current.attachment = observation.attachment
                observe(observation.connectionState, on: &current)
                current.connectionRoute = verifiedRoute(observation, descriptor: current.descriptor)
            } else {
                current.verificationFailed = true
                current.connectionState = .unknown
                current.connectionRoute = nil
            }
            records[current.id] = current
        }
    }

    private func verifiedRoute(_ inspection: AttachmentInspection, descriptor: ConnectionDescriptor)
        -> ConnectionRouteReport?
    {
        guard inspection.ownership == .verified, inspection.connectionState == .connected,
            let report = inspection.connectionRoute
        else { return nil }
        do {
            try report.validate(for: descriptor)
            return report
        } catch { return nil }
    }

    private func disconnectRecord(_ id: UUID) async throws {
        do { try await disconnectCurrentRecord(id) } catch {
            recordFailure(id, error, preservingBusyVerification: true)
            throw error
        }
    }

    private func recordFailure(
        _ id: UUID, _ error: any Error, preservingBusyVerification: Bool = false
    ) {
        guard var record = records[id] else { return }
        record.resourceCleanupError = error as? MountResourceCleanupError
        if record.resourceCleanupError != nil {
            // This error is produced only after mount, image, and directory absence checks.
            // Keep it in memory; a reopened journal must inspect the resources again.
            record.attachment = nil
            record.phase = .unmountingBridge
            record.connectionState = .closed
        }
        if !preservingBusyVerification || (error as? POSIXError)?.code != .EBUSY {
            record.verificationFailed = true
            record.connectionRoute = nil
            // An earlier observation no longer describes this disk, as in a failed refresh.
            if record.resourceCleanupError == nil { record.connectionState = .unknown }
        }
        records[id] = record
    }

    private func disconnectCurrentRecord(_ id: UUID) async throws {
        try requireAvailableJournal()
        guard var record = records[id] else { throw ProtocolError.invalidState }
        let inspection = try await backend.inspectBridge(record.descriptor, at: record.bridgeURL)
        try requireAvailableJournal()
        guard inspection.ownership != .conflicting,
            inspection.ownership == .verified || inspection.attachment == nil
        else {
            records[id]?.verificationFailed = true
            throw AttachmentError.ownershipUnverified
        }
        record.verificationFailed = false
        record.resourceCleanupError = nil
        observe(inspection.connectionState, on: &record)
        record.connectionRoute = verifiedRoute(inspection, descriptor: record.descriptor)
        if let attachment = inspection.attachment {
            record.attachment = attachment
            record.phase = .detachingImage
            try checkpoint(record)
            try await backend.detachImage(
                attachment, descriptor: record.descriptor, bridgeURL: record.bridgeURL)
            try requireAvailableJournal()
        }
        record.attachment = nil
        record.phase = .unmountingBridge
        try checkpoint(record)
        try await backend.unmountBridge(record.descriptor, at: record.bridgeURL)
        try requireAvailableJournal()
        try remove(id)
    }

    /// A different disk's failed save must stop suspended operations too. Ordinary checkpoints
    /// cannot clear that uncertainty; only explicit recovery may reconcile it and resume work.
    private func requireAvailableJournal() throws {
        guard !journalUnavailable else { throw AttachmentError.journalUnavailable }
    }

    private func checkpoint(_ record: AttachedDisk) throws {
        var next = records
        next[record.id] = record
        try persist(next)
        records = next
        generation = UUID()
    }

    private func remove(_ id: UUID) throws {
        var next = records
        next[id] = nil
        try persist(next)
        records = next
        generation = UUID()
    }

    private func persist(_ records: [UUID: AttachedDisk]) throws {
        do {
            try journal.save(
                records.values.sorted { $0.id.uuidString < $1.id.uuidString }.map {
                    try $0.journalEntry()
                })
            journalUnavailable = false
        } catch {
            journalUnavailable = true
            throw AttachmentError.journalUnavailable
        }
    }

    private func identity(_ descriptor: ConnectionDescriptor) -> String {
        [
            descriptor.targetName, descriptor.lun.stableIdentifier,
        ].joined(separator: "\0")
    }
}

/// Asks a confirmed bridge's extension to stop reconnecting, at most once per forced release.
private final class StopReconnectingOnce: Sendable {
    private let backend: any AttachmentBackend
    private let descriptor: ConnectionDescriptor
    private let bridgeURL: URL
    private let pending: Mutex<Bool>

    init(
        backend: any AttachmentBackend, descriptor: ConnectionDescriptor, bridgeURL: URL,
        enabled: Bool
    ) {
        self.backend = backend
        self.descriptor = descriptor
        self.bridgeURL = bridgeURL
        pending = Mutex(enabled)
    }

    @Sendable func send() async {
        let first = pending.withLock { pending in
            defer { pending = false }
            return pending
        }
        guard first else { return }
        await backend.abandonConnectionRecovery(descriptor, at: bridgeURL)
    }
}
