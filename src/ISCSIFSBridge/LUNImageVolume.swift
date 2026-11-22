import Darwin
import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Synchronization

/// An explicit reserved-source choice, never proof of native unmount or storage release.
/// FSKit's unmount callback has no force discriminator. The attempt can therefore also
/// run during forced unmount; deactivate and generic shutdown always abandon immediately.
public enum ReservedUnmountBehavior: Sendable, Equatable {
    case abandon
    case attemptTransportCompletion
}

/// A single immutable directory entry backed by a writable, fixed-length remote disk.
/// Uses the macOS 26 operations API, with an explicitly selected 27 cache diagnostic.
public final class LUNImageVolume: FSVolume, FSVolume.Operations, FSVolume.ReadWriteOperations,
    FSVolume.XattrOperations, @unchecked Sendable
{
    public static let imageName = "Disk.img"
    private let disk: any ImageDisk
    private let reservedDisk: ReservedRemoteDisk?
    // Constructed before any caller Task boundary; cancellation can revoke the
    // original lower owner even before normal completion has published its task.
    private let reservedTransportCompletion: ReservedTransportCompletion?
    private let normalTransportCancellation: VolumeTransportCancellation
    private let reservedUnmountBehavior: ReservedUnmountBehavior
    private let sourceCapacity: DiskCapacity
    private let resourceIdentity: Data?
    private let connectionRoute: ConnectionRouteReport?
    private let owner: UUID
    private let recoveryControl: (any LUNRecoveryControl)?
    private let lifecycleObserver: VolumeLifecycleDiagnostics.Observer
    private let ioDiagnostics: IODiagnostics.Recorder?
    private let itemLock = NSLock()
    private var localAttributes = LocalXattrs()
    // A flush or another request must not overtake part of a chunked FSKit operation.
    private let ioGate = AsyncGate()
    private var ioEpoch: UInt64 = 0
    private struct ReservedFailure: Sendable {
        let id = UUID()
        let ticket: ReservedSynchronizationFailure
        let normalized: POSIXError
    }
    private struct RecoveryAttempt: Sendable {
        let id = UUID()
        let completion = VolumeRecoveryCompletion()
    }
    private var reservedFailure: ReservedFailure?
    private var recoveredFailures: [ReservedFailure] = []
    private var recoveryAttempt: RecoveryAttempt?
    // FSKit reports the aggregate access remaining after a close, not the access
    // being closed. Only access this state while holding ioGate.
    private var imageOpenModes: FSVolume.OpenModes = []
    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
        // Separate from the old aggregate access modes. All fields use itemLock;
        // disk operations still use ioGate. The OS has closed the item even when
        // its final barrier fails, so failure is retained independently of access.
        private var cacheItemOpen = false
        private var cacheFinalBarrierNeeded = false
        private var cacheCloseTask: Task<POSIXError?, Never>?
        private var cacheCloseAdmission: CacheCloseAdmission?
        private var cacheCloseRecoveryID: UUID?
        private var cacheBarrierFailure: POSIXError?
        private var cacheBarrierFailureID: UUID?
        var isCacheCloseWaitingForRecovery: Bool {
            itemLock.withLock {
                guard let active = recoveryAttempt?.id else { return false }
                return cacheCloseTask != nil && cacheCloseRecoveryID == active
            }
        }
    #endif
    private let maximumIOChunk = 1_048_576
    private var closingTask: Task<Void, Never>?
    private var normalTransportTask: Task<ReservedTransportCloseResult, Never>?
    var isTransportCompletionStarted: Bool { itemLock.withLock { normalTransportTask != nil } }

    fileprivate final class CacheCloseAdmission: Sendable {}
    private var mountDeadline: ContinuousClock.Instant?
    private var mountClock: (@Sendable () -> ContinuousClock.Instant)?
    private var mountedObservation: (@Sendable () -> Bool)?
    /// Records a completed mount process-wide (`ProcessMountRegistry`).
    private var mountCompletionObserver: (@Sendable () -> Void)?
    private var mountDeadlineTask: Task<Void, Never>?
    private var mountDeadlineExpired = false
    private var mountCompleted = false
    private var mountAbandoned = false
    public let rootItem: FSItem
    let imageItem: ImageItem
    var queuedIOCount: Int { get async { await ioGate.waitingCount } }
    private let timestamp = timespec(tv_sec: Int(Date().timeIntervalSince1970), tv_nsec: 0)

    public convenience init(
        disk: any ImageDisk, identifier: UUID,
        name: String = ApplicationIdentity.current.applicationName,
        resourceIdentity: Data? = nil,
        sourceCapacity: DiskCapacity? = nil, connectionRoute: ConnectionRouteReport? = nil
    ) {
        let owner = UUID()
        self.init(
            disk: disk, identifier: identifier, name: name, resourceIdentity: resourceIdentity,
            sourceCapacity: sourceCapacity, connectionRoute: connectionRoute,
            owner: owner, lifecycleObserver: VolumeLifecycleDiagnostics.log,
            ioDiagnostics: IODiagnostics.live(layer: .volume, scopeID: owner))
    }

    /// Holds the live reservation owner for this raw image's entire volume lifetime.
    public convenience init(
        reservedDisk: ReservedRemoteDisk, identifier: UUID,
        name: String = ApplicationIdentity.current.applicationName,
        resourceIdentity: Data? = nil, connectionRoute: ConnectionRouteReport? = nil,
        unmountBehavior: ReservedUnmountBehavior = .abandon
    ) {
        self.init(
            reservedDisk: reservedDisk, identifier: identifier, name: name,
            resourceIdentity: resourceIdentity, connectionRoute: connectionRoute,
            owner: UUID(), recoveryControl: nil, unmountBehavior: unmountBehavior)
    }

    convenience init(
        reservedDisk: ReservedRemoteDisk, identifier: UUID,
        name: String = ApplicationIdentity.current.applicationName,
        resourceIdentity: Data?, connectionRoute: ConnectionRouteReport? = nil,
        owner: UUID, recoveryControl: (any LUNRecoveryControl)?,
        unmountBehavior: ReservedUnmountBehavior = .abandon
    ) {
        self.init(
            disk: ReservedVolumeDisk(reservedDisk), identifier: identifier, name: name,
            resourceIdentity: resourceIdentity, connectionRoute: connectionRoute,
            owner: owner, lifecycleObserver: VolumeLifecycleDiagnostics.log,
            ioDiagnostics: IODiagnostics.live(layer: .volume, scopeID: owner),
            recoveryControl: recoveryControl, unmountBehavior: unmountBehavior)
    }

    init(
        disk: any ImageDisk, identifier: UUID,
        name: String = ApplicationIdentity.current.applicationName,
        resourceIdentity: Data? = nil,
        sourceCapacity: DiskCapacity? = nil, connectionRoute: ConnectionRouteReport? = nil,
        owner: UUID = UUID(),
        lifecycleObserver: @escaping VolumeLifecycleDiagnostics.Observer,
        ioDiagnostics: IODiagnostics.Recorder? = nil,
        recoveryControl: (any LUNRecoveryControl)? = nil,
        unmountBehavior: ReservedUnmountBehavior = .abandon
    ) {
        self.disk = disk
        reservedDisk = (disk as? ReservedVolumeDisk)?.reserved
        reservedTransportCompletion = reservedDisk?.transportCompletion()
        normalTransportCancellation = VolumeTransportCancellation(
            completion: reservedTransportCompletion)
        reservedUnmountBehavior = unmountBehavior
        self.sourceCapacity = sourceCapacity ?? disk.capacity
        self.resourceIdentity = resourceIdentity
        self.connectionRoute = connectionRoute
        self.owner = owner
        self.recoveryControl = recoveryControl
        self.lifecycleObserver = lifecycleObserver
        self.ioDiagnostics = ioDiagnostics
        self.rootItem = ImageItem(owner: owner, node: .root)
        self.imageItem = ImageItem(owner: owner, node: .raw)
        super.init(
            volumeID: FSVolume.Identifier(uuid: identifier), volumeName: FSFileName(string: name))
    }

    public var maximumLinkCount: Int { 2 }
    public var maximumNameLength: Int { 255 }
    public var maximumXattrSize: Int { LocalXattrs.maximumValueSize }
    public var restrictsOwnershipChanges: Bool { true }
    public var truncatesLongNames: Bool { false }
    public var maximumFileSize: UInt64 { disk.capacity.byteCount }

    // FSKit reads this policy after mount completes. Keep the kernel's mount
    // mode consistent with the immutable access mode of the remote disk.
    public var requestedMountOptions: FSVolume.MountOptions {
        disk.isReadOnly ? .readOnly : []
    }

    public var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let result = FSVolume.SupportedCapabilities()
        result.supports2TBFiles = true
        result.supports64BitObjectIDs = true
        result.supportsFastStatFS = true
        result.caseFormat = .sensitive
        return result
    }

    public var volumeStatistics: FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: ISCSIFileSystem.shortName)
        result.blockSize = Int(disk.capacity.blockSize)
        result.ioSize = 1_048_576
        result.totalBlocks = disk.capacity.blockCount
        result.usedBlocks = disk.capacity.blockCount
        // This private namespace has one immutable-size, fully backed image and
        // no allocator. Its existing bytes can all be overwritten. Sparse-image
        // clients use this budget even when they open an encoded image through
        // the raw file; zero available blocks incorrectly makes them unwritable.
        let reserve =
            (disk as? SparseImageDisk)?.rewriteReserveBlocks ?? disk.capacity.blockCount
        result.totalBlocks += reserve
        result.freeBlocks = reserve
        result.availableBlocks = reserve
        result.totalFiles = 2
        result.freeFiles = 0
        return result
    }

    public func activate(
        options: FSTaskOptions,
        replyHandler reply: @escaping @Sendable (FSItem?, (any Error)?) -> Void
    ) {
        activateRoot(replyHandler: reply)
    }

    func activateRoot(
        replyHandler reply: @escaping @Sendable (FSItem?, (any Error)?) -> Void
    ) {
        let failure = itemLock.withLock { () -> (any Error)? in
            if let failure = mountCompletionFailure() { return failure }
            reply(rootItem, nil)
            return nil
        }
        if let failure {
            Task {
                await shutdown()
                reply(nil, failure)
            }
        }
    }
    public func deactivate(options: FSDeactivateOptions = []) async throws {
        // macOS 26.0 can deliver deactivation without an unmount callback.
        // Close the URL-backed session without issuing new block I/O. A prior
        // unmount or a later resource unload shares this same teardown task.
        await withLifecycle(.deactivate, flags: UInt64(options.rawValue)) {
            await self.shutdown()
        }
    }
    public func mount(options: FSTaskOptions) async throws {
        try await completeMount()
    }

    func completeMount() async throws {
        let failure = itemLock.withLock { () -> (any Error)? in
            if let failure = mountCompletionFailure() { return failure }
            mountCompleted = true
            mountCompletionObserver?()
            cancelMountDeadline()
            return nil
        }
        if let failure {
            await shutdown()
            throw failure
        }
    }

    /// The caller may die after loadResource succeeds but before the volume is mounted.
    /// Bound that gap without expiring an established mount or its idle connection.
    func requireMountCompletion(
        before deadline: ContinuousClock.Instant, timing: MountCompletionTiming,
        isMounted: @escaping @Sendable () -> Bool = { false },
        onMountCompleted: (@Sendable () -> Void)? = nil
    ) throws {
        try itemLock.withLock {
            guard closingTask == nil, !mountCompleted, mountDeadline == nil,
                !mountDeadlineExpired
            else { throw ProtocolError.invalidState }
            guard timing.now() < deadline else {
                mountDeadlineExpired = true
                throw ProtocolError.timedOut
            }
            mountDeadline = deadline
            mountClock = timing.now
            mountedObservation = isMounted
            mountCompletionObserver = onMountCompleted
            mountDeadlineTask = Task { [weak self] in
                do { try await timing.sleepUntil(deadline) } catch { return }
                guard !Task.isCancelled else { return }
                await self?.expireUncompletedMount()
            }
        }
    }

    // Called under itemLock, including the callback's clock check if the timer runs late.
    private func mountCompletionFailure() -> (any Error)? {
        if !mountCompleted, let deadline = mountDeadline, let now = mountClock,
            now() >= deadline
        {
            // macOS 26.0 may publish a URL-backed mount without calling mount().
            // Preserve only a kernel-confirmed mount of this exact resource.
            if mountedObservation?() == true {
                mountCompleted = true
                mountCompletionObserver?()
                cancelMountDeadline()
            } else {
                mountDeadlineExpired = true
            }
        }
        if mountDeadlineExpired { return ProtocolError.timedOut }
        if closingTask != nil || mountAbandoned { return POSIXError(.ENOTCONN) }
        return nil
    }

    /// Whether the volume reached its mount: the mount callback, or the kernel's own mount
    /// table at the deadline.
    var isMountCompleted: Bool { itemLock.withLock { mountCompleted } }

    /// Closes a volume whose mount was abandoned before it completed. Once this has begun, a
    /// late activation or mount callback fails (ENOTCONN), so the volume can never be mounted
    /// afterwards. A volume that has completed its mount is never touched.
    /// - Returns: Whether the volume is now closed without a completed mount.
    @discardableResult
    func abandonUncompletedMount() async -> Bool {
        let abandoned = itemLock.withLock { () -> Bool in
            guard !mountCompleted else { return false }
            mountAbandoned = true
            return true
        }
        if abandoned { await shutdown() }
        return abandoned
    }

    private func cancelMountDeadline() {
        mountDeadlineTask?.cancel()
        mountDeadlineTask = nil
        mountDeadline = nil
        mountClock = nil
        mountedObservation = nil
    }

    private func expireUncompletedMount() async {
        let expired = itemLock.withLock {
            guard !mountCompleted, closingTask == nil, let deadline = mountDeadline,
                let now = mountClock, now() >= deadline
            else { return false }
            _ = mountCompletionFailure()
            return mountDeadlineExpired
        }
        if expired { await shutdown() }
    }

    public func unmount() async {
        // FSKit sends synchronize before teardown. This callback has no error return.
        await withLifecycle(.unmount) {
            if self.reservedUnmountBehavior == .attemptTransportCompletion {
                _ = await self.finishTransportAfterDrainingIO()
            }
            // Always join cleanup, including cancellation or an unmet final barrier.
            await self.shutdown()
        }
    }

    public func shutdown() async {
        await beginShutdown().value
    }

    /// Seals new image I/O and joins this volume's original I/O, recovery and
    /// cache-close owners, then joins the disk's terminal synchronization and Logout.
    /// A disk alias may already have completed that lower operation; its historical
    /// result does not prove that every volume operation succeeded or that the lower
    /// barrier followed this drain. Neither result proves native callback completion,
    /// filesystem unmount, reservation release, writer admission or backing retirement.
    public func finishTransportAfterDrainingIO() async -> ReservedTransportCloseResult {
        guard let completion = reservedTransportCompletion else { return .abandoned }
        return await withTaskCancellationHandler {
            if Task.isCancelled { normalTransportCancellation.cancel() }
            let task = itemLock.withLock {
                if let normalTransportTask { return normalTransportTask }
                cancelMountDeadline()
                let recovery = recoveryAttempt?.completion
                #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                    let cacheClose = cacheCloseTask
                #endif
                let task = Task {
                    self.itemLock.withLock {}  // Publish the seal before any work.
                    if let recovery { await recovery.wait() }
                    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                        _ = await cacheClose?.value
                    #endif
                    var qualified = true
                    do {
                        try await self.ioGate.acquire()
                        do {
                            try self.itemLock.withLock {
                                guard self.closingTask == nil,
                                    !self.normalTransportCancellation.isCancelled,
                                    !completion.isCancelled,
                                    self.recoveryAttempt == nil, self.reservedFailure == nil,
                                    self.imageOpenModes.isEmpty
                                else { throw POSIXError(.EBUSY) }
                                #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                                    guard self.cacheCloseTask == nil,
                                        !self.cacheItemOpen, !self.cacheFinalBarrierNeeded,
                                        self.cacheBarrierFailure == nil
                                    else { throw POSIXError(.EBUSY) }
                                #endif
                            }
                            await self.ioGate.release()
                        } catch {
                            await self.ioGate.release()
                            throw error
                        }
                    } catch {
                        qualified = false
                        completion.cancel()
                    }
                    let result = await completion.wait()
                    return self.normalTransportCancellation.finish(qualified ? result : .abandoned)
                }
                normalTransportTask = task
                return task
            }
            return await task.value
        } onCancel: {
            self.normalTransportCancellation.cancel()
        }
    }

    /// Publish terminal shutdown synchronously; callers await its shared task outside locks.
    func beginShutdown() -> Task<Void, Never> {
        normalTransportCancellation.cancel()
        return itemLock.withLock {
            if let closingTask { return closingTask }
            cancelMountDeadline()
            let disk = disk
            let trace = VolumeLifecycleDiagnostics.Trace(
                volumeID: owner, operation: .shutdown, flags: 0, observer: lifecycleObserver)
            let task = Task {
                trace.record(.begin)
                await disk.close()
                trace.record(.finished)
            }
            closingTask = task
            return task
        }
    }

    public func synchronize(flags: FSSyncFlags) async throws {
        try await IODiagnostics.withOperation(.synchronize, recorder: ioDiagnostics) { trace in
            try await self.withLifecycle(
                .synchronize, flags: UInt64(bitPattern: Int64(flags.rawValue))
            ) {
                trace?.record(.validated)
                try await self.diskIO(trace: trace) {
                    try await IODiagnostics.backend(.synchronize, trace: trace) { _ in
                        try await self.synchronizeBackend()
                    }
                }
            }
        }
    }

    /// Identifies one incident in one live volume, independently of its stable filesystem ID.
    /// This is a matching value, not authorization to control a volume.
    public struct SynchronizationRecoverySelection: Equatable, Sendable {
        public let liveVolumeID: UUID
        public let failureID: UUID
        public let ioEpoch: UInt64

        public init(liveVolumeID: UUID, failureID: UUID, ioEpoch: UInt64) {
            self.liveVolumeID = liveVolumeID
            self.failureID = failureID
            self.ioEpoch = ioEpoch
        }
    }

    /// Retained incident evidence for a subsequently matched request, not an eligibility
    /// check. It can remain after a failed attempt revokes access; reading it reserves nothing.
    public var synchronizationFailureSelection: SynchronizationRecoverySelection? {
        itemLock.withLock {
            guard let reservedFailure, closingTask == nil else { return nil }
            return SynchronizationRecoverySelection(
                liveVolumeID: owner, failureID: reservedFailure.id, ioEpoch: ioEpoch)
        }
    }

    public var recoveryControlSnapshot: LUNRecoveryControlSnapshot {
        itemLock.withLock {
            let failure = reservedFailure.map {
                SynchronizationRecoverySelection(
                    liveVolumeID: owner, failureID: $0.id, ioEpoch: ioEpoch)
            }
            return LUNRecoveryControlSnapshot(
                liveVolumeID: owner, resourceIdentity: resourceIdentity, failure: failure,
                isClosing: closingTask != nil || normalTransportTask != nil,
                isRecovering: recoveryAttempt != nil)
        }
    }

    /// Recovers the current incident for an in-process caller. An asynchronous control
    /// request must instead use the matching overload, preserving its original selection.
    /// Neither overload proves producer flush or unmount; shutdown can still close the volume.
    public func recoverSynchronizationFailure() async throws {
        try await withLifecycle(.recoverSynchronization) {
            try await self.recoverReservedFailure(matching: nil)
        }
    }

    /// The selection is checked while installing the attempt and again after waiting for
    /// I/O. A stale request never selects a later incident or starts backend recovery.
    public func recoverSynchronizationFailure(matching selection: SynchronizationRecoverySelection)
        async throws
    {
        try await withLifecycle(.recoverSynchronization) {
            try await self.recoverReservedFailure(matching: selection)
        }
    }

    private func recoverReservedFailure(matching expected: SynchronizationRecoverySelection?)
        async throws
    {
        #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
            // An old close can publish its failure after releasing ioGate. Drain it
            // before recovery, never while holding the gate that its barrier needs.
            if let pending = itemLock.withLock({ cacheCloseTask }) { _ = await pending.value }
        #endif
        try Task.checkCancellation()
        let (reserved, failure, attempt, selection) = try itemLock.withLock {
            guard let reservedDisk, let reservedFailure, closingTask == nil,
                normalTransportTask == nil,
                recoveryAttempt == nil, ioEpoch < .max, recoveredFailures.count < 8
            else { throw POSIXError(.EBUSY) }
            let selection = SynchronizationRecoverySelection(
                liveVolumeID: owner, failureID: reservedFailure.id, ioEpoch: ioEpoch)
            guard expected == nil || expected == selection else { throw POSIXError(.EBUSY) }
            let attempt = RecoveryAttempt()
            recoveryAttempt = attempt
            return (reservedDisk, reservedFailure, attempt, selection)
        }
        do {
            try await ioGate.acquire()
            do {
                try Task.checkCancellation()
                try itemLock.withLock {
                    guard closingTask == nil, recoveryAttempt?.id == attempt.id,
                        reservedFailure?.id == selection.failureID,
                        selection.liveVolumeID == owner, selection.ioEpoch == ioEpoch
                    else { throw POSIXError(.EBUSY) }
                    #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                        guard cacheCloseTask == nil || cacheCloseRecoveryID == attempt.id else {
                            throw POSIXError(.EBUSY)
                        }
                        guard cacheBarrierFailure == nil || cacheBarrierFailureID == failure.id
                        else {
                            throw POSIXError(.EIO)
                        }
                    #endif
                }
                try await reserved.recoverSynchronizationFailure(matching: failure.ticket)
                // Network commit already reopened its generation. No throwing cancellation
                // or shutdown check follows it; terminal shutdown still rejects ordinary I/O.
                itemLock.withLock {
                    if reservedFailure?.id == failure.id {
                        recoveredFailures.append(failure)
                        reservedFailure = nil
                        #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                            if cacheBarrierFailureID == failure.id {
                                cacheBarrierFailure = nil
                                cacheBarrierFailureID = nil
                            }
                        #endif
                    }
                    ioEpoch += 1
                    recoveryAttempt = nil
                }
                await ioGate.release()
            } catch {
                await ioGate.release()
                throw error
            }
            await attempt.completion.finish()
        } catch {
            itemLock.withLock {
                if recoveryAttempt?.id == attempt.id { recoveryAttempt = nil }
            }
            await attempt.completion.finish()
            throw Self.posixIOError(error)
        }
    }

    /// Called only under ioGate, before error normalization or gate release.
    private func synchronizeBackend() async throws {
        do { try await disk.synchronize() } catch let failure as ReservedSynchronizationFailure {
            if reservedDisk != nil {
                itemLock.withLock {
                    if reservedFailure == nil {
                        reservedFailure = ReservedFailure(
                            ticket: failure, normalized: Self.posixIOError(failure.underlyingError))
                    }
                }
            }
            throw failure.underlyingError
        }
    }

    public func reclaimItem(
        _ item: FSItem, replyHandler reply: @escaping @Sendable ((any Error)?) -> Void
    ) {
        itemLock.withLock {
            do {
                _ = try checked(item)
                _ = item.tryReclaim({})
                reply(nil)
            } catch { reply(error) }
        }
    }

    public func lookupItem(
        named name: FSFileName, inDirectory directory: FSItem,
        replyHandler reply: @escaping @Sendable (FSItem?, FSFileName?, (any Error)?) -> Void
    ) {
        // Lookup replies and tryReclaim must share a synchronization context.
        itemLock.withLock {
            do {
                guard try checked(directory).directory else { throw POSIXError(.ENOTDIR) }
                switch name.string {
                case ".", "..": reply(rootItem, FSFileName(string: name.string!), nil)
                case Self.imageName: reply(imageItem, FSFileName(string: Self.imageName), nil)
                default: throw POSIXError(.ENOENT)
                }
            } catch { reply(nil, nil, error) }
        }
    }

    public func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem)
        async throws -> FSItem.Attributes
    {
        try makeAttributes(of: item)
    }

    func makeAttributes(of item: FSItem) throws -> FSItem.Attributes {
        // Attribute sequence numbers must follow the order of populated values.
        try itemLock.withLock {
            let node = try checked(item)
            let result = FSItem.Attributes()
            result.fileID = node.directory ? .rootDirectory : FSItem.Identifier(3)
            result.parentID = .rootDirectory
            result.type = node.directory ? .directory : .file
            // Only an explicit diagnostic control needs owner metadata writes. The
            // namespace remains immutable; create/remove/setAttributes still refuse.
            result.mode =
                node.directory
                ? (recoveryControl == nil ? 0o500 : 0o700) : (disk.isReadOnly ? 0o400 : 0o600)
            result.uid = geteuid()
            result.gid = getegid()
            result.linkCount = node.directory ? 2 : 1
            result.size = node.directory ? 0 : disk.capacity.byteCount
            result.allocSize = result.size
            result.flags = 0
            result.supportsLimitedXAttrs = false
            result.accessTime = timestamp
            result.modifyTime = timestamp
            result.changeTime = timestamp
            result.birthTime = timestamp
            result.addedTime = timestamp
            return result
        }
    }

    public func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem)
        async throws -> FSItem.Attributes
    {
        _ = try checked(item)
        // Neither the directory entry nor the LUN's length belongs to this file system.
        throw POSIXError(.EPERM)
    }

    private func localXattrNames(for item: FSItem) -> [FSFileName] {
        guard (try? checked(item)) != nil else { return [] }
        var names = [
            FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
            FSFileName(string: ConnectionDescriptor.sourceBlockSizeAttributeName),
        ]
        if resourceIdentity?.count == 32 {
            names.insert(FSFileName(string: ConnectionDescriptor.identityAttributeName), at: 0)
        }
        if connectionRoute?.resourceIdentity == resourceIdentity, connectionRoute != nil {
            names.append(FSFileName(string: ConnectionDescriptor.connectionRouteAttributeName))
        }
        if ioDiagnostics != nil {
            names.append(FSFileName(string: IODiagnostics.bindingAttributeName))
        }
        if recoveryControl != nil, item === rootItem {
            names.append(FSFileName(string: LUNRecoveryControlAttributes.status))
        }
        return names
    }

    private struct DiagnosticBinding: Encodable {
        let version: Int
        let volumeID: UUID
        let recorder: IODiagnostics.Binding
    }

    public func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        _ = try checked(item)
        if name.string == LUNRecoveryControlAttributes.command { throw POSIXError(.ENOATTR) }
        if name.string == ConnectionDescriptor.connectionControlAttributeName {
            throw POSIXError(.ENOATTR)
        }
        if name.string == ConnectionDescriptor.readOnlyConnectionControlAttributeName {
            // A read-only mount refuses the write-only control in the kernel (EROFS), so this
            // volume answers a read instead. Stopping can't be undone, so only a read-only
            // disk, which has nothing unsaved to lose, offers it. As with the write, never
            // through ioGate: a blocked callback holds the gate this request must release.
            guard disk.isReadOnly else { throw POSIXError(.ENOATTR) }
            await disk.abandonConnectionRecovery()
            return ConnectionDescriptor.abandonRecoveryControlValue
        }
        if name.string == LUNRecoveryControlAttributes.status {
            guard item === rootItem else { throw POSIXError(.EPERM) }
            guard let recoveryControl else { throw POSIXError(.ENOATTR) }
            let value = try await recoveryControl.status(for: self)
            guard value.count <= LUNRecoveryControlAttributes.maximumStatusBytes else {
                throw POSIXError(.E2BIG)
            }
            return value
        }
        if name.string == IODiagnostics.bindingAttributeName {
            guard let ioDiagnostics else { throw POSIXError(.ENOATTR) }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let bytes = try encoder.encode(
                DiagnosticBinding(version: 1, volumeID: owner, recorder: ioDiagnostics.binding))
            guard bytes.count <= 1024 else { throw POSIXError(.E2BIG) }
            return bytes
        }
        if name.string == ConnectionDescriptor.connectionRouteAttributeName {
            guard let connectionRoute, connectionRoute.resourceIdentity == resourceIdentity else {
                throw POSIXError(.ENOATTR)
            }
            return try connectionRoute.encoded()
        }
        if name.string == ConnectionDescriptor.sourceBlockSizeAttributeName {
            var bytes = [UInt8](repeating: 0, count: 4)
            bytes.put(sourceCapacity.blockSize, at: 0)
            return Data(bytes)
        }
        if name.string == ConnectionDescriptor.connectionStateAttributeName {
            guard itemLock.withLock({ closingTask == nil }) else {
                return DiskConnectionState.closed.encoded
            }
            let state = await disk.connectionState()
            return itemLock.withLock {
                if closingTask != nil { return DiskConnectionState.closed.encoded }
                if reservedFailure != nil || recoveryAttempt != nil {
                    return DiskConnectionState.interrupted.encoded
                }
                #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                    if cacheBarrierFailure != nil { return DiskConnectionState.interrupted.encoded }
                #endif
                return state.encoded
            }
        }
        if name.string == ConnectionDescriptor.identityAttributeName {
            guard let resourceIdentity, resourceIdentity.count == 32 else {
                throw POSIXError(.ENOATTR)
            }
            return resourceIdentity
        }
        guard let name = name.string, name != "com.apple.ResourceFork" else {
            throw POSIXError(.ENOATTR)
        }
        return try itemLock.withLock {
            try localAttributes.value(named: name, on: checked(item).node)
        }
    }

    public func xattrs(of item: FSItem) async throws -> [FSFileName] {
        _ = try checked(item)
        return try itemLock.withLock {
            let node = try checked(item).node
            return localXattrNames(for: item)
                + localAttributes.names(on: node).map {
                    FSFileName(string: $0)
                }
        }
    }

    public func setXattr(
        named name: FSFileName, to value: Data?, on item: FSItem,
        policy: FSVolume.SetXattrPolicy
    ) async throws {
        guard let name = name.string else { throw POSIXError(.EINVAL) }
        if name == ConnectionDescriptor.connectionControlAttributeName {
            // Write-only, and never through ioGate or checkActiveIO: a blocked callback holds
            // the gate, and this request exists to release it while the disk reconnects.
            _ = try checked(item)
            guard value == ConnectionDescriptor.abandonRecoveryControlValue else {
                throw POSIXError(.EINVAL)
            }
            await disk.abandonConnectionRecovery()
            return
        }
        if name == LUNRecoveryControlAttributes.status { throw POSIXError(.EPERM) }
        if name == LUNRecoveryControlAttributes.command {
            _ = try checked(item)
            guard item === rootItem, let recoveryControl else { throw POSIXError(.EPERM) }
            guard policy == .alwaysSet, let value, !value.isEmpty else {
                throw POSIXError(.EINVAL)
            }
            guard value.count <= LUNRecoveryControlAttributes.maximumCommandBytes else {
                throw POSIXError(.E2BIG)
            }
            // The handler authenticates outside itemLock/ioGate. Ordinary metadata
            // and data I/O continue to reject the retained synchronization failure.
            try await recoveryControl.submit(value, to: self)
            return
        }
        guard name != ConnectionDescriptor.identityAttributeName,
            name != ConnectionDescriptor.readOnlyConnectionControlAttributeName,
            name != ConnectionDescriptor.connectionStateAttributeName,
            name != ConnectionDescriptor.sourceBlockSizeAttributeName,
            name != ConnectionDescriptor.connectionRouteAttributeName,
            name != IODiagnostics.bindingAttributeName,
            name != "com.apple.ResourceFork"
        else { throw POSIXError(.EPERM) }
        try checkActiveIO()
        try itemLock.withLock {
            try localAttributes.set(value, named: name, on: checked(item).node, policy: policy)
        }
    }

    public func enumerateDirectory(
        _ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?, packer: FSDirectoryEntryPacker
    ) async throws -> FSDirectoryVerifier {
        try enumerateDirectoryEntries(
            directory, startingAt: cookie, verifier: verifier, attributes: attributes,
            packEntry: packer.packEntry)
    }

    func enumerateDirectoryEntries(
        _ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packEntry: (
            FSFileName, FSItem.ItemType, FSItem.Identifier, FSDirectoryCookie, FSItem.Attributes?
        )
            -> Bool
    ) throws -> FSDirectoryVerifier {
        guard try checked(directory).directory else { throw POSIXError(.ENOTDIR) }
        guard cookie.rawValue <= 3 else {
            throw NSError(
                domain: NSPOSIXErrorDomain, code: FSError.Code.invalidDirectoryCookie.rawValue)
        }
        guard verifier.rawValue == 0 || verifier.rawValue == 1 else { throw POSIXError(.ESTALE) }
        // Cookies describe positions in the same immutable namespace in both
        // readdir modes. Attribute enumerations omit the two root aliases.
        let names = [".", "..", Self.imageName]
        for index in Int(cookie.rawValue)..<names.count {
            if attributes != nil, index < 2 { continue }
            let isImage = index == 2
            let packed = packEntry(
                FSFileName(string: names[index]), isImage ? .file : .directory,
                isImage ? FSItem.Identifier(3) : .rootDirectory,
                FSDirectoryCookie(rawValue: UInt64(index + 1)),
                attributes == nil ? nil : try makeAttributes(of: imageItem))
            if !packed { break }
        }
        return FSDirectoryVerifier(rawValue: 1)
    }

    public func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        try await withLifecycle(.open, flags: UInt64(modes.rawValue)) {
            let node = try self.checkedOpen(item, modes: modes)
            guard !node.directory else { return }
            try await self.diskIO {
                try await self.checkConnectedIO()
                self.imageOpenModes.formUnion(modes)
            }
        }
    }

    public func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        let reference = ImageItemReference(value: item)
        try await IODiagnostics.withOperation(.close, recorder: ioDiagnostics) { trace in
            try await self.withLifecycle(.close, flags: UInt64(modes.rawValue)) {
                guard !(try self.checked(reference.value).directory) else { return }
                trace?.record(.validated)
                try await self.diskIO(trace: trace) {
                    if self.imageOpenModes.contains(.write), !modes.contains(.write) {
                        try await IODiagnostics.backend(.synchronize, trace: trace) { _ in
                            try await self.synchronizeBackend()
                        }
                    }
                    // Keep write access pending if its barrier failed. A later explicit
                    // close must not silently forget that failure; never retry it here.
                    self.imageOpenModes = modes
                }
            }
        }
    }

    public func read(
        from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer
    ) async throws -> Int {
        let destination = ImageReadDestination(buffer)
        return try await readCallback(
            from: item, at: offset, length: length, bufferLength: destination.length,
            consume: { data, displacement in try destination.copy(data, at: displacement) },
            finalize: { count in try destination.clearTail(after: count) })
    }

    // The public callback uses this same path; the end event includes final buffer work.
    func readCallback(
        from item: FSItem, at offset: off_t, length: Int, bufferLength: Int,
        consume: @escaping @Sendable (Data, Int) throws -> Void,
        finalize: @escaping @Sendable (Int) throws -> Void
    ) async throws -> Int {
        let reference = ImageItemReference(value: item)
        return try await IODiagnostics.withOperation(.readCallback, recorder: ioDiagnostics) { _ in
            let count = try await self.readChunks(
                from: reference.value, at: offset, length: length,
                bufferLength: bufferLength, consume: consume)
            try finalize(count)
            return count
        }
    }

    func readChunks(
        from item: FSItem, at offset: off_t, length: Int, bufferLength: Int,
        consume: @escaping @Sendable (Data, Int) throws -> Void
    ) async throws -> Int {
        let reference = ImageItemReference(value: item)
        return try await IODiagnostics.withOperation(.read, recorder: ioDiagnostics) { trace in
            guard !(try checked(reference.value).directory) else { throw POSIXError(.EISDIR) }
            guard offset >= 0, length >= 0 else { throw POSIXError(.EINVAL) }
            let available =
                UInt64(offset) < disk.capacity.byteCount
                ? disk.capacity.byteCount - UInt64(offset) : 0
            let count = Int(min(UInt64(length), available))
            guard bufferLength >= count else { throw POSIXError(.EFAULT) }
            trace?.record(.validated)
            return try await diskIO(trace: trace) {
                var cursor = 0
                while cursor < count {
                    try self.checkActiveIO(trace: trace)
                    let size = min(self.maximumIOChunk, count - cursor)
                    let chunkOffset = offset + Int64(cursor)
                    let data = try await IODiagnostics.backend(.read, trace: trace) { _ in
                        try await self.disk.read(offset: chunkOffset, length: size)
                    }
                    try self.checkActiveIO(trace: trace)
                    guard data.count == size else { throw POSIXError(.EIO) }
                    try consume(data, cursor)
                    cursor += size
                }
                return count
            }
        }
    }

    public func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        let reference = ImageItemReference(value: item)
        return try await IODiagnostics.withOperation(.write, recorder: ioDiagnostics) { trace in
            guard !(try checked(reference.value).directory) else { throw POSIXError(.EISDIR) }
            guard !disk.isReadOnly else { throw POSIXError(.EROFS) }
            guard offset >= 0 else { throw POSIXError(.EINVAL) }
            guard UInt64(offset) <= disk.capacity.byteCount,
                UInt64(contents.count) <= disk.capacity.byteCount - UInt64(offset)
            else { throw POSIXError(.ENOSPC) }
            trace?.record(.validated)
            try await diskIO(trace: trace) {
                if let sparse = self.disk as? SparseImageDisk {
                    try sparse.validateWrite(offset: offset, data: contents)
                }
                #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
                    if !contents.isEmpty {
                        self.itemLock.withLock { self.cacheFinalBarrierNeeded = true }
                    }
                #endif
                guard !contents.isEmpty else { return }
                // A reconnection between this callback's chunks and its flush may follow a
                // target restart that lost earlier chunks with its cache. Send every chunk
                // again until all of them and a GOOD flush happen within one epoch; the
                // buffer is still held. Retrying only the interrupted command isn't enough.
                try await self.disk.repeatingWithinOneEpoch {
                    var cursor = 0
                    while cursor < contents.count {
                        try self.checkActiveIO(trace: trace)
                        let size = min(self.maximumIOChunk, contents.count - cursor)
                        let start = contents.startIndex + cursor
                        let chunkOffset = offset + Int64(cursor)
                        let chunk = Data(contents[start..<(start + size)])
                        try await IODiagnostics.backend(.write, trace: trace) { _ in
                            try await self.disk.write(offset: chunkOffset, data: chunk)
                        }
                        try self.checkActiveIO(trace: trace)
                        cursor += size
                    }
                    // URL resources may not receive synchronize for F_FULLFSYNC. Complete each
                    // delivered write only after the target flush, retaining the I/O gate.
                    try await IODiagnostics.backend(.synchronize, trace: trace) { _ in
                        try await self.synchronizeBackend()
                    }
                    try self.checkActiveIO(trace: trace)
                }
            }
            return contents.count
        }
    }

    public func createItem(
        named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest
    ) async throws -> (FSItem, FSFileName) {
        throw POSIXError(.EPERM)
    }

    public func createSymbolicLink(
        named name: FSFileName, inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName
    ) async throws -> (FSItem, FSFileName) {
        throw POSIXError(.EPERM)
    }

    public func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem)
        async throws -> FSFileName
    {
        throw POSIXError(.EPERM)
    }

    public func renameItem(
        _ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName,
        to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?
    ) async throws -> FSFileName {
        throw POSIXError(.EPERM)
    }

    public func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem)
        async throws
    {
        throw POSIXError(.EPERM)
    }

    public func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        _ = try checked(item)
        throw POSIXError(.EINVAL)
    }

    private func withLifecycle(
        _ operation: VolumeLifecycleDiagnostics.Operation, flags: UInt64 = 0,
        _ work: () async throws -> Void
    ) async rethrows {
        let trace = VolumeLifecycleDiagnostics.Trace(
            volumeID: owner, operation: operation, flags: flags, observer: lifecycleObserver)
        trace.record(.begin)
        do {
            try await work()
            trace.record(.finished)
        } catch {
            trace.record(.finished, error: error)
            throw error
        }
    }

    private func checked(_ item: FSItem) throws -> ImageItem {
        guard let node = item as? ImageItem, node.owner == owner else { throw POSIXError(.ESTALE) }
        return node
    }

    private func checkedOpen(_ item: FSItem, modes: FSVolume.OpenModes) throws -> ImageItem {
        let node = try checked(item)
        if modes.contains(.write) {
            guard !node.directory else { throw POSIXError(.EISDIR) }
            guard !disk.isReadOnly else { throw POSIXError(.EROFS) }
        }
        return node
    }

    private func checkConnectedIO() async throws {
        // A reconnecting disk is admitted: its I/O waits for the new session.
        switch await disk.connectionState() {
        case .connected, .reconnecting: break
        case .unknown, .interrupted, .closed: throw POSIXError(.EIO)
        }
        try checkActiveIO()
    }

    private func diskIO<Value: Sendable>(
        trace: IODiagnostics.Trace? = nil, cleanup: CacheCloseAdmission? = nil,
        _ work: @Sendable () async throws -> Value
    ) async throws -> Value {
        do {
            let admission = try captureIOAdmission(trace: trace, cleanup: cleanup)
            return try await performIO(admission: admission, trace: trace, work)
        } catch { throw Self.posixIOError(error) }
    }

    struct IOAdmission: Sendable {
        fileprivate let volumeID: UUID
        fileprivate let epoch: UInt64
        fileprivate let cleanup: CacheCloseAdmission?
    }

    /// Capture before waiting; admission belongs to this volume and this recovery epoch.
    func captureIOAdmission(trace: IODiagnostics.Trace? = nil) throws -> IOAdmission {
        try captureIOAdmission(trace: trace, cleanup: nil)
    }

    private func captureIOAdmission(
        trace: IODiagnostics.Trace?, cleanup: CacheCloseAdmission?
    ) throws -> IOAdmission {
        try checkActiveIO(trace: trace)
        return try itemLock.withLock {
            guard permitsNewIO(cleanup: cleanup) else { throw POSIXError(.EIO) }
            return IOAdmission(volumeID: owner, epoch: ioEpoch, cleanup: cleanup)
        }
    }

    // Only an already-published cleanup owner may enter after the normal seal.
    // Active chunk loops deliberately keep checkActiveIO's existing semantics.
    private func permitsNewIO(cleanup: CacheCloseAdmission?) -> Bool {
        if normalTransportTask == nil { return true }
        #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
            return cleanup != nil && cleanup === cacheCloseAdmission
        #else
            return false
        #endif
    }

    func performIO<Value: Sendable>(
        admission: IOAdmission, trace: IODiagnostics.Trace? = nil,
        _ work: @Sendable () async throws -> Value
    ) async throws -> Value {
        do {
            try checkActiveIO(trace: trace)
            trace?.record(.gateWaiting)
            try await ioGate.acquire()
            trace?.record(.gateAcquired)
            do {
                try checkActiveIO(trace: trace)
                guard
                    itemLock.withLock({
                        admission.volumeID == owner && admission.epoch == ioEpoch
                            && permitsNewIO(cleanup: admission.cleanup)
                    })
                else { throw POSIXError(.EIO) }
                let result = try await work()
                try checkActiveIO(trace: trace)
                await ioGate.release()
                return result
            } catch {
                await ioGate.release()
                throw error
            }
        } catch {
            throw Self.posixIOError(error)
        }
    }

    private static func posixIOError(_ error: any Error) -> POSIXError {
        if let error = error as? POSIXError { return error }
        if error is CancellationError { return POSIXError(.ECANCELED) }
        if case ProtocolError.timedOut = error { return POSIXError(.ETIMEDOUT) }
        if case ProtocolError.busy = error { return POSIXError(.EBUSY) }
        if case ProtocolError.scsiFailure(let status, let bytes) = error,
            status == 2, let sense = try? SCSISense(data: bytes), !sense.isDeferred,
            sense.key == 7,
            sense.additionalSenseCode == 0x27
        {
            return POSIXError(.EROFS)
        }
        return POSIXError(.EIO)
    }

    private func checkActiveIO(trace: IODiagnostics.Trace? = nil) throws {
        do { try Task.checkCancellation() } catch {
            trace?.record(.rejected, detail: .cancelled, error: error)
            throw error
        }
        guard itemLock.withLock({ closingTask == nil }) else {
            trace?.record(.rejected, detail: .closing, error: POSIXError(.EIO))
            throw POSIXError(.EIO)
        }
        try itemLock.withLock {
            guard recoveryAttempt == nil else { throw POSIXError(.EBUSY) }
            if let failure = reservedFailure { throw failure.normalized }
        }
        #if ISCSI_FSKIT_CACHE_DIAGNOSTIC
            if let failure = itemLock.withLock({ cacheBarrierFailure }) {
                trace?.record(.rejected, detail: .cacheBarrier, error: failure)
                throw failure
            }
        #endif
    }

}

/// Upper cancellation remains sticky even when the lower transport already has
/// a successful historical result. Only this volume's committed result freezes it.
private final class VolumeTransportCancellation: Sendable {
    private struct State: Sendable {
        var cancelled = false
        var result: ReservedTransportCloseResult?
    }
    private let state = Mutex(State())
    private let completion: ReservedTransportCompletion?

    init(completion: ReservedTransportCompletion?) { self.completion = completion }

    var isCancelled: Bool { state.withLock { $0.cancelled } }

    func cancel() {
        state.withLock { value in
            guard value.result == nil else { return }
            value.cancelled = true
            // The lower controller cannot call back into this upper controller.
            completion?.cancel()
        }
    }

    func finish(_ candidate: ReservedTransportCloseResult) -> ReservedTransportCloseResult {
        state.withLock { value in
            if let result = value.result { return result }
            let result = value.cancelled ? .abandoned : candidate
            value.result = result
            return result
        }
    }
}

#if ISCSI_FSKIT_CACHE_DIAGNOSTIC
    // DataCacheHandler owns every open/close in this build. Never also register the
    // old OpenCloseOperations protocol, or forward the new callbacks to its methods.
    @available(macOS 27.0, *)
    extension LUNImageVolume: FSVolume.DataCacheHandler {
        public var isDataCacheInhibited: Bool { false }

        public func open(
            _ item: FSItem, modes: FSVolume.OpenModes, cacheMode: FSVolume.DataCacheMode,
            context: FSContext
        ) async throws -> FSOpenItemResult {
            FSOpenItemResult(
                grantedCoherency: try await negotiateCacheOpen(
                    item, modes: modes, cacheMode: cacheMode))
        }

        public func upgrade(
            _ item: FSItem, cacheMode: FSVolume.DataCacheMode, context: FSContext
        ) async throws -> FSUpgradeItemResult {
            FSUpgradeItemResult(
                grantedCoherency: try await negotiateCacheUpgrade(item, cacheMode: cacheMode))
        }

        public func close(_ item: FSItem, context: FSContext) async {
            await finishCacheClose(item)
        }

        func negotiateCacheOpen(
            _ item: FSItem, modes: FSVolume.OpenModes, cacheMode: FSVolume.DataCacheMode
        ) async throws -> FSVolume.KernelCacheCoherencyType {
            // Low 32 bits: access; high 32 bits: requested cache mode. A successful
            // cacheGrant event records the actual granted coherency, always noCache.
            let flags = UInt64(modes.rawValue) | (UInt64(cacheMode.rawValue) << 32)
            try await withLifecycle(.cacheOpen, flags: flags) {
                let node = try self.checkedOpen(item, modes: modes)
                if let pending = self.itemLock.withLock({ self.cacheCloseTask }) {
                    _ = await pending.value
                }
                try await self.diskIO {
                    try await self.checkConnectedIO()
                    try self.itemLock.withLock {
                        guard self.cacheCloseTask == nil else { throw POSIXError(.EBUSY) }
                        if !node.directory {
                            self.cacheItemOpen = true
                            // Upgrade has no access modes. Conservatively require one
                            // final barrier for ANY open of a writable image, including
                            // an initial reader; never infer a writer count from cacheMode.
                            self.cacheFinalBarrierNeeded = !self.disk.isReadOnly
                        }
                    }
                }
            }
            await withLifecycle(
                .cacheGrant, flags: UInt64(FSVolume.KernelCacheCoherencyType.noCache.rawValue)
            ) {}
            return .noCache
        }

        func negotiateCacheUpgrade(
            _ item: FSItem, cacheMode: FSVolume.DataCacheMode
        ) async throws -> FSVolume.KernelCacheCoherencyType {
            try await withLifecycle(.cacheUpgrade, flags: UInt64(cacheMode.rawValue)) {
                let node = try self.checked(item)
                try await self.diskIO {
                    try await self.checkConnectedIO()
                    try self.itemLock.withLock {
                        guard self.cacheCloseTask == nil else { throw POSIXError(.EBUSY) }
                        guard node.directory || self.cacheItemOpen else { throw POSIXError(.EBADF) }
                    }
                }
            }
            await withLifecycle(
                .cacheGrant, flags: UInt64(FSVolume.KernelCacheCoherencyType.noCache.rawValue)
            ) {}
            return .noCache
        }

        func finishCacheClose(_ item: FSItem) async {
            let trace = VolumeLifecycleDiagnostics.Trace(
                volumeID: owner, operation: .cacheClose, flags: 0, observer: lifecycleObserver)
            trace.record(.begin)
            do {
                guard !(try checked(item).directory) else {
                    trace.record(.finished)
                    return
                }
                let task = try itemLock.withLock { () -> Task<POSIXError?, Never>? in
                    if let cacheCloseTask { return cacheCloseTask }
                    guard normalTransportTask == nil else { throw POSIXError(.EIO) }
                    guard cacheItemOpen || cacheFinalBarrierNeeded else { return nil }
                    let admission = CacheCloseAdmission()
                    cacheCloseAdmission = admission
                    cacheItemOpen = false
                    let barrierNeeded = cacheFinalBarrierNeeded
                    cacheFinalBarrierNeeded = false
                    let recovery = recoveryAttempt
                    cacheCloseRecoveryID = recovery?.id
                    // This independent cleanup task completes even if its caller is
                    // cancelled. It never owns disk.close() or the volume shutdown.
                    let task = Task<POSIXError?, Never> {
                        // A close arriving during recovery must perform its own barrier
                        // afterward, with the then-current volume epoch, outside all locks.
                        if let recovery { await recovery.completion.wait() }
                        var failure: POSIXError?
                        if barrierNeeded {
                            do {
                                try await self.diskIO(cleanup: admission) {
                                    do {
                                        try await self.synchronizeBackend()
                                        try self.checkActiveIO()
                                    } catch {
                                        let failure = Self.posixIOError(error)
                                        // Publish BEFORE releasing ioGate: a queued
                                        // request must not reach a connected backend
                                        // in the gap after this barrier failed.
                                        self.itemLock.withLock {
                                            if self.cacheBarrierFailure == nil {
                                                self.cacheBarrierFailure = failure
                                                if self.closingTask == nil,
                                                    let retained = self.reservedFailure,
                                                    retained.normalized == failure
                                                {
                                                    self.cacheBarrierFailureID = retained.id
                                                }
                                            }
                                        }
                                        throw failure
                                    }
                                }
                            } catch { failure = Self.posixIOError(error) }
                        }
                        self.itemLock.withLock {
                            if self.cacheBarrierFailure == nil {
                                self.cacheBarrierFailure = failure
                                if self.closingTask == nil, let retained = self.reservedFailure,
                                    retained.normalized == failure
                                {
                                    self.cacheBarrierFailureID = retained.id
                                }
                            }
                            self.cacheCloseTask = nil
                            self.cacheCloseAdmission = nil
                            self.cacheCloseRecoveryID = nil
                        }
                        return failure
                    }
                    cacheCloseTask = task
                    return task
                }
                let result = await task?.value
                let failure = result ?? itemLock.withLock { cacheBarrierFailure }
                // Errorless completion means the OS item is closed, not saved. This
                // event and the retained failure expose an unmet barrier after close.
                trace.record(.finished, error: failure)
            } catch { trace.record(.finished, error: error) }
        }
    }
#else
    extension LUNImageVolume: FSVolume.OpenCloseOperations {}
#endif

/// The read operation owns this FSKit buffer until its reply. Each copy is synchronous;
/// no raw pointer or span survives an await, and chunks never copy concurrently.
private final class ImageReadDestination: @unchecked Sendable {
    private let buffer: FSMutableFileDataBuffer
    var length: Int { buffer.length }

    init(_ buffer: FSMutableFileDataBuffer) { self.buffer = buffer }

    func clearTail(after count: Int) throws {
        try buffer.withUnsafeMutableBytes { bytes in
            try clearImageReadTail(bytes, after: count)
        }
    }

    func copy(_ data: Data, at displacement: Int) throws {
        try buffer.withUnsafeMutableBytes { bytes in
            guard displacement >= 0, displacement <= bytes.count,
                data.count <= bytes.count - displacement
            else { throw POSIXError(.EFAULT) }
            let destination = UnsafeMutableRawBufferPointer(
                rebasing: bytes[displacement..<(displacement + data.count)])
            _ = data.copyBytes(to: destination.bindMemory(to: UInt8.self))
        }
    }
}

/// FSKit can retain the unused portion of a short read in its page cache. Initialize
/// that portion before replying, while preserving the actual byte count and EOF.
func clearImageReadTail(_ bytes: UnsafeMutableRawBufferPointer, after count: Int) throws {
    guard count >= 0, count <= bytes.count else { throw POSIXError(.EFAULT) }
    let tail = UnsafeMutableRawBufferPointer(rebasing: bytes[count...])
    tail.initializeMemory(as: UInt8.self, repeating: 0)
}

/// Retain the callback-owned item through a structured diagnostic wrapper. This adds
/// no concurrent item access; ownership validation still occurs inside that wrapper.
private struct ImageItemReference: @unchecked Sendable {
    let value: FSItem
}
