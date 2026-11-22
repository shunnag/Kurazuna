import Darwin
import Foundation
import ISCSICore
import ISCSIPlatform
import OSLog

/// What becomes of a block-resource generation whose mount will not complete (REC022).
///
/// FSKit on macOS 27.3 keeps a loaded block resource, and the marker device it opened, in this
/// extension instance for as long as the instance lives when the mount client exits between
/// loadResource and activation, or when the kernel mount fails after activation: it sends
/// neither deactivation nor unloadResource, and `FSResource.revoke()` is refused here by the
/// sandbox. When an instance ends, fskitd logs "Revoking resource" and the device is closed.
/// FSKit itself ends an instance right after a failed load, and after `deactivateVolume` on an
/// ordinary unmount. So once such a generation is closed without a mount and FSKit has not
/// unloaded it within `grace`, this instance ends, unless `ProcessMountRegistry` shows that a
/// mount ever completed in this process or that another generation is loading or loaded here.
/// Nothing has been mounted from the device then, so no data is at stake.
struct BlockLoadAbandonment: Sendable {
    /// How often an unmounted generation checks for its deadline and its withdrawn resource.
    var interval: Duration
    /// How long a closed, unmounted generation waits for FSKit's own unload.
    var grace: Duration
    /// Throws `CancellationError` when the generation's watch is cancelled.
    var sleep: @Sendable (Duration) async throws -> Void
    /// Whether anything is mounted from the device; nil when that is unknown.
    var deviceMountState: @Sendable (BlockMountIdentity) -> Bool?
    /// Ends this extension instance.
    var terminate: @Sendable () -> Void

    static let system = BlockLoadAbandonment(
        interval: .seconds(1), grace: .seconds(2), sleep: { try await Task.sleep(for: $0) },
        deviceMountState: { $0.deviceMountState() },
        terminate: {
            logger.notice("FSKitLifecycle abandoned block resource; ending this instance")
            exit(EXIT_SUCCESS)
        })

    static let logger = Logger(subsystem: "dev.soba.iscsi", category: "FSKitLifecycle")
}

/// Process-wide facts that veto ending an extension instance for an abandoned load (REC022).
/// One controller serves one generation at a time, and production has one file system per
/// process, but the instance is never ended on the evidence of one controller alone.
final class ProcessMountRegistry: @unchecked Sendable {
    static let shared = ProcessMountRegistry()
    private let lock = NSLock()
    private var mountCompleted = false
    private var active: Set<UUID> = []

    /// Latched for the life of the process once any volume here has completed a mount.
    func recordCompletedMount() { lock.withLock { mountCompleted = true } }
    var hasCompletedMount: Bool { lock.withLock { mountCompleted } }
    /// A generation is active from the start of its load until its controller clears it.
    func begin(_ generation: UUID) { _ = lock.withLock { active.insert(generation) } }
    func end(_ generation: UUID) { _ = lock.withLock { active.remove(generation) } }
    /// Whether this process may end for `generation`: no mount has ever completed here, and no
    /// other generation is loading or loaded.
    func permitsEnding(for generation: UUID) -> Bool {
        lock.withLock { !mountCompleted && active.subtracting([generation]).isEmpty }
    }
}

struct MountCompletionTiming: Sendable {
    let timeout: Duration
    let now: @Sendable () -> ContinuousClock.Instant
    let sleepUntil: @Sendable (ContinuousClock.Instant) async throws -> Void
    var isMounted: @Sendable (ConnectionDescriptor, URL) -> Bool = { _, _ in false }
    var isBlockMounted: @Sendable (BlockMountIdentity) -> Bool = { $0.contains() }

    static let system = MountCompletionTiming(
        timeout: .seconds(45), now: { ContinuousClock.now },
        sleepUntil: { try await Task.sleep(until: $0, clock: .continuous) },
        isMounted: { MountedFSKitBridge.contains($0, resourceURL: $1) })
}

/// Serializes load/unload across suspension. A cancelled generation can never publish its volume.
public actor ResourceController {
    public typealias Opener = @Sendable (ConnectionDescriptor, Bool) async throws -> LUNImageVolume
    private struct LoadedVolume: Sendable {
        let descriptor: ConnectionDescriptor
        let volume: LUNImageVolume
    }
    private let opener: Opener
    private let mountTiming: MountCompletionTiming
    private let abandonment: BlockLoadAbandonment?
    private let mounts: ProcessMountRegistry
    private var descriptor: ConnectionDescriptor?
    private var resourceURL: URL?
    private var blockMount: BlockMountIdentity?
    private var blockCheck: (@Sendable () throws -> Void)?
    private var generation: UUID?
    private var task: Task<LoadedVolume, any Error>?
    private var volume: LUNImageVolume?
    private var unloading = false
    /// The generation whose load or mount was abandoned; it can never publish a volume.
    private var abandonedGeneration: UUID?
    private var watch: Task<Void, Never>?

    /// Without `abandonment`: production file systems pass `.system` explicitly.
    public init(opener: @escaping Opener) {
        self.opener = opener
        mountTiming = .system
        abandonment = nil
        mounts = .shared
    }

    init(
        opener: @escaping Opener, mountTiming: MountCompletionTiming,
        abandonment: BlockLoadAbandonment? = nil, mounts: ProcessMountRegistry = .shared
    ) {
        self.opener = opener
        self.mountTiming = mountTiming
        self.abandonment = abandonment
        self.mounts = mounts
    }

    public func load(
        _ descriptor: ConnectionDescriptor, readOnly: Bool, resourceURL: URL? = nil
    ) async throws
        -> LUNImageVolume
    {
        let mountedURL: URL
        if let resourceURL {
            guard descriptor.acceptsResourceURL(resourceURL) else {
                throw POSIXError(.EINVAL)
            }
            mountedURL = resourceURL
        } else {
            mountedURL = try descriptor.resourceURL
        }
        return try await load(resourceURL: mountedURL, readOnly: readOnly) { descriptor }
    }

    /// Reserve the generation before resolving user-scoped metadata. Unload and cancellation
    /// can then prevent a late lookup from opening a new network connection.
    /// - Parameter withdrawn: For a block resource, whether the app has withdrawn the mount
    ///   resource this load resolved: true only when it definitely no longer exists. The app
    ///   withdraws it only after removing the bridge directory, so no mount can complete.
    func load(
        resourceURL: URL, readOnly: Bool, blockMount: BlockMountIdentity? = nil,
        check: (@Sendable () throws -> Void)? = nil,
        withdrawn: (@Sendable () async -> Bool)? = nil,
        onLoaded: (@Sendable () -> Void)? = nil,
        resolve: @escaping @Sendable () async throws -> ConnectionDescriptor
    ) async throws -> LUNImageVolume {
        guard generation == nil else { throw ProtocolError.busy }
        if let blockMount {
            guard let reference = try? ConnectionResourceReference(url: resourceURL),
                reference.mountID == blockMount.mountID
            else { throw POSIXError(.EINVAL) }
        } else {
            guard
                (try? ConnectionResourceReference(url: resourceURL)) != nil
                    || (try? ConnectionDescriptor(resourceURL: resourceURL)) != nil
            else { throw POSIXError(.EINVAL) }
        }
        let deadline = mountTiming.now().advanced(by: mountTiming.timeout)
        let generation = UUID()
        let opener = self.opener
        let task = Task {
            let descriptor = try await resolve()
            try Task.checkCancellation()
            guard self.generation == generation, !self.unloading else {
                throw CancellationError()
            }
            guard descriptor.acceptsResourceURL(resourceURL) else { throw POSIXError(.EINVAL) }
            self.descriptor = descriptor
            let volume = try await opener(descriptor, readOnly || descriptor.readOnly)
            return LoadedVolume(descriptor: descriptor, volume: volume)
        }
        self.resourceURL = resourceURL
        self.blockMount = blockMount
        self.blockCheck = check
        self.generation = generation
        self.task = task
        mounts.begin(generation)
        if let blockMount, let abandonment {
            watch = Task {
                await self.watchBlockGeneration(
                    generation, mount: blockMount, deadline: deadline, policy: abandonment,
                    withdrawn: withdrawn)
            }
        }
        do {
            let loaded = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
            let volume = loaded.volume
            guard self.generation == generation, !unloading, !Task.isCancelled,
                abandonedGeneration != generation
            else {
                await volume.shutdown()
                throw CancellationError()
            }
            do {
                let timing = mountTiming
                let mounts = self.mounts
                try volume.requireMountCompletion(
                    before: deadline, timing: timing,
                    isMounted: {
                        if let blockMount { return timing.isBlockMounted(blockMount) }
                        return timing.isMounted(loaded.descriptor, resourceURL)
                    }, onMountCompleted: { mounts.recordCompletedMount() })
            } catch {
                await volume.shutdown()
                throw error
            }
            self.volume = volume
            // Publish while the generation is still serialized by this actor.
            onLoaded?()
            return volume
        } catch {
            if self.generation == generation, !unloading { clear() }
            throw error
        }
    }

    /// Closing an already authenticated resource must not depend on an unlocked
    /// Keychain. Bind the request to the descriptor retained by this generation.
    public func unload(
        resourceURL: URL, onUnloaded: (@Sendable () -> Void)? = nil
    ) async throws {
        guard blockMount == nil,
            descriptor?.acceptsResourceURL(resourceURL)
                ?? (self.resourceURL?.absoluteString == resourceURL.absoluteString)
        else {
            throw POSIXError(.EINVAL)
        }
        try await unloadGeneration(onUnloaded: onUnloaded)
    }

    func checkBlockResource() throws {
        guard generation != nil, !unloading, volume != nil, blockMount != nil,
            let blockCheck
        else { throw POSIXError(.ENOTSUP) }
        try Task.checkCancellation()
        try blockCheck()
        try Task.checkCancellation()
    }

    /// Only the resource kind and retained device name are needed for cleanup. Do not read
    /// its header or resolve Keychain metadata again after the volume has failed or locked.
    func unload(
        blockDeviceName: String, onUnloaded: (@Sendable () -> Void)? = nil
    ) async throws {
        guard let blockMount, blockMount.bsdName == blockDeviceName else {
            throw POSIXError(.EINVAL)
        }
        try await unloadGeneration(onUnloaded: onUnloaded)
    }

    public func unload(_ descriptor: ConnectionDescriptor) async throws {
        guard
            self.descriptor == descriptor
                || (self.descriptor == nil
                    && resourceURL.map({ descriptor.acceptsResourceURL($0) }) == true)
        else { throw POSIXError(.EINVAL) }
        try await unloadGeneration()
    }

    private func unloadGeneration(onUnloaded: (@Sendable () -> Void)? = nil) async throws {
        guard let generation else { throw POSIXError(.EINVAL) }
        guard !unloading else { throw ProtocolError.busy }
        unloading = true
        task?.cancel()
        if let volume {
            await volume.shutdown()
        } else if let task, case .success(let loaded) = await task.result {
            await loaded.volume.shutdown()
        }
        if self.generation == generation {
            clear()
            // A newer load cannot publish between clear and the status update.
            onUnloaded?()
        }
    }

    /// Watches one block generation until its mount completes, or ends it once the mount is
    /// abandoned: at the load's mount deadline, or as soon as the app has withdrawn its mount
    /// resource. A load still in progress is cancelled (FSKit ends the instance after a failed
    /// load). A loaded volume is closed, and when FSKit has not unloaded it within the grace
    /// period, this instance ends (see `BlockLoadAbandonment`). Never while anything is mounted
    /// from the device, or while that is unknown.
    private func watchBlockGeneration(
        _ generation: UUID, mount: BlockMountIdentity, deadline: ContinuousClock.Instant,
        policy: BlockLoadAbandonment, withdrawn: (@Sendable () async -> Bool)?
    ) async {
        while true {
            do { try await policy.sleep(policy.interval) } catch { return }
            guard self.generation == generation, !unloading else { return }
            if volume?.isMountCompleted == true { return }
            switch policy.deviceMountState(mount) {
            case true?:
                // Mounted: FSKit deactivates it after its unmount and ends the instance.
                mounts.recordCompletedMount()
                return
            case nil: continue
            case false?: break
            }
            let expired = mountTiming.now() >= deadline
            let reason: String
            if expired {
                reason = "deadline"
            } else if let withdrawn, await withdrawn() {
                reason = "withdrawn"
            } else {
                continue
            }
            guard self.generation == generation, !unloading else { return }
            guard let volume else {
                BlockLoadAbandonment.logger.notice(
                    "FSKitLifecycle abandoned block load reason=\(reason, privacy: .public)")
                abandonedGeneration = generation
                task?.cancel()
                return
            }
            guard await volume.abandonUncompletedMount() else { return }
            BlockLoadAbandonment.logger.notice(
                "FSKitLifecycle abandoned unmounted block volume reason=\(reason, privacy: .public)"
            )
            do { try await policy.sleep(policy.grace) } catch { return }
            guard self.generation == generation, !unloading, !volume.isMountCompleted,
                policy.deviceMountState(mount) == false
            else { return }
            guard mounts.permitsEnding(for: generation) else {
                BlockLoadAbandonment.logger.notice(
                    "FSKitLifecycle kept this instance: a mount completed or another load is here")
                return
            }
            policy.terminate()
            return
        }
    }

    private func clear() {
        if let generation { mounts.end(generation) }
        watch?.cancel()
        watch = nil
        abandonedGeneration = nil
        task = nil
        descriptor = nil
        resourceURL = nil
        blockMount = nil
        blockCheck = nil
        generation = nil
        volume = nil
        unloading = false
    }
}
