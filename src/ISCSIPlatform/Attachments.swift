import Darwin
import Foundation
import ISCSICore
import OSLog

public struct DiskAttachment: Sendable, Equatable {
    public let device: String
    public let volumeURLs: [URL]
    public let volumeMountIssue: VolumeMountIssue?
    public init(
        device: String, volumeURLs: [URL], volumeMountIssue: VolumeMountIssue? = nil
    ) {
        self.device = device
        self.volumeURLs = volumeURLs
        self.volumeMountIssue = volumeMountIssue
    }
}

public struct VolumeMountIssue: Error, Sendable, Equatable {
    public let status: Int32
    public let detail: String
    public init(status: Int32, detail: String) {
        self.status = status
        self.detail = detail
    }
}

public enum AttachmentRecoveryState: Sendable, Equatable {
    case ready, resourceCleanupPending, needsInspection
}

public struct AttachedDisk: Sendable, Identifiable {
    public let id: UUID
    public let descriptor: ConnectionDescriptor
    public let bridgeURL: URL
    public var attachment: DiskAttachment?
    public var phase: AttachmentPhase
    public var verificationFailed: Bool
    /// A live absence observation, never a conclusion drawn from a persisted phase.
    public internal(set) var resourceCleanupError: MountResourceCleanupError?
    /// Any state other than reconnecting ends a reconnecting episode.
    public var connectionState = DiskConnectionState.unknown {
        didSet {
            guard connectionState != .reconnecting else { return }
            reconnectingSince = nil
            reconnectingLongEnough = false
        }
    }
    /// When the coordinator first observed this disk reconnecting, in an episode not
    /// interrupted by any other observed state. Never persisted.
    public internal(set) var reconnectingSince: ContinuousClock.Instant?
    /// The disk had been reconnecting for `forcedReleaseReconnectingDelay` when last evaluated.
    public internal(set) var reconnectingLongEnough = false
    /// How long a disk must keep reconnecting before its forced release is offered without a
    /// failed normal ejection, so that the offer doesn't come and go during a short blip.
    public static let forcedReleaseReconnectingDelay = Duration.seconds(10)
    public var connectionRoute: ConnectionRouteReport?
    public var connectedPortal: Portal {
        !verificationFailed && connectionState == .connected
            ? connectionRoute?.connectedPortal ?? descriptor.portal : descriptor.portal
    }
    public var needsCleanup: Bool { phase != .connected || verificationFailed }
    /// A forced observation proved that a resource here belongs to something else. Only
    /// explicit recovery, which inspects everything again, clears this live observation.
    public internal(set) var forcedReleaseRefused = false
    /// A record not known to be healthy, with more to release than its connection
    /// information, or a disk that has kept reconnecting to its server for
    /// `forcedReleaseReconnectingDelay`. A confirmed forced release can be offered for it
    /// without first failing a normal ejection; a healthy disk is offered one only after that
    /// failure. A disk with nothing to write reconnects for as long as its server is away, and
    /// its normal ejection may have to wait for the server; the confirmation says that unsaved
    /// changes will be lost.
    public var offersForcedRelease: Bool {
        guard resourceCleanupError == nil, !forcedReleaseRefused, connectionState != .connected
        else { return false }
        if connectionState == .reconnecting { return reconnectingLongEnough }
        return verificationFailed || phase == .unmountingBridge
    }

    /// Stamps the start of a reconnecting episode and evaluates its length at `now`.
    mutating func evaluateReconnecting(at now: ContinuousClock.Instant) {
        guard connectionState == .reconnecting else { return }
        let since = reconnectingSince ?? now
        reconnectingSince = since
        reconnectingLongEnough = since.duration(to: now) >= Self.forcedReleaseReconnectingDelay
    }

    init(entry: AttachmentJournalEntry) {
        id = entry.id
        descriptor = entry.descriptor
        bridgeURL = entry.bridgeURL
        attachment = nil
        phase = entry.phase
        verificationFailed = true
    }

    func journalEntry() throws -> AttachmentJournalEntry {
        try AttachmentJournalEntry(
            id: id, descriptor: descriptor, bridgeURL: bridgeURL, phase: phase)
    }
}

public enum AttachmentError: Error, Sendable, Equatable {
    case alreadyConnected
    case duplicateConnections
    case invalidImageResponse
    case readOnlyGeometryRequired
    case writeCompletionUnavailable
    case imageIdentityChanged
    case ownershipUnverified
    case recoveryRequired
    case journalUnreadable
    case journalUnavailable
    case connectionInterrupted
}

public enum BridgeOwnership: Sendable { case absent, verified, conflicting }

public struct AttachmentInspection: Sendable {
    public let ownership: BridgeOwnership
    public let attachment: DiskAttachment?
    public let connectionState: DiskConnectionState
    public let connectionRoute: ConnectionRouteReport?
    public init(
        ownership: BridgeOwnership, attachment: DiskAttachment?,
        connectionState: DiskConnectionState = .unknown,
        connectionRoute: ConnectionRouteReport? = nil
    ) {
        self.ownership = ownership
        self.attachment = attachment
        self.connectionState = connectionState
        self.connectionRoute = connectionRoute
    }
}

public protocol AttachmentBackend: Sendable {
    func bridgeURL(for id: UUID) async throws -> URL
    func untrackedBridges(excluding trackedURLs: [URL]) async throws -> [URL]
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    func inspectBridges(_ entries: [AttachmentJournalEntry]) async throws
        -> [UUID: Result<AttachmentInspection, any Error>]
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> DiskAttachment
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        async throws
    func forceEjectionIdentity(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws -> DiskAttachmentIdentity
    func forceDetachImage(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws
    func forceUnmountBridge(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws

    /// Observes a bridge for a confirmed forced release. An identity attribute that can't be
    /// read, for example because the extension has stopped, isn't a conflict here: ownership
    /// is then proven from facts the app checks alone. An attribute that answers with another
    /// identity remains a conflict.
    func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws -> AttachmentInspection
    /// Captures what a forced release would act on; `attachment` is the observed inner image.
    func forcedReleaseIdentity(
        _ attachment: DiskAttachment?, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws -> ForcedReleaseIdentity
    /// Best effort, before a confirmed forced release: asks the bridge's file system extension
    /// to stop reconnecting, so I/O waiting for the server fails at once instead of holding
    /// the release for the recovery window. No answer, or an error, is ignored.
    func abandonConnectionRecovery(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async
    /// Forcibly unmounts and detaches the confirmed inner image.
    func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws
    /// After the inner image is gone, forcibly unmounts the bridge, ejects its marker and
    /// discards the remaining local resources. Each resource already absent is skipped.
    func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws
    /// As `forceReleaseImage`, running `beforeReleasing` once every check on what it releases
    /// has passed, just before the first step that can't be undone, and only then.
    func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws
    /// As `forceReleaseBridge`, running `beforeReleasing` like `forceReleaseImage` does.
    func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws
}

extension AttachmentBackend {
    public func abandonConnectionRecovery(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async
    {}

    public func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws -> AttachmentInspection
    {
        try await inspectBridge(descriptor, at: bridgeURL)
    }

    public func forcedReleaseIdentity(
        _ attachment: DiskAttachment?, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws -> ForcedReleaseIdentity {
        guard let attachment else { return ForcedReleaseIdentity(image: nil) }
        return ForcedReleaseIdentity(
            image: try await forceEjectionIdentity(
                attachment, descriptor: descriptor, bridgeURL: bridgeURL))
    }

    public func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        guard let image = identity.image else { throw AttachmentError.imageIdentityChanged }
        try await forceDetachImage(image, descriptor: descriptor, bridgeURL: bridgeURL)
    }

    public func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        if let image = identity.image {
            try await forceUnmountBridge(image, descriptor: descriptor, bridgeURL: bridgeURL)
        } else {
            try await unmountBridge(descriptor, at: bridgeURL)
        }
    }

    /// A backend without checks of its own before releasing runs `beforeReleasing` first.
    public func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        await beforeReleasing()
        try await forceReleaseImage(identity, descriptor: descriptor, bridgeURL: bridgeURL)
    }

    public func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        await beforeReleasing()
        try await forceReleaseBridge(identity, descriptor: descriptor, bridgeURL: bridgeURL)
    }

    public func forceEjectionIdentity(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws -> DiskAttachmentIdentity {
        throw AttachmentError.recoveryRequired
    }

    public func forceDetachImage(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        throw AttachmentError.recoveryRequired
    }

    public func forceUnmountBridge(
        _ identity: DiskAttachmentIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        try await unmountBridge(descriptor, at: bridgeURL)
    }

    public func inspectBridges(_ entries: [AttachmentJournalEntry]) async throws
        -> [UUID: Result<AttachmentInspection, any Error>]
    {
        var results: [UUID: Result<AttachmentInspection, any Error>] = [:]
        for entry in entries {
            do {
                results[entry.id] = .success(
                    try await inspectBridge(entry.descriptor, at: entry.bridgeURL))
            } catch { results[entry.id] = .failure(error) }
        }
        return results
    }
}

/// Performs user-session operations without a shell, private API, or root helper.
public struct SystemAttachmentBackend: AttachmentBackend {
    typealias MountRunner = @Sendable (String, [String], TimeInterval) async throws -> Data
    typealias AttributeReader = @Sendable (String, String, Int) async -> BridgeAttributeRead
    typealias AttributeWriter = @Sendable (String, String, Data) async -> BridgeAttributeWrite
    typealias DirectoryRemover = @Sendable (String) async -> BridgeDirectoryRemoval
    typealias BridgeUnmounter = @Sendable (String) async -> BridgeUnmount
    /// How long an ordinary bridge unmount keeps trying while the bridge is busy. Another
    /// app can still have the bridge's Disk.img open after the inner image has detached:
    /// Parallels Desktop, for example, reads the backing image of every newly mounted volume
    /// to detect an operating system, which holds the file for 3–5 s on a healthy disk (and
    /// gives up after 30 s).
    public static let busyBridgeWait = Duration.seconds(10)
    /// The wait for a busy bridge, with its clock, which tests replace.
    struct BusyBridgeWait: Sendable {
        var limit: Duration
        var interval: Duration
        var now: @Sendable () -> ContinuousClock.Instant
        /// Throws `CancellationError` when the ejection is cancelled.
        var sleep: @Sendable (Duration) async throws -> Void

        static let system = Self(
            limit: SystemAttachmentBackend.busyBridgeWait, interval: .milliseconds(500),
            now: { ContinuousClock.now }, sleep: { try await Task.sleep(for: $0) })
    }
    /// What `statfs` reports for a path: its mount and the mounted file system.
    struct PathStatus: Sendable, Equatable {
        let mountPath: String
        let source: String
        let type: String
        let owner: uid_t
        let flags: UInt32
    }
    /// Calls that stat a path, which a mounted bridge's file system extension answers. Only
    /// ordinary inspections use them; a confirmed forced release never does.
    struct PathQueries: Sendable {
        var resolve: @Sendable (URL) -> String
        var status: @Sendable (String) -> Result<PathStatus, POSIXError>

        static let system = Self(
            resolve: { $0.resolvingSymlinksInPath().path },
            status: { path in
                var info = statfs()
                guard statfs(path, &info) == 0 else {
                    return .failure(POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO))
                }
                func text<T>(_ value: inout T) -> String {
                    withUnsafeBytes(of: &value) {
                        String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
                    }
                }
                return .success(
                    PathStatus(
                        mountPath: text(&info.f_mntonname), source: text(&info.f_mntfromname),
                        type: text(&info.f_fstypename), owner: info.f_owner,
                        flags: info.f_flags))
            })
    }
    private let root: URL
    private let diskImages: DiskImages
    private let blockResources: BlockMountResources?
    private let mountCommand: MountRunner
    private let resources: (any MountResourceStore)?
    private let readAttribute: AttributeReader
    private let writeAttribute: AttributeWriter
    private let removeDirectory: DirectoryRemover
    private let mounts: @Sendable () throws -> [CachedMountTable.Entry]
    private let paths: PathQueries
    private let unmountPath: BridgeUnmounter
    private let busyWait: BusyBridgeWait
    public init(root: URL) {
        // Unsigned command-line probes retain the legacy URL path. A signed app with
        // shared metadata configured must fail closed if that store is unavailable.
        let configured =
            Bundle.main.object(forInfoDictionaryKey: "ISCSISharedKeychainAccessGroup")
            != nil
        let blockEnabled =
            Bundle.main.object(forInfoDictionaryKey: "ISCSIUsesBlockResources")
            as? Bool == true
        self.init(
            root: root,
            resources: configured || blockEnabled
                ? KeychainMountResourceStore.sharedForCurrentBundle() : nil,
            blockResources: blockEnabled
                ? BlockMountResources(
                    bridgeRoot: root.standardizedFileURL.resolvingSymlinksInPath()) : nil,
            mountCommand: { program, arguments, timeout in
                try await SystemCommand.run(program, arguments: arguments, timeout: timeout)
            })
    }
    init(
        root: URL, resources: (any MountResourceStore)? = nil,
        blockResources: BlockMountResources? = nil, diskImages: DiskImages = DiskImages(),
        mountCommand: @escaping MountRunner,
        readAttribute: @escaping AttributeReader = {
            await BridgeAttributeRead.bounded(path: $0, name: $1, capacity: $2)
        },
        writeAttribute: @escaping AttributeWriter = {
            await BridgeAttributeWrite.bounded(path: $0, name: $1, value: $2)
        },
        removeDirectory: @escaping DirectoryRemover = {
            await BridgeDirectoryRemoval.bounded(path: $0)
        },
        mounts: @escaping @Sendable () throws -> [CachedMountTable.Entry] = {
            try CachedMountTable.read()
        },
        paths: PathQueries = .system,
        unmountPath: @escaping BridgeUnmounter = { await BridgeUnmount.bounded(path: $0) },
        busyWait: BusyBridgeWait = .system
    ) {
        self.root = root.standardizedFileURL.resolvingSymlinksInPath()
        self.mountCommand = mountCommand
        self.resources = resources
        self.blockResources = blockResources
        self.diskImages = diskImages
        self.readAttribute = readAttribute
        self.writeAttribute = writeAttribute
        self.removeDirectory = removeDirectory
        self.mounts = mounts
        self.paths = paths
        self.unmountPath = unmountPath
        self.busyWait = busyWait
    }

    public func bridgeURL(for id: UUID) async throws -> URL {
        root.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    public func untrackedBridges(excluding trackedURLs: [URL]) async throws -> [URL] {
        guard trackedURLs.count <= 128,
            trackedURLs.allSatisfy({
                $0.standardizedFileURL.deletingLastPathComponent().path == root.path
                    && UUID(uuidString: $0.lastPathComponent)?.uuidString == $0.lastPathComponent
            })
        else { throw AttachmentError.ownershipUnverified }
        let mounts = try Self.mountedPaths()
        let inventory = try await diskImages.inventory()
        let trackedIDs = Set(trackedURLs.compactMap { UUID(uuidString: $0.lastPathComponent) })
        let markerImages =
            blockResources.map { manager in
                trackedIDs.map {
                    manager.files.directory.appendingPathComponent($0.uuidString + ".img")
                }
            } ?? []
        var unknown = try Self.untrackedBridgeURLs(
            root: root, mountedPaths: mounts,
            imagePaths: inventory.imagePaths,
            trackedURLs: trackedURLs, trackedMarkerImages: markerImages)
        if let blockResources, try blockResources.files.hasUntrackedFiles(excluding: trackedIDs) {
            unknown.append(blockResources.files.directory)
        }
        return Array(Set(unknown)).sorted { $0.path < $1.path }
    }

    /// Inspect only our namespace. A nested mount or unexpected image is never covered by a
    /// record for its parent directory, even when that parent is a verified FSKit volume.
    static func untrackedBridgeURLs(
        root: URL, mountedPaths: [String], imagePaths: [String], trackedURLs: [URL],
        trackedMarkerImages: [URL] = []
    ) throws -> [URL] {
        guard mountedPaths.count <= 4096, imagePaths.count <= 1024 else {
            throw ProtocolError.limitExceeded("mounted resources")
        }
        let rootPath = root.standardizedFileURL.path
        let tracked = Set(trackedURLs.map { $0.standardizedFileURL.path })
        let trackedImages = Set(tracked.map { $0 + "/Disk.img" })
            .union(trackedMarkerImages.map { $0.standardizedFileURL.path })
        var unknown: Set<String> = []
        for path in mountedPaths {
            let path = URL(fileURLWithPath: path).standardizedFileURL.path
            if path == rootPath || path.hasPrefix(rootPath + "/") && !tracked.contains(path) {
                unknown.insert(path)
            }
        }
        for path in imagePaths where path.hasPrefix("/") {
            let url = URL(fileURLWithPath: path).standardizedFileURL
            if url.path.hasPrefix(rootPath + "/"), !trackedImages.contains(url.path) {
                unknown.insert(url.deletingLastPathComponent().path)
            }
        }
        return unknown.sorted().map { URL(fileURLWithPath: $0, isDirectory: true) }
    }

    private static func mountedPaths() throws -> [String] {
        // MNT_NOWAIT reads the kernel's cached table without contacting remote filesystems.
        for _ in 0..<3 {
            let count = getfsstat(nil, 0, MNT_NOWAIT)
            guard count >= 0 else { throw posixError() }
            guard count <= 4064 else { throw ProtocolError.limitExceeded("mounted filesystems") }
            var mounts: [statfs] = .init(repeating: statfs(), count: Int(count) + 32)
            let actual = mounts.withUnsafeMutableBufferPointer { buffer in
                getfsstat(
                    buffer.baseAddress, Int32(buffer.count * MemoryLayout<statfs>.stride),
                    MNT_NOWAIT)
            }
            guard actual >= 0 else { throw posixError() }
            guard Int(actual) < mounts.count else { continue }
            return mounts.prefix(Int(actual)).map { mount in
                var mount = mount
                return withUnsafePointer(to: &mount.f_mntonname) { pointer in
                    pointer.withMemoryRebound(to: CChar.self, capacity: 1024) {
                        String(cString: $0)
                    }
                }
            }
        }
        throw ProtocolError.busy
    }

    public func mountBridge(_ descriptor: ConnectionDescriptor, at url: URL) async throws {
        try validate(url, descriptor: descriptor)
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let directory = open(url.path, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw Self.posixError() }
        defer { close(directory) }
        let resourceURL: URL
        if let resources {
            let reference = try await resources.save(descriptor)
            try reference.validate(descriptor)
            resourceURL = reference.url
        } else {
            resourceURL = try descriptor.resourceURL
        }
        // Avoid accepting more buffered raw writes after a session has failed.
        if blockResources != nil && resources == nil { throw AttachmentError.ownershipUnverified }
        let marker = try await blockResources?.prepare(descriptor)
        let source = marker?.media.device ?? resourceURL.absoluteString
        let arguments = [
            "-F", "-t", ApplicationIdentity.current.fileSystemType, "-o",
            "nobrowse,nosuid,nodev,noexec,sync", source,
            url.path,
        ]
        try Task.checkCancellation()
        let runner = mountCommand
        // Let the bounded mount finish before cancellation so recovery can observe and unload it.
        // Initialization has a 45-second budget; leave time for its failure and cleanup callbacks.
        let deadline = ContinuousClock.now.advanced(by: .seconds(60))
        do {
            _ = try await Task.detached { try await runner("/sbin/mount", arguments, 60) }.value
        } catch let error as SystemCommandError where Self.isInitialExtensionLaunchFailure(error) {
            // launchd can evict an extension job for the previous path and reject the request
            // that triggered eviction. Only repeat the initial load of this still-unused bridge.
            try await Task.sleep(for: .milliseconds(350))
            if let resources {
                let reference = try ConnectionResourceReference(descriptor: descriptor)
                guard try await resources.resolve(reference) == descriptor else {
                    throw AttachmentError.ownershipUnverified
                }
            }
            let inventory = try await diskImages.inventory()
            guard !inventory.hasImage(under: url) else { throw AttachmentError.ownershipUnverified }
            if let blockResources {
                guard let marker,
                    try blockResources.current(descriptor, inventory: inventory, expectedMount: nil)
                        == marker
                else { throw AttachmentError.ownershipUnverified }
            }
            try validate(url, descriptor: descriptor)
            let path = url.path
            guard
                try !mounts().contains(where: {
                    $0.path == path || $0.path.hasPrefix(path + "/") || $0.source == source
                })
            else { throw AttachmentError.ownershipUnverified }
            var original = stat()
            var current = stat()
            guard fstat(directory, &original) == 0, lstat(path, &current) == 0,
                current.st_mode & S_IFMT == S_IFDIR, current.st_uid == geteuid(),
                current.st_mode & 0o777 == 0o700,
                original.st_dev == current.st_dev, original.st_ino == current.st_ino,
                try FileManager.default.contentsOfDirectory(atPath: path).isEmpty
            else { throw AttachmentError.ownershipUnverified }
            try Task.checkCancellation()
            let remaining = ContinuousClock.now.duration(to: deadline).components.seconds
            guard remaining >= 45 else { throw error }
            Logger(subsystem: ApplicationIdentity.current.bundleIdentifier, category: "Mount")
                .notice("Retrying initial FSKit extension launch once")
            _ = try await Task.detached {
                try await runner("/sbin/mount", arguments, TimeInterval(remaining))
            }.value
        }
        try Task.checkCancellation()
        try await requireOwnership(descriptor, at: url, verifyWritePolicy: true)
    }

    static func isInitialExtensionLaunchFailure(_ error: SystemCommandError) -> Bool {
        guard case .failed("mount", 69, let diagnostic) = error else { return false }
        let lines = diagnostic.split(whereSeparator: \.isNewline)
        return lines.count == 2 && lines[0].hasPrefix("mount: Loading resource: ")
            && lines[0].hasSuffix("(com.apple.extensionKit.errorDomain error 2.)")
            && lines[1]
                == "mount: File system named \(ApplicationIdentity.current.fileSystemType) not found"
    }

    public func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> AttachmentInspection
    {
        try await inspection(descriptor, at: bridgeURL, images: await diskImages.inventory())
    }

    public func inspectBridges(_ entries: [AttachmentJournalEntry]) async throws
        -> [UUID: Result<AttachmentInspection, any Error>]
    {
        guard entries.count <= 128 else { throw ProtocolError.limitExceeded("connected disks") }
        // One DiskImages snapshot for the entire refresh, rather than one process per LUN.
        let images = try await diskImages.inventory()
        var results: [UUID: Result<AttachmentInspection, any Error>] = [:]
        for entry in entries {
            do {
                results[entry.id] = .success(
                    try await inspection(entry.descriptor, at: entry.bridgeURL, images: images))
            } catch { results[entry.id] = .failure(error) }
        }
        return results
    }

    public func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws
        -> DiskAttachment
    {
        try await requireOwnership(descriptor, at: bridgeURL, verifyWritePolicy: true)
        let image = bridgeURL.appendingPathComponent("Disk.img")
        guard try await !diskImages.inventory().hasImage(under: bridgeURL, excluding: image) else {
            throw AttachmentError.ownershipUnverified
        }
        return try await diskImages.attachImage(
            at: image, readOnly: descriptor.readOnly, presentation: descriptor.imagePresentation)
    }

    public func detachImage(
        _ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        try await requireOwnership(descriptor, at: bridgeURL)
        let image = bridgeURL.appendingPathComponent("Disk.img")
        guard try await !diskImages.inventory().hasImage(under: bridgeURL, excluding: image) else {
            throw AttachmentError.ownershipUnverified
        }
        try await diskImages.detach(attachment, at: image)
    }

    // MARK: Forced release

    /// The bridge as a confirmed forced release sees it. `mounted` covers a legacy URL
    /// bridge, which has no cached block-media binding to report in `mount`.
    private struct ForcedObservation: Equatable {
        let ownership: BridgeOwnership
        let attachment: DiskAttachment?
        let connectionState: DiskConnectionState
        let mount: CachedMountTable.Entry?
        let mounted: Bool
    }

    public func forcedReleaseInspection(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws -> AttachmentInspection
    {
        let observation = try await forcedObservation(
            descriptor, at: bridgeURL, inventory: await diskImages.inventory())
        return AttachmentInspection(
            ownership: observation.ownership, attachment: observation.attachment,
            connectionState: observation.connectionState)
    }

    /// Ownership comes from the cached mount table and this record's private marker, which
    /// never ask the file system extension. The identity attribute is still read, with a
    /// deadline: an answer naming another resource is a conflict, while an error or no
    /// answer leaves the proof to those local facts. Its connection state is read only from
    /// an extension that answered with this record's identity.
    private func forcedObservation(
        _ descriptor: ConnectionDescriptor, at url: URL, inventory: DiskImageInventory
    ) async throws -> ForcedObservation {
        try validateLexically(url, descriptor: descriptor)
        let image = url.appendingPathComponent("Disk.img")
        // Through an earlier ejection still pending for the image: see `forcedAttachment`.
        let attachment = try inventory.forcedAttachment(at: image)
        func observation(
            _ ownership: BridgeOwnership, state: DiskConnectionState = .unknown,
            mount: CachedMountTable.Entry? = nil, mounted: Bool = false
        ) -> ForcedObservation {
            ForcedObservation(
                ownership: ownership, attachment: attachment, connectionState: state,
                mount: mount, mounted: mounted)
        }
        guard !inventory.hasImage(under: url, excluding: image) else {
            return observation(.conflicting)
        }
        guard let blockResources else {
            // A legacy URL bridge has no local marker to bind it to this record. As its
            // ordinary inspection does, it requires the extension's own identity answer, but
            // reads it with a deadline: no answer in time fails instead of waiting.
            let (ownership, state) = try await forcedLegacyOwnership(
                descriptor, at: url, attached: attachment != nil)
            return observation(ownership, state: state, mounted: ownership == .verified)
        }
        guard
            let mount = try blockResources.forcedBridgeMount(
                descriptor, at: url, inventory: inventory)
        else {
            // Nothing is mounted at the bridge, so an inner image can't be this record's.
            return observation(attachment == nil ? .absent : .conflicting)
        }
        switch Self.forcedIdentityAnswer(
            await readAttribute(url.path, ConnectionDescriptor.identityAttributeName, 33),
            expected: try descriptor.resourceIdentity)
        {
        case .mismatching:
            return observation(.conflicting, mount: mount, mounted: true)
        case .unanswered:
            return observation(.verified, mount: mount, mounted: true)
        case .matching:
            return observation(
                .verified, state: await forcedConnectionState(at: url), mount: mount,
                mounted: true)
        }
    }

    enum ForcedIdentityAnswer: Equatable { case matching, mismatching, unanswered }

    /// Only a value is an answer. Any error, including a missing or unsupported attribute,
    /// and a read that didn't finish in time, leave ownership to the local proof. A value
    /// longer than the buffer (ERANGE) is an answer naming something else.
    static func forcedIdentityAnswer(_ read: BridgeAttributeRead, expected: Data)
        -> ForcedIdentityAnswer
    {
        switch read {
        case .value(let bytes): Data(bytes) == expected ? .matching : .mismatching
        case .failed(let code): code == ERANGE ? .mismatching : .unanswered
        case .timedOut: .unanswered
        }
    }

    private func forcedConnectionState(at url: URL) async -> DiskConnectionState {
        guard
            case .value(let bytes) = await readAttribute(
                url.path, ConnectionDescriptor.connectionStateAttributeName, 3),
            bytes.count == 2
        else { return .unknown }
        return (try? DiskConnectionState(encoded: Data(bytes))) ?? .unknown
    }

    /// Only a bridge proven to be this record's, mounted now, receives the request. Writing it
    /// can't release anything; a stopped extension simply doesn't answer before the deadline.
    /// The writable Disk.img (0600) is tried first: the kernel may refuse an attribute write on
    /// the read-only root directory (0500) before the extension sees it. A read-only mount
    /// refuses every attribute write (EROFS) before the extension sees it; its volume answers
    /// a read of its own control name instead, with the request's value.
    public func abandonConnectionRecovery(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async
    {
        guard
            let observation = try? await forcedObservation(
                descriptor, at: bridgeURL, inventory: await diskImages.inventory()),
            observation.ownership == .verified, observation.mounted
        else { return }
        for path in [bridgeURL.appendingPathComponent("Disk.img").path, bridgeURL.path] {
            switch await writeAttribute(
                path, ConnectionDescriptor.connectionControlAttributeName,
                ConnectionDescriptor.abandonRecoveryControlValue)
            {
            // An extension that doesn't answer in time won't answer the second write either.
            case .written, .timedOut: return
            case .failed(let code):
                guard code == EROFS else { continue }
                switch await readAttribute(
                    path, ConnectionDescriptor.readOnlyConnectionControlAttributeName,
                    ConnectionDescriptor.abandonRecoveryControlValue.count + 1)
                {
                case .value(let bytes)
                where Data(bytes) == ConnectionDescriptor.abandonRecoveryControlValue:
                    return
                case .timedOut: return
                // An extension without the read-only control, or a writable volume.
                case .value, .failed: continue
                }
            }
        }
    }

    private func forcedBridgeResource(
        _ descriptor: ConnectionDescriptor, at url: URL, observation: ForcedObservation
    ) async throws -> BlockMountResources.ForceIdentity? {
        guard observation.mount != nil, let blockResources else { return nil }
        return try await blockResources.captureForceIdentity(descriptor, at: url)
    }

    public func forcedReleaseIdentity(
        _ attachment: DiskAttachment?, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws -> ForcedReleaseIdentity {
        let first = try await forcedObservation(
            descriptor, at: bridgeURL, inventory: await diskImages.inventory())
        guard first.ownership != .conflicting,
            first.ownership == .verified || first.attachment == nil
        else { throw AttachmentError.ownershipUnverified }
        guard first.attachment?.device == attachment?.device else {
            throw AttachmentError.imageIdentityChanged
        }
        let resource = try await forcedBridgeResource(
            descriptor, at: bridgeURL, observation: first)
        var image: DiskAttachmentIdentity?
        if let attachment = first.attachment {
            image = try await diskImages.captureForceEjectionIdentity(
                attachment, at: bridgeURL.appendingPathComponent("Disk.img"))
        }
        let second = try await forcedObservation(
            descriptor, at: bridgeURL, inventory: await diskImages.inventory())
        guard second.ownership == first.ownership, second.mounted == first.mounted,
            second.mount == first.mount, second.attachment?.device == first.attachment?.device,
            try await forcedBridgeResource(descriptor, at: bridgeURL, observation: second)
                == resource
        else { throw AttachmentError.imageIdentityChanged }
        return ForcedReleaseIdentity(
            image: image, bridgeMounted: first.mounted, bridgeResource: resource)
    }

    public func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        try await forceReleaseImage(
            identity, descriptor: descriptor, bridgeURL: bridgeURL, beforeReleasing: {})
    }

    public func forceReleaseImage(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        let image = bridgeURL.appendingPathComponent("Disk.img")
        guard let expected = identity.image, expected.imageURL == image else {
            throw AttachmentError.imageIdentityChanged
        }
        let current = try await forcedObservation(
            descriptor, at: bridgeURL, inventory: await diskImages.inventory())
        guard current.ownership != .conflicting else { throw AttachmentError.ownershipUnverified }
        // An earlier attempt, or the user, already detached it.
        guard let attachment = current.attachment else { return }
        guard current.ownership == .verified, attachment.device == expected.device,
            current.mounted == identity.bridgeMounted,
            try await forcedBridgeResource(descriptor, at: bridgeURL, observation: current)
                == identity.bridgeResource
        else { throw AttachmentError.imageIdentityChanged }
        try await diskImages.forceDetach(expected, at: image, beforeEjecting: beforeReleasing)
    }

    public func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL
    ) async throws {
        try await forceReleaseBridge(
            identity, descriptor: descriptor, bridgeURL: bridgeURL, beforeReleasing: {})
    }

    public func forceReleaseBridge(
        _ identity: ForcedReleaseIdentity, descriptor: ConnectionDescriptor, bridgeURL: URL,
        beforeReleasing: @escaping @Sendable () async -> Void
    ) async throws {
        try validateLexically(bridgeURL, descriptor: descriptor)
        if let image = identity.image,
            image.imageURL != bridgeURL.appendingPathComponent("Disk.img")
        {
            throw AttachmentError.imageIdentityChanged
        }
        var inventory = try await diskImages.inventory()
        let image = bridgeURL.appendingPathComponent("Disk.img")
        if inventory.hasPendingEjection(at: image), try inventory.forcedAttachment(at: image) == nil
        {
            // The image is gone, but an earlier ejection of it hasn't ended: give it the same
            // bounded wait as the image step, once reconnecting stops, then look again.
            await beforeReleasing()
            guard
                await diskImages.waitForPendingEjection(
                    at: image, timeout: DiskImages.pendingEjectionWait)
            else { throw ProtocolError.timedOut }
            inventory = try await diskImages.inventory()
        }
        guard !inventory.hasImage(under: bridgeURL) else { throw POSIXError(.EBUSY) }
        let current = try await forcedObservation(descriptor, at: bridgeURL, inventory: inventory)
        switch current.ownership {
        case .conflicting:
            throw AttachmentError.ownershipUnverified
        case .verified:
            // A bridge mounted after the confirmation was prepared isn't the one confirmed.
            guard identity.bridgeMounted else { throw AttachmentError.imageIdentityChanged }
            guard let blockResources else {
                // Legacy URL bridges have no captured block-media identity. Preserve their
                // existing normal unmount; never apply force to an unbound mount. The
                // observation just proved, within a deadline, that it is this record's.
                await beforeReleasing()
                _ = try await SystemCommand.run("/sbin/umount", arguments: [bridgeURL.path])
                break
            }
            guard let expected = identity.bridgeResource else {
                throw AttachmentError.ownershipUnverified
            }
            try await blockResources.forceEject(
                descriptor, at: bridgeURL, expected: expected, beforeUnmounting: beforeReleasing)
            try await blockResources.confirmUnmountedIdentity(
                descriptor, at: bridgeURL, expected: expected)
        case .absent:
            // An earlier attempt, or the system, already unmounted it.
            if let expected = identity.bridgeResource, let blockResources {
                try await blockResources.confirmUnmountedIdentity(
                    descriptor, at: bridgeURL, expected: expected)
            }
        }
        // Removes the directory, then normally ejects and removes a remaining marker and
        // the connection information, each only if still present.
        try await forcedDiscardEmptyBridge(descriptor, at: bridgeURL)
    }

    /// As `discardEmptyBridge`, without asking the bridge's path: the cached mount table shows
    /// that nothing is mounted there, and the directory is removed within a deadline.
    private func forcedDiscardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws
    {
        try validateLexically(bridgeURL, descriptor: descriptor)
        guard try mountEntry(at: bridgeURL) == nil,
            try await !diskImages.inventory().hasImage(under: bridgeURL)
        else { throw POSIXError(.EBUSY) }
        switch await removeDirectory(bridgeURL.path) {
        case .removed: break
        case .failed(let code):
            guard code == ENOENT else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
        case .timedOut: throw POSIXError(.ETIMEDOUT)
        }
        if let blockResources {
            await withdrawMountResource(descriptor)
            try await blockResources.cleanup(descriptor)
        }
        if let resources {
            do {
                try await resources.remove(ConnectionResourceReference(descriptor: descriptor))
            } catch {
                // As in `discardEmptyBridge`: only after all three absence checks above.
                throw MountResourceCleanupError(underlying: error)
            }
        }
    }

    /// The mount at exactly this path in the kernel's cached table, which never asks it.
    private func mountEntry(at url: URL) throws -> CachedMountTable.Entry? {
        let path = url.standardizedFileURL.path
        let matching = try mounts().filter { $0.path == path }
        guard matching.count <= 1 else { throw AttachmentError.ownershipUnverified }
        return matching.first
    }

    /// A legacy bridge's ownership for a forced release. The mount comes from the cached
    /// table; the extension's identity answer, and only then its state, are read within the
    /// deadline. No answer in time, or an error other than a missing attribute, fails.
    private func forcedLegacyOwnership(
        _ descriptor: ConnectionDescriptor, at url: URL, attached: Bool
    ) async throws -> (BridgeOwnership, DiskConnectionState) {
        guard let mount = try mountEntry(at: url) else {
            return (attached ? .conflicting : .absent, .unknown)
        }
        guard mount.type == ApplicationIdentity.current.fileSystemType, mount.owner == getuid(),
            !mount.source.hasPrefix("/dev/")
        else { return (.conflicting, .unknown) }
        switch await readAttribute(url.path, ConnectionDescriptor.identityAttributeName, 33) {
        case .value(let bytes):
            guard Data(bytes) == (try descriptor.resourceIdentity) else {
                return (.conflicting, .unknown)
            }
            return (.verified, await forcedConnectionState(at: url))
        case .failed(let code):
            if [ENOATTR, ENOTSUP, ERANGE].contains(code) { return (.conflicting, .unknown) }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        case .timedOut:
            throw POSIXError(.ETIMEDOUT)
        }
    }

    public func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) async throws {
        try validate(bridgeURL, descriptor: descriptor)
        guard try await !diskImages.inventory().hasImage(under: bridgeURL) else {
            throw POSIXError(.EBUSY)
        }
        switch try ownership(descriptor, at: bridgeURL) {
        case .conflicting: throw AttachmentError.ownershipUnverified
        case .verified: try await unmountVerifiedBridge(descriptor, at: bridgeURL)
        case .absent: break
        }
        try await discardEmptyBridge(descriptor, at: bridgeURL)
    }

    /// The ordinary unmount of a bridge proven to be this record's. A busy bridge is usually
    /// held for a moment by another app reading Disk.img, whatever the connection's state; it
    /// is tried again within `busyWait`, each time after observing that it is still this
    /// record's. Still busy then, the disk is reported in use (EBUSY), which keeps its verified
    /// connection. Any other failure, such as the EIO of a stopped disk's final
    /// synchronization, is reported at once as the umount command reported it.
    private func unmountVerifiedBridge(_ descriptor: ConnectionDescriptor, at url: URL)
        async throws
    {
        let started = busyWait.now()
        while true {
            // As the umount command did: a cancelled ejection starts no unmount. One that has
            // started runs to its result or deadline.
            try Task.checkCancellation()
            switch await unmountPath(url.path) {
            case .unmounted:
                return
            case .timedOut:
                throw SystemCommandError.timedOut(program: "umount")
            case .failed(let code) where code == EBUSY:
                guard started.duration(to: busyWait.now()) + busyWait.interval <= busyWait.limit
                else { throw POSIXError(.EBUSY) }
                try await busyWait.sleep(busyWait.interval)
                switch try ownership(descriptor, at: url) {
                case .verified: continue
                // Unmounted meanwhile, for example by the user; the caller discards the rest.
                case .absent: return
                case .conflicting: throw AttachmentError.ownershipUnverified
                }
            case .failed(let code):
                throw SystemCommandError.failed(
                    program: "umount", status: 1,
                    detail: "umount: unmount(\(url.path)): \(String(cString: strerror(code)))\n")
            }
        }
    }

    /// Used during recovery only after observing that no mounted resource remains.
    public func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        async throws
    {
        try validate(bridgeURL, descriptor: descriptor)
        guard try ownership(descriptor, at: bridgeURL) == .absent,
            try await !diskImages.inventory().hasImage(under: bridgeURL)
        else { throw POSIXError(.EBUSY) }
        if rmdir(bridgeURL.path) != 0, errno != ENOENT { throw Self.posixError() }
        if let blockResources {
            await withdrawMountResource(descriptor)
            try await blockResources.cleanup(descriptor)
        }
        if let resources {
            do {
                try await resources.remove(ConnectionResourceReference(descriptor: descriptor))
            } catch {
                // This distinction is valid only after all three absence checks above.
                // Never turn a failed unmount or a conflicting resource into cleanup-only work.
                throw MountResourceCleanupError(underlying: error)
            }
        }
    }

    /// Tells a file system extension instance still loading this record's marker, or holding it
    /// loaded but never mounted, to give it up (REC022): the instance treats the definite
    /// absence of the mount resource it resolved as abandonment. Called only after the bridge
    /// directory is gone, so no mount of this record can complete. A failure is not an error
    /// here: the instance still gives the marker up at its own mount deadline, and the final
    /// removal after the marker cleanup reports it.
    private func withdrawMountResource(_ descriptor: ConnectionDescriptor) async {
        guard let resources,
            let reference = try? ConnectionResourceReference(descriptor: descriptor)
        else { return }
        try? await resources.remove(reference)
    }

    public static func parseAttachment(_ data: Data) throws -> DiskAttachment {
        try DiskImages.parseAttachment(data)
    }

    private func inspection(
        _ descriptor: ConnectionDescriptor, at bridgeURL: URL, images: DiskImageInventory
    ) async throws -> AttachmentInspection {
        try validate(bridgeURL, descriptor: descriptor)
        let expected = bridgeURL.appendingPathComponent("Disk.img")
        let image = try images.attachment(at: expected)
        let owner = try ownership(descriptor, at: bridgeURL)
        if owner == .verified {
            try await requireOwnership(descriptor, at: bridgeURL, images: images)
        }
        let conflicting =
            (owner == .absent && image != nil)
            || images.hasImage(under: bridgeURL, excluding: expected)
        let state: DiskConnectionState =
            owner == .verified && !conflicting ? connectionState(at: bridgeURL) : .unknown
        return AttachmentInspection(
            ownership: conflicting ? .conflicting : owner, attachment: image,
            connectionState: state,
            connectionRoute: state == .connected ? connectionRoute(descriptor, at: bridgeURL) : nil)
    }

    private func connectionRoute(_ descriptor: ConnectionDescriptor, at url: URL)
        -> ConnectionRouteReport?
    {
        var bytes = [UInt8](repeating: 0, count: ConnectionRouteReport.maximumEncodedLength + 1)
        let count = bytes.withUnsafeMutableBytes { buffer in
            getxattr(
                url.path, ConnectionDescriptor.connectionRouteAttributeName, buffer.baseAddress,
                buffer.count, 0, XATTR_NOFOLLOW)
        }
        guard count > 0, count <= ConnectionRouteReport.maximumEncodedLength else { return nil }
        return try? ConnectionRouteReport(data: Data(bytes.prefix(count)), descriptor: descriptor)
    }

    private func connectionState(at url: URL) -> DiskConnectionState {
        var bytes = [UInt8](repeating: 0, count: 3)
        let count = bytes.withUnsafeMutableBytes { buffer in
            getxattr(
                url.path, ConnectionDescriptor.connectionStateAttributeName,
                buffer.baseAddress, buffer.count, 0, XATTR_NOFOLLOW)
        }
        guard count == 2 else { return .unknown }
        return (try? DiskConnectionState(encoded: Data(bytes.prefix(2)))) ?? .unknown
    }

    private func requireOwnership(
        _ descriptor: ConnectionDescriptor, at url: URL, verifyWritePolicy: Bool = false,
        images: DiskImageInventory? = nil
    ) async throws {
        try validate(url, descriptor: descriptor)
        let state = try bridgeState(descriptor, at: url)
        guard state.ownership == .verified else {
            throw AttachmentError.ownershipUnverified
        }
        if state.source.hasPrefix("/dev/") {
            let inventory: DiskImageInventory
            if let images {
                inventory = images
            } else {
                inventory = try await diskImages.inventory()
            }
            guard let blockResources,
                let marker = try blockResources.current(
                    descriptor, inventory: inventory,
                    expectedMount: url),
                marker.media.device == state.source, let mountID = descriptor.mountID
            else { throw AttachmentError.ownershipUnverified }
            let identity = try BlockMountIdentity(
                bsdName: String(marker.media.device.dropFirst(5)), mountID: mountID)
            guard
                identity.matches(
                    type: ApplicationIdentity.current.fileSystemType, source: state.source,
                    mountPoint: url.path, owner: getuid())
            else {
                throw AttachmentError.ownershipUnverified
            }
            if verifyWritePolicy {
                try Self.validateBlockMountPolicy(flags: state.flags, readOnly: descriptor.readOnly)
            }
        } else if verifyWritePolicy {
            try Self.validateWritableMountPolicy(flags: state.flags, readOnly: descriptor.readOnly)
        }
    }

    static func validateBlockMountPolicy(flags: UInt32, readOnly: Bool) throws {
        guard flags & UInt32(MNT_ASYNC) == 0,
            readOnly || flags & UInt32(MNT_RDONLY) == 0
        else { throw AttachmentError.writeCompletionUnavailable }
    }

    // A successful mount command does not prove FSKit applied its options.
    // Keep inspection and normal ejection available when this policy fails.
    static func validateWritableMountPolicy(flags: UInt32, readOnly: Bool) throws {
        guard !readOnly else { return }
        guard flags & UInt32(MNT_SYNCHRONOUS) != 0,
            flags & UInt32(MNT_ASYNC | MNT_RDONLY) == 0
        else { throw AttachmentError.writeCompletionUnavailable }
    }

    private func validate(_ url: URL, descriptor: ConnectionDescriptor) throws {
        try validateLexically(url, descriptor: descriptor)
        guard paths.resolve(root) == root.path,
            paths.resolve(url) == url.standardizedFileURL.path
        else { throw POSIXError(.EINVAL) }
    }

    /// The bridge's path, checked without asking any file system. Resolving it stats the
    /// mount point, which a stopped or reconnecting extension may never answer, so a forced
    /// release relies on this alone. In place of the symlink check, the path is only acted on
    /// as a mount point listed in the kernel's cached table, whose paths are already resolved,
    /// or removed with rmdir, which never follows a final symlink.
    private func validateLexically(_ url: URL, descriptor: ConnectionDescriptor) throws {
        guard let mountID = descriptor.mountID, url.isFileURL, url.host?.isEmpty != false,
            url.query == nil,
            url.fragment == nil,
            url.standardizedFileURL.deletingLastPathComponent().path == root.path,
            url.lastPathComponent == mountID.uuidString
        else { throw POSIXError(.EINVAL) }
    }

    private func ownership(_ descriptor: ConnectionDescriptor, at url: URL) throws
        -> BridgeOwnership
    {
        try bridgeState(descriptor, at: url).ownership
    }

    private func bridgeState(_ descriptor: ConnectionDescriptor, at url: URL) throws
        -> (ownership: BridgeOwnership, flags: UInt32, source: String)
    {
        let info: PathStatus
        switch paths.status(url.path) {
        case .success(let status): info = status
        case .failure(let error):
            if error.code == .ENOENT { return (.absent, 0, "") }
            throw error
        }
        guard info.mountPath == url.standardizedFileURL.path else {
            return (.absent, info.flags, "")
        }
        let source = info.source
        guard info.type == ApplicationIdentity.current.fileSystemType, info.owner == getuid()
        else {
            return (.conflicting, info.flags, source)
        }
        var data = [UInt8](repeating: 0, count: 33)
        let count = data.withUnsafeMutableBytes { bytes in
            getxattr(
                url.path, ConnectionDescriptor.identityAttributeName, bytes.baseAddress,
                bytes.count, 0, XATTR_NOFOLLOW)
        }
        if count < 0 {
            if [ENOATTR, ENOTSUP, ERANGE].contains(errno) {
                return (.conflicting, info.flags, source)
            }
            throw Self.posixError()
        }
        guard count == 32 else { return (.conflicting, info.flags, source) }
        return (
            Data(data.prefix(32)) == (try descriptor.resourceIdentity) ? .verified : .conflicting,
            info.flags, source
        )
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
