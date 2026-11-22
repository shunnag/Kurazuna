import CryptoKit
import FSKit
import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Security

public final class ISCSIFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations,
    FSManageableResourceMaintenanceOperations,
    @unchecked Sendable
{
    #if ISCSI_OWNED_LIO_FIXTURE
        public static let isOwnedLIOFixture = true
        #if ISCSI_OWNED_LIO_RECOVERY
            public static let shortName = "iscsirecovery"
            public static let extensionBundleID = "dev.soba.iscsi.ownedlio.recovery.FileSystem"
        #elseif ISCSI_OWNED_LIO_PARENT_SCOPE
            public static let shortName = "iscsiscope"
            public static let extensionBundleID = "dev.soba.iscsi.ownedlio.scope.FileSystem"
        #else
            public static let shortName = "iscsilab"
            public static let extensionBundleID = "dev.soba.iscsi.ownedlio.FileSystem"
        #endif
    #else
        public static let isOwnedLIOFixture = false
        public static let shortName = ApplicationIdentity.current.fileSystemType
        public static let extensionBundleID = ApplicationIdentity.current.extensionBundleIdentifier
    #endif
    private let controller: ResourceController
    private let resources: any MountResourceStore

    public override init() {
        let credentials = KeychainCredentialStore.sharedForCurrentBundle()
        resources = KeychainMountResourceStore.sharedForCurrentBundle()
        controller = ResourceController(
            opener: { descriptor, readOnly in
                try await LUNVolumeFactory.open(
                    descriptor, readOnly: readOnly, credentials: credentials)
            }, mountTiming: .system, abandonment: .system)
        super.init()
    }

    public init(
        controller: ResourceController,
        resources: any MountResourceStore = KeychainMountResourceStore.sharedForCurrentBundle()
    ) {
        self.controller = controller
        self.resources = resources
        super.init()
    }

    /// Opt-in source selected by an embedding extension with a real target control plane.
    /// Ordinary installed extensions keep the default factory until such a source is supplied.
    public init(
        reservedSource: any ReservedLUNSource,
        credentials: any CredentialStore = KeychainCredentialStore.sharedForCurrentBundle(),
        resources: any MountResourceStore = KeychainMountResourceStore.sharedForCurrentBundle(),
        unmountBehavior: ReservedUnmountBehavior = .abandon
    ) {
        self.resources = resources
        controller = ResourceController { descriptor, readOnly in
            try await LUNVolumeFactory.openReserved(
                descriptor, readOnly: readOnly, credentials: credentials, source: reservedSource,
                unmountBehavior: unmountBehavior)
        }
        super.init()
    }

    public func probeResource(resource: FSResource) async throws -> FSProbeResult {
        let descriptor: ConnectionDescriptor
        do {
            if let resource = resource as? FSGenericURLResource {
                descriptor = try await resources.descriptor(for: resource.url)
            } else if let block = resource as? FSBlockDeviceResource {
                let binding = try BlockMountResourceBinding.read(block)
                descriptor = try await resources.resolve(binding.marker.reference)
                try binding.marker.reference.validate(descriptor)
            } else {
                return .notRecognized
            }
        } catch { return .notRecognized }
        return .usable(
            name: ApplicationIdentity.current.applicationName,
            containerID: FSContainerIdentifier(uuid: Self.identifier(for: descriptor)))
    }

    public func loadResource(resource: FSResource, options: FSTaskOptions) async throws -> FSVolume
    {
        let readOnly =
            options.taskOptions.contains("--rdonly") || options.taskOptions.contains("-r")
        return try await loadVolume(resource: resource, readOnly: readOnly)
    }

    func loadVolume(resource: FSResource, readOnly: Bool) async throws -> LUNImageVolume {
        let volume: LUNImageVolume
        if let resource = resource as? FSGenericURLResource {
            let url = resource.url
            let resources = self.resources
            volume = try await controller.load(
                resourceURL: url, readOnly: readOnly,
                onLoaded: { [self] in containerStatus = .ready },
                resolve: { try await resources.descriptor(for: url) })
        } else if let block = resource as? FSBlockDeviceResource {
            let binding = try BlockMountResourceBinding.read(block)
            let check = LoadedBlockResourceCheck(resource: block, binding: binding)
            volume = try await loadVolume(
                binding: binding, readOnly: readOnly, check: check.check)
        } else {
            throw POSIXError(.EINVAL)
        }
        return volume
    }

    func loadVolume(
        binding: BlockMountResourceBinding, readOnly: Bool,
        check: (@Sendable () throws -> Void)? = nil
    ) async throws
        -> LUNImageVolume
    {
        let resources = self.resources
        let reference = binding.marker.reference
        return try await controller.load(
            resourceURL: reference.url, readOnly: readOnly, blockMount: binding.mount, check: check,
            withdrawn: { await Self.isWithdrawn(reference, from: resources) },
            onLoaded: { [self] in containerStatus = .ready },
            resolve: {
                let descriptor = try await resources.resolve(reference)
                try reference.validate(descriptor)
                guard binding.isWritable || readOnly || descriptor.readOnly else {
                    throw POSIXError(.EROFS)
                }
                return descriptor
            })
    }

    /// Whether the app has withdrawn this mount's resource: only a definite "not found" counts.
    /// A locked or otherwise unavailable Keychain, or any other failure, never does.
    static func isWithdrawn(
        _ reference: ConnectionResourceReference, from resources: any MountResourceStore
    ) async -> Bool {
        do {
            _ = try await resources.resolve(reference)
            return false
        } catch {
            let error = error as NSError
            return error.domain == NSOSStatusErrorDomain && error.code == Int(errSecItemNotFound)
        }
    }

    public func unloadResource(resource: FSResource, options: FSTaskOptions) async throws {
        try await unloadVolume(resource: resource)
    }

    public func startCheck(task: FSTask, options: FSTaskOptions) throws -> Progress {
        let progress = Progress(totalUnitCount: 1)
        progress.isCancellable = true
        let completion = DispatchGroup()
        let cancellation = BlockResourceCheckCancellation()
        completion.enter()
        let cancel: @Sendable () -> Void = {
            cancellation.cancel()
            completion.wait()
        }
        // Install handlers before completion can clear the framework's handler.
        progress.cancellationHandler = cancel
        task.cancellationHandler = {
            cancel()
            return nil
        }
        let controller = self.controller
        Task {
            defer { completion.leave() }
            do {
                try cancellation.check()
                try await controller.checkBlockResource()
                try cancellation.check()
                progress.completedUnitCount = 1
                task.didComplete(error: nil)
            } catch { task.didComplete(error: error) }
        }
        return progress
    }

    public func startFormat(task: FSTask, options: FSTaskOptions) throws -> Progress {
        // Formatting the local marker must never format or replace a remote LUN.
        throw POSIXError(.ENOTSUP)
    }

    public override func wipe(
        _ resource: FSBlockDeviceResource,
        completionHandler reply: @escaping @Sendable ((any Error)?) -> Void
    ) {
        reply(POSIXError(.ENOTSUP))
    }

    func unloadVolume(resource: FSResource) async throws {
        if let resource = resource as? FSGenericURLResource {
            try await controller.unload(
                resourceURL: resource.url, onUnloaded: { [self] in didUnloadResource() })
        } else if let resource = resource as? FSBlockDeviceResource {
            try await unloadVolume(blockDeviceName: resource.bsdName)
        } else {
            throw POSIXError(.EINVAL)
        }
    }

    func unloadVolume(blockDeviceName: String) async throws {
        try await controller.unload(
            blockDeviceName: blockDeviceName, onUnloaded: { [self] in didUnloadResource() })
    }

    private func didUnloadResource() {
        containerStatus = .notReady(status: POSIXError(.ENOTCONN))
    }

    public static func identifier(for descriptor: ConnectionDescriptor) -> UUID {
        let identity = [
            descriptor.profileID.uuidString, descriptor.portal.description.lowercased(),
            descriptor.initiatorName, descriptor.targetName, descriptor.lun.stableIdentifier,
        ].joined(separator: "\0")
        var hash = Array(SHA256.hash(data: Data(identity.utf8)).prefix(16))
        hash[6] = (hash[6] & 0x0F) | 0x80  // UUID version 8: application-defined identity.
        hash[8] = (hash[8] & 0x3F) | 0x80
        return UUID(
            uuid: (
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]
            ))
    }
}

private final class BlockResourceCheckCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.withLock { cancelled = true } }
    func check() throws {
        if lock.withLock({ cancelled }) { throw CancellationError() }
    }
}
