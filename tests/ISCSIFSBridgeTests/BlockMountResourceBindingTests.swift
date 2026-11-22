import FSKit
import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIFSBridge

private actor BindingLatch {
    private var signalled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if signalled { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func signal() {
        signalled = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

private actor BindingMetadata: MountResourceStore {
    let value: ConnectionDescriptor?
    let started: BindingLatch?
    let release: BindingLatch?
    let cancelled: BindingLatch?
    private var unavailable = false
    private(set) var resolves = 0

    init(
        _ value: ConnectionDescriptor?, started: BindingLatch? = nil,
        release: BindingLatch? = nil, cancelled: BindingLatch? = nil
    ) {
        self.value = value
        self.started = started
        self.release = release
        self.cancelled = cancelled
    }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        try ConnectionResourceReference(descriptor: descriptor)
    }
    func resolve(_ reference: ConnectionResourceReference) async throws -> ConnectionDescriptor {
        resolves += 1
        let cancelled = self.cancelled
        return try await withTaskCancellationHandler {
            await started?.signal()
            // Deliberately allow a cancelled metadata lookup to finish late.
            await release?.wait()
            guard !unavailable else { throw POSIXError(.EACCES) }
            guard let value else { throw POSIXError(.ENOENT) }
            return value
        } onCancel: {
            Task { await cancelled?.signal() }
        }
    }
    func remove(_ reference: ConnectionResourceReference) {}
    func lock() { unavailable = true }
}

private actor BindingOpenCount {
    private(set) var value = 0
    func increment() { value += 1 }
}

private final class BindingCheck: @unchecked Sendable {
    private let lock = NSLock()
    private var failure = false
    private var count = 0
    var calls: Int { lock.withLock { count } }
    func fail() { lock.withLock { failure = true } }
    func check() throws {
        try lock.withLock {
            count += 1
            if failure { throw POSIXError(.EIO) }
        }
    }
}

private func bindingDescriptor(readOnly: Bool = false) throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("[2001:db8::1]:3260"),
        initiatorName: "iqn.2026-10.test:" + String(repeating: "a", count: 206),
        targetName: "iqn.2026-10.test:" + String(repeating: "b", count: 206),
        lun: LogicalUnit(addressKey: "0001400200034004"), readOnly: readOnly,
        chapUsername: "fixture-initiator", isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID(),
        credentialID: UUID(), targetCHAPUsername: "fixture-target", portalGroupTag: 65535,
        settingsBinding: Data(repeating: 7, count: 32))
}

private func binding(
    _ descriptor: ConnectionDescriptor, writable: Bool = true
) throws -> BlockMountResourceBinding {
    let marker = BlockMountResource(
        reference: try ConnectionResourceReference(descriptor: descriptor))
    return try BlockMountResourceBinding(
        bsdName: "disk41", blockSize: 512, physicalBlockSize: 4096, blockCount: 2048,
        isWritable: writable
    ) { try marker.encodedHeader() }
}

@Test(arguments: ["blockSize", "physicalSize", "small", "large", "revoked", "path", "overflow"])
func invalidMarkerDevicesAreRefusedBeforeHeaderIO(_ change: String) {
    var reads = 0
    #expect(throws: POSIXError(.EINVAL)) {
        try BlockMountResourceBinding(
            bsdName: change == "path" ? "/dev/disk41" : "disk41",
            blockSize: change == "blockSize" ? 4096 : 512,
            physicalBlockSize: change == "physicalSize" ? 8192 : 4096,
            blockCount: change == "small"
                ? 2047 : change == "large" ? 2049 : change == "overflow" ? UInt64.max : 2048,
            isWritable: true, isRevoked: change == "revoked"
        ) {
            reads += 1
            return Data()
        }
    }
    #expect(reads == 0)
}

@Test(arguments: 0..<8)
func blockBindingsPreserveTheFullDescriptorAndBothReadOnlyPolicies(_ flags: Int) async throws {
    let descriptorRO = flags & 1 != 0
    let requestedRO = flags & 2 != 0
    let markerWritable = flags & 4 != 0
    let descriptor = try bindingDescriptor(readOnly: descriptorRO)
    let disk = try MemoryDisk(readOnly: descriptorRO || requestedRO)
    let count = BindingOpenCount()
    let controller = ResourceController { candidate, readOnly in
        await count.increment()
        #expect(candidate == descriptor)
        #expect(readOnly == (descriptorRO || requestedRO))
        return LUNImageVolume(disk: disk, identifier: UUID())
    }
    let store = BindingMetadata(descriptor)
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    let resource = try binding(descriptor, writable: markerWritable)
    let header = try resource.marker.encodedHeader()
    for name in [
        descriptor.portal.host, descriptor.targetName, descriptor.chapUsername!,
        descriptor.targetCHAPUsername!,
    ] {
        #expect(header.range(of: Data(name.utf8)) == nil)
    }
    if !markerWritable && !descriptorRO && !requestedRO {
        await #expect(throws: POSIXError(.EROFS)) {
            try await fileSystem.loadVolume(binding: resource, readOnly: false)
        }
        #expect(await count.value == 0)
        return
    }
    _ = try await fileSystem.loadVolume(binding: resource, readOnly: requestedRO)
    await store.lock()
    await #expect(throws: POSIXError(.EINVAL)) {
        try await controller.unload(blockDeviceName: "disk42")
    }
    await #expect(throws: POSIXError(.EINVAL)) {
        try await controller.unload(resourceURL: resource.marker.reference.url)
    }
    #expect(await disk.connectionState() == .connected)
    try await controller.unload(blockDeviceName: "disk41")
    #expect(await store.resolves == 1)
    #expect(await count.value == 1)
    #expect(await disk.connectionState() == .closed)
}

@Test(arguments: [false, true])
func missingOrSubstitutedBlockMetadataCannotOpenAConnection(_ missing: Bool) async throws {
    let descriptor = try bindingDescriptor()
    let wrong = missing ? nil : try descriptor.assigningMountID(UUID())
    let count = BindingOpenCount()
    let controller = ResourceController { _, _ in
        await count.increment()
        throw POSIXError(.EIO)
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: BindingMetadata(wrong))
    await #expect(throws: (any Error).self) {
        try await fileSystem.loadVolume(binding: binding(descriptor), readOnly: false)
    }
    #expect(await count.value == 0)
}

@Test(arguments: [false, true], [false, true])
func cancellationDuringMetadataLookupCannotOpenALateConnection(
    _ blockResource: Bool, _ callerCancellation: Bool
) async throws {
    let descriptor = try bindingDescriptor()
    let resource = try binding(descriptor)
    let started = BindingLatch()
    let release = BindingLatch()
    let cancelled = BindingLatch()
    let store = BindingMetadata(
        descriptor, started: started, release: release, cancelled: cancelled)
    let count = BindingOpenCount()
    let controller = ResourceController { _, _ in
        await count.increment()
        return LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    let loading = Task {
        if blockResource {
            return try await fileSystem.loadVolume(binding: resource, readOnly: false)
        }
        return try await fileSystem.loadVolume(
            resource: FSGenericURLResource(url: resource.marker.reference.url), readOnly: false)
    }
    await started.wait()
    await #expect(throws: ProtocolError.busy) {
        try await controller.load(descriptor, readOnly: true)
    }
    let unloading: Task<Void, any Error>?
    if callerCancellation {
        loading.cancel()
        unloading = nil
    } else {
        unloading = Task {
            if blockResource {
                try await controller.unload(blockDeviceName: "disk41")
            } else {
                try await controller.unload(resourceURL: resource.marker.reference.url)
            }
        }
    }
    await cancelled.wait()
    await release.signal()
    await #expect(throws: CancellationError.self) { try await loading.value }
    try await unloading?.value
    #expect(await count.value == 0)
    // A completed cancellation releases the slot for another generation.
    _ = try await controller.load(descriptor, readOnly: true)
    try await controller.unload(descriptor)
    #expect(await count.value == 1)
}

@Test func aBlockMaintenanceCheckUsesItsLoadedGenerationAndNeverReopensMetadata() async throws {
    let descriptor = try bindingDescriptor()
    let disk = try MemoryDisk()
    let controller = ResourceController { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) }
    let store = BindingMetadata(descriptor)
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    let check = BindingCheck()
    await #expect(throws: POSIXError(.ENOTSUP)) { try await controller.checkBlockResource() }
    _ = try await fileSystem.loadVolume(
        binding: binding(descriptor), readOnly: false, check: check.check)
    await store.lock()
    try await controller.checkBlockResource()
    #expect(check.calls == 1)
    check.fail()
    await #expect(throws: POSIXError(.EIO)) { try await controller.checkBlockResource() }
    #expect(await store.resolves == 1)
    try await controller.unload(blockDeviceName: "disk41")
    #expect(await disk.connectionState() == .closed)
    await #expect(throws: POSIXError(.ENOTSUP)) { try await controller.checkBlockResource() }
}
