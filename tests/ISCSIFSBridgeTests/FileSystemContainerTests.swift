import FSKit
import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIFSBridge

private func containerDescriptor() throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
}

private actor ContainerResources: MountResourceStore {
    let descriptor: ConnectionDescriptor
    init(_ descriptor: ConnectionDescriptor) { self.descriptor = descriptor }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        try ConnectionResourceReference(descriptor: descriptor)
    }
    func resolve(_ reference: ConnectionResourceReference) -> ConnectionDescriptor { descriptor }
    func remove(_ reference: ConnectionResourceReference) {}
}

@Test func unloadedResourceStopsReportingReady() async throws {
    let descriptor = try containerDescriptor()
    let disk = try MemoryDisk(readOnly: true)
    let controller = ResourceController { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) }
    let fileSystem = ISCSIFileSystem(
        controller: controller, resources: ContainerResources(descriptor))
    let resource = FSGenericURLResource(url: try descriptor.resourceURL)
    #expect(fileSystem.containerStatus.state == .notReady)
    _ = try await fileSystem.loadVolume(resource: resource, readOnly: true)
    #expect(fileSystem.containerStatus.state == .ready)
    let other = try descriptor.assigningMountID(UUID())
    await #expect(throws: POSIXError(.EINVAL)) {
        try await fileSystem.unloadVolume(resource: FSGenericURLResource(url: other.resourceURL))
    }
    #expect(fileSystem.containerStatus.state == .ready)
    try await fileSystem.unloadVolume(resource: resource)
    #expect(await disk.connectionState() == .closed)
    #expect(fileSystem.containerStatus.state == .notReady)
    let status = fileSystem.containerStatus.status.map { $0 as NSError }
    #expect(status?.code == Int(POSIXErrorCode.ENOTCONN.rawValue))
}

@Test func blockResourcePublishesReadyAndNotReadyThroughTheSameGeneration() async throws {
    let descriptor = try containerDescriptor()
    let disk = try MemoryDisk(readOnly: true)
    let controller = ResourceController { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) }
    let fileSystem = ISCSIFileSystem(
        controller: controller, resources: ContainerResources(descriptor))
    let marker = BlockMountResource(
        reference: try ConnectionResourceReference(descriptor: descriptor))
    let binding = try BlockMountResourceBinding(
        bsdName: "disk41", blockSize: 512, physicalBlockSize: 4096, blockCount: 2048,
        isWritable: true
    ) { try marker.encodedHeader() }
    _ = try await fileSystem.loadVolume(binding: binding, readOnly: true)
    #expect(fileSystem.containerStatus.state == .ready)
    await #expect(throws: POSIXError(.EINVAL)) {
        try await fileSystem.unloadVolume(blockDeviceName: "disk42")
    }
    #expect(fileSystem.containerStatus.state == .ready)
    try await fileSystem.unloadVolume(blockDeviceName: "disk41")
    #expect(fileSystem.containerStatus.state == .notReady)
    #expect(await disk.connectionState() == .closed)
}

@Test func failedLoadDoesNotPublishReady() async throws {
    let descriptor = try containerDescriptor()
    let controller = ResourceController { _, _ in throw POSIXError(.EIO) }
    let fileSystem = ISCSIFileSystem(
        controller: controller, resources: ContainerResources(descriptor))
    await #expect(throws: POSIXError(.EIO)) {
        try await fileSystem.loadVolume(
            resource: FSGenericURLResource(url: descriptor.resourceURL), readOnly: true)
    }
    #expect(fileSystem.containerStatus.state == .notReady)
}

private actor HeldContainerCloseDisk: ImageDisk {
    let capacity: DiskCapacity
    let isReadOnly = true
    private var closeReply: CheckedContinuation<Void, Never>?
    private var closed = false
    var closeStarted: Bool { closeReply != nil }

    init() throws { capacity = try MemoryDisk(readOnly: true).capacity }
    func read(offset: Int64, length: Int) async throws -> Data { Data(repeating: 0, count: length) }
    func write(offset: Int64, data: Data) async throws { throw POSIXError(.EROFS) }
    func synchronize() async throws {}
    func close() async {
        await withCheckedContinuation { closeReply = $0 }
        closed = true
    }
    func releaseClose() {
        closeReply?.resume()
        closeReply = nil
    }
    func connectionState() async -> DiskConnectionState { closed ? .closed : .connected }
}

@Test func containerStaysReadyUntilOriginalShutdownCompletes() async throws {
    let descriptor = try containerDescriptor()
    let disk = try HeldContainerCloseDisk()
    let controller = ResourceController { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) }
    let fileSystem = ISCSIFileSystem(
        controller: controller, resources: ContainerResources(descriptor))
    let url = try descriptor.resourceURL
    let resource = FSGenericURLResource(url: url)
    _ = try await fileSystem.loadVolume(resource: resource, readOnly: true)
    let unloading = Task {
        try await fileSystem.unloadVolume(resource: FSGenericURLResource(url: url))
    }
    do {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await disk.closeStarted) {
            guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
            try await Task.sleep(for: .milliseconds(2))
        }
    } catch {
        await disk.releaseClose()
        _ = try? await unloading.value
        throw error
    }
    #expect(fileSystem.containerStatus.state == .ready)
    await #expect(throws: ProtocolError.busy) {
        try await fileSystem.loadVolume(resource: resource, readOnly: true)
    }
    #expect(fileSystem.containerStatus.state == .ready)
    await disk.releaseClose()
    try await unloading.value
    #expect(fileSystem.containerStatus.state == .notReady)
    #expect(await disk.connectionState() == .closed)
}
