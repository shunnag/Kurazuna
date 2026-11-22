import FSKit
import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIFSBridge

private actor ReferenceMetadata: MountResourceStore {
    private let value: ConnectionDescriptor?
    private var unavailable = false
    private(set) var resolves = 0
    init(_ value: ConnectionDescriptor?) { self.value = value }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        try ConnectionResourceReference(descriptor: descriptor)
    }
    func resolve(_ reference: ConnectionResourceReference) throws -> ConnectionDescriptor {
        resolves += 1
        guard !unavailable else { throw POSIXError(.EACCES) }
        guard let value else { throw POSIXError(.ENOENT) }
        return value
    }
    func remove(_ reference: ConnectionResourceReference) {}
    func makeUnavailable() { unavailable = true }
}

@Test func aLoadedResourceCanUnloadAfterItsMetadataBecomesUnavailable() async throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let disk = try MemoryDisk(readOnly: true)
    let controller = ResourceController { _, _ in LUNImageVolume(disk: disk, identifier: UUID()) }
    let store = ReferenceMetadata(descriptor)
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    let resource = FSGenericURLResource(
        url: try ConnectionResourceReference(descriptor: descriptor).url)
    _ = try await fileSystem.loadVolume(resource: resource, readOnly: true)
    await store.makeUnavailable()
    let other = try descriptor.assigningMountID(UUID())
    await #expect(throws: POSIXError(.EINVAL)) {
        try await fileSystem.unloadVolume(
            resource: FSGenericURLResource(
                url: try ConnectionResourceReference(descriptor: other).url))
    }
    #expect(await disk.connectionState() == .connected)
    do { try await fileSystem.unloadVolume(resource: resource) } catch {
        try await controller.unload(descriptor)
        throw error
    }
    #expect(await store.resolves == 1)
    #expect(await disk.connectionState() == .closed)
}

private actor ReferenceOpenCount {
    private(set) var value = 0
    func open() { value += 1 }
}

@Test func unresolvedOrSubstitutedResourceMetadataCannotOpenANetworkSession() async throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    let count = ReferenceOpenCount()
    for wrong in [nil, try descriptor.assigningMountID(UUID())] {
        let controller = ResourceController { _, _ in
            await count.open()
            throw POSIXError(.EIO)
        }
        let fileSystem = ISCSIFileSystem(
            controller: controller, resources: ReferenceMetadata(wrong))
        let resource = FSGenericURLResource(url: reference.url)
        await #expect(throws: (any Error).self) {
            try await fileSystem.loadVolume(resource: resource, readOnly: false)
        }
    }
    #expect(await count.value == 0)
}

@Test func boundedResourcesLoadTheFullDescriptorAndPreserveReadOnlyPolicy() async throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:" + String(repeating: "a", count: 206),
        targetName: "iqn.2026-10.test:" + String(repeating: "b", count: 206),
        lun: LogicalUnit(addressKey: "0001400200034004"), readOnly: true,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID(), portalGroupTag: 65535,
        settingsBinding: Data(repeating: 1, count: 32))
    let controller = ResourceController { candidate, readOnly in
        #expect(candidate == descriptor)
        #expect(readOnly)
        return LUNImageVolume(disk: try MemoryDisk(readOnly: readOnly), identifier: UUID())
    }
    let fileSystem = ISCSIFileSystem(
        controller: controller, resources: ReferenceMetadata(descriptor))
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    _ = try await fileSystem.loadVolume(
        resource: FSGenericURLResource(url: reference.url), readOnly: false)
    try await controller.unload(descriptor)
}

private func authenticatedLegacyDescriptor(mountID: UUID? = UUID(), credentialID: UUID? = nil)
    throws -> ConnectionDescriptor
{
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, chapUsername: "Mac",
        isid: [0x80, 1, 2, 3, 4, 5], mountID: mountID, credentialID: credentialID,
        targetCHAPUsername: "Storage", settingsBinding: Data(repeating: 1, count: 32))
}

@Test(arguments: [false, true])
func authenticatedLegacyURLsRequirePublishedMetadataEvenWithoutCredentialUUID(_ usesUUID: Bool)
    async throws
{
    let descriptor = try authenticatedLegacyDescriptor(credentialID: usesUUID ? UUID() : nil)
    let store = ReferenceMetadata(descriptor)
    let controller = ResourceController { candidate, readOnly in
        #expect(candidate == descriptor && !readOnly)
        return LUNImageVolume(disk: try MemoryDisk(readOnly: false), identifier: UUID())
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    _ = try await fileSystem.loadVolume(
        resource: FSGenericURLResource(url: descriptor.resourceURL), readOnly: false)
    #expect(await store.resolves == 1)
    // Existing ownership/cleanup names still recognize the legacy form without rereading metadata.
    #expect(try descriptor.acceptsResourceURL(descriptor.resourceURL))
    await store.makeUnavailable()
    try await fileSystem.unloadVolume(resource: FSGenericURLResource(url: descriptor.resourceURL))
    #expect(await store.resolves == 1)
}

@Test(arguments: ["missing", "unavailable", "substituted", "noMountID"])
func unauthorisedAuthenticatedLegacyURLsNeverReachTheOpener(_ condition: String) async throws {
    let descriptor = try authenticatedLegacyDescriptor(
        mountID: condition == "noMountID" ? nil : UUID())
    let store = ReferenceMetadata(
        condition == "missing" ? nil : try descriptor.assigningMountID(UUID()))
    if condition == "unavailable" { await store.makeUnavailable() }
    let count = ReferenceOpenCount()
    let controller = ResourceController { _, _ in
        await count.open()
        throw POSIXError(.EIO)
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    await #expect(throws: (any Error).self) {
        try await fileSystem.loadVolume(
            resource: FSGenericURLResource(url: descriptor.resourceURL), readOnly: false)
    }
    #expect(await count.value == 0)
    #expect(await store.resolves == (condition == "noMountID" ? 0 : 1))
}

@Test(arguments: ["target", "readOnly", "chap", "targetCHAP", "credential", "settings", "portal"])
func legacyURLMutationsCannotBorrowPublishedCredentialAuthority(_ field: String) async throws {
    let descriptor = try authenticatedLegacyDescriptor(credentialID: UUID())
    var parts = try #require(
        URLComponents(url: descriptor.resourceURL, resolvingAgainstBaseURL: false))
    if field == "portal" {
        parts.host = "other.invalid"
    } else {
        let value: String
        switch field {
        case "target": value = "iqn.2026-10.test:other"
        case "readOnly": value = "1"
        case "credential": value = UUID().uuidString.lowercased()
        case "settings": value = String(repeating: "02", count: 32)
        default: value = "Other"
        }
        parts.queryItems = parts.queryItems?.map {
            $0.name == field ? URLQueryItem(name: field, value: value) : $0
        }
    }
    let changed = try #require(parts.url)
    let store = ReferenceMetadata(descriptor)
    let count = ReferenceOpenCount()
    let controller = ResourceController { _, _ in
        await count.open()
        throw POSIXError(.EIO)
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    await #expect(throws: ProtocolError.malformed("mount resource binding")) {
        try await fileSystem.loadVolume(
            resource: FSGenericURLResource(url: changed), readOnly: false)
    }
    #expect(await count.value == 0)
    #expect(await store.resolves == 1)
}

@Test(arguments: [false, true])
func anonymousLegacyURLsRemainExplicitConnectionsWithoutSavedCredentialAuthority(_ hasMountID: Bool)
    async throws
{
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: true, isid: [0x80, 1, 2, 3, 4, 5],
        mountID: hasMountID ? UUID() : nil)
    let store = ReferenceMetadata(nil)
    let controller = ResourceController { candidate, readOnly in
        #expect(candidate.chapUsername == nil && candidate.credentialID == nil)
        #expect(candidate.targetCHAPUsername == nil && readOnly)
        return LUNImageVolume(disk: try MemoryDisk(readOnly: readOnly), identifier: UUID())
    }
    let fileSystem = ISCSIFileSystem(controller: controller, resources: store)
    _ = try await fileSystem.loadVolume(
        resource: FSGenericURLResource(url: descriptor.resourceURL), readOnly: true)
    try await controller.unload(descriptor)
    #expect(await store.resolves == 0)
}
