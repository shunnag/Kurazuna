import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

@Test func localXattrsPreserveValuesAndEnforceCreateReplaceDeletePolicies() throws {
    var attributes = LocalXattrs()
    let name = "com.apple.provenance"
    let first = Data([1, 2, 3])
    try attributes.set(first, named: name, on: .root, policy: .mustCreate)
    #expect(throws: POSIXError(.EEXIST)) {
        try attributes.set(Data([0]), named: name, on: .root, policy: .mustCreate)
    }
    #expect(try attributes.value(named: name, on: .root) == first)
    #expect(throws: POSIXError(.ENOATTR)) {
        try attributes.set(first, named: name, on: .raw, policy: .mustReplace)
    }
    try attributes.set(Data([4]), named: name, on: .root, policy: .mustReplace)
    #expect(try attributes.value(named: name, on: .root) == Data([4]))
    #expect(attributes.names(on: .root) == [name])
    try attributes.set(nil, named: name, on: .root, policy: .delete)
    #expect(attributes.names(on: .root).isEmpty)
    #expect(throws: POSIXError(.ENOATTR)) {
        try attributes.value(named: name, on: .root)
    }
}

@Test func localXattrBudgetFailurePreservesTheOldValueAndDeletionReleasesSpace() throws {
    var attributes = LocalXattrs()
    let value = Data(repeating: 0x51, count: LocalXattrs.maximumValueSize)
    var count: UInt64 = 0
    while count < 300 {
        do {
            try attributes.set(value, named: "test\(count)", on: .raw, policy: .alwaysSet)
        } catch let error as POSIXError where error.code == .ENOSPC { break }
        count += 1
    }
    #expect(count > 0 && count < 300)
    #expect(throws: POSIXError(.E2BIG)) {
        try attributes.set(value + Data([0]), named: "test0", on: .raw, policy: .alwaysSet)
    }
    #expect(try attributes.value(named: "test0", on: .raw) == value)
    try attributes.set(nil, named: "test0", on: .raw, policy: .delete)
    try attributes.set(value, named: "test\(count)", on: .raw, policy: .mustCreate)
    #expect(try attributes.value(named: "test\(count)", on: .raw) == value)
}

@Test func nativeXattrsNeverAlterRemoteDataOrPermitAResourceFork() async throws {
    let disk = try MemoryDisk()
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let name = FSFileName(string: "com.apple.provenance")
    let value = Data([1, 2, 3, 4])
    try await volume.setXattr(named: name, to: value, on: volume.imageItem, policy: .mustCreate)
    #expect(try await volume.xattr(named: name, of: volume.imageItem) == value)
    #expect(try await volume.xattrs(of: volume.imageItem).map(\.string).contains(name.string))
    #expect(await disk.flushes == 0)
    #expect(try await disk.read(offset: 0, length: 4096) == Data(repeating: 0, count: 4096))
    let fork = FSFileName(string: "com.apple.ResourceFork")
    await #expect(throws: POSIXError(.EPERM)) {
        try await volume.setXattr(
            named: fork, to: Data([0]), on: volume.imageItem, policy: .alwaysSet)
    }
    await #expect(throws: POSIXError(.ENOATTR)) {
        try await volume.xattr(named: fork, of: volume.imageItem)
    }
    #expect(try volume.makeAttributes(of: volume.imageItem).supportsLimitedXAttrs == false)
}

@Test func mountedRouteMetadataIsReadOnlyBoundedAndNeverChangesDiskData() async throws {
    let disk = try MemoryDisk()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("source.local"),
        initiatorName: "iqn.2026-10.test:initiator",
        targetName: "iqn.2026-10.test:disk", lun: LogicalUnit(0), readOnly: false,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let destination = try Portal("storage.local")
    let report = try ConnectionRouteReport(
        resourceIdentity: descriptor.resourceIdentity, connectedPortal: destination,
        contactedPortals: [descriptor.portal, destination],
        permanentRedirects: [
            PermanentPortalRedirect(source: descriptor.portal, destinations: [destination])
        ], creationOrder: 1)
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), resourceIdentity: try descriptor.resourceIdentity,
        connectionRoute: report)
    let name = FSFileName(string: ConnectionDescriptor.connectionRouteAttributeName)
    for item in [volume.rootItem, volume.imageItem] {
        #expect(try await volume.xattrs(of: item).map(\.string).contains(name.string))
        let bytes = try await volume.xattr(named: name, of: item)
        #expect(try ConnectionRouteReport(data: bytes, descriptor: descriptor) == report)
        for policy in [FSVolume.SetXattrPolicy.alwaysSet, .mustCreate, .mustReplace, .delete] {
            await #expect(throws: POSIXError(.EPERM)) {
                try await volume.setXattr(
                    named: name, to: policy == .delete ? nil : Data([0]), on: item, policy: policy)
            }
        }
    }
    let unbound = LUNImageVolume(
        disk: disk, identifier: UUID(), resourceIdentity: Data(repeating: 9, count: 32),
        connectionRoute: report)
    #expect(try await !unbound.xattrs(of: unbound.rootItem).map(\.string).contains(name.string))
    await #expect(throws: POSIXError(.ENOATTR)) {
        try await unbound.xattr(named: name, of: unbound.rootItem)
    }
    #expect(await disk.flushes == 0)
    #expect(try await disk.read(offset: 0, length: 4096) == Data(repeating: 0, count: 4096))
}
