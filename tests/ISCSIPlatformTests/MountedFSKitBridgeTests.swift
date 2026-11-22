import Darwin
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

@Test(arguments: ApplicationIdentity.allCases)
func aMountFromTheOtherEditionCannotCompleteThisMount(_ identity: ApplicationIdentity) {
    let id = UUID()
    let source = "iscsi-fskit://test/" + id.uuidString
    let path = "/private/tmp/Mounts/" + id.uuidString
    let other: ApplicationIdentity = identity == .release ? .development : .release
    #expect(
        MountedFSKitBridge.matches(
            mountEntry(source: source, path: path, type: identity.fileSystemType),
            source: source, mountID: id, owner: 501, identity: identity))
    #expect(
        !MountedFSKitBridge.matches(
            mountEntry(source: source, path: path, type: other.fileSystemType),
            source: source, mountID: id, owner: 501, identity: identity))
}

private func mountEntry(
    source: String, path: String, type: String = ApplicationIdentity.current.fileSystemType,
    owner: uid_t = 501
) -> statfs {
    var entry = statfs()
    entry.f_owner = owner
    func put<T>(_ text: String, into field: inout T) {
        withUnsafeMutableBytes(of: &field) { bytes in
            let value = Array(text.utf8.prefix(bytes.count - 1)) + [0]
            bytes.copyBytes(from: value)
        }
    }
    put(source, into: &entry.f_mntfromname)
    put(path, into: &entry.f_mntonname)
    put(type, into: &entry.f_fstypename)
    return entry
}

@Test private func aBoundedSourceStillRequiresItsExactBindingOwnerAndEdition() throws {
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    let source = try #require(
        MountedFSKitBridge.mountSource(for: descriptor, resourceURL: reference.url))
    let id = try #require(descriptor.mountID)
    let path = "/private/tmp/Mounts/" + id.uuidString
    #expect(
        MountedFSKitBridge.matches(
            mountEntry(source: source, path: path), source: source, mountID: id, owner: 501))
    for invalid in [
        mountEntry(source: "unknown", path: path),
        mountEntry(source: String(source.dropLast()), path: path),
        mountEntry(source: source, path: path, owner: 502),
        mountEntry(source: source, path: path, type: "apfs"),
    ] {
        #expect(!MountedFSKitBridge.matches(invalid, source: source, mountID: id, owner: 501))
    }
    let other = try ConnectionResourceReference(descriptor: descriptor.assigningMountID(UUID()))
    #expect(MountedFSKitBridge.mountSource(for: descriptor, resourceURL: other.url) == nil)
}

@Test private func kernelMountObservationRequiresTheSameSourceOwnerAndFSKitType() {
    let id = UUID()
    let source = "iscsi-fskit://127.0.0.1/profile?mount=\(id.uuidString.lowercased())"
    let path = "/private/tmp/Mounts/\(id.uuidString)"
    let valid = mountEntry(source: source, path: path)
    #expect(MountedFSKitBridge.matches(valid, source: source, mountID: id, owner: 501))
    let invalid = [
        mountEntry(source: source, path: path, owner: 502),
        mountEntry(source: source, path: path, type: "apfs"),
        mountEntry(source: source + "-other", path: path),
        mountEntry(source: String(source.dropLast()), path: path),
    ]
    for entry in invalid {
        #expect(!MountedFSKitBridge.matches(entry, source: source, mountID: id, owner: 501))
    }
}

@Test private func fullSourceObservationAlsoSupportsAnExplicitManualMountPoint() {
    let id = UUID()
    let source = "iscsi-fskit://127.0.0.1/profile?mount=\(id.uuidString.lowercased())"
    #expect(
        MountedFSKitBridge.matches(
            mountEntry(source: source, path: "/private/tmp/Manual"),
            source: source, mountID: id, owner: 501))
}

@Test private func truncatedSourceRequiresBothTheFullPrefixAndThisMountsUUIDDirectory() {
    let id = UUID()
    let source =
        "iscsi-fskit://127.0.0.1/" + String(repeating: "a", count: 1100)
        + "?mount=\(id.uuidString.lowercased())"
    let path = "/private/tmp/Mounts/\(id.uuidString)"
    #expect(
        MountedFSKitBridge.matches(
            mountEntry(source: source, path: path), source: source, mountID: id, owner: 501))
    for entry in [
        mountEntry(source: source, path: "/private/tmp/Mounts/\(UUID().uuidString)"),
        mountEntry(source: source, path: path + "/Disk.img"),
        mountEntry(source: String(source.prefix(900)), path: path),
        mountEntry(source: "iscsi-fskit://different/" + source, path: path),
    ] {
        #expect(!MountedFSKitBridge.matches(entry, source: source, mountID: id, owner: 501))
    }
}

@Test(arguments: [false, true])
private func theOriginalEncodedMountSourceSurvivesKernelObservation(_ longSource: Bool) throws {
    let id = UUID()
    let suffix = longSource ? String(repeating: "a", count: 200) : "disk"
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:" + suffix,
        targetName: "iqn.2026-10.test:" + suffix, lun: LogicalUnit(0), readOnly: true,
        chapUsername: longSource ? String(repeating: "b", count: 223) : nil,
        isid: [0x80, 1, 2, 3, 4, 5], mountID: id,
        credentialID: longSource ? UUID() : nil,
        targetCHAPUsername: longSource ? String(repeating: "c", count: 223) : nil,
        settingsBinding: longSource ? Data(repeating: 1, count: 32) : nil)
    let canonical = try descriptor.resourceURL.absoluteString
    let encoded = canonical.replacingOccurrences(of: "test:", with: "test%3A")
    var components = try #require(URLComponents(string: encoded))
    components.percentEncodedQuery = components.percentEncodedQuery?.split(separator: "&")
        .reversed().joined(separator: "&")
    let url = try #require(components.url)
    #expect(try ConnectionDescriptor(resourceURL: url) == descriptor)
    let source = try #require(MountedFSKitBridge.mountSource(for: descriptor, resourceURL: url))
    #expect(source == url.absoluteString)
    #expect(source != canonical)
    let limit = MemoryLayout.size(ofValue: statfs().f_mntfromname) - 1
    #expect((source.utf8.count > limit) == longSource)
    let path = "/private/tmp/Mounts/" + id.uuidString
    let entry = mountEntry(source: source, path: path)
    #expect(MountedFSKitBridge.matches(entry, source: source, mountID: id, owner: 501))
    #expect(!MountedFSKitBridge.matches(entry, source: canonical, mountID: id, owner: 501))
    for invalid in [
        mountEntry(source: source, path: path, owner: 502),
        mountEntry(source: source, path: path, type: "apfs"),
        mountEntry(source: "different" + source, path: path),
    ] {
        #expect(!MountedFSKitBridge.matches(invalid, source: source, mountID: id, owner: 501))
    }
    components.queryItems?.removeAll { $0.name == "readOnly" }
    components.queryItems?.append(URLQueryItem(name: "readOnly", value: "0"))
    #expect(MountedFSKitBridge.mountSource(for: descriptor, resourceURL: components.url) == nil)
    #expect(MountedFSKitBridge.mountSource(for: descriptor, resourceURL: nil) == canonical)
}
