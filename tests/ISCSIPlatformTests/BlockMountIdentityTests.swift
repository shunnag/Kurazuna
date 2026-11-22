import Darwin
import Foundation
import Testing

@testable import ISCSIPlatform

@Test(arguments: ["disk0", "disk42", "disk7s1", "disk12s3s4"])
func aBlockMountAcceptsCanonicalBSDNames(_ name: String) throws {
    let identity = try BlockMountIdentity(bsdName: name, mountID: UUID())
    #expect(identity.bsdName == name)
}

@Test(arguments: [
    "", "/dev/disk4", "disk", "disk-1", "disk1s", "disk1/../disk2", "disk1\0", "disk1\n", "rdisk1",
    "disk" + String(repeating: "1", count: 64),
])
func aBlockMountRejectsPathsAndAmbiguousDeviceNames(_ name: String) {
    #expect(throws: POSIXError(.EINVAL)) { try BlockMountIdentity(bsdName: name, mountID: UUID()) }
}

@Test(arguments: ApplicationIdentity.allCases)
func blockMountObservationsBindTheSourceOwnerNamespaceAndFullMountName(
    _ application: ApplicationIdentity
) throws {
    let mountID = UUID()
    let identity = try BlockMountIdentity(
        bsdName: "disk41", mountID: mountID, owner: 501, application: application)
    let path = "/Users/test/Library/Application Support/iSCSI/Mounts/" + mountID.uuidString
    #expect(
        identity.matches(
            type: application.fileSystemType, source: "/dev/disk41", mountPoint: path, owner: 501))
    let wrong = [
        ("apfs", "/dev/disk41", path, uid_t(501)),
        (application.fileSystemType, "/dev/disk42", path, uid_t(501)),
        (application.fileSystemType, "disk41", path, uid_t(501)),
        (application.fileSystemType, "/dev/disk41", path, uid_t(502)),
        (application.fileSystemType, "/dev/disk41", path + "/child", uid_t(501)),
        (application.fileSystemType, "/dev/disk41", path + "/", uid_t(501)),
        (
            application.fileSystemType, "/dev/disk41",
            path.replacingOccurrences(of: "/Mounts/", with: "/Other/"), uid_t(501)
        ),
        (
            application.fileSystemType, "/dev/disk41",
            path.replacingOccurrences(of: mountID.uuidString, with: UUID().uuidString), uid_t(501)
        ),
        (application.fileSystemType, "/dev/disk41", path + "\0", uid_t(501)),
    ]
    for (type, source, mount, owner) in wrong {
        #expect(!identity.matches(type: type, source: source, mountPoint: mount, owner: owner))
    }
}

@Test func theDeviceMountStateReadsTheKernelTableForAnyMountOfTheDevice() throws {
    // The startup volume is mounted from some device; a device that does not exist is not.
    var root = statfs()
    #expect(statfs("/", &root) == 0)
    let source = withUnsafeBytes(of: &root.f_mntfromname) {
        String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
    }
    if source.hasPrefix("/dev/"), BlockMountIdentity.isValidBSDName(String(source.dropFirst(5))) {
        let mounted = try BlockMountIdentity(bsdName: String(source.dropFirst(5)), mountID: UUID())
        #expect(mounted.deviceMountState() == true)
        // The narrower bridge observation still requires this app's own mount.
        #expect(!mounted.contains())
    }
    let absent = try BlockMountIdentity(bsdName: "disk999999", mountID: UUID())
    #expect(absent.deviceMountState() == false)
    #expect(!absent.contains())
}
