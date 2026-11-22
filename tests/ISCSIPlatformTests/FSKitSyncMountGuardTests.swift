import Darwin
import FSKitNativeDiagnostics
import Foundation
import Testing

@testable import ISCSIPlatform

@Test func aNativeMountUpdateRejectsUnknownTypesBeforeLookingUpThePath() {
    for type in [nil, "", "apfs", "kurazuna.other", "kurazunadev.other"] {
        let result: ISCSITestSyncMount
        if let type {
            result = iscsi_test_fskit_sync_mount("/does/not/exist", "iscsi-fskit://test/disk", type)
        } else {
            result = iscsi_test_fskit_sync_mount("/does/not/exist", "iscsi-fskit://test/disk", nil)
        }
        #expect(result.error == EINVAL)
        #expect(result.syscallAttempted == 0)
    }
}

@Test(arguments: ApplicationIdentity.allCases)
func neitherEditionCanUpdateAnOrdinaryDirectoryMount(_ identity: ApplicationIdentity) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    ).resolvingSymlinksInPath()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let result = iscsi_test_fskit_sync_mount(
        directory.path, "iscsi-fskit://test/disk", identity.fileSystemType)
    #expect(result.error == EPERM)
    #expect(result.syscallAttempted == 0)
}
