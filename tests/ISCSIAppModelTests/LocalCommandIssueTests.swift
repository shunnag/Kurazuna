import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test(arguments: ["mount", "hdiutil", "diskutil"])
private func localCommandTimeoutDoesNotDescribeAServerResponseFailure(_ program: String) {
    let local = AppIssue(SystemCommandError.timedOut(program: program))
    let remote = AppIssue(ProtocolError.timedOut)
    #expect(local.message == String(localized: "The operation took too long. Try again."))
    #expect(local.message != remote.message)
    #expect(local.detail == "\(program): timed out")
    #expect(local.recoveryAction == nil)
}

@Test(arguments: ["hdiutil", "diskutil"])
private func localEjectionTimeoutKeepsTheDiskNameAndRecoveryAction(_ program: String) {
    let name = "Archive"
    let issue = AppIssue(
        SystemCommandError.timedOut(program: program),
        context: .ejectingDisk(name, connectionState: .connected))
    #expect(issue.title == String(localized: "“\(name)” Couldn’t Be Ejected"))
    #expect(
        issue.message
            == String(
                localized:
                    "The disk may still be connected. Check it in Disk Utility, then try again."))
    #expect(issue.recoveryAction == .openDiskUtility)
    #expect(issue.detail == "\(program): timed out")
}

@Test(arguments: ["mount", "hdiutil", "diskutil"], [Int32(1), 69, 78])
private func connectionCommandFailuresDescribeDiskPreparation(_ program: String, _ status: Int32)
    throws
{
    let server = try ServerProfile(name: "Storage", portal: Portal("nas.local"))
    let error = SystemCommandError.failed(program: program, status: status, detail: "診断用の詳細")
    let issue = AppIssue(error, context: .connectingDisk)
    #expect(issue.title == String(localized: "The Disk Couldn’t Be Connected"))
    #expect(
        issue.message
            == String(localized: "The disk couldn’t be prepared for use on this Mac. Try again."))
    #expect(issue.detail == "\(program) (\(status)): 診断用の詳細")
    #expect(issue.message != AppIssue(error, context: .findingDisks(server)).message)
    #expect(issue.recoveryAction == nil && issue.forceEjectionDiskID == nil)
}

@Test(arguments: ["mount", "hdiutil", "diskutil"])
private func commandFailuresDuringEjectionKeepTheDiskName(_ program: String) {
    let issue = AppIssue(
        SystemCommandError.failed(program: program, status: 69, detail: "Diagnostic detail"),
        context: .ejectingDisk("Archive", connectionState: .connected))
    #expect(issue.title == String(localized: "“\("Archive")” Couldn’t Be Ejected"))
    #expect(issue.recoveryAction == .openDiskUtility)
    #expect(issue.detail == "\(program) (69): Diagnostic detail")
}

@Test
private func specificConnectionErrorsKeepTheirExistingGuidance() {
    let errors: [any Error] = [
        ProtocolError.localNetworkAccessRequired, ProtocolError.authenticationFailed,
        ProtocolError.timedOut, POSIXError(.EBUSY), AttachmentError.readOnlyGeometryRequired,
        AttachmentError.writeCompletionUnavailable,
        VolumeMountIssue(status: 1, detail: "Not mounted"),
        SystemCommandError.timedOut(program: "mount"),
    ]
    for error in errors {
        let original = AppIssue(error)
        let connecting = AppIssue(error, context: .connectingDisk)
        #expect(connecting.title == original.title)
        #expect(connecting.message == original.message)
        #expect(connecting.recoveryAction == original.recoveryAction)
        #expect(connecting.detail == original.detail)
    }
}

private let extensionLaunchDiagnostic =
    "mount: Loading resource: The operation couldn’t be completed. (com.apple.extensionKit.errorDomain error 2.)\nmount: File system named iscsifs not found\n"

@Test(arguments: [
    extensionLaunchDiagnostic,
    "mount: リソースの読み込み: 操作を完了できませんでした。(com.apple.extensionKit.errorDomain error 2.)",
    "Error Domain=com.apple.extensionKit.errorDomain Code=2 UserInfo={NSUnderlyingError=4099}",
])
private func extensionLaunchFailuresOfferSettingsAndPreserveDiagnostics(_ diagnostic: String) {
    let issue = AppIssue(
        SystemCommandError.failed(program: "mount", status: 69, detail: diagnostic),
        context: .connectingDisk)
    #expect(
        issue.title
            == String(
                localized:
                    "The \(ApplicationIdentity.current.applicationName) Extension Couldn’t Be Started"
            ))
    #expect(
        issue.message
            == String(
                localized:
                    "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then check that \(ApplicationIdentity.current.applicationName) is enabled. If it’s already enabled, eject any connected iSCSI disks and restart your Mac, then try again."
            ))
    #expect(issue.recoveryAction == .openExtensionSettings)
    #expect(issue.forceEjectionDiskID == nil)
    #expect(issue.detail == "mount (69): \(diagnostic)")
}

@Test(arguments: [
    "(com.apple.extensionKit.errorDomain error 20.)",
    "Error Domain=com.apple.extensionKit.errorDomain Code=20 UserInfo={}",
    "Error Domain=com.apple.extensionKit.errorDomain Code=2.0 UserInfo={}",
    "(com.apple.extensionKit.errorDomain error 1.)",
    "(another.extensionKit.errorDomain error 2.)",
    "ExtensionKit error 2.",
    "mount: File system named iscsifs not found",
])
private func otherMountFailuresKeepDiskPreparationGuidance(_ diagnostic: String) {
    let issue = AppIssue(
        SystemCommandError.failed(program: "mount", status: 69, detail: diagnostic),
        context: .connectingDisk)
    #expect(issue.title == String(localized: "The Disk Couldn’t Be Connected"))
    #expect(
        issue.message
            == String(localized: "The disk couldn’t be prepared for use on this Mac. Try again."))
    #expect(issue.recoveryAction == nil)
    #expect(issue.detail == "mount (69): \(diagnostic)")
}

@Test(arguments: ["hdiutil", "diskutil", "umount", "/other/mount"])
private func otherCommandsCannotBecomeExtensionLaunchFailures(_ program: String) {
    let issue = AppIssue(
        SystemCommandError.failed(program: program, status: 69, detail: extensionLaunchDiagnostic),
        context: .connectingDisk)
    #expect(issue.title == String(localized: "The Disk Couldn’t Be Connected"))
    #expect(issue.recoveryAction == nil)
}

@Test(arguments: [Int32(1), 78, 127])
private func otherMountExitStatusesKeepDiskPreparationGuidance(_ status: Int32) {
    let issue = AppIssue(
        SystemCommandError.failed(
            program: "mount", status: status, detail: extensionLaunchDiagnostic),
        context: .connectingDisk)
    #expect(issue.title == String(localized: "The Disk Couldn’t Be Connected"))
    #expect(issue.recoveryAction == nil)
}

@Test(arguments: [0, 1, 2])
private func extensionLaunchGuidanceIsLimitedToConnectingDisks(_ kind: Int) throws {
    let context: AppIssue.Context =
        switch kind {
        case 0: .general
        case 1: .findingDisks(try ServerProfile(name: "Storage", portal: Portal("nas.local")))
        default: .ejectingDisk("Archive", connectionState: .connected)
        }
    let issue = AppIssue(
        SystemCommandError.failed(program: "mount", status: 69, detail: extensionLaunchDiagnostic),
        context: context)
    let previous = AppIssue(
        SystemCommandError.failed(program: "mount", status: 69, detail: "Unrelated failure"),
        context: context)
    #expect(issue.title == previous.title)
    #expect(issue.message == previous.message)
    #expect(issue.recoveryAction == previous.recoveryAction)
    #expect(issue.detail == "mount (69): \(extensionLaunchDiagnostic)")
}
