import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test(arguments: [false, true])
private func localNetworkPermissionFailureOffersSettingsAndExplainsRetry(_ searching: Bool)
    throws
{
    let server = try ServerProfile(name: "Storage", portal: Portal("nas.local"))
    let issue = AppIssue(
        ProtocolError.localNetworkAccessRequired,
        context: searching ? .findingDisks(server) : .general)
    #expect(issue.title == String(localized: "Local Network Access Is Needed"))
    #expect(
        issue.message
            == String(
                localized:
                    "Check \(ApplicationIdentity.current.applicationName)’s access in System Settings > Privacy & Security > Local Network. If you just allowed access, try again."
            ))
    #expect(issue.recoveryAction == .openSystemSettings)
    #expect(issue.forceEjectionDiskID == nil)
}

@Test func genericPermissionAndTimeoutErrorsDoNotClaimLocalNetworkDenial() {
    for error in [POSIXError(.EPERM), POSIXError(.EACCES)] {
        #expect(AppIssue(error).recoveryAction != .openSystemSettings)
    }
    #expect(AppIssue(ProtocolError.timedOut).recoveryAction != .openSystemSettings)
}
