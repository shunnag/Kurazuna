import ISCSICore
import Testing

@testable import ISCSIAppModel

@Test(arguments: [
    ProtocolError.limitExceeded("login redirects"), .limitExceeded("login redirect loop"),
    .limitExceeded("login redirect addresses"), .limitExceeded("login connection attempts"),
    .malformed("redirect TargetAddress"), .malformed("redirect TargetAddress portal group"),
])
func redirectFailureExplainsWhichServerSettingsToCheck(_ error: ProtocolError) {
    let issue = AppIssue(error)
    #expect(issue.title == "Couldn’t Connect to the Server")
    #expect(
        issue.message
            == "Check the server’s connection addresses and iSCSI settings, then try again.")
    #expect(issue.recoveryAction == nil)
}
