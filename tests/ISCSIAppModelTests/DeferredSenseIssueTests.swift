import Foundation
import ISCSICore
import Testing

@testable import ISCSIAppModel

@Test(arguments: [UInt8(0x70), 0x71, 0x72, 0x73])
@MainActor func deferredSenseExplainsTheEarlierErrorAndPossibleUnsavedChanges(_ response: UInt8) {
    let data =
        response == 0x70 || response == 0x71
        ? Data([response, 0, 7, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x27, 0])
        : Data([response, 7, 0x27, 0, 0, 0, 0, 0])
    let issue = AppIssue(ProtocolError.scsiFailure(status: 2, sense: data))
    if response == 0x71 || response == 0x73 {
        #expect(issue.title == String(localized: "The Disk Reported a Problem"))
        #expect(
            issue.message
                == String(
                    localized:
                        "The disk reported a problem with an earlier operation. Recent changes may not have been saved. Check the disk on the server before connecting again."
                ))
        #expect(issue.recoveryAction == nil)
    } else {
        #expect(issue.title != String(localized: "The Disk Reported a Problem"))
    }
}
