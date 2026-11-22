import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test(arguments: [UInt8(0), 1, 2, 3])
@MainActor func aTargetEventUsesTheInterruptedConnectionGuidance(_ event: UInt8) {
    let issue = AppIssue(ProtocolError.targetEvent(event))
    let reference = AppIssue(AttachmentError.connectionInterrupted)
    #expect(issue.title == reference.title && issue.message == reference.message)
    #expect(issue.recoveryAction == nil)
}
