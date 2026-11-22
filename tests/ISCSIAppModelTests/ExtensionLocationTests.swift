import Foundation
import ISCSICore
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test(arguments: [false, true])
@MainActor func anotherCopyCannotMakeTheRunningAppReadyToConnect(_ enabled: Bool) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let current = root.appendingPathComponent("Current.app", isDirectory: true)
    let other = root.appendingPathComponent("Other.app", isDirectory: true)
    for app in [current, other] {
        try FileManager.default.createDirectory(
            at: FileSystemExtensionAvailability.expectedModuleURL(in: app)!,
            withIntermediateDirectories: true)
    }
    let registrations = [
        FileSystemExtensionRegistration(
            bundleIdentifier: FileSystemExtensionAvailability.bundleIdentifier,
            moduleURL: FileSystemExtensionAvailability.expectedModuleURL(in: other)!,
            isEnabled: enabled)
    ]
    let model = AppModel(extensionCheck: {
        AppModel.assessExtension(registrations, applicationURL: current)
    })
    model.document = try ProfileDocument(identity: .makeNew())
    model.recoveryComplete = true
    await model.refreshExtension()
    #expect(model.extensionState == .differentCopy)
    #expect(!model.canConnect)
    #expect(
        model.extensionState.noticeTitle
            == String(
                localized: "Check the \(ApplicationIdentity.current.applicationName) Installation"))
    #expect(
        model.extensionState.noticeMessage
            == String(
                localized:
                    "The file system extension belongs to another copy of \(ApplicationIdentity.current.applicationName). Eject connected disks before reinstalling \(ApplicationIdentity.current.applicationName), then click Check Again."
            ))
}
