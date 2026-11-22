import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test func releasePermissionGuidanceNamesKurazuna() {
    let guidance = AppPermissionGuidance(identity: .release)
    #expect(guidance.enableTitle == "Allow Kurazuna to Connect Disks")
    #expect(guidance.installationTitle == "Check the Kurazuna Installation")
    #expect(guidance.launchFailureTitle == "The Kurazuna Extension Couldn’t Be Started")
    #expect(
        guidance.enableMessage
            == "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then turn on Kurazuna."
    )
    #expect(guidance.localNetworkMessage.contains("check Kurazuna in System Settings"))
}

@Test func developmentPermissionGuidanceSelectsDevelopmentWithoutRenamingTheProtocol() {
    let guidance = AppPermissionGuidance(identity: .development)
    #expect(guidance.enableTitle == "Allow Kurazuna Development to Connect Disks")
    #expect(guidance.installationTitle == "Check the Kurazuna Development Installation")
    #expect(guidance.launchFailureTitle == "The Kurazuna Development Extension Couldn’t Be Started")
    #expect(guidance.enableMessage.hasSuffix("then turn on Kurazuna Development."))
    #expect(guidance.localNetworkMessage.contains("check Kurazuna Development in System Settings"))
    #expect(guidance.installationMessage.contains("another copy of Kurazuna Development."))
    #expect(guidance.installationMessage.contains("Use This Copy"))
    #expect(guidance.unavailableMessage.hasPrefix("Kurazuna Development couldn’t check"))
    #expect(guidance.unavailableMessage.contains("reinstall Kurazuna Development."))
    #expect(guidance.launchFailureMessage.contains("check that Kurazuna Development is enabled."))
    #expect(guidance.launchFailureMessage.contains("eject any connected iSCSI disks"))
    #expect(!guidance.launchFailureMessage.contains("Kurazuna Development disks"))
}

@Test @MainActor func thePermissionBannerNamesTheEditionThatOwnsTheExtension() {
    let name = ApplicationIdentity.current.applicationName
    #expect(AppModel.ExtensionState.disabled.noticeTitle == "Allow \(name) to Connect Disks")
    #expect(AppModel.ExtensionState.disabled.noticeMessage.hasSuffix("then turn on \(name)."))
    #expect(
        AppModel.ExtensionState.differentCopy.noticeMessage.contains("another copy of \(name)."))
}

/// The quit alert keeps a name of several words on one line.
@Test func appNamesInSentencesDoNotBreak() {
    #expect(!AppName.inSentence.contains(" "))
    #expect(AppName.inSentence.replacingOccurrences(of: "\u{00A0}", with: " ") == AppName.display)
    // The Development edition's name has two words.
    #expect(AppName.inSentence("Kurazuna Development") == "Kurazuna\u{00A0}Development")
}

@Test
func readOnlyLaunchExplainsFinderMoveWithoutBypassingTheExtensionCheck() {
    for state in [FileSystemExtensionAvailability.differentCopy, .unavailable, .disabled] {
        #expect(AppModel.state(for: state, readOnly: true) == .readOnlyLocation)
    }
    #expect(AppModel.state(for: .ready, readOnly: true) == .ready)
    #expect(AppModel.state(for: .differentCopy, readOnly: false) == .differentCopy)
    #expect(AppModel.state(for: .disabled, readOnly: false) == .disabled)
}
