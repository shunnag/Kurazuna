import Foundation
import ISCSICore
import Security
import Testing

@testable import ISCSIPlatform

@Test func releaseUsesTheKurazunaSettingsAndKeychain() {
    let identity = ApplicationIdentity.release
    #expect(identity.bundleIdentifier == "dev.soba.iscsi.kurazuna")
    #expect(identity.extensionBundleIdentifier == "dev.soba.iscsi.kurazuna.FileSystem")
    #expect(identity.fileSystemType == "kurazuna")
    #expect(identity.keychainGroupSuffix == "dev.soba.iscsi.kurazuna.shared")
    #expect(identity.credentialService == "dev.soba.iscsi.kurazuna.chap")
    #expect(
        identity.supportDirectory(in: URL(fileURLWithPath: "/private/tmp/Support")).path
            == "/private/tmp/Support/Kurazuna")
}

@Test func developmentUsesAnIndependentPersistentNamespace() {
    let release = ApplicationIdentity.release
    let development = ApplicationIdentity.development
    let support = URL(fileURLWithPath: "/private/tmp/Support")
    #expect(development.bundleIdentifier == "dev.soba.iscsi.kurazuna.development")
    #expect(development.fileSystemType == "kurazunadev")
    #expect(development.extensionBundleIdentifier != release.extensionBundleIdentifier)
    #expect(development.keychainGroupSuffix != release.keychainGroupSuffix)
    #expect(development.credentialService != release.credentialService)
    #expect(development.supportDirectory(in: support) != release.supportDirectory(in: support))
    #expect(development.applicationName != release.applicationName)
}

@Test(arguments: ApplicationIdentity.allCases)
func aCredentialQueryCannotCrossEditions(_ identity: ApplicationIdentity) throws {
    let context = CredentialContext(
        profileID: UUID(), portal: try Portal("127.0.0.1"), username: "test")
    let group = "FQTM2788K5." + identity.keychainGroupSuffix
    let query = try KeychainCredentialStore.query(
        for: context, accessGroup: group, identity: identity)
    #expect(query[kSecAttrAccount as String] as? String == context.account)
    #expect(query[kSecAttrService as String] as? String == identity.credentialService)
    #expect(query[kSecAttrAccessGroup as String] as? String == group)
    #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
    #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
    let other: ApplicationIdentity = identity == .release ? .development : .release
    for invalid in [
        nil, "", "FQTM2788K5." + other.keychainGroupSuffix,
        "$(TeamIdentifierPrefix)" + identity.keychainGroupSuffix,
        "." + identity.keychainGroupSuffix, "invalid." + identity.keychainGroupSuffix,
        group + ".other",
    ] {
        do {
            _ = try KeychainCredentialStore.query(
                for: context, accessGroup: invalid, identity: identity)
            Issue.record("An invalid or other-edition group must reject before a Keychain call")
        } catch let error as NSError {
            #expect(error.domain == NSOSStatusErrorDomain)
            #expect(error.code == Int(errSecMissingEntitlement))
        }
    }
}

@Test(arguments: ApplicationIdentity.allCases)
func extensionAvailabilityIgnoresTheOtherEdition(_ identity: ApplicationIdentity) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let app = root.appendingPathComponent("Test.app")
    let module = try #require(FileSystemExtensionAvailability.expectedModuleURL(in: app))
    try FileManager.default.createDirectory(at: module, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let other: ApplicationIdentity = identity == .release ? .development : .release
    let wrong = FileSystemExtensionRegistration(
        bundleIdentifier: other.extensionBundleIdentifier, moduleURL: module, isEnabled: true)
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [wrong], applicationURL: app, identity: identity) == .unavailable)
    let own = FileSystemExtensionRegistration(
        bundleIdentifier: identity.extensionBundleIdentifier, moduleURL: module, isEnabled: true)
    let assessment = FileSystemExtensionAvailability.assess(
        [wrong, own], applicationURL: app, identity: identity)
    #expect(assessment.availability == .ready)
    #expect(assessment.matchingModuleCount == 1)
    #expect(assessment.enabledMatchingModuleCount == 1)
}
