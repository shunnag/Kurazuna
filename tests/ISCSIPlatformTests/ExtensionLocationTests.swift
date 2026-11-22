import Foundation
import Testing

@testable import ISCSIPlatform

private func locationFixture() throws -> (URL, URL, URL) {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true)
    let app = root.appendingPathComponent("App.app", isDirectory: true)
    let module = FileSystemExtensionAvailability.expectedModuleURL(in: app)!
    try FileManager.default.createDirectory(at: module, withIntermediateDirectories: true)
    return (root, app, module)
}

private func registration(
    _ url: URL, enabled: Bool = true, id: String = FileSystemExtensionAvailability.bundleIdentifier
) -> FileSystemExtensionRegistration {
    FileSystemExtensionRegistration(bundleIdentifier: id, moduleURL: url, isEnabled: enabled)
}

@Test(arguments: [false, true])
func anExtensionMustMatchTheHostsPhysicalBundleLocation(_ enabled: Bool) throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let expected: FileSystemExtensionAvailability = enabled ? .ready : .disabled
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [registration(module, enabled: enabled)], applicationURL: app) == expected)
    let alias = root.appendingPathComponent("Alias.app", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: app)
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [registration(module, enabled: enabled)], applicationURL: alias) == expected)
    let aliasedModule = FileSystemExtensionAvailability.expectedModuleURL(in: alias)!
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [registration(aliasedModule, enabled: enabled)], applicationURL: app) == expected)
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [
                registration(module, enabled: enabled), registration(module, id: "com.apple.other"),
            ], applicationURL: app) == expected)
    let alternateCase = URL(fileURLWithPath: module.path.uppercased(), isDirectory: true)
    if FileManager.default.fileExists(atPath: alternateCase.path) {
        #expect(
            FileSystemExtensionAvailability.evaluate(
                [registration(alternateCase, enabled: enabled)], applicationURL: app) == expected)
    }
}

@Test func missingAmbiguousOrInvalidRegistrationsNeverMakeTheExtensionReady() throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let valid = registration(module)
    for records in [[], [registration(module, id: "com.apple.other")], [valid, valid]] {
        #expect(
            FileSystemExtensionAvailability.evaluate(records, applicationURL: app) == .unavailable)
    }
    for invalid in [
        URL(string: "https://example.test/App.app")!, root.appendingPathComponent("App.txt"),
    ] {
        #expect(
            FileSystemExtensionAvailability.evaluate([valid], applicationURL: invalid)
                == .unavailable)
    }
    for invalid in [
        URL(string: "https://example.test/ISCSIFSExtension.appex")!,
        URL(string: module.absoluteString + "?other=1")!,
        URL(string: module.absoluteString + "#other")!,
        URL(string: module.absoluteString + "%00other")!,
    ] {
        #expect(
            FileSystemExtensionAvailability.evaluate([registration(invalid)], applicationURL: app)
                == .unavailable)
    }
    try FileManager.default.removeItem(at: module)
    #expect(FileSystemExtensionAvailability.evaluate([valid], applicationURL: app) == .unavailable)
    try Data().write(to: URL(fileURLWithPath: module.path, isDirectory: false))
    #expect(FileSystemExtensionAvailability.evaluate([valid], applicationURL: app) == .unavailable)
}

@Test(arguments: [false, true])
func anotherInstalledCopyIsDistinctFromAMissingOrDisabledExtension(_ enabled: Bool) throws {
    let (root, app, _) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let other = root.appendingPathComponent("Other.app", isDirectory: true)
    let module = FileSystemExtensionAvailability.expectedModuleURL(in: other)!
    try FileManager.default.createDirectory(at: module, withIntermediateDirectories: true)
    #expect(
        FileSystemExtensionAvailability.evaluate(
            [registration(module, enabled: enabled)], applicationURL: app) == .differentCopy)
}

@Test(arguments: [false, true])
func anAssessmentReportsTheIdentityUsedForItsAvailabilityDecision(_ enabled: Bool) throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let assessment = FileSystemExtensionAvailability.assess(
        [registration(module, enabled: enabled), registration(module, id: "com.apple.other")],
        applicationURL: app)
    #expect(assessment.availability == (enabled ? .ready : .disabled))
    #expect(assessment.matchingModuleCount == 1)
    #expect(assessment.enabledMatchingModuleCount == (enabled ? 1 : 0))
    let expected = try #require(assessment.expectedIdentity)
    let actual = try #require(assessment.registeredIdentity)
    #expect(expected == actual)
    #expect(expected.inode != 0)
}

@Test func assessmentIdentitiesDistinguishAnotherCopyFromAnAlias() throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let other = root.appendingPathComponent("Other.app", isDirectory: true)
    let otherModule = FileSystemExtensionAvailability.expectedModuleURL(in: other)!
    try FileManager.default.createDirectory(at: otherModule, withIntermediateDirectories: true)
    let different = FileSystemExtensionAvailability.assess(
        [registration(otherModule)], applicationURL: app)
    #expect(different.availability == .differentCopy)
    let differentExpected = try #require(different.expectedIdentity)
    let differentRegistered = try #require(different.registeredIdentity)
    #expect(differentExpected != differentRegistered)
    let alias = root.appendingPathComponent("Alias.app", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: app)
    let same = FileSystemExtensionAvailability.assess(
        [registration(module)], applicationURL: alias)
    #expect(same.availability == .ready)
    let sameExpected = try #require(same.expectedIdentity)
    let sameRegistered = try #require(same.registeredIdentity)
    #expect(sameExpected == sameRegistered)
}

@Test func anAssessmentCountsAmbiguityWithoutSelectingARegistration() throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    for (records, count, enabled) in [
        ([FileSystemExtensionRegistration](), 0, 0),
        ([registration(module, id: "com.apple.other")], 0, 0),
        ([registration(module), registration(module, enabled: false)], 2, 1),
    ] {
        let assessment = FileSystemExtensionAvailability.assess(records, applicationURL: app)
        #expect(assessment.availability == .unavailable)
        #expect(assessment.matchingModuleCount == count)
        #expect(assessment.enabledMatchingModuleCount == enabled)
        #expect(assessment.expectedIdentity == nil)
        #expect(assessment.registeredIdentity == nil)
    }
}

@Test func anAssessmentDoesNotReportAnUnverifiedDirectoryIdentity() throws {
    let (root, app, module) = try locationFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    for invalid in [
        URL(string: "https://example.test/ISCSIFSExtension.appex")!,
        URL(string: module.absoluteString + "?secret=hidden")!,
        URL(string: module.absoluteString + "#private")!,
    ] {
        let assessment = FileSystemExtensionAvailability.assess(
            [registration(invalid)], applicationURL: app)
        #expect(assessment.availability == .unavailable)
        #expect(assessment.expectedIdentity == nil && assessment.registeredIdentity == nil)
    }
    try FileManager.default.removeItem(at: module)
    for isRegularFile in [false, true] {
        if isRegularFile { try Data().write(to: URL(fileURLWithPath: module.path)) }
        let assessment = FileSystemExtensionAvailability.assess(
            [registration(module)], applicationURL: app)
        #expect(assessment.availability == .unavailable)
        #expect(assessment.expectedIdentity == nil && assessment.registeredIdentity == nil)
    }
}
