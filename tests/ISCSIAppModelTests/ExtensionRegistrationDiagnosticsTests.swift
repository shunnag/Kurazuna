import Foundation
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test func extensionDiagnosticsDoNotIncludeInstallationPaths() {
    let application = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString + "/private-user/credential-secret/Kurazuna.app")
    let module = FileSystemExtensionAvailability.expectedModuleURL(in: application)!
    let assessment = FileSystemExtensionAvailability.assess(
        [
            FileSystemExtensionRegistration(
                bundleIdentifier: FileSystemExtensionAvailability.bundleIdentifier,
                moduleURL: module, isEnabled: true)
        ], applicationURL: application)
    let fields = ExtensionRegistrationDiagnostics.registrationFields(assessment)
    #expect(fields.contains("state=unavailable own=1 enabled=1"))
    #expect(fields.contains("expectedIdentity=0 registeredIdentity=0"))
    #expect(!fields.contains("private-user"))
    #expect(!fields.contains("credential-secret"))
    #expect(!fields.contains("/Users/"))
    #expect(!fields.contains("file:"))
}

@Test func extensionDiagnosticErrorsExcludeDescriptionsAndUnknownDomains() {
    let details = [NSLocalizedDescriptionKey: "password=credential-secret user=private-user"]
    let known = NSError(domain: NSCocoaErrorDomain, code: 4099, userInfo: details)
    #expect(
        ExtensionRegistrationDiagnostics.failureFields(known)
            == "domain=NSCocoaErrorDomain code=4099")
    let unknown = NSError(domain: "private-user.credential-secret", code: 17, userInfo: details)
    #expect(ExtensionRegistrationDiagnostics.failureFields(unknown) == "domain=other code=17")
    #expect(
        ExtensionRegistrationDiagnostics.failureFields(CancellationError())
            == "domain=cancellation code=0")
}
