import Foundation
import ISCSICore
import Security
import Testing

@testable import ISCSIPlatform

@Test(arguments: [false, true])
func mutualKeychainSaveReachesTheProductionStore(_ throughProtocol: Bool) async throws {
    // A missing access group rejects before any SecItem operation. Both dispatch paths
    // must reach that production guard, rather than the protocol's unsupported fallback.
    let store = KeychainCredentialStore(accessGroup: nil)
    let context = CredentialContext(
        profileID: UUID(), portal: try Portal("127.0.0.1"),
        username: "Mac", targetUsername: "Server")
    do {
        if throughProtocol {
            let reference: any CredentialStore = store
            try await reference.save(
                password: "disposable initiator secret",
                targetPassword: "disposable server secret", context: context)
        } else {
            try await store.save(
                password: "disposable initiator secret",
                targetPassword: "disposable server secret", context: context)
        }
        Issue.record("Missing access group must reject before touching the Keychain")
    } catch let error as NSError {
        #expect(error.domain == NSOSStatusErrorDomain)
        #expect(error.code == Int(errSecMissingEntitlement))
    }
}
