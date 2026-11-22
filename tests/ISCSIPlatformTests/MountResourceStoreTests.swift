import Foundation
import ISCSICore
import Security
import Testing

@testable import ISCSIPlatform

private func storedMountDescriptor() throws -> ConnectionDescriptor {
    try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:initiator", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
}

@Test func storedMountMetadataRejectsMissingCorruptedAndSubstitutedConnections() throws {
    let descriptor = try storedMountDescriptor()
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    let data = try KeychainMountResourceStore.encode(descriptor)
    #expect(try KeychainMountResourceStore.decode(data, reference: reference) == descriptor)
    let other = try descriptor.assigningMountID(UUID())
    for corrupt in [
        Data(), Data([0xFF]), Data(repeating: 65, count: 4097),
        Data(reference.url.absoluteString.utf8), try KeychainMountResourceStore.encode(other),
    ] {
        #expect(throws: ProtocolError.self) {
            try KeychainMountResourceStore.decode(corrupt, reference: reference)
        }
    }
}

@Test(arguments: ApplicationIdentity.allCases)
func mountMetadataHasAnEditionSpecificServiceAndValidatedSharedGroup(
    _ identity: ApplicationIdentity
) throws {
    let reference = try ConnectionResourceReference(descriptor: storedMountDescriptor())
    let group = "FQTM2788K5." + identity.keychainGroupSuffix
    let query = try KeychainMountResourceStore.query(
        reference, accessGroup: group, identity: identity)
    #expect(
        query[kSecAttrService as String] as? String == identity.bundleIdentifier + ".mount-resource"
    )
    #expect(query[kSecAttrService as String] as? String != identity.credentialService)
    #expect(query[kSecAttrAccessGroup as String] as? String == group)
    #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
    #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
    for invalid in [nil, "", "FQTM2788K5.other.shared", "invalid." + identity.keychainGroupSuffix] {
        #expect(throws: NSError.self) {
            try KeychainMountResourceStore.query(
                reference, accessGroup: invalid, identity: identity)
        }
    }
}

@Test func missingMountMetadataEntitlementFailsBeforeAnyMountCanStart() async throws {
    let store = KeychainMountResourceStore(accessGroup: nil)
    let descriptor = try storedMountDescriptor()
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    for operation in 0..<3 {
        do {
            switch operation {
            case 0: _ = try await store.save(descriptor)
            case 1: _ = try await store.resolve(reference)
            default: try await store.remove(reference)
            }
            Issue.record("Missing access group must reject before SecItem operations")
        } catch let error as NSError {
            #expect(error.domain == NSOSStatusErrorDomain)
            #expect(error.code == Int(errSecMissingEntitlement))
        }
    }
    #expect(try await store.descriptor(for: descriptor.resourceURL) == descriptor)
}
