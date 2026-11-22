import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform

private actor BlockLimitsCredentials: CredentialStore {
    let value: CHAPCredentials?
    init(_ value: CHAPCredentials?) { self.value = value }
    func credentials(context: CredentialContext) throws -> CHAPCredentials {
        guard let value, context.username == value.username,
            context.targetUsername == value.targetUsername
        else { throw ProtocolError.invalidState }
        return value
    }
    func save(password: String, context: CredentialContext) throws {
        throw ProtocolError.invalidState
    }
    func remove(context: CredentialContext) throws { throw ProtocolError.invalidState }
}

/// Uses the production volume factory and byte I/O against one private RAM target.
/// This does not mount FSKit, use DiskImages, or access the real Keychain.
enum BlockLimitsProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let source = try Portal(portal)
        let phase =
            ProcessInfo.processInfo.environment["ISCSI_TEST_BLOCK_LIMIT_PHASE"] ?? "unaligned"
        guard source.host == "127.0.0.1", ["aligned", "unaligned"].contains(phase) else {
            throw ProtocolError.invalidState
        }
        let descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: source,
            initiatorName: "iqn.2026-10.dev.soba:block-limits-" + UUID().uuidString.lowercased(),
            targetName: "iqn.2026-10.test:memory", lun: LogicalUnit(0), readOnly: false,
            chapUsername: credentials?.username,
            isid: [0x80] + (0..<5).map { _ in UInt8.random(in: .min ... .max) },
            mountID: UUID(), credentialID: credentials == nil ? nil : UUID(),
            targetCHAPUsername: credentials?.targetUsername)
        let volume = try await LUNVolumeFactory.open(
            descriptor, readOnly: false, credentials: BlockLimitsCredentials(credentials))
        do {
            let (image, _) = try await (volume as any FSVolume.Operations).lookupItem(
                named: FSFileName(string: LUNImageVolume.imageName), inDirectory: volume.rootItem)
            let offset = phase == "aligned" ? 4096 : 509
            let count = phase == "aligned" ? 32_768 : 32_797
            let bytes = Data((0..<count).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
            guard try await volume.write(contents: bytes, to: image, at: off_t(offset)) == count,
                try await volume.xattr(
                    named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
                    of: volume.rootItem) == DiskConnectionState.connected.encoded
            else { throw ProtocolError.malformed("block-limit volume write") }
            await volume.shutdown()
            let result: [String: Any] = [
                "complete": true, "phase": phase, "offset": offset, "bytes": count,
                "productionVolumeFactory": true, "nativeFSKitMount": false,
                "realKeychainUsed": false,
            ]
            print(
                "BLOCK_LIMITS_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
        } catch {
            await volume.shutdown()
            throw error
        }
    }
}
