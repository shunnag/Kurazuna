import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform

private actor ProtectionCredentials: CredentialStore {
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

/// Production volume callbacks over disposable loopback media; no native mount or real Keychain.
enum WriteProtectionProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let env = ProcessInfo.processInfo.environment
        let source = try Portal(portal)
        guard source.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let readOnly = env["ISCSI_TEST_PROTECT_READ_ONLY"] == "1"
        let expectedProtection = env["ISCSI_TEST_WRITE_PROTECTED"] == "1"
        let descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: source,
            initiatorName: "iqn.2026-10.dev.soba:write-protection-"
                + UUID().uuidString.lowercased(),
            targetName: "iqn.2026-10.test:memory", lun: LogicalUnit(0), readOnly: readOnly,
            chapUsername: credentials?.username,
            isid: [0x80] + (0..<5).map { _ in UInt8.random(in: .min ... .max) },
            mountID: UUID(), credentialID: credentials == nil ? nil : UUID(),
            targetCHAPUsername: credentials?.targetUsername)
        var report: [String: Any] = [
            "complete": true, "productionVolumeFactory": true, "nativeFSKitMount": false,
            "realKeychainUsed": false, "requestedReadOnly": readOnly,
        ]
        let volume: LUNImageVolume
        do {
            volume = try await LUNVolumeFactory.open(
                descriptor, readOnly: readOnly, credentials: ProtectionCredentials(credentials))
        } catch {
            report["opened"] = false
            report["openError"] = String(describing: error)
            report["openErrno"] = (error as? POSIXError)?.code.rawValue ?? 0
            try emit(report)
            return
        }
        report["opened"] = true
        do {
            let (image, _) = try await (volume as any FSVolume.Operations).lookupItem(
                named: FSFileName(string: LUNImageVolume.imageName), inDirectory: volume.rootItem)
            if expectedProtection && !readOnly {
                // The old factory advertises RW and only discovers protection on its first WRITE.
                do {
                    _ = try await volume.write(
                        contents: Data(repeating: 0x6D, count: 512), to: image, at: 0)
                    report["lateWriteAccepted"] = true
                } catch { report["lateWriteError"] = String(describing: error) }
            } else if readOnly {
                do {
                    try await volume.openItem(image, modes: [.write])
                    report["writeOpenErrno"] = 0
                } catch { report["writeOpenErrno"] = (error as? POSIXError)?.code.rawValue ?? 0 }
            } else {
                let content = Data((0..<4099).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
                report["writtenBytes"] = try await volume.write(
                    contents: content, to: image, at: 509)
            }
            await volume.shutdown()
            try emit(report)
            if expectedProtection && !readOnly {
                throw ProtocolError.malformed("write-protected disk opened read/write")
            }
        } catch {
            await volume.shutdown()
            throw error
        }
    }

    private static func emit(_ report: [String: Any]) throws {
        print(
            "WRITE_PROTECTION_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: report, options: [.sortedKeys]), as: UTF8.self))
    }
}
