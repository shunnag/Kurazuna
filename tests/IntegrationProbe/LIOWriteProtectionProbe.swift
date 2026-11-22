import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform

private actor LIOProtectionCredentials: CredentialStore {
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

/// Real kernel MODE headers and media over TCP; no native FSKit mount or real Keychain.
enum LIOWriteProtectionProbe {
    private struct Plan: Decodable {
        let portal: String
        let nonce: UUID
        let blockSize: UInt32
        let writeProtected: Bool
        let mutualCHAP: Bool
    }

    static func run(planURL: URL) async throws {
        let plan = try JSONDecoder().decode(Plan.self, from: Data(contentsOf: planURL))
        let portal = try Portal(plan.portal)
        guard portal.host == "127.0.0.1", [UInt32(512), 4096].contains(plan.blockSize) else {
            throw ProtocolError.invalidState
        }
        let nonce = plan.nonce.uuidString.lowercased()
        let credentials: CHAPCredentials? =
            plan.mutualCHAP
            ? try CHAPCredentials(
                username: "test-user", password: "correct horse battery staple",
                targetUsername: "test-server", targetPassword: "independent server password") : nil
        let configuration = try LoginConfiguration(
            initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + nonce,
            targetName: "iqn.2026-10.dev.soba:lio-" + nonce, credentials: credentials)
        let lun = try LogicalUnit(0)

        // Inspect both genuine header formats, independently of the factory's policy.
        let discovery = try await SessionConnector.connect(
            portal: portal, configuration: configuration)
        do {
            let information = try await DiskProbe.diskInformation(
                session: discovery.session, lun: lun)
            let six = try await DiskProbe.readOnly(
                .modeSense6(), session: discovery.session, lun: lun)
            guard information.isWriteProtected == plan.writeProtected,
                information.capacity.blockSize == plan.blockSize,
                information.capacity.byteCount == 8 * 1_048_576,
                try SCSIModeHeader(modeSense6: six.data).isWriteProtected == plan.writeProtected,
                await discovery.session.closeGracefully()
            else { throw ProtocolError.malformed("LIO protection information or Logout") }
        } catch {
            await discovery.session.close()
            throw error
        }

        func descriptor(readOnly: Bool) throws -> ConnectionDescriptor {
            try ConnectionDescriptor(
                profileID: UUID(), portal: portal, initiatorName: configuration.initiatorName,
                targetName: "iqn.2026-10.dev.soba:lio-" + nonce, lun: lun, readOnly: readOnly,
                chapUsername: credentials?.username, isid: configuration.isid,
                mountID: UUID(), credentialID: credentials == nil ? nil : UUID(),
                targetCHAPUsername: credentials?.targetUsername)
        }
        let store = LIOProtectionCredentials(credentials)
        let replacement = Data((0..<4099).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
        var rwRejected = false
        do {
            let volume = try await LUNVolumeFactory.open(
                descriptor(readOnly: false), readOnly: false, credentials: store)
            do {
                guard !plan.writeProtected else {
                    throw ProtocolError.malformed("Protected LIO factory accepted RW")
                }
                let (image, _) = try await (volume as any FSVolume.Operations).lookupItem(
                    named: FSFileName(string: LUNImageVolume.imageName),
                    inDirectory: volume.rootItem)
                try await volume.openItem(image, modes: [.write])
                guard
                    try await volume.write(contents: replacement, to: image, at: 509)
                        == replacement.count
                else { throw ProtocolError.malformed("LIO protection normal write") }
                try await volume.closeItem(image, modes: [.write])
                await volume.shutdown()
            } catch {
                await volume.shutdown()
                throw error
            }
        } catch let error as POSIXError where plan.writeProtected && error.code == .EROFS {
            rwRejected = true
        }
        guard rwRejected == plan.writeProtected else {
            throw ProtocolError.malformed("LIO protection admission")
        }

        // The descriptor alone must preserve RO even if the factory caller passes false.
        let readOnlyVolume = try await LUNVolumeFactory.open(
            descriptor(readOnly: true), readOnly: false, credentials: store)
        do {
            let (image, _) = try await (readOnlyVolume as any FSVolume.Operations).lookupItem(
                named: FSFileName(string: LUNImageVolume.imageName),
                inDirectory: readOnlyVolume.rootItem)
            try await expectReadOnly { try await readOnlyVolume.openItem(image, modes: [.write]) }
            try await expectReadOnly {
                _ = try await readOnlyVolume.write(contents: replacement, to: image, at: 509)
            }
            await readOnlyVolume.shutdown()
        } catch {
            await readOnlyVolume.shutdown()
            throw error
        }

        // Read all bytes over a fresh RO production disk session, including adjacent data.
        let readback = try await SessionConnector.connect(
            portal: portal, configuration: configuration)
        do {
            let information = try await DiskProbe.diskInformation(
                session: readback.session, lun: lun)
            let limits = try await DiskProbe.blockLimits(session: readback.session, lun: lun)
            guard information.isWriteProtected == plan.writeProtected,
                information.capacity.byteCount == 8 * 1_048_576,
                information.capacity.blockSize == plan.blockSize
            else { throw ProtocolError.malformed("LIO protection changed during reconnect") }
            let disk = RemoteDisk(
                session: readback.session, lun: lun, capacity: information.capacity, readOnly: true,
                maximumTransferBlocks: limits?.maximumTransferBlocks ?? 0)
            let bytes = try await disk.read(offset: 0, length: 8 * 1_048_576)
            var expected = Data(repeating: 0x39, count: bytes.count)
            if !plan.writeProtected { expected.replaceSubrange(509..<4608, with: replacement) }
            guard bytes == expected, await readback.session.closeGracefully() else {
                throw ProtocolError.malformed("LIO protection whole-media readback or Logout")
            }
            let result: [String: Any] = [
                "complete": true, "blockSize": plan.blockSize,
                "writeProtected": plan.writeProtected, "mutualCHAP": plan.mutualCHAP,
                "protectedRWRejectedBeforeIO": rwRejected,
                "factoryBytesWritten": plan.writeProtected ? 0 : replacement.count,
                "readOnlyDescriptorEnforced": true, "readOnlyOpenAndWriteErrno": 30,
                "mode6HeaderVerified": true, "readOnlyReconnectedBytesCompared": bytes.count,
                "nativeFSKitMount": false, "realKeychainUsed": false,
            ]
            try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]).write(
                to: planURL.deletingLastPathComponent().appending(path: "Probe.json"))
        } catch {
            await readback.session.close()
            throw error
        }
    }

    private static func expectReadOnly(_ operation: () async throws -> Void) async throws {
        do {
            try await operation()
        } catch let error as POSIXError where error.code == .EROFS { return }
        throw ProtocolError.malformed("Read-only LIO callback did not return EROFS")
    }
}
