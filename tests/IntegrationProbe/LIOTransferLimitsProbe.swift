import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform

private actor LIOLimitCredentials: CredentialStore {
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

/// A kernel-backed LIO target supplies both VPD limits and stored bytes. No native mount.
enum LIOTransferLimitsProbe {
    private struct Plan: Decodable {
        let portal: String
        let nonce: UUID
        let blockSize: UInt32
        let maximumTransferBlocks: UInt32
        let mutualCHAP: Bool
    }

    static func run(planURL: URL) async throws {
        let plan = try JSONDecoder().decode(Plan.self, from: Data(contentsOf: planURL))
        let portal = try Portal(plan.portal)
        guard portal.host == "127.0.0.1", [UInt32(512), 4096].contains(plan.blockSize),
            plan.maximumTransferBlocks > 0, plan.maximumTransferBlocks <= 128
        else { throw ProtocolError.invalidState }
        let nonce = plan.nonce.uuidString.lowercased()
        let credentials: CHAPCredentials? =
            plan.mutualCHAP
            ? try CHAPCredentials(
                username: "test-user", password: "correct horse battery staple",
                targetUsername: "test-server", targetPassword: "independent server password")
            : nil
        let initiator = "iqn.2026-10.dev.soba:lio-probe-" + nonce
        let target = "iqn.2026-10.dev.soba:lio-" + nonce
        let configuration = try LoginConfiguration(
            initiatorName: initiator, targetName: target, credentials: credentials)
        let descriptor = try ConnectionDescriptor(
            profileID: UUID(), portal: portal, initiatorName: initiator,
            targetName: target, lun: LogicalUnit(0), readOnly: false,
            chapUsername: credentials?.username, isid: configuration.isid,
            mountID: UUID(), credentialID: credentials == nil ? nil : UUID(),
            targetCHAPUsername: credentials?.targetUsername)
        let volume = try await LUNVolumeFactory.open(
            descriptor, readOnly: false, credentials: LIOLimitCredentials(credentials))
        let replacement = Data((0..<1_048_613).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
        do {
            let (image, _) = try await (volume as any FSVolume.Operations).lookupItem(
                named: FSFileName(string: LUNImageVolume.imageName), inDirectory: volume.rootItem)
            guard
                try await volume.write(contents: replacement, to: image, at: 4099)
                    == replacement.count
            else { throw ProtocolError.malformed("LIO limited volume write") }
            await volume.shutdown()
        } catch {
            await volume.shutdown()
            throw error
        }
        // Reconnect read-only through the production TCP, inquiry, limit and RemoteDisk APIs.
        let connected = try await SessionConnector.connect(
            portal: portal, configuration: configuration)
        let session = connected.session
        do {
            let lun = try LogicalUnit(0)
            let information = try await DiskProbe.diskInformation(session: session, lun: lun)
            let limits = try await DiskProbe.blockLimits(session: session, lun: lun)
            guard information.capacity.byteCount == 8 * 1_048_576,
                information.capacity.blockSize == plan.blockSize,
                limits?.maximumTransferBlocks == plan.maximumTransferBlocks
            else { throw ProtocolError.malformed("LIO reported block limits") }
            let disk = RemoteDisk(
                session: session, lun: lun, capacity: information.capacity, readOnly: true,
                maximumTransferBlocks: plan.maximumTransferBlocks)
            let bytes = try await disk.read(offset: 0, length: 8 * 1_048_576)
            var expected = Data(repeating: 0x39, count: bytes.count)
            expected.replaceSubrange(4099..<(4099 + replacement.count), with: replacement)
            guard bytes == expected, await session.closeGracefully() else {
                throw ProtocolError.malformed("LIO whole-media readback or Logout")
            }
            let result: [String: Any] = [
                "complete": true, "blockSize": plan.blockSize,
                "maximumTransferBlocks": plan.maximumTransferBlocks,
                "mutualCHAP": plan.mutualCHAP, "factoryBytesWritten": replacement.count,
                "readOnlyReconnectedBytesCompared": bytes.count,
                "nativeFSKitMount": false, "realKeychainUsed": false,
            ]
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            try data.write(to: planURL.deletingLastPathComponent().appending(path: "Probe.json"))
        } catch {
            await session.close()
            throw error
        }
    }
}
