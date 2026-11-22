import Foundation
import ISCSICore
import ISCSINetwork
import Synchronization

/// Talks to an independent Linux LIO block backstore, without mounting a filesystem.
/// The controller changes only its disposable device-mapper target at the ready barrier.
enum LIOBlockFaultProbe {
    private struct Plan: Decodable {
        let portal: String
        let nonce: UUID
        let mode: String
        let mutualCHAP: Bool
    }

    private final class ObservedTransport: ByteTransport, Sendable {
        let tcp: TCPTransport
        private let scsiCount = Mutex(0)
        var commands: Int { scsiCount.withLock { $0 } }

        init(_ tcp: TCPTransport) { self.tcp = tcp }
        func send(_ data: Data) async throws {
            if data.first.map({ $0 & 0x3F }) == 1 { scsiCount.withLock { $0 += 1 } }
            try await tcp.send(data)
        }
        func receive(maximumLength: Int) async throws -> Data {
            try await tcp.receive(maximumLength: maximumLength)
        }
        func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data {
            try await tcp.receive(
                maximumLength: maximumLength, waitingForActivity: waitingForActivity)
        }
        func close() async { await tcp.close() }
    }

    static func run(planURL: URL) async throws {
        let root = planURL.deletingLastPathComponent()
        let plan = try JSONDecoder().decode(Plan.self, from: Data(contentsOf: planURL))
        guard ["healthy", "write-error", "sync-error"].contains(plan.mode) else {
            throw ProtocolError.malformed("LIO fault mode")
        }
        let portal = try Portal(plan.portal)
        guard portal.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let nonce = plan.nonce.uuidString.lowercased()
        let credentials: CHAPCredentials? =
            plan.mutualCHAP
            ? try CHAPCredentials(
                username: "test-user", password: "correct horse battery staple",
                targetUsername: "test-server", targetPassword: "independent server password")
            : nil
        let tcp = try TCPTransport(portal: portal, timeout: 10, waitForConnectivity: false)
        let transport = ObservedTransport(tcp)
        let session = try ISCSISession(
            transport: transport,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.dev.soba:lio-probe-" + nonce,
                targetName: "iqn.2026-10.dev.soba:lio-" + nonce, credentials: credentials))
        do {
            try await tcp.connect()
            try await session.login()
            let lun = try LogicalUnit(0)
            let information = try await DiskProbe.diskInformation(session: session, lun: lun)
            guard information.capacity.byteCount == 8 * 1_048_576,
                information.capacity.blockSize == 512
            else { throw ProtocolError.malformed("LIO block fixture capacity") }
            let disk = RemoteDisk(
                session: session, lun: lun, capacity: information.capacity, readOnly: false)
            guard try await disk.read(offset: 0, length: 512) == Data(repeating: 0x39, count: 512)
            else { throw ProtocolError.malformed("LIO seed bytes") }
            let bytes = Data(repeating: 0x6D, count: 65_536)
            if plan.mode == "sync-error" { try await disk.write(offset: 4096, data: bytes) }
            var report: [String: Any] = [
                "mode": plan.mode, "nonce": nonce, "mutualCHAP": plan.mutualCHAP,
                "mountedFilesystem": false,
            ]
            if plan.mode == "healthy" {
                let unaligned = Data(repeating: 0x6D, count: 65_573)
                try await disk.write(offset: 4099, data: unaligned)
                try await disk.synchronize()
                let expected =
                    Data(repeating: 0x39, count: 3) + unaligned
                    + Data(repeating: 0x39, count: 66_048 - 3 - unaligned.count)
                guard try await disk.read(offset: 4096, length: expected.count) == expected,
                    await disk.connectionState() == .connected
                else { throw ProtocolError.malformed("LIO healthy readback") }
                report["readbackMatched"] = true
            } else {
                try save(
                    ["nonce": nonce, "mode": plan.mode], to: root.appending(path: "Ready.json"))
                try await waitForFault(root: root, nonce: nonce)
                do {
                    if plan.mode == "write-error" {
                        try await disk.write(offset: 4096, data: bytes)
                    } else {
                        try await disk.synchronize()
                    }
                    throw ProtocolError.malformed("LIO injected mutation reported success")
                } catch ProtocolError.scsiFailure(let status, let sense) {
                    guard status == 2 else { throw ProtocolError.malformed("LIO error status") }
                    report["status"] = status
                    report["senseHex"] = sense.map { String(format: "%02x", $0) }.joined()
                }
                guard await disk.connectionState() == .interrupted,
                    await session.state == .ready
                else { throw ProtocolError.malformed("LIO failed disk state") }
                let before = transport.commands
                try await expectBlocked { _ = try await disk.read(offset: 0, length: 512) }
                try await expectBlocked { try await disk.write(offset: 512, data: bytes) }
                try await expectBlocked { try await disk.synchronize() }
                guard transport.commands == before else {
                    throw ProtocolError.malformed("LIO I/O admitted after failure")
                }
                report["interrupted"] = true
                report["laterIOCommands"] = transport.commands - before
            }
            let closedNormally = await session.closeGracefully()
            guard closedNormally, await session.state == .closed else {
                throw ProtocolError.malformed("LIO normal Logout")
            }
            report["normalLogout"] = true
            report["scsiCommands"] = transport.commands
            report["complete"] = true
            try save(report, to: root.appending(path: "Probe.json"))
        } catch {
            await session.close()
            throw error
        }
    }

    private static func waitForFault(root: URL, nonce: String) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(45))
        let url = root.appending(path: "FaultApplied.json")
        while !FileManager.default.fileExists(atPath: url.path) {
            guard clock.now < deadline else { throw ProtocolError.timedOut }
            try await clock.sleep(for: .milliseconds(50))
        }
        let data = try Data(contentsOf: url)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            object["nonce"] as? String == nonce, object["faultApplied"] as? Bool == true
        else { throw ProtocolError.malformed("LIO fault barrier") }
    }

    private static func expectBlocked(_ operation: () async throws -> Void) async throws {
        do {
            try await operation()
            throw ProtocolError.malformed("LIO disk remained usable after failed mutation")
        } catch ProtocolError.invalidState {}
    }

    private static func save(_ object: [String: Any], to url: URL) throws {
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw ProtocolError.invalidState
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try data.write(to: url, options: .atomic)
    }
}
