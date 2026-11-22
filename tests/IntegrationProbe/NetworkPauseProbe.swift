import Foundation
import ISCSICore
import ISCSINetwork

/// Only a disposable loopback peer may pause this probe; no mounted disk is involved.
enum NetworkPauseProbe {
    static func run(portal: String) async throws {
        let portal = try Portal(portal)
        let environment = ProcessInfo.processInfo.environment
        guard portal.host == "127.0.0.1", portal.port > 1024,
            let mode = environment["ISCSI_TEST_PAUSED_NETWORK_MODE"],
            ["read-control", "read-expired", "write-control", "write-expired"].contains(mode),
            let token = environment["ISCSI_TEST_PAUSED_NETWORK_NONCE"],
            let nonce = UUID(uuidString: token), nonce.uuidString.lowercased() == token
        else { throw ProtocolError.malformed("private network pause fixture") }
        let writing = mode.hasPrefix("write-")
        let expired = mode.hasSuffix("-expired")
        var payload = Data("Network pause validation \(token)\n".utf8)
        payload.append(Data(repeating: 0xB6, count: 2048 - payload.count))
        let transport = try TCPTransport(portal: portal, timeout: 10)
        let session = try ISCSISession(
            transport: transport,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:pause-\(token)",
                targetName: "iqn.2026-10.test:memory"),
            commandTimeout: .seconds(2), heartbeatInterval: .seconds(300))
        do {
            try await transport.connect()
            try await session.login()
            let clock = ContinuousClock()
            let started = clock.now
            let outcome: String
            do {
                let result = try await session.execute(
                    writing
                        ? .write10(lba: 2, blocks: 4, blockSize: 512)
                        : .read10(lba: 2, blocks: 4, blockSize: 512),
                    lun: LogicalUnit(0), output: writing ? payload : Data())
                guard !expired else {
                    throw ProtocolError.malformed("paused operation accepted an expired response")
                }
                if !writing {
                    guard
                        result.data
                            == Data((1024..<3072).map { UInt8(truncatingIfNeeded: $0 * 3) })
                    else { throw ProtocolError.malformed("paused read contents") }
                }
                outcome = "success"
            } catch let error as ProtocolError {
                guard expired, error == .timedOut else { throw error }
                outcome = "timedOut"
            }
            let elapsed = started.duration(to: clock.now).components
            let elapsedSeconds = Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
            var followupRejected = false
            let stateAfterOperation = String(describing: await session.state)
            if expired {
                guard await session.state == .failed else {
                    throw ProtocolError.malformed("paused timeout did not fail the session")
                }
                do {
                    _ = try await session.execute(.synchronizeCache10(), lun: LogicalUnit(0))
                    throw ProtocolError.malformed("paused session admitted followup I/O")
                } catch let error as ProtocolError {
                    guard error == .invalidState else { throw error }
                    followupRejected = true
                }
            } else if writing {
                _ = try await session.execute(.synchronizeCache10(), lun: LogicalUnit(0))
                let read = try await session.execute(
                    .read10(lba: 2, blocks: 4, blockSize: 512), lun: LogicalUnit(0))
                guard read.data == payload else {
                    throw ProtocolError.malformed("paused control write readback")
                }
            }
            let graceful = await session.closeGracefully()
            guard graceful == !expired, await session.state == .closed else {
                throw ProtocolError.malformed("paused session termination")
            }
            let report: [String: Any] = [
                "mode": mode, "nonce": token, "outcome": outcome,
                "commandDeadlineSeconds": 2, "transportDeadlineSeconds": 10,
                "operationElapsedSeconds": elapsedSeconds,
                "stateAfterOperation": stateAfterOperation,
                "followupRejected": followupRejected, "gracefulLogout": graceful,
                "finalState": String(describing: await session.state),
                "realNetworkFramework": true, "injectedClock": false,
                "macSystemSleepTest": false,
            ]
            print(
                "NETWORK_PAUSE_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: report, options: .sortedKeys), as: UTF8.self))
        } catch {
            await session.close()
            throw error
        }
    }
}
