import Foundation
import ISCSICore
import ISCSINetwork

enum AsyncShutdownProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let portal = try Portal(portal)
        guard portal.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let mode = ProcessInfo.processInfo.environment["ISCSI_TEST_ASYNC_MODE"] ?? "idle"
        let transport = try TCPTransport(portal: portal)
        let session = try ISCSISession(
            transport: transport,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:async-probe",
                targetName: "iqn.2026-10.test:memory", credentials: credentials),
            commandTimeout: .seconds(2))
        try await transport.connect()
        try await session.login()
        var operationSucceeded = false
        if mode == "logout" {
            try await session.logout()
            operationSucceeded = true
        } else if [
            "read", "write", "drop", "session-drop", "scsi-event", "invalid-flags", "invalid-tag",
            "renegotiation", "fast-abort",
        ].contains(mode) {
            do {
                if mode == "write" {
                    _ = try await session.execute(
                        SCSICommand.write10(lba: 0, blocks: 4, blockSize: 512),
                        lun: LogicalUnit(0), output: Data(repeating: 7, count: 2048))
                } else {
                    _ = try await session.execute(
                        SCSICommand.read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0))
                }
                throw ProtocolError.malformed("async operation unexpectedly succeeded")
            } catch let error as ProtocolError {
                let expected: ProtocolError
                switch mode {
                case "drop": expected = .targetEvent(2)
                case "session-drop": expected = .targetEvent(3)
                case "scsi-event": expected = .targetEvent(0)
                case "invalid-flags", "invalid-tag":
                    expected = .malformed("asynchronous message header")
                case "renegotiation": expected = .targetEvent(1)
                case "fast-abort": expected = .unsupported("asynchronous event")
                default: expected = .targetEvent(1)
                }
                guard error == expected else { throw error }
            }
        } else if ["vendor", "other-cid"].contains(mode) {
            let read = try await session.execute(
                SCSICommand.read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0))
            guard read.data == Data((0..<512).map { UInt8(truncatingIfNeeded: $0 * 3) }) else {
                throw ProtocolError.malformed("async control fixture read")
            }
            try await session.logout()
            operationSucceeded = true
        } else {
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while await session.state == .ready {
                guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                try await Task.sleep(for: .milliseconds(1))
            }
        }
        let graceful = await session.closeGracefully()
        let expected = [
            "idle", "read", "write", "ping", "zero", "reserved", "reserved-ping", "renegotiation",
        ]
        .contains(mode)
        if mode != "logout", !["vendor", "other-cid"].contains(mode), graceful != expected {
            throw ProtocolError.malformed("asynchronous Logout outcome")
        }
        let report: [String: Any] = [
            "mode": mode, "graceful": graceful,
            "operationSucceeded": operationSucceeded,
            "state": String(describing: await session.state),
        ]
        print(
            "ASYNC_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: report, options: .sortedKeys), as: UTF8.self))
        await session.close()
    }
}
