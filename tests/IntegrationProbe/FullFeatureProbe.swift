import Foundation
import ISCSICore
import ISCSINetwork

enum FullFeatureProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let portal = try Portal(portal)
        guard portal.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let environment = ProcessInfo.processInfo.environment
        let mode = environment["ISCSI_TEST_TEXT_MODE"] ?? "idle"
        let negative = environment["ISCSI_TEST_TEXT_NEGATIVE"] == "1"
        let transport = try TCPTransport(portal: portal)
        let session = try ISCSISession(
            transport: transport,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:text-probe",
                targetName: "iqn.2026-10.test:memory", credentials: credentials),
            commandTimeout: .seconds(2))
        try await transport.connect()
        try await session.login()
        if mode != "write" && mode != "read" && !negative {
            try await Task.sleep(for: .milliseconds(50))
        }
        var rejected = false
        do {
            if mode == "write" {
                _ = try await session.execute(
                    SCSICommand.write10(lba: 0, blocks: 48, blockSize: 512), lun: LogicalUnit(0),
                    output: Data(repeating: 7, count: 24_576))
            } else {
                let read = try await session.execute(
                    SCSICommand.read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0))
                guard read.data == Data((0..<512).map { UInt8(truncatingIfNeeded: $0 * 3) }) else {
                    throw ProtocolError.malformed("Text fixture read contents")
                }
            }
            guard !negative else { throw ProtocolError.invalidState }
            _ = try await session.execute(.synchronizeCache10(), lun: LogicalUnit(0))
        } catch let error as ProtocolError {
            guard negative else { throw error }
            switch error {
            case .malformed, .limitExceeded, .timedOut: rejected = true
            default: throw error
            }
        }
        let graceful = await session.closeGracefully()
        guard negative ? (rejected && !graceful) : graceful else {
            throw ProtocolError.malformed("Text fixture shutdown")
        }
        print(
            "TEXT_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: ["mode": mode, "rejected": rejected, "graceful": graceful],
                        options: .sortedKeys), as: UTF8.self))
    }
}
