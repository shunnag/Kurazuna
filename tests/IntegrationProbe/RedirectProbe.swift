import Foundation
import ISCSICore
import ISCSINetwork

enum RedirectProbe {
    static func run(portal: String, discovery: Bool, credentials: CHAPCredentials?) async throws {
        let portal = try Portal(portal)
        guard portal.host == "127.0.0.1" else {
            throw ProtocolError.malformed("redirect loopback fixture")
        }
        let seconds = Int(ProcessInfo.processInfo.environment["ISCSI_TEST_REDIRECT_TIMEOUT"] ?? "5")
        guard let seconds, (1...10).contains(seconds) else { throw ProtocolError.invalidState }
        let configuration = try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:integration",
            targetName: discovery ? nil : "iqn.2026-10.test:memory", credentials: credentials)
        let result = try await SessionConnector.connect(
            portal: portal, configuration: configuration, timeout: .seconds(seconds))
        do {
            if discovery {
                let targets = try await result.session.discover()
                guard targets.contains(where: { $0.name == "iqn.2026-10.test:memory" }) else {
                    throw ProtocolError.malformed("redirect discovery result")
                }
            } else {
                let lun = try LogicalUnit(0)
                let information = try await DiskProbe.diskInformation(
                    session: result.session, lun: lun)
                guard information.capacity.byteCount == 65_536 else {
                    throw ProtocolError.malformed("redirect fixture capacity")
                }
                let disk = RemoteDisk(
                    session: result.session, lun: lun,
                    capacity: information.capacity, readOnly: false)
                let written = Data((0..<4129).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
                try await disk.write(offset: 509, data: written)
                try await disk.synchronize()
                guard try await disk.read(offset: 509, length: written.count) == written,
                    try await disk.read(offset: 0, length: 509)
                        == Data((0..<509).map { UInt8(truncatingIfNeeded: $0 * 3) }),
                    try await disk.read(offset: 4638, length: 31)
                        == Data((4638..<4669).map { UInt8(truncatingIfNeeded: $0 * 3) })
                else { throw ProtocolError.malformed("redirect fixture contents") }
            }
            try await result.session.logout()
        } catch {
            await result.session.close()
            throw error
        }
        let report: [String: Any] = [
            "portal": result.portal.description,
            "redirects": result.redirects.count, "discovery": discovery,
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: .sortedKeys)
        print("REDIRECT_RESULT " + String(decoding: data, as: UTF8.self))
    }
}
