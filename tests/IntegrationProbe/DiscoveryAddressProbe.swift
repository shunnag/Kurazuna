import Foundation
import ISCSICore
import ISCSINetwork

enum DiscoveryAddressProbe {
    static func run(
        portal: String, discoveryCredentials: CHAPCredentials?, credentials: CHAPCredentials?
    ) async throws {
        let initial = try Portal(portal)
        guard initial.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let discovery = try await SessionConnector.connect(
            portal: initial,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:address-probe", credentials: discoveryCredentials),
            timeout: .seconds(5))
        let target: DiscoveredTarget
        do {
            let targets = try await discovery.session.discover()
            guard targets.count == 1, let first = targets.first,
                first.name == "iqn.2026-10.test:memory"
            else {
                throw ProtocolError.malformed("discovery address fixture")
            }
            target = first
            try await discovery.session.logout()
        } catch {
            await discovery.session.close()
            throw error
        }
        let addresses = try target.connectionAddresses(fallback: discovery.portal)
        guard addresses.allSatisfy({ ["127.0.0.1", "::1"].contains($0.portal.host) }) else {
            throw ProtocolError.malformed("private discovery fixture addresses")
        }
        let normal = try await SessionConnector.connect(
            addresses: addresses,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:address-probe",
                targetName: target.name, credentials: credentials), timeout: .seconds(5))
        let group = await normal.session.targetPortalGroupTag
        do {
            let lun = try LogicalUnit(0)
            let information = try await DiskProbe.diskInformation(session: normal.session, lun: lun)
            guard information.capacity.byteCount == 65_536 else { throw ProtocolError.invalidState }
            let disk = RemoteDisk(
                session: normal.session, lun: lun, capacity: information.capacity, readOnly: false)
            let data = Data((0..<4129).map { UInt8(truncatingIfNeeded: $0 * 7 + 91) })
            try await disk.write(offset: 509, data: data)
            try await disk.synchronize()
            var expected = Data((0..<65_536).map { UInt8(truncatingIfNeeded: $0 * 3) })
            expected.replaceSubrange(509..<4638, with: data)
            guard try await disk.read(offset: 0, length: expected.count) == expected else {
                throw ProtocolError.malformed("discovery fixture full contents")
            }
            try await normal.session.logout()
        } catch {
            await normal.session.close()
            throw error
        }
        let report: [String: Any] = [
            "discoveryPortal": discovery.portal.description,
            "normalPortal": normal.portal.description,
            "portalGroup": group.map { Int($0) } as Any? ?? NSNull(),
        ]
        print(
            "DISCOVERY_ADDRESS_RESULT "
                + String(
                    decoding: try JSONSerialization.data(
                        withJSONObject: report, options: .sortedKeys), as: UTF8.self))
    }
}
