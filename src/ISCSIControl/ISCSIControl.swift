import Darwin
import Foundation
import ISCSICore
import ISCSINetwork

@main
struct ISCSIControl {
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments.isEmpty || arguments == ["--help"] {
                print(
                    """
                    Usage:
                      iscsi discover <server[:port]>
                      iscsi info <server[:port]> <target-name> [lun]

                    IPv6: enclose the address in brackets, for example [::1]:3260.
                    Set ISCSI_INITIATOR_NAME to use a persistent initiator name.
                    These commands do not write to the remote disk.
                    """)
                return
            }
            guard
                (arguments[0] == "discover" && arguments.count == 2)
                    || (arguments[0] == "info" && (3...4).contains(arguments.count))
            else { throw ProtocolError.malformed("command arguments; use --help") }
            let portal = try Portal(arguments[1])
            let initiator =
                ProcessInfo.processInfo.environment["ISCSI_INITIATOR_NAME"]
                ?? "iqn.2026-10.dev.soba:\(UUID().uuidString.lowercased())"
            let configuration = try LoginConfiguration(
                initiatorName: initiator, targetName: arguments[0] == "info" ? arguments[2] : nil)
            let connection = try await SessionConnector.connect(
                portal: portal, configuration: configuration)
            let session = connection.session
            do {
                if arguments[0] == "discover" {
                    let targets = try await session.discover()
                    for target in targets {
                        print(target.name)
                        for address in target.addresses { print("  \(address)") }
                    }
                    if targets.isEmpty { print("No disks found.") }
                } else {
                    let number: UInt16
                    if arguments.count == 4 {
                        guard let parsed = UInt16(arguments[3]) else {
                            throw ProtocolError.malformed("logical unit number")
                        }
                        number = parsed
                    } else {
                        number = 0
                    }
                    let lun = try LogicalUnit(number)
                    let information = try await DiskProbe.diskInformation(
                        session: session, lun: lun)
                    let capacity = information.capacity
                    print("Target: \(arguments[2])")
                    print("Logical unit: \(number)")
                    if !information.device.displayName.isEmpty {
                        print("Device: \(information.device.displayName)")
                    }
                    print("Capacity: \(capacity.byteCount) bytes")
                    print("Block size: \(capacity.blockSize) bytes")
                }
                try await session.logout()
            } catch {
                await session.closeGracefully()
                throw error
            }
        } catch {
            FileHandle.standardError.write(Data("iscsi: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
