import Darwin
import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork
import ISCSIPlatform
import Network

/// Invoked only by scripts/test-integration.py against its disposable in-memory target.
@main
struct IntegrationProbe {
    static func main() async {
        do { try await run() } catch {
            FileHandle.standardError.write(
                Data("Integration failed: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    static func run() async throws {
        #if DEBUG
            if CommandLine.arguments.count == 2,
                CommandLine.arguments[1] == "--volume-selectors"
            {
                try VolumeSelectorsProbe.run()
                return
            }
        #endif
        guard CommandLine.arguments.count == 3 else {
            throw ProtocolError.malformed("integration probe arguments")
        }
        if CommandLine.arguments[1] == "--lio-block-fault" {
            try await LIOBlockFaultProbe.run(
                planURL: URL(fileURLWithPath: CommandLine.arguments[2]))
            return
        }
        if CommandLine.arguments[1] == "--lio-transfer-limits" {
            try await LIOTransferLimitsProbe.run(
                planURL: URL(fileURLWithPath: CommandLine.arguments[2]))
            return
        }
        if CommandLine.arguments[1] == "--lio-write-protection" {
            try await LIOWriteProtectionProbe.run(
                planURL: URL(fileURLWithPath: CommandLine.arguments[2]))
            return
        }
        if CommandLine.arguments[1] == "--block-limits-loopback" {
            try await BlockLimitsProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        if CommandLine.arguments[1] == "--write-protection-loopback" {
            try await WriteProtectionProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        #if DEBUG
            if CommandLine.arguments[1] == "--mounted-bridge" {
                guard let url = URL(string: CommandLine.arguments[2]) else {
                    throw ProtocolError.invalidState
                }
                let descriptor = try ConnectionDescriptor(resourceURL: url)
                guard descriptor.portal.host == "127.0.0.1", let mountID = descriptor.mountID else {
                    throw ProtocolError.invalidState
                }
                let value: [String: Any] = [
                    "matched": MountedFSKitBridge.contains(descriptor),
                    "mountID": mountID.uuidString,
                    "networkIO": false,
                ]
                let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
                print("KERNEL_MOUNT_OBSERVATION " + String(decoding: data, as: UTF8.self))
                return
            }
        #endif
        if CommandLine.arguments[1] == "--transport-loopback" {
            try await validateTransport()
            return
        }
        if CommandLine.arguments[1] == "--paused-network-loopback" {
            try await NetworkPauseProbe.run(portal: CommandLine.arguments[2])
            return
        }
        #if DEBUG
            if CommandLine.arguments[1] == "--mount-completion-loopback" {
                try await MountCompletionProbe.run(portal: CommandLine.arguments[2])
                return
            }
        #endif
        if CommandLine.arguments[1] == "--redirect-loopback" {
            let discovery =
                ProcessInfo.processInfo.environment["ISCSI_TEST_REDIRECT_DISCOVERY"] == "1"
            try await RedirectProbe.run(
                portal: CommandLine.arguments[2], discovery: discovery,
                credentials: credentials(discovery: discovery))
            return
        }
        if CommandLine.arguments[1] == "--permanent-redirect-loopback" {
            let discovery =
                ProcessInfo.processInfo.environment["ISCSI_TEST_REDIRECT_DISCOVERY"] == "1"
            try await PermanentRedirectProbe.run(
                portal: CommandLine.arguments[2], discovery: discovery,
                credentials: credentials(discovery: discovery))
            return
        }
        if CommandLine.arguments[1] == "--mounted-redirect-loopback" {
            try await MountedRedirectProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        if CommandLine.arguments[1] == "--deferred-sense-loopback" {
            try await DeferredSenseProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        if CommandLine.arguments[1] == "--discovery-addresses-loopback" {
            try await DiscoveryAddressProbe.run(
                portal: CommandLine.arguments[2],
                discoveryCredentials: credentials(discovery: true), credentials: credentials())
            return
        }
        if CommandLine.arguments[1] == "--async-shutdown-loopback" {
            try await AsyncShutdownProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        if CommandLine.arguments[1] == "--full-feature-loopback" {
            try await FullFeatureProbe.run(
                portal: CommandLine.arguments[2], credentials: credentials())
            return
        }
        let discoveryTransport = try await makeTransport()
        try await validateDiscovery(transport: discoveryTransport)
        let transport = try await makeTransport()
        let configuration = try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:integration",
            targetName: "iqn.2026-10.test:memory", credentials: credentials(),
            initialCommandSequenceNumber: initialCommandSequenceNumber())
        let exerciseNOP = ProcessInfo.processInfo.environment["ISCSI_TEST_NOP"] == "1"
        let fault = ProcessInfo.processInfo.environment["ISCSI_TEST_FAULT"]
        let shortDeadline =
            fault == "silent-write-status" || fault == "nop-without-command-response"
        let session = try ISCSISession(
            transport: transport, configuration: configuration,
            commandTimeout: shortDeadline ? .seconds(1) : .seconds(30),
            heartbeatInterval: exerciseNOP ? .milliseconds(60) : .seconds(10),
            heartbeatTimeout: .seconds(1))
        try await validateDisk(
            session: session, configuration: configuration, exerciseNOP: exerciseNOP)
    }

    private static func loopbackTransport(timeout: TimeInterval = 15) throws -> TCPTransport {
        let portal = try Portal(CommandLine.arguments[2])
        guard portal.host == "127.0.0.1" else {
            throw ProtocolError.malformed("loopback required")
        }
        return try TCPTransport(portal: portal, timeout: timeout)
    }

    private static func makeTransport() async throws -> any ByteTransport {
        if CommandLine.arguments[1] == "--disposable-loopback" {
            let tcp = try loopbackTransport()
            try await tcp.connect()
            return tcp
        } else if CommandLine.arguments[1] == "--stdio-target" {
            return try ProcessTransport(scriptPath: CommandLine.arguments[2])
        } else {
            throw ProtocolError.malformed("integration probe mode")
        }
    }

    private static func validateDisk(
        session: ISCSISession, configuration: LoginConfiguration, exerciseNOP: Bool
    ) async throws {
        do {
            try await session.login()
            if exerciseNOP {
                let lostEcho =
                    ProcessInfo.processInfo.environment["ISCSI_TEST_FAULT"] == "lost-idle-echo"
                try await Task.sleep(for: lostEcho ? .milliseconds(1500) : .milliseconds(250))
            }
            if ProcessInfo.processInfo.environment["ISCSI_TEST_LUN_INSPECTION"] == "1" {
                let inspections = try await DiskProbe.inspectLogicalUnits(session: session)
                guard inspections.map(\.lun.displayIdentifier) == (0..<7).map({ String($0) }),
                    inspections[1].result == .failure(.unsupportedDevice(type: 1)),
                    inspections[2].result == .failure(.notReady),
                    inspections[3].result == .failure(.noMedia),
                    inspections[4].result == .failure(.accessRestricted),
                    inspections[5].result == .failure(.invalidInformation)
                else { throw ProtocolError.malformed("independent mixed LUN inspection") }
                for index in [0, 6] {
                    let information = try inspections[index].result.get()
                    guard information.capacity.byteCount == 65_536,
                        information.device.displayName == "SobaDev RAM Disk"
                    else { throw ProtocolError.malformed("independent usable LUN information") }
                }
                try await session.logout()
                print("PASS: mixed LUN results, usable disks preserved, no block I/O")
                return
            }
            let units = try await DiskProbe.logicalUnits(session: session)
            guard units.count == 1, let reported = units.first else {
                throw ProtocolError.malformed("independent LUN enumeration")
            }
            let descriptor = try ConnectionDescriptor(
                profileID: UUID(), portal: Portal("127.0.0.1"),
                initiatorName: configuration.initiatorName, targetName: "iqn.2026-10.test:memory",
                lun: reported, readOnly: false, isid: configuration.isid)
            let lun = try ConnectionDescriptor(resourceURL: descriptor.resourceURL).lun
            let information = try await DiskProbe.diskInformation(session: session, lun: lun)
            let headerOnly =
                ProcessInfo.processInfo.environment["ISCSI_TEST_FAULT"] == "inquiry-header-only"
            guard information.device.displayName == (headerOnly ? "" : "SobaDev RAM Disk") else {
                throw ProtocolError.malformed("independent INQUIRY information")
            }
            let capacity = information.capacity
            guard
                let baseLBA = UInt64(
                    ProcessInfo.processInfo.environment["ISCSI_TEST_BASE_LBA"] ?? "0")
            else { throw ProtocolError.malformed("integration base LBA") }
            let (baseBytes, overflow) = baseLBA.multipliedReportingOverflow(
                by: UInt64(capacity.blockSize))
            guard !overflow, let base = Int64(exactly: baseBytes),
                capacity.byteCount >= 4096, baseBytes <= capacity.byteCount - 4096
            else { throw ProtocolError.malformed("integration base offset") }
            let disk = RemoteDisk(session: session, lun: lun, capacity: capacity, readOnly: false)
            if let operation = ProcessInfo.processInfo.environment["ISCSI_TEST_MUTATION_RETIREMENT"]
            {
                try await MutationFailureProbe.run(
                    disk: disk, session: session, operation: operation)
                return
            }
            if ProcessInfo.processInfo.environment["ISCSI_TEST_IMAGE_IO"] == "1" {
                try await validateLargeImageWrite(disk: disk)
                try await session.logout()
                print(
                    "PASS: FSKit volume large write, complete readback, unchanged neighbors, flush")
                return
            }
            let before = try await disk.read(offset: base, length: 4096)
            let replacement = Data((0..<1537).map { UInt8(truncatingIfNeeded: $0 * 7) })
            try await disk.write(offset: base + 511, data: replacement)
            let after = try await disk.read(offset: base, length: 4096)
            guard after.prefix(511) == before.prefix(511),
                Data(after[511..<2048]) == replacement,
                after.suffix(2048) == before.suffix(2048)
            else { throw ProtocolError.malformed("partial-sector write verification") }
            // Two disjoint updates in one sector must survive read-modify-write suspension.
            async let first: Void = disk.write(
                offset: base + 64, data: Data(repeating: 0xCC, count: 33))
            async let second: Void = disk.write(
                offset: base + 128, data: Data(repeating: 0xDD, count: 65))
            _ = try await (first, second)
            let concurrent = try await disk.read(offset: base, length: 512)
            var expected = Data(after.prefix(512))
            expected.replaceSubrange(64..<97, with: repeatElement(UInt8(0xCC), count: 33))
            expected.replaceSubrange(128..<193, with: repeatElement(UInt8(0xDD), count: 65))
            guard concurrent == expected else {
                throw ProtocolError.malformed("concurrent sector update")
            }
            try await disk.synchronize()
            try await session.logout()
            print(
                "PASS: login, INQUIRY, capacity, segmented read, R2T bursts, concurrent partial writes, flush, logout"
            )
        } catch {
            await session.close()
            throw error
        }
    }

    private static func validateLargeImageWrite(disk: RemoteDisk) async throws {
        let volume = LUNImageVolume(disk: disk, identifier: UUID())
        let (item, _) = try await (volume as any FSVolume.Operations).lookupItem(
            named: FSFileName(string: LUNImageVolume.imageName),
            inDirectory: volume.rootItem)
        let start: Int64 = 511
        let count = 16_777_217
        let tile = Data((0..<256).map { UInt8(truncatingIfNeeded: $0 * 7 + 11) })
        var contents = Data()
        contents.reserveCapacity(count)
        for _ in 0..<(count / tile.count) { contents.append(tile) }
        contents.append(tile.prefix(count % tile.count))
        guard try await volume.write(contents: contents, to: item, at: start) == count else {
            throw ProtocolError.malformed("large image write count")
        }
        // Read back every byte through the real RemoteDisk and session, not a memory ImageDisk.
        var cursor = 0
        while cursor < count {
            let size = min(1_048_576, count - cursor)
            let data = try await disk.read(offset: start + Int64(cursor), length: size)
            guard data == contents[cursor..<(cursor + size)] else {
                throw ProtocolError.malformed("large image write readback")
            }
            cursor += size
        }
        let prefix = try await disk.read(offset: 0, length: Int(start))
        let end = start + Int64(count)
        let suffix = try await disk.read(offset: end, length: 512)
        let expectedPrefix = Data((0..<Int(start)).map { UInt8(truncatingIfNeeded: $0 * 3) })
        let expectedSuffix = Data((0..<512).map { UInt8(truncatingIfNeeded: (Int(end) + $0) * 3) })
        guard prefix == expectedPrefix, suffix == expectedSuffix else {
            throw ProtocolError.malformed("large image write neighbors")
        }
        try await volume.synchronize(flags: .wait)
    }

    private static func credentials(discovery: Bool = false) throws -> CHAPCredentials? {
        let environment = ProcessInfo.processInfo.environment
        let chap = environment["ISCSI_TEST_CHAP"] == "1"
        let mutual = environment["ISCSI_TEST_MUTUAL_CHAP"] == "1"
        let search: DiscoveryAuthentication
        switch environment["ISCSI_TEST_DISCOVERY_AUTH"] {
        case nil: search = .sameAsConnection
        case "none": search = .none
        case "chap", "mutual":
            search = .chap(
                try CHAPIdentity(
                    username: "search-user",
                    targetUsername: environment["ISCSI_TEST_DISCOVERY_AUTH"] == "mutual"
                        ? "search-server" : nil))
        default: throw ProtocolError.malformed("discovery authentication fixture")
        }
        let server = try ServerProfile(
            name: "RAM fixture", portal: Portal("127.0.0.1"),
            chapUsername: chap ? "test-user" : nil,
            targetCHAPUsername: mutual ? "test-server" : nil, discoveryAuthentication: search)
        let context = discovery ? server.discoveryCredentialContext : server.credentialContext
        guard let context else { return nil }
        let separate = context.use == .discovery
        return try CHAPCredentials(
            username: context.username,
            password: separate ? "independent discovery password" : "correct horse battery staple",
            targetUsername: context.targetUsername,
            targetPassword: context.targetUsername == nil
                ? nil
                : separate ? "independent discovery server password" : "independent server password"
        )
    }

    private static func initialCommandSequenceNumber() throws -> UInt32 {
        guard let value = ProcessInfo.processInfo.environment["ISCSI_TEST_INITIAL_CMDSN"] else {
            return 1
        }
        guard let number = UInt32(value) else {
            throw ProtocolError.malformed("integration initial command number")
        }
        return number
    }

    private static func validateDiscovery(transport: any ByteTransport) async throws {
        let configuration = try LoginConfiguration(
            initiatorName: "iqn.2026-10.test:discovery", credentials: credentials(discovery: true),
            initialCommandSequenceNumber: initialCommandSequenceNumber())
        let session = try ISCSISession(transport: transport, configuration: configuration)
        do {
            try await session.login()
            let targets = try await session.discover()
            guard targets.map(\.name) == ["iqn.2026-10.test:memory"] else {
                throw ProtocolError.malformed("independent discovery result")
            }
            try await session.logout()
        } catch {
            await session.close()
            throw error
        }
    }

    private static func validateTransport() async throws {
        let transport = try loopbackTransport(timeout: 0.1)
        do {
            try await transport.connect()
            try await transport.send(Data([0xA1]))
            switch ProcessInfo.processInfo.environment["ISCSI_TEST_TRANSPORT"] {
            case "receive-timeout":
                do {
                    _ = try await transport.receive(maximumLength: 1)
                    throw ProtocolError.malformed("receive did not time out")
                } catch ProtocolError.timedOut {}
            case "idle-receive":
                let data = try await transport.receive(maximumLength: 1, waitingForActivity: true)
                guard data == Data([0xB2]) else {
                    throw ProtocolError.malformed("idle receive data")
                }
            case "cancel-receive":
                let pending = Task {
                    try await transport.receive(maximumLength: 1, waitingForActivity: true)
                }
                try await Task.sleep(for: .milliseconds(50))
                pending.cancel()
                do {
                    _ = try await pending.value
                    throw ProtocolError.malformed("cancelled receive succeeded")
                } catch is CancellationError {}
            case "close-receive":
                let pending = Task {
                    try await transport.receive(maximumLength: 1, waitingForActivity: true)
                }
                try await Task.sleep(for: .milliseconds(50))
                await transport.close()
                do {
                    _ = try await pending.value
                    throw ProtocolError.malformed("closed receive succeeded")
                } catch ProtocolError.connectionClosed {
                } catch NWError.posix(.ECANCELED) {}
            default:
                throw ProtocolError.malformed("transport check")
            }
            await transport.close()
        } catch {
            await transport.close()
            throw error
        }
    }
}
