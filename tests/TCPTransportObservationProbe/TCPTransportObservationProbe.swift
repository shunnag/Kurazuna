import Darwin
import Foundation
import ISCSICore
@_spi(Validation) import ISCSINetwork

private struct Plan: Decodable {
    let nonce: UUID
    let port: UInt16
}

private enum ProbeError: Error {
    case plan, unexpectedEndpoint, cancellation, reply, closeDeadline
}

/// Own loopback server only; no iSCSI, filesystem, credentials or app operations.
@main
struct TCPTransportObservationProbe {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 2 else { throw ProbeError.plan }
            let file = try FileHandle(
                forReadingFrom: URL(fileURLWithPath: CommandLine.arguments[1]))
            defer { try? file.close() }
            let data = try file.read(upToCount: 1025) ?? Data()
            guard data.count <= 1024, (try file.read(upToCount: 1) ?? Data()).isEmpty else {
                throw ProbeError.plan
            }
            let plan = try JSONDecoder().decode(Plan.self, from: data)
            guard plan.port != 0 else { throw ProbeError.plan }
            try await run(plan)
        } catch {
            try? emit(["stage": "failed", "failureDomain": String(reflecting: type(of: error))])
            exit(1)
        }
    }

    private static func run(_ plan: Plan) async throws {
        let transport = try TCPTransport(
            portal: Portal("127.0.0.1:\(plan.port)"), timeout: 15, waitForConnectivity: false)
        defer { withExtendedLifetime(transport) {} }
        do {
            do {
                _ = try await transport.validationIPv4Endpoints()
                throw ProbeError.unexpectedEndpoint
            } catch TCPConnectionObservationError.unavailable {}
            try await transport.connect()
            let first = try await transport.validationIPv4Endpoints()
            guard first.localAddress == Data([127, 0, 0, 1]),
                first.remoteAddress == Data([127, 0, 0, 1]), first.remotePort == plan.port
            else { throw ProbeError.unexpectedEndpoint }

            let cancelled = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                return try await transport.validationIPv4Endpoints()
            }
            do {
                _ = try await cancelled.value
                throw ProbeError.cancellation
            } catch is CancellationError {}

            let nonce = plan.nonce.uuidString
            try await transport.send(Data(nonce.utf8))
            try await receive(Data("first:\(nonce)".utf8), from: transport)
            guard try await transport.validationIPv4Endpoints() == first else {
                throw ProbeError.unexpectedEndpoint
            }
            try emit([
                "stage": "ready", "nonce": nonce, "PID": Int(getpid()),
                "cancelledObservationDidNotCloseTransport": true,
                "localAddress": "127.0.0.1", "localPort": first.localPort,
                "remoteAddress": "127.0.0.1", "remotePort": first.remotePort,
            ])

            try await receive(Data("release:\(nonce)".utf8), from: transport)
            guard try await transport.validationIPv4Endpoints() == first else {
                throw ProbeError.unexpectedEndpoint
            }
            try emit(["stage": "rechecked", "nonce": nonce, "PID": Int(getpid())])
            await transport.close()
            let deadline = ContinuousClock.now.advanced(by: .seconds(2))
            while true {
                do {
                    _ = try await transport.validationIPv4Endpoints()
                } catch TCPConnectionObservationError.unavailable { break }
                guard ContinuousClock.now < deadline else { throw ProbeError.closeDeadline }
                try await Task.sleep(for: .milliseconds(10))
            }
            try emit([
                "stage": "complete", "nonce": nonce, "PID": Int(getpid()),
                "normalTCPClosureProven": false, "VMStarts": 0,
            ])
        } catch {
            await transport.close()
            throw error
        }
    }

    private static func receive(_ expected: Data, from transport: TCPTransport) async throws {
        var result = Data()
        while result.count < expected.count {
            result.append(try await transport.receive(maximumLength: expected.count - result.count))
        }
        guard result == expected else { throw ProbeError.reply }
    }

    private static func emit(_ value: [String: Any]) throws {
        var data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        data.append(10)
        try FileHandle.standardOutput.write(contentsOf: data)
    }
}
