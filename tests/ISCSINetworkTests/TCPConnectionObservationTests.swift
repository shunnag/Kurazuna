import Foundation
import ISCSICore
import Network
import Testing

@_spi(Validation) @testable import ISCSINetwork

@Test func numericConnectionEndpointsPreserveBothActualAddressesAndPorts() throws {
    let pair = try #require(
        TCPIPv4EndpointPair(
            local: .hostPort(host: "192.0.2.101", port: 49_321),
            remote: .hostPort(host: "192.0.2.29", port: 3260)))
    #expect(pair.localAddress == Data([192, 0, 2, 101]))
    #expect(pair.localPort == 49_321)
    #expect(pair.remoteAddress == Data([192, 0, 2, 29]))
    #expect(pair.remotePort == 3260)
}

@Test func incompleteOrUnsupportedEndpointsCannotSupplyConnectionIdentity() {
    let valid = NWEndpoint.hostPort(host: "127.0.0.1", port: 3260)
    let invalid: [NWEndpoint?] = [
        nil,
        .hostPort(host: "example.invalid", port: 3260),
        .hostPort(host: "::1", port: 3260),
        .hostPort(host: "0.0.0.0", port: 3260),
        .hostPort(host: "127.0.0.1", port: .any),
        .unix(path: "/validation-only"),
    ]
    for endpoint in invalid {
        #expect(TCPIPv4EndpointPair(local: endpoint, remote: valid) == nil)
        #expect(TCPIPv4EndpointPair(local: valid, remote: endpoint) == nil)
    }
}

@Test func anUnstartedTransportHasNoObservedReadyConnection() async throws {
    let transport = try TCPTransport(portal: Portal("127.0.0.1:3260"))
    await #expect(throws: TCPConnectionObservationError.unavailable) {
        try await transport.validationIPv4Endpoints()
    }
    await transport.close()
}

@Test func cancellingAnObservationDoesNotInventAnEndpoint() async throws {
    let transport = try TCPTransport(portal: Portal("127.0.0.1:3260"))
    let observation = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await transport.validationIPv4Endpoints()
    }
    await #expect(throws: CancellationError.self) { try await observation.value }
    await #expect(throws: TCPConnectionObservationError.unavailable) {
        try await transport.validationIPv4Endpoints()
    }
    await transport.close()
}
