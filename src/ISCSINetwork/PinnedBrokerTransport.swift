import CryptoKit
import Foundation
import ISCSICore
import Network
import Security

@_spi(Validation)
public struct BrokerTLSNegotiation: Sendable {
    public let protocolVersion: UInt16
    public let cipherSuite: UInt16
    public let applicationProtocol: String
    public let leafPinVerified: Bool
}

/// One local helper's out-of-band TLS identity. It supplies no storage ownership authority.
public struct BrokerTLSIdentity: Sendable {
    public let serverName: String
    public let leafCertificateSHA256: Data

    public init(serverName: String, leafCertificateSHA256: Data) throws {
        let labels = serverName.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...253).contains(serverName.utf8.count), leafCertificateSHA256.count == 32,
            labels.allSatisfy({ label in
                (1...63).contains(label.utf8.count)
                    && label.utf8.allSatisfy({
                        $0 == 45 || (48...57).contains($0) || (97...122).contains($0)
                    })
                    && label.first != "-" && label.last != "-"
            })
        else { throw ProtocolError.malformed("broker TLS identity") }
        self.serverName = serverName
        self.leafCertificateSHA256 = leafCertificateSHA256
    }
}

/// Authenticated TLS 1.3 stream to an explicitly selected loopback helper. No instance is
/// published before the exact leaf, SSL name/validity policy, cipher and ALPN are verified.
/// Client role/case authentication belongs to the broker protocol, after this handshake.
public final class PinnedBrokerTransport: SendAdmissionTransport, Sendable {
    public static let applicationProtocol = "soba-iscsi-broker/1"
    private let transport: TCPTransport
    private let negotiation: BrokerTLSNegotiation

    private init(_ transport: TCPTransport, negotiation: BrokerTLSNegotiation) {
        self.transport = transport
        self.negotiation = negotiation
    }

    @_spi(Validation)
    public var validationNegotiation: BrokerTLSNegotiation { negotiation }

    @_spi(Validation)
    public func validationCancellationObserved() async -> Bool {
        await transport.cancellationObserved()
    }

    public static func open(
        portal: Portal, identity: BrokerTLSIdentity, timeout: TimeInterval
    ) async throws -> PinnedBrokerTransport {
        try await open(
            portal: portal, identity: identity, timeout: timeout, failedCancellation: nil)
    }

    @_spi(Validation)
    public static func validationOpen(
        portal: Portal, identity: BrokerTLSIdentity, timeout: TimeInterval,
        failedCancellation: @escaping @Sendable (Bool) -> Void
    ) async throws -> PinnedBrokerTransport {
        try await open(
            portal: portal, identity: identity, timeout: timeout,
            failedCancellation: failedCancellation)
    }

    private static func open(
        portal: Portal, identity: BrokerTLSIdentity, timeout: TimeInterval,
        failedCancellation: (@Sendable (Bool) -> Void)?
    ) async throws -> PinnedBrokerTransport {
        guard portal.host == "127.0.0.1" else {
            throw ProtocolError.unsupported("non-loopback broker")
        }
        try Task.checkCancellation()
        let verification = BrokerPinVerification()
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_append_tls_ciphersuite(options, .AES_128_GCM_SHA256)
        sec_protocol_options_add_tls_application_protocol(options, applicationProtocol)
        sec_protocol_options_set_tls_server_name(options, identity.serverName)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_false_start_enabled(options, false)
        sec_protocol_options_set_verify_block(
            options,
            { _, trust, complete in
                let reference = sec_trust_copy_ref(trust).takeRetainedValue()
                guard let chain = SecTrustCopyCertificateChain(reference) as? [SecCertificate],
                    let leaf = chain.first,
                    Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data))
                        == identity.leafCertificateSHA256,
                    SecTrustSetAnchorCertificates(reference, [leaf] as CFArray) == errSecSuccess,
                    SecTrustSetAnchorCertificatesOnly(reference, true) == errSecSuccess,
                    SecTrustSetPolicies(
                        reference, SecPolicyCreateSSL(true, identity.serverName as CFString))
                        == errSecSuccess,
                    SecTrustSetNetworkFetchAllowed(reference, false) == errSecSuccess
                else {
                    verification.record(false)
                    complete(false)
                    return
                }
                let valid = SecTrustEvaluateWithError(reference, nil)
                verification.record(valid)
                complete(valid)
            }, DispatchQueue(label: "dev.soba.iscsi.broker-pin"))
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let transport = try TCPTransport(
            portal: portal, timeout: timeout, parameters: NWParameters(tls: tls, tcp: tcp),
            readyCheck: { connection in
                guard verification.verified,
                    let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                        as? NWProtocolTLS.Metadata,
                    sec_protocol_metadata_get_negotiated_tls_protocol_version(
                        metadata.securityProtocolMetadata) == .TLSv13,
                    sec_protocol_metadata_get_negotiated_tls_ciphersuite(
                        metadata.securityProtocolMetadata) == .AES_128_GCM_SHA256
                else { throw ProtocolError.malformed("broker TLS handshake") }
                let name = sec_protocol_metadata_copy_negotiated_protocol(
                    metadata.securityProtocolMetadata)
                defer { free(UnsafeMutableRawPointer(mutating: name)) }
                guard name.map({ String(cString: $0) == applicationProtocol }) == true else {
                    throw ProtocolError.malformed("broker TLS application protocol")
                }
                verification.recordNegotiation(
                    BrokerTLSNegotiation(
                        protocolVersion: UInt16(
                            sec_protocol_metadata_get_negotiated_tls_protocol_version(
                                metadata.securityProtocolMetadata
                            ).rawValue),
                        cipherSuite: UInt16(
                            sec_protocol_metadata_get_negotiated_tls_ciphersuite(
                                metadata.securityProtocolMetadata
                            ).rawValue),
                        applicationProtocol: String(cString: name!),
                        leafPinVerified: verification.verified))
            })
        do {
            try await transport.connect()
            try Task.checkCancellation()
            guard let negotiation = verification.negotiation else {
                throw ProtocolError.invalidState
            }
            return PinnedBrokerTransport(transport, negotiation: negotiation)
        } catch {
            await transport.close()
            if let failedCancellation {
                let deadline = ContinuousClock.now.advanced(by: .seconds(2))
                var observed = false
                while ContinuousClock.now < deadline {
                    if await transport.cancellationObserved() {
                        observed = true
                        break
                    }
                    // This diagnostic also observes cancellation when the caller is cancelled.
                    await Task.detached { try? await Task.sleep(for: .milliseconds(5)) }.value
                }
                failedCancellation(observed)
            }
            throw error
        }
    }

    public func send(_ data: Data) async throws { try await transport.send(data) }
    public func send(
        _ data: Data,
        whileAdmitted: @escaping @Sendable (_ submit: () -> Void) throws -> Void
    ) async throws {
        try await transport.send(data, whileAdmitted: whileAdmitted)
    }
    public func receive(maximumLength: Int) async throws -> Data {
        try await transport.receive(maximumLength: maximumLength)
    }
    public func receive(maximumLength: Int, waitingForActivity: Bool) async throws -> Data {
        try await transport.receive(
            maximumLength: maximumLength, waitingForActivity: waitingForActivity)
    }
    public func close() async { await transport.close() }
}

private final class BrokerPinVerification: @unchecked Sendable {
    private let lock = NSLock()
    private var accepted = false
    private var failed = false
    private var ready: BrokerTLSNegotiation?
    var negotiation: BrokerTLSNegotiation? { lock.withLock { failed ? nil : ready } }
    var verified: Bool { lock.withLock { accepted && !failed } }
    func record(_ valid: Bool) {
        lock.withLock {
            accepted = valid
            if !valid { failed = true }
        }
    }
    func recordNegotiation(_ negotiation: BrokerTLSNegotiation) {
        lock.withLock { if accepted && !failed { ready = negotiation } }
    }
}
