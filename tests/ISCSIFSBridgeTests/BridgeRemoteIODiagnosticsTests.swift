import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private actor BridgeIOTransport: ByteTransport {
    private var responses: [Data]
    private var responseIndex = 0
    private var waiter: CheckedContinuation<Void, Never>?
    private var closed = false
    private(set) var writes: [Data] = []
    init(_ responses: [Data]) { self.responses = responses }
    func send(_ data: Data) async throws {
        writes.append(data)
        waiter?.resume()
        waiter = nil
    }
    func receive(maximumLength: Int) async throws -> Data {
        while !closed && (responses.isEmpty || writes.count < responseIndex + 1) {
            await withCheckedContinuation { waiter = $0 }
        }
        guard !closed, !responses.isEmpty else { throw ProtocolError.connectionClosed }
        let body = Data(responses[0].prefix(maximumLength))
        responses[0].removeFirst(body.count)
        if responses[0].isEmpty {
            responses.removeFirst()
            responseIndex += 1
        }
        return body
    }
    func close() async {
        closed = true
        waiter?.resume()
        waiter = nil
    }
}

private func bridgeIOFrame(
    opcode: UInt8, flags: UInt8, tag: UInt32, stat: UInt32, exp: UInt32,
    status: UInt8 = 0, data: Data = Data()
) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = opcode
    header[1] = flags
    header[3] = status
    header.replaceSubrange(8..<14, with: [0x80, 1, 2, 3, 4, 5])
    header.put(UInt16(1), at: 14)
    header.put(tag, at: 16)
    header.put(stat, at: 24)
    header.put(exp, at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: data).encoded()
}

@Test func ioBridgeRemoteParentChainAndRetainedRejectionBindActualComponents() async throws {
    let security = try TextParameters([
        .init("AuthMethod", "None"), .init("TargetPortalGroupTag", "1"),
    ]).encoded()
    let operational = try TextParameters([
        .init("HeaderDigest", "None"), .init("DataDigest", "None"),
        .init("MaxRecvDataSegmentLength", "8192"), .init("MaxConnections", "1"),
        .init("InitialR2T", "Yes"), .init("ImmediateData", "No"),
        .init("MaxBurstLength", "262144"), .init("FirstBurstLength", "65536"),
        .init("MaxOutstandingR2T", "1"), .init("DataPDUInOrder", "Yes"),
        .init("DataSequenceInOrder", "Yes"), .init("ErrorRecoveryLevel", "0"),
        .init("DefaultTime2Wait", "2"), .init("DefaultTime2Retain", "0"),
    ]).encoded()
    let sense = Data([0, 8, 0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    let transport = try BridgeIOTransport([
        bridgeIOFrame(opcode: 0x23, flags: 0x81, tag: 1, stat: 0, exp: 1, data: security),
        bridgeIOFrame(opcode: 0x23, flags: 0x87, tag: 1, stat: 1, exp: 1, data: operational),
        bridgeIOFrame(
            opcode: 0x25, flags: 0x81, tag: 2, stat: 2, exp: 2, data: Data(repeating: 7, count: 512)
        ),
        bridgeIOFrame(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3, status: 2, data: sense),
        bridgeIOFrame(opcode: 0x26, flags: 0x80, tag: 4, stat: 4, exp: 3),
    ])
    let session = try ISCSISession(
        transport: transport,
        configuration: LoginConfiguration(
            initiatorName: "iqn.2026-10.dev.soba:test", targetName: "iqn.2026-10.dev.soba:disk",
            isid: [0x80, 1, 2, 3, 4, 5]))
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(7), at: 0)
    capacity.put(UInt32(512), at: 4)
    let network = IODiagnostics.Recorder(layer: .remoteDisk)
    let bridge = IODiagnostics.Recorder(layer: .volume)
    let disk = try RemoteDisk(
        session: session, lun: LogicalUnit(0),
        capacity: DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        diagnostics: network)
    let volume = LUNImageVolume(
        disk: disk, identifier: UUID(), lifecycleObserver: { _ in }, ioDiagnostics: bridge)
    try await session.login()
    do {
        try await volume.openItem(volume.imageItem, modes: [.read, .write])
        #expect(
            try await volume.readCallback(
                from: volume.imageItem, at: 0, length: 32, bufferLength: 32,
                consume: { _, _ in }, finalize: { _ in }) == 32)
        let parentAttempt = try #require(
            bridge.snapshot().events.first {
                $0.operation == .read && $0.stage == .backendBegin
            })
        let child = try #require(
            network.snapshot().events.first {
                $0.operation == .read && $0.stage == .entered
            })
        #expect(child.parentScopeID == bridge.scopeID)
        #expect(child.parentOperationID == parentAttempt.operationID)
        #expect(child.parentBackendAttemptID == parentAttempt.backendAttemptID)
        #expect(network.scopeID != bridge.scopeID)
        // A read leaves nothing to flush; count one written block so the flush is sent.
        disk.coverage.endMutation(disk.coverage.beginMutation(epoch: 0))
        await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
        let cause = try #require(network.snapshot().summary.retainedMutationCause)
        #expect(cause.backendKind == .synchronize10)
        let commandsBefore = await transport.writes.count
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.readChunks(from: volume.imageItem, at: 0, length: 1, bufferLength: 1) {
                _, _ in
            }
        }
        #expect(await transport.writes.count == commandsBefore)
        #expect(
            network.snapshot().events.last { $0.stage == .retainedMutationRejected }?
                .retainedCauseID == cause.id)
        let beforeClose = network.snapshot().events.count
        await #expect(throws: POSIXError(.EIO)) {
            try await volume.closeItem(volume.imageItem, modes: [])
        }
        #expect(await transport.writes.count == commandsBefore)
        let closeAttempt = try #require(
            bridge.snapshot().events.first {
                $0.operation == .close && $0.stage == .backendBegin
            })
        let closeChild = try #require(
            network.snapshot().events.dropFirst(beforeClose).first {
                $0.operation == .synchronize && $0.stage == .entered
            })
        #expect(closeChild.parentScopeID == bridge.scopeID)
        #expect(closeChild.parentOperationID == closeAttempt.operationID)
        #expect(closeChild.parentBackendAttemptID == closeAttempt.backendAttemptID)
        #expect(
            network.snapshot().events.last { $0.stage == .retainedMutationRejected }?
                .retainedCauseID == cause.id)
        #expect(
            network.snapshot().summary.activeOperations == 0
                && bridge.snapshot().summary.activeOperations == 0)
        await volume.shutdown()
        #expect(await session.state == .closed)
    } catch {
        await volume.shutdown()
        throw error
    }
}
