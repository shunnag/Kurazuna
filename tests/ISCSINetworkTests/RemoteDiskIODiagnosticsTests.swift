import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private func ioFailure(_ tag: UInt32, sense: Data) throws -> Data {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = 0x21
    header[1] = 0x80
    header[3] = 2
    header.put(tag, at: 16)
    header.put(tag, at: 24)
    header.put(tag, at: 28)
    header.put(UInt32(32), at: 32)
    return try PDU(header: header, data: Data([0, UInt8(sense.count)]) + sense).encoded()
}

private func ioDisk(
    _ session: ISCSISession, recorder: IODiagnostics.Recorder?, readOnly: Bool = false
) throws -> RemoteDisk {
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(7), at: 0)
    capacity.put(UInt32(512), at: 4)
    return try RemoteDisk(
        session: session, lun: LogicalUnit(0),
        capacity: DiskCapacity(readCapacity10: Data(capacity)), readOnly: readOnly,
        diagnostics: recorder)
}

@Test(arguments: [false, true])
func ioNetworkCancelledValidationAndShortcutErrorPrecedenceIsUnchanged(_ enabled: Bool) async throws
{
    let recorder = enabled ? IODiagnostics.Recorder(layer: .remoteDisk) : nil
    var responses = try loginFixtures(normal: true)
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 2, stat: 2, exp: 1))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder, readOnly: true)
    try await session.login()
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        await #expect(throws: POSIXError(.EINVAL)) { try await disk.read(offset: -1, length: 1) }
        #expect(try await disk.read(offset: 0, length: 0).isEmpty)
        await #expect(throws: POSIXError(.EROFS)) { try await disk.write(offset: 0, data: Data()) }
        try await disk.synchronize()
    }
    try await cancelled.value
    #expect(await disk.connectionState() == .connected)
    #expect(await transport.writes.count == 2)
    #expect(recorder?.retainedMutationCauseID == nil)
    await disk.close()
}

@Test(arguments: [false, true])
func ioNetworkValidationDoesNotBecomeTheLaterMutationCause(_ enabled: Bool) async throws {
    let recorder = enabled ? IODiagnostics.Recorder(layer: .remoteDisk) : nil
    let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var responses = try loginFixtures(normal: true)
    responses.append(try ioFailure(2, sense: sense))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder)
    try await session.login()
    await #expect(throws: POSIXError(.EINVAL)) { try await disk.read(offset: -1, length: 1) }
    #expect(recorder?.retainedMutationCauseID == nil)
    markUnsynchronizedWrite(disk)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.synchronize()
    }
    #expect(await disk.connectionState() == .interrupted)
    for _ in 0..<3 {
        await #expect(throws: ProtocolError.invalidState) { try await disk.synchronize() }
    }
    #expect(await transport.writes.count == 3)
    if let recorder {
        let value = recorder.snapshot()
        let cause = try #require(value.summary.retainedMutationCause)
        #expect(cause.backendKind == .synchronize10 && cause.backendAttemptID != nil)
        #expect(cause.result.protocolCategory == .scsiFailure)
        let rejections = value.events.filter { $0.stage == .retainedMutationRejected }
        #expect(rejections.count == 3 && rejections.allSatisfy { $0.retainedCauseID == cause.id })
        #expect(value.events.filter { $0.stage == .mutationFailureRetained }.count == 1)
        #expect(value.summary.activeOperations == 0 && value.summary.integrityValid)
    }
    await disk.close()
    #expect(await session.state == .closed)
}

@Test(arguments: [false, true])
func ioNetworkFallbackBindsOnlyAnUnhandledSync16Failure(_ failSecond: Bool) async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let unsupported = Data([0x72, 5, 0x20, 0, 0, 0, 0, 0])
    let failure = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var responses = try loginFixtures(normal: true)
    responses.append(try ioFailure(2, sense: unsupported))
    responses.append(
        failSecond
            ? try ioFailure(3, sense: failure)
            : try fixture(opcode: 0x21, flags: 0x80, tag: 3, stat: 3, exp: 3))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 4, stat: 4, exp: 3))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder)
    try await session.login()
    markUnsynchronizedWrite(disk)
    if failSecond {
        await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: failure)) {
            try await disk.synchronize()
        }
    } else {
        try await disk.synchronize()
    }
    let snapshot = recorder.snapshot()
    let attempts = snapshot.events.filter { $0.stage == .backendBegin }
    #expect(attempts.map(\.detail) == [.synchronize10, .synchronize16])
    #expect(Set(attempts.compactMap(\.backendAttemptID)).count == 2)
    if failSecond {
        let cause = try #require(snapshot.summary.retainedMutationCause)
        #expect(cause.backendKind == .synchronize16)
        #expect(cause.backendAttemptID == attempts.last?.backendAttemptID)
        #expect(await disk.connectionState() == .interrupted)
    } else {
        #expect(snapshot.summary.retainedMutationCause == nil)
        #expect(await disk.connectionState() == .connected)
    }
    let commands = await transport.writes.map { Array($0) }.filter { $0[0] & 0x3F == 1 }
    #expect(commands.map { $0[32] } == [0x35, 0x91])
    await disk.close()
}

@Test(arguments: [false, true])
func ioNetworkReadAndRMWReadFailuresRemainNonretaining(_ readModifyWrite: Bool) async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    let failure = Data([0x72, 3, 0x11, 0, 0, 0, 0, 0])
    var responses = try loginFixtures(normal: true)
    responses.append(try ioFailure(2, sense: failure))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder)
    try await session.login()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: failure)) {
        if readModifyWrite {
            try await disk.write(offset: 1, data: Data([0xA5]))
        } else {
            _ = try await disk.read(offset: 0, length: 512)
        }
    }
    #expect(await disk.connectionState() == .connected)
    #expect(recorder.retainedMutationCauseID == nil)
    #expect(
        recorder.snapshot().events.filter { $0.stage == .backendBegin }.map(\.detail) == [.read])
    #expect(await transport.writes.count == 3)
    await disk.close()
}

@Test(arguments: [false, true])
func ioNetworkEmptyAndReadOnlyShortcutsDispatchNoBackend(_ readOnly: Bool) async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk)
    var responses = try loginFixtures(normal: true)
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 2, stat: 2, exp: 1))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder, readOnly: readOnly)
    try await session.login()
    #expect(try await disk.read(offset: 0, length: 0).isEmpty)
    if readOnly {
        await #expect(throws: POSIXError(.EROFS)) { try await disk.write(offset: 0, data: Data()) }
        try await disk.synchronize()
    } else {
        try await disk.write(offset: 0, data: Data())
    }
    #expect(!recorder.snapshot().events.contains { $0.stage == .backendBegin })
    #expect(await transport.writes.count == 2)
    #expect(recorder.retainedMutationCauseID == nil)
    await disk.close()
}

@Test func ioNetworkRetainedCauseSurvivesAnExhaustedEventPrefix() async throws {
    let recorder = IODiagnostics.Recorder(layer: .remoteDisk, capacity: 1)
    let failure = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var responses = try loginFixtures(normal: true)
    responses.append(try ioFailure(2, sense: failure))
    responses.append(try fixture(opcode: 0x26, flags: 0x80, tag: 3, stat: 3, exp: 2))
    let transport = ScriptedTransport(responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    let disk = try ioDisk(session, recorder: recorder)
    try await session.login()
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: failure)) {
        try await disk.write(offset: 0, data: Data(repeating: 7, count: 512))
    }
    let value = recorder.snapshot()
    #expect(value.events.count == 1 && value.summary.suppressedEvents > 0)
    #expect(value.summary.retainedMutationCause?.backendKind == .write)
    #expect(value.summary.retainedMutationCause?.backendAttemptID != nil)
    #expect(await disk.connectionState() == .interrupted)
    await disk.close()
}
