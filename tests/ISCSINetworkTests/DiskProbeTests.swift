import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private struct ProbeScript {
    var responses = try! loginFixtures(normal: true)
    private var tag: UInt32 = 2
    private var stat: UInt32 = 2

    mutating func data(_ data: Data, allocation: UInt32, wrongTag: Bool = false) throws {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x25
        header[1] = data.count < allocation ? 0x83 : 0x81
        header.put(wrongTag ? 99 : tag, at: 16)
        header.put(stat, at: 24)
        header.put(tag, at: 28)
        header.put(UInt32(32), at: 32)
        header.put(allocation - UInt32(data.count), at: 44)
        responses.append(try PDU(header: header, data: data).encoded())
        tag += 1
        stat += 1
    }

    mutating func status(
        _ status: UInt8 = 2, key: UInt8 = 2, asc: UInt8 = 4, response: UInt8 = 0x72
    ) throws {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x21
        header[1] = 0x80
        header[3] = status
        header.put(tag, at: 16)
        header.put(stat, at: 24)
        header.put(tag, at: 28)
        header.put(UInt32(32), at: 32)
        let raw = probeSense(response: response, key: key, asc: asc)
        let sense: [UInt8] = status == 2 ? [0, UInt8(raw.count)] + Array(raw) : []
        responses.append(try PDU(header: header, data: Data(sense)).encoded())
        tag += 1
        stat += 1
    }

    mutating func report(_ luns: [LogicalUnit]) throws {
        var bytes = Array(repeating: UInt8(0), count: 8)
        bytes.put(UInt32(luns.count * 8), at: 0)
        bytes += luns.flatMap(\.wireBytes)
        try data(Data(bytes), allocation: 65_536)
    }

    mutating func inquiry(device: UInt8 = 0, format: UInt8 = 2) throws {
        var bytes = Array(repeating: UInt8(0), count: 36)
        bytes[0] = device
        bytes[2] = 6
        bytes[3] = format
        bytes[4] = 31
        bytes.replaceSubrange(8..<16, with: "SobaDev ".utf8)
        bytes.replaceSubrange(16..<32, with: "Memory Disk     ".utf8)
        try data(Data(bytes), allocation: 96)
    }

    mutating func capacity(blockSize: UInt32 = 512, protected: Bool = false) throws {
        var bytes = Array(repeating: UInt8(0), count: 32)
        bytes.put(UInt64(127), at: 0)
        bytes.put(blockSize, at: 8)
        try data(Data(bytes), allocation: 32)
        if blockSize >= 512 && blockSize <= 65_536 && blockSize.nonzeroBitCount == 1 {
            try mode(protected: protected)
        }
    }

    mutating func mode(protected: Bool, tenByte: Bool = true) throws {
        try data(
            tenByte
                ? Data([0, 6, 0, protected ? 0x80 : 0, 0, 0, 0, 0])
                : Data([3, 0, protected ? 0x80 : 0, 0]), allocation: tenByte ? 8 : 4)
    }

    func open() async throws -> (ISCSISession, ScriptedTransport) {
        let transport = ScriptedTransport(responses)
        let session = try ISCSISession(
            transport: transport, configuration: configuration(normal: true))
        try await session.login()
        return (session, transport)
    }
}

private func probeSense(response: UInt8, key: UInt8, asc: UInt8) -> Data {
    if response & 0x7F == 0x70 || response & 0x7F == 0x71 {
        return Data([response, 0, key, 0, 0, 0, 0, 6, 0, 0, 0, 0, asc, 0])
    }
    return Data([response, key, asc, 0, 0, 0, 0, 0])
}

@Test(arguments: [UInt8(0x70), 0x72])
func currentSenseRetainsAttentionRetryAndTheCapacityFallback(_ response: UInt8) async throws {
    var script = ProbeScript()
    try script.status(key: 6, asc: 0x29, response: response)
    try script.inquiry()
    try script.status(key: 5, asc: 0x20, response: response)
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(127), at: 0)
    capacity.put(UInt32(512), at: 4)
    try script.data(Data(capacity), allocation: 8)
    try script.mode(protected: false)
    let (session, transport) = try await script.open()
    let info = try await DiskProbe.diskInformation(session: session, lun: LogicalUnit(0))
    #expect(info.capacity.byteCount == 65_536)
    #expect(await commands(transport).map(\.opcode) == [0x12, 0x12, 0x9E, 0x25, 0x5A])
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73])
func aDeferredProbeFailureStopsInspectionBeforeAnotherLUNIsAccessed(_ response: UInt8) async throws
{
    var script = ProbeScript()
    try script.report([LogicalUnit(0), LogicalUnit(1)])
    try script.inquiry()
    try script.status(key: 2, asc: 0x3A, response: response)
    try script.inquiry()
    try script.capacity()
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: 2, asc: 0x3A))
    ) {
        try await DiskProbe.inspectLogicalUnits(session: session)
    }
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12, 0x9E])
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73], [UInt8(0x20), 0x24])
func aDeferredUnsupportedCapacityErrorCannotBeHiddenByAFallback(_ response: UInt8, _ asc: UInt8)
    async throws
{
    var script = ProbeScript()
    try script.status(key: 5, asc: asc, response: response)
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(127), at: 0)
    capacity.put(UInt32(512), at: 4)
    // A tempting valid fallback must never conceal the error from the earlier command.
    try script.data(Data(capacity), allocation: 8)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: 5, asc: asc))
    ) {
        try await DiskProbe.capacity(session: session, lun: LogicalUnit(0))
    }
    #expect(await commands(transport).map(\.opcode) == [0x9E])
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await #expect(throws: ProtocolError.invalidState) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(0))
    }
    #expect(await commands(transport).map(\.opcode) == [0x9E])
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73], [SCSICommand.inquiry(), .readCapacity16()])
func deferredUnitAttentionDoesNotRetryTheCurrentReadOnlyCommand(
    _ response: UInt8, _ command: SCSICommand
) async throws {
    var script = ProbeScript()
    try script.status(key: 6, asc: 0x29, response: response)
    try script.data(
        Data(repeating: 0, count: Int(command.transferLength)), allocation: command.transferLength)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: 6, asc: 0x29))
    ) {
        try await DiskProbe.readOnly(command, session: session, lun: LogicalUnit(0))
    }
    #expect(await commands(transport).map(\.opcode) == [command.cdb[0]])
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73], [UInt8(0x04), 0x3A, 0x25])
func deferredDeviceSenseDoesNotMisdiagnoseTheCurrentDisk(_ response: UInt8, _ asc: UInt8)
    async throws
{
    var script = ProbeScript()
    try script.inquiry()
    try script.status(key: asc == 0x25 ? 5 : 2, asc: asc, response: response)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: asc == 0x25 ? 5 : 2, asc: asc))
    ) {
        try await DiskProbe.diskInformation(session: session, lun: LogicalUnit(0))
    }
    #expect(await commands(transport).map(\.opcode) == [0x12, 0x9E])
    #expect(await session.state == .failed)
    await session.close()
}

private func commands(_ transport: ScriptedTransport) async -> [(lun: [UInt8], opcode: UInt8)] {
    await transport.writes.compactMap { data in
        let bytes = [UInt8](data)
        guard bytes[0] & 0x3F == 1 else { return nil }
        return (Array(bytes[8..<16]), bytes[32])
    }
}

@Test(arguments: [false, true], [false, true])
func modeProtectionUsesSixBytesOnlyAfterAnUnsupportedOpcode(_ protected: Bool, _ tenByte: Bool)
    async throws
{
    var script = ProbeScript()
    if !tenByte { try script.status(key: 5, asc: 0x20) }
    try script.mode(protected: protected, tenByte: tenByte)
    let (session, transport) = try await script.open()
    #expect(try await DiskProbe.writeProtection(session: session, lun: LogicalUnit(0)) == protected)
    #expect(await commands(transport).map(\.opcode) == (tenByte ? [0x5A] : [0x5A, 0x1A]))
    await session.close()
}

@Test func modeProtectionRetainsUnknownWhenNeitherFormatIsSupported() async throws {
    var script = ProbeScript()
    try script.status(key: 5, asc: 0x20)
    try script.status(key: 5, asc: 0x20)
    let (session, transport) = try await script.open()
    #expect(try await DiskProbe.writeProtection(session: session, lun: LogicalUnit(0)) == nil)
    #expect(await commands(transport).map(\.opcode) == [0x5A, 0x1A])
    #expect(await session.state == .ready)
    await session.close()
}

@Test(arguments: [false, true])
func modeProtectionTriesTheHeaderPageOnlyForCurrentInvalidFields(_ tenByte: Bool) async throws {
    var script = ProbeScript()
    if !tenByte { try script.status(key: 5, asc: 0x20) }
    try script.status(key: 5, asc: 0x24)
    try script.mode(protected: true, tenByte: tenByte)
    let (session, transport) = try await script.open()
    #expect(try await DiskProbe.writeProtection(session: session, lun: LogicalUnit(0)) == true)
    let requests = await transport.writes.map { [UInt8]($0) }.filter { $0[0] & 0x3F == 1 }
    #expect(requests.last?[34] == 0)
    #expect(requests.last?[33] == 8)
    #expect(requests.count == (tenByte ? 2 : 3))
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73], [UInt8(5), 6])
func deferredModeErrorsCannotBeHiddenByPagesOrAnotherOpcode(_ response: UInt8, _ key: UInt8)
    async throws
{
    var script = ProbeScript()
    let asc: UInt8 = key == 5 ? 0x24 : 0x29
    try script.status(key: key, asc: asc, response: response)
    try script.mode(protected: false)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: key, asc: asc))
    ) { try await DiskProbe.writeProtection(session: session, lun: LogicalUnit(0)) }
    #expect(await commands(transport).map(\.opcode) == [0x5A])
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    await session.close()
}

@Test(arguments: [UInt8(0x70), 0x72])
func aCurrentModeDeviceErrorDoesNotBecomeUnknownOrCauseAFallback(_ response: UInt8) async throws {
    var script = ProbeScript()
    try script.status(key: 4, asc: 0x44, response: response)
    try script.mode(protected: false)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: 4, asc: 0x44))
    ) { try await DiskProbe.writeProtection(session: session, lun: LogicalUnit(0)) }
    #expect(await commands(transport).map(\.opcode) == [0x5A])
    #expect(await session.state == .ready)
    await session.close()
}

@Test func diskInformationIncludesTheObservedProtectionState() async throws {
    var script = ProbeScript()
    try script.inquiry()
    try script.capacity(protected: true)
    let (session, _) = try await script.open()
    let information = try await DiskProbe.diskInformation(session: session, lun: LogicalUnit(0))
    #expect(information.isWriteProtected == true)
    await session.close()
}

@Test func diskProbeChecksInquiryBeforeCapacity() async throws {
    var script = ProbeScript()
    try script.inquiry()
    try script.capacity()
    let (session, transport) = try await script.open()
    let information = try await DiskProbe.diskInformation(session: session, lun: LogicalUnit(256))
    #expect(information.device.displayName == "SobaDev Memory Disk")
    #expect(information.capacity.byteCount == 65_536)
    let sent = await commands(transport)
    #expect(sent.map(\.opcode) == [0x12, 0x9E, 0x5A])
    #expect(sent.allSatisfy { $0.lun == [0x41, 0, 0, 0, 0, 0, 0, 0] })
    await session.close()
}

@Test(arguments: [UInt8(1), 5, 0x0E, 0x14, 0x1F, 0x20, 0x40, 0x7F, 0xFF])
func nonDiskOrUnavailableDevicesReceiveNoCapacityOrBlockCommands(_ device: UInt8) async throws {
    var script = ProbeScript()
    try script.inquiry(device: device)
    let (session, transport) = try await script.open()
    let expected: DiskProbeIssue =
        device >> 5 == 0 ? .unsupportedDevice(type: device & 0x1F) : .unavailable
    await #expect(throws: expected) {
        try await DiskProbe.diskInformation(session: session, lun: LogicalUnit(0))
    }
    #expect(await session.state == .ready)
    #expect(await commands(transport).map(\.opcode) == [0x12])
    await session.close()
}

@Test func mixedLUNInspectionPreservesHealthyDisksAndExplainsDeviceFailures() async throws {
    let luns = try (0..<9).map { try LogicalUnit(UInt16($0)) }
    var script = ProbeScript()
    try script.report(luns)
    try script.inquiry()
    try script.capacity()
    try script.inquiry(device: 1)
    try script.inquiry()
    try script.status()
    try script.inquiry()
    try script.status(asc: 0x3A)
    try script.inquiry()
    try script.status(0x18)
    try script.data(Data([0, 0, 6, 2, 31]), allocation: 96)
    try script.inquiry()
    try script.capacity(blockSize: 3)
    try script.inquiry()
    try script.status(key: 5, asc: 0x25)
    try script.inquiry()
    try script.capacity()
    let (session, transport) = try await script.open()
    let inspections = try await DiskProbe.inspectLogicalUnits(session: session)
    #expect(inspections.map(\.lun) == luns)
    #expect(try inspections[0].result.get().capacity.byteCount == 65_536)
    let issues: [DiskProbeIssue] = [
        .unsupportedDevice(type: 1), .notReady, .noMedia, .accessRestricted,
        .invalidInformation, .invalidInformation, .unavailable,
    ]
    for (index, issue) in issues.enumerated() {
        #expect(inspections[index + 1].result == .failure(issue))
    }
    #expect(try inspections[8].result.get().device.displayName == "SobaDev Memory Disk")
    #expect(await session.state == .ready)
    let sent = await commands(transport)
    #expect(sent.count == 19)
    #expect(sent.filter { $0.lun == luns[1].wireBytes }.map(\.opcode) == [0x12])
    #expect(sent.filter { $0.lun == luns[5].wireBytes }.map(\.opcode) == [0x12])
    await session.close()
}

@Test func malformedWireResponseStopsLUNInspectionBeforeAnotherDeviceIsProbed() async throws {
    var script = ProbeScript()
    try script.report([LogicalUnit(0), LogicalUnit(1)])
    var inquiry = Array(repeating: UInt8(0), count: 36)
    inquiry[3] = 2
    inquiry[4] = 31
    try script.data(Data(inquiry), allocation: 96, wrongTag: true)
    let (session, transport) = try await script.open()
    await #expect(throws: ProtocolError.self) {
        try await DiskProbe.inspectLogicalUnits(session: session)
    }
    #expect(await session.state == .failed)
    #expect(await transport.isClosed)
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12])
}

@Test func inquiryUnitAttentionHasABoundedRetryAndDoesNotHideTheNextLUN() async throws {
    var script = ProbeScript()
    try script.report([LogicalUnit(0), LogicalUnit(1)])
    for _ in 0..<3 { try script.status(key: 6, asc: 0x29) }
    try script.inquiry()
    try script.capacity()
    let (session, transport) = try await script.open()
    let inspections = try await DiskProbe.inspectLogicalUnits(session: session)
    #expect(inspections[0].result == .failure(.commandFailed(status: 2)))
    #expect(try inspections[1].result.get().capacity.byteCount == 65_536)
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12, 0x12, 0x12, 0x12, 0x9E, 0x5A])
    await session.close()
}

@Test func shortSelfConsistentInquiryAndUnknownResponseFormatAreHandledSeparately() async throws {
    var script = ProbeScript()
    try script.report([LogicalUnit(0), LogicalUnit(1)])
    try script.data(Data([0, 0, 6, 2, 0]), allocation: 96)
    try script.capacity()
    try script.inquiry(format: 0)
    let (session, transport) = try await script.open()
    let inspections = try await DiskProbe.inspectLogicalUnits(session: session)
    #expect(try inspections[0].result.get().device.displayName.isEmpty)
    #expect(inspections[1].result == .failure(.unsupportedDevice(type: 0)))
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12, 0x9E, 0x5A, 0x12])
    await session.close()
}

@Test(arguments: [UInt8(0x70), 0x72], [UInt8(0x20), 0x24])
func onlyCurrentUnsupportedSenseMakesBlockLimitsOptional(_ response: UInt8, _ asc: UInt8)
    async throws
{
    var script = ProbeScript()
    try script.status(key: 5, asc: asc, response: response)
    let (session, transport) = try await script.open()
    #expect(try await DiskProbe.blockLimits(session: session, lun: LogicalUnit(0)) == nil)
    #expect(await session.state == .ready)
    #expect(await commands(transport).map(\.opcode) == [0x12])
    await session.close()
}

@Test(arguments: [UInt8(0x71), 0x73], [UInt8(0x20), 0x24])
func deferredBlockLimitsErrorsCannotBeConcealedByAnOptionalPage(_ response: UInt8, _ asc: UInt8)
    async throws
{
    var script = ProbeScript()
    try script.status(key: 5, asc: asc, response: response)
    let (session, transport) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: 2, sense: probeSense(response: response, key: 5, asc: asc))
    ) { try await DiskProbe.blockLimits(session: session, lun: LogicalUnit(0)) }
    #expect(await session.state == .failed)
    await #expect(throws: ProtocolError.invalidState) {
        try await DiskProbe.blockLimits(session: session, lun: LogicalUnit(0))
    }
    #expect(await commands(transport).map(\.opcode) == [0x12])
    #expect(await transport.isClosed)
    await session.close()
}

@Test(arguments: [UInt8(8), 0x18, 2])
func otherBlockLimitsDeviceErrorsRemainFailures(_ status: UInt8) async throws {
    var script = ProbeScript()
    try script.status(status, key: 2, asc: 4)
    let (session, _) = try await script.open()
    await #expect(
        throws: ProtocolError.scsiFailure(
            status: status, sense: status == 2 ? probeSense(response: 0x72, key: 2, asc: 4) : Data()
        )
    ) { try await DiskProbe.blockLimits(session: session, lun: LogicalUnit(0)) }
    #expect(await session.state == .ready)
    await session.close()
}

@Test func aCurrentAttentionBeforeBlockLimitsIsRetriedWithinTheExistingBound() async throws {
    var script = ProbeScript()
    try script.status(key: 6, asc: 0x29)
    var page = Array(repeating: UInt8(0), count: 64)
    page[1] = 0xB0
    page[3] = 60
    page.put(UInt32(3), at: 8)
    try script.data(Data(page), allocation: 64)
    let (session, transport) = try await script.open()
    #expect(
        try await DiskProbe.blockLimits(session: session, lun: LogicalUnit(0))?
            .maximumTransferBlocks == 3)
    #expect(await commands(transport).map(\.opcode) == [0x12, 0x12])
    await session.close()
}

@Test func cancellingLUNInspectionClosesTheSessionAndDoesNotReturnPartialResults() async throws {
    var script = ProbeScript()
    try script.report([LogicalUnit(0), LogicalUnit(1)])
    let (session, transport) = try await script.open()
    let inspection = Task { try await DiskProbe.inspectLogicalUnits(session: session) }
    defer { inspection.cancel() }
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while await commands(transport).count < 2, clock.now < deadline {
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12])
    inspection.cancel()
    await #expect(throws: CancellationError.self) { try await inspection.value }
    #expect(await transport.isClosed)
    #expect(await session.state == .failed)
    #expect(await commands(transport).map(\.opcode) == [0xA0, 0x12])
}

/// A target without a device identification page answers its INQUIRY with CHECK CONDITION,
/// ILLEGAL REQUEST: the logical unit has no names. One answer, no retry, and the session
/// stays usable, so opening the disk neither fails nor waits for it.
@Test(arguments: [UInt8(0x70), 0x72], [UInt8(0x20), 0x24])
func anIdentificationPageRejectedAsAnIllegalRequestMeansNoNames(_ response: UInt8, _ asc: UInt8)
    async throws
{
    var script = ProbeScript()
    try script.status(key: 5, asc: asc, response: response)
    let (session, transport) = try await script.open()
    #expect(try await DiskProbe.logicalUnitDesignator(session: session, lun: LogicalUnit(0)) == nil)
    #expect(await commands(transport).map(\.opcode) == [0x12])
    #expect(await session.state == .ready)
    await session.close()
}
