import Foundation
import ISCSICore
import Synchronization
import Testing

@testable import ISCSINetwork

/// Target replies in order. Each status-bearing reply consumes the next task tag and StatSN.
private struct RetryScript {
    var responses = try! loginFixtures(normal: true)
    private var tag: UInt32 = 2

    private mutating func header(_ opcode: UInt8, flags: UInt8) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = flags
        header.put(tag, at: 16)
        header.put(tag, at: 24)
        header.put(tag, at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    mutating func status(_ status: UInt8, sense: Data = Data()) throws {
        var header = header(0x21, flags: 0x80)
        header[3] = status
        let data = sense.isEmpty ? Data() : Data([0, UInt8(sense.count)]) + sense
        responses.append(try PDU(header: header, data: data).encoded())
        tag += 1
    }

    mutating func good() throws { try status(0) }

    /// A complete write: the target requests the data, then reports GOOD status.
    mutating func written(length: UInt32 = 512) throws {
        var transfer = header(0x31, flags: 0x80)
        transfer.put(UInt32(73), at: 20)
        transfer.put(length, at: 44)
        responses.append(try PDU(header: transfer).encoded())
        try good()
    }

    mutating func data(_ data: Data, allocation: UInt32) throws {
        var header = header(0x25, flags: data.count < allocation ? 0x83 : 0x81)
        header.put(allocation - UInt32(data.count), at: 44)
        responses.append(try PDU(header: header, data: data).encoded())
        tag += 1
    }

    /// READ CAPACITY(16) and MODE SENSE(10) replies for a re-probed disk.
    mutating func probe(lastBlock: UInt64 = 7, blockSize: UInt32 = 512, protected: Bool = false)
        throws
    {
        var capacity = Array(repeating: UInt8(0), count: 32)
        capacity.put(lastBlock, at: 0)
        capacity.put(blockSize, at: 8)
        try data(Data(capacity), allocation: 32)
        if lastBlock == 7, blockSize == 512 {
            try data(Data([0, 6, 0, protected ? 0x80 : 0, 0, 0, 0, 0]), allocation: 8)
        }
    }

    mutating func logout() throws {
        responses.append(
            try fixture(opcode: 0x26, flags: 0x80, tag: tag, stat: tag, exp: tag))
    }
}

private func attention(_ asc: UInt8, _ qualifier: UInt8 = 0, deferred: Bool = false) -> Data {
    Data([deferred ? 0x73 : 0x72, 6, asc, qualifier, 0, 0, 0, 0])
}

/// A manual clock: each sleep advances it, optionally by more than requested. It keeps two
/// times: awake time, which the disk counts, and time that also counts the Mac asleep, as
/// `ContinuousClock` does. A Mac that sleeps through a pause advances only the second.
private final class RetryClock: Sendable {
    private struct State {
        var awake = Duration.zero
        var withSleep = Duration.zero
        var sleeps: [Duration] = []
    }
    private let state = Mutex(State())
    private let overshoot: Duration
    private let asleep: Duration
    init(overshoot: Duration = .zero, asleep: Duration = .zero) {
        self.overshoot = overshoot
        self.asleep = asleep
    }
    var sleeps: [Duration] { state.withLock { $0.sleeps } }
    var elapsedWithSleep: Duration { state.withLock { $0.withSleep } }
    /// Awake time.
    var clock: RecoveryClock { view(countingSleep: false) }
    /// Time that also counts the Mac asleep.
    var clockCountingSleep: RecoveryClock { view(countingSleep: true) }

    private func view(countingSleep: Bool) -> RecoveryClock {
        RecoveryClock(
            elapsed: { self.state.withLock { countingSleep ? $0.withSleep : $0.awake } },
            sleepUntil: { deadline in
                self.state.withLock {
                    let requested = deadline - (countingSleep ? $0.withSleep : $0.awake)
                    $0.sleeps.append(requested)
                    $0.awake += requested + self.overshoot
                    $0.withSleep += requested + self.overshoot + self.asleep
                }
            })
    }
}

private func retryDisk(
    _ script: RetryScript, clock: RetryClock = RetryClock(), countingSleep: Bool = false,
    writeProtection: Bool? = false
) async throws -> (RemoteDisk, ISCSISession, ScriptedTransport) {
    let transport = ScriptedTransport(script.responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(7), at: 0)
    capacity.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        diagnostics: nil, reservedAccess: nil, writeProtection: writeProtection,
        retryClock: countingSleep ? clock.clockCountingSleep : clock.clock)
    try await session.login()
    return (disk, session, transport)
}

private func commandOpcodes(_ transport: ScriptedTransport) async -> [UInt8] {
    await transport.writes.map { [UInt8]($0) }.filter { $0[0] & 0x3F == 1 }.map { $0[32] }
}

private enum DiskOperation: String, CaseIterable { case read, write, synchronize }

extension RemoteDisk {
    fileprivate func perform(_ operation: DiskOperation) async throws {
        switch operation {
        case .read: _ = try await read(offset: 0, length: 512)
        case .write: try await write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        case .synchronize:
            markUnsynchronizedWrite(self)
            try await synchronize()
        }
    }
}

extension RetryScript {
    fileprivate mutating func succeed(_ operation: DiskOperation) throws {
        switch operation {
        case .read: try data(Data(repeating: 0x5A, count: 512), allocation: 512)
        case .write: try written()
        case .synchronize: try good()
        }
    }
}

private func opcode(_ operation: DiskOperation) -> UInt8 {
    switch operation {
    case .read: 0x28
    case .write: 0x2A
    case .synchronize: 0x35
    }
}

@Test(arguments: DiskOperation.allCases)
private func aUnitAttentionIsRetriedWithoutAnotherProbe(_ operation: DiskOperation) async throws {
    // Commands cleared by another initiator: the device didn't run this command.
    var script = RetryScript()
    try script.status(2, sense: attention(0x2F))
    try script.succeed(operation)
    try script.logout()
    let (disk, session, transport) = try await retryDisk(script)
    try await disk.perform(operation)
    #expect(await disk.connectionState() == .connected)
    #expect(disk.mutationEvidence.incident == nil)
    #expect(await commandOpcodes(transport) == [opcode(operation), opcode(operation)])
    await disk.close()
    #expect(await session.state == .closed)
}

@Test(
    arguments: DiskOperation.allCases,
    [(UInt8(0x29), UInt8(0)), (0x2A, 9), (0x3F, 0x0E), (0x28, 0)])
private func aDeviceAttentionReprobesAnUnchangedDiskThenRetries(
    _ operation: DiskOperation, _ code: (UInt8, UInt8)
) async throws {
    var script = RetryScript()
    try script.status(2, sense: attention(code.0, code.1))
    try script.probe()
    try script.succeed(operation)
    try script.logout()
    let (disk, session, transport) = try await retryDisk(script)
    try await disk.perform(operation)
    #expect(await disk.connectionState() == .connected)
    #expect(
        await commandOpcodes(transport) == [opcode(operation), 0x9E, 0x5A, opcode(operation)])
    await disk.close()
    #expect(await session.state == .closed)
}

private struct DeviceChange: Sendable, CustomStringConvertible {
    let lastBlock: UInt64
    let blockSize: UInt32
    let protected: Bool
    var description: String { "\(lastBlock)/\(blockSize)/\(protected)" }
    static let all = [
        Self(lastBlock: 15, blockSize: 512, protected: false),
        Self(lastBlock: 7, blockSize: 4096, protected: false),
        Self(lastBlock: 7, blockSize: 512, protected: true),
    ]
}

@Test(arguments: DiskOperation.allCases, DeviceChange.all)
private func aChangedDeviceAfterAResetLatchesTheDiskWithoutRetrying(
    _ operation: DiskOperation, _ change: DeviceChange
) async throws {
    let sense = attention(0x29)
    var script = RetryScript()
    try script.status(2, sense: sense)
    try script.probe(
        lastBlock: change.lastBlock, blockSize: change.blockSize, protected: change.protected)
    try script.logout()
    let (disk, session, transport) = try await retryDisk(script)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.perform(operation)
    }
    #expect(await disk.connectionState() == .interrupted)
    let expectedOperation: MutationIncident.Operation =
        switch operation {
        case .read: .read
        case .write: .write
        case .synchronize: .synchronize
        }
    #expect(disk.mutationEvidence.incident?.operation == expectedOperation)
    // No command reaches the replacement device, including the original one.
    let probed: [UInt8] = change.lastBlock == 7 && change.blockSize == 512 ? [0x9E, 0x5A] : [0x9E]
    #expect(await commandOpcodes(transport) == [opcode(operation)] + probed)
    for next in DiskOperation.allCases {
        await #expect(throws: ProtocolError.invalidState) { try await disk.perform(next) }
    }
    #expect(await commandOpcodes(transport).count == 1 + probed.count)
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func anUnknownOpeningProtectionStateMustStillMatchTheReprobe() async throws {
    let sense = attention(0x29)
    var script = RetryScript()
    try script.status(2, sense: sense)
    try script.probe(protected: false)
    try script.logout()
    let (disk, session, _) = try await retryDisk(script, writeProtection: nil)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.perform(.write)
    }
    #expect(await disk.connectionState() == .interrupted)
    await disk.close()
    #expect(await session.state == .closed)
}

@Test(arguments: DiskOperation.allCases, [UInt8(0x08), 0x28])
private func busyAndTaskSetFullAreRetriedAfterABoundedBackoff(
    _ operation: DiskOperation, _ status: UInt8
) async throws {
    var script = RetryScript()
    try script.status(status)
    try script.status(status)
    try script.succeed(operation)
    try script.logout()
    let clock = RetryClock()
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    try await disk.perform(operation)
    #expect(await disk.connectionState() == .connected)
    #expect(clock.sleeps == [.milliseconds(500), .seconds(2)])
    #expect(await commandOpcodes(transport) == Array(repeating: opcode(operation), count: 3))
    await disk.close()
    #expect(await session.state == .closed)
}

private struct Exhaustion: Sendable, CustomStringConvertible {
    let status: UInt8
    let sense: Data
    var description: String { "\(status)/\(sense.count)" }
    static let all = [
        Self(status: 8, sense: Data()), Self(status: 0x28, sense: Data()),
        Self(status: 2, sense: attention(0x2F)),
    ]
}

@Test(arguments: DiskOperation.allCases, Exhaustion.all)
private func exhaustedRetriesKeepTheOriginalFailureBehavior(
    _ operation: DiskOperation, _ failure: Exhaustion
) async throws {
    var script = RetryScript()
    for _ in 0..<3 { try script.status(failure.status, sense: failure.sense) }
    try script.logout()
    let (disk, session, transport) = try await retryDisk(script)
    await #expect(throws: ProtocolError.scsiFailure(status: failure.status, sense: failure.sense)) {
        try await disk.perform(operation)
    }
    #expect(await commandOpcodes(transport) == Array(repeating: opcode(operation), count: 3))
    // A failed read alone leaves the disk usable, exactly as without a retry.
    #expect(await disk.connectionState() == (operation == .read ? .connected : .interrupted))
    #expect((disk.mutationEvidence.incident != nil) == (operation != .read))
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func theRetryWindowBoundsTheTotalBackoff() async throws {
    var script = RetryScript()
    try script.status(8)
    try script.status(8)
    try script.logout()
    // The first backoff wakes so late that the second would end beyond ten seconds.
    let clock = RetryClock(overshoot: .milliseconds(9_000))
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    await #expect(throws: ProtocolError.scsiFailure(status: 8, sense: Data())) {
        try await disk.perform(.write)
    }
    #expect(clock.sleeps == [.milliseconds(500)])
    #expect(await commandOpcodes(transport) == [0x2A, 0x2A])
    #expect(await disk.connectionState() == .interrupted)
    await disk.close()
    #expect(await session.state == .closed)
}

private struct Kept: Sendable, CustomStringConvertible {
    let status: UInt8
    let sense: Data
    var description: String { "\(status)/\(Array(sense.prefix(3)))" }
    static let all = [
        Self(status: 2, sense: Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])),
        Self(status: 2, sense: Data([0x72, 4, 0x44, 0, 0, 0, 0, 0])),
        Self(status: 2, sense: Data([0x72, 5, 0x24, 0, 0, 0, 0, 0])),
        Self(status: 2, sense: Data([0x72, 7, 0x27, 0, 0, 0, 0, 0])),
        Self(status: 0x18, sense: Data()),
    ]
}

@Test(arguments: Kept.all)
private func otherWriteFailuresAreNeverRetried(_ failure: Kept) async throws {
    var script = RetryScript()
    try script.status(failure.status, sense: failure.sense)
    try script.logout()
    let (disk, session, transport) = try await retryDisk(script)
    await #expect(throws: ProtocolError.scsiFailure(status: failure.status, sense: failure.sense)) {
        try await disk.perform(.write)
    }
    #expect(await commandOpcodes(transport) == [0x2A])
    #expect(await disk.connectionState() == .interrupted)
    await disk.close()
    #expect(await session.state == .closed)
}

@Test(arguments: [DiskOperation.write, .synchronize])
private func aDeferredUnitAttentionStillLatchesWithoutARetry(_ operation: DiskOperation)
    async throws
{
    let sense = attention(0x29, deferred: true)
    var script = RetryScript()
    try script.status(2, sense: sense)
    let (disk, session, transport) = try await retryDisk(script)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.perform(operation)
    }
    #expect(await commandOpcodes(transport) == [opcode(operation)])
    #expect(await disk.connectionState() == .interrupted)
    #expect(disk.mutationEvidence.incident != nil)
    await disk.close()
    #expect(await session.state != .ready)
}

// REC024: LOGICAL UNIT FAILURE (04h/3Eh/01h) on a READ, as a Windows Server 2025 target whose
// service stops reports it. SessionRecoveryTests covers the lost connection that follows.
private let logicalUnitFailure = Data(windowsLogicalUnitFailure)

@Test func aReadsLogicalUnitFailureIsSentAgainAfterTheBusyBackoff() async throws {
    var script = RetryScript()
    try script.status(2, sense: logicalUnitFailure)
    try script.status(2, sense: logicalUnitFailure)
    try script.succeed(.read)
    try script.logout()
    let clock = RetryClock()
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    #expect(try await disk.read(offset: 0, length: 512) == Data(repeating: 0x5A, count: 512))
    #expect(clock.sleeps == [.milliseconds(500), .seconds(2)])
    #expect(await commandOpcodes(transport) == [0x28, 0x28, 0x28])
    #expect(await disk.connectionState() == .connected)
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func aPersistentLogicalUnitFailureFailsTheReadWithTheOriginalError() async throws {
    var script = RetryScript()
    for _ in 0..<3 { try script.status(2, sense: logicalUnitFailure) }
    try script.logout()
    let clock = RetryClock()
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: logicalUnitFailure)) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(clock.sleeps == [.milliseconds(500), .seconds(2)])
    #expect(await commandOpcodes(transport) == [0x28, 0x28, 0x28])
    #expect(await disk.connectionState() == .connected)
    #expect(disk.mutationEvidence.incident == nil)
    await disk.close()
    #expect(await session.state == .closed)
}

private struct Paused: Sendable, CustomStringConvertible {
    let status: UInt8
    let sense: Data
    var description: String { status == 8 ? "busy" : "logical unit failure" }
    static let all = [
        Self(status: 8, sense: Data()), Self(status: 2, sense: logicalUnitFailure),
    ]
}

@Test(arguments: Paused.all)
private func aPauseTheMacSleepsThroughDoesNotUseUpTheRetryWindow(_ paused: Paused)
    async throws
{
    var script = RetryScript()
    try script.status(paused.status, sense: paused.sense)
    try script.succeed(.read)
    try script.logout()
    // The Mac sleeps for a minute during the half-second pause.
    let clock = RetryClock(asleep: .seconds(60))
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    #expect(try await disk.read(offset: 0, length: 512) == Data(repeating: 0x5A, count: 512))
    #expect(clock.sleeps == [.milliseconds(500)])
    // Counted with the time asleep, the pause ended after the ten-second window.
    #expect(clock.elapsedWithSleep > RemoteDisk.unexecutedRetryWindow)
    #expect(await commandOpcodes(transport) == [0x28, 0x28])
    #expect(await disk.connectionState() == .connected)
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func countedWithTheTimeAsleepTheSamePauseWouldEndTheRetryWindow() async throws {
    var script = RetryScript()
    try script.status(2, sense: logicalUnitFailure)
    try script.logout()
    let clock = RetryClock(asleep: .seconds(60))
    let (disk, session, transport) = try await retryDisk(script, clock: clock, countingSleep: true)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: logicalUnitFailure)) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(clock.sleeps == [.milliseconds(500)])
    #expect(await commandOpcodes(transport) == [0x28])
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func awakeTimePastTheRetryWindowEndsItWithoutAnotherAttempt() async throws {
    var script = RetryScript()
    try script.status(2, sense: logicalUnitFailure)
    try script.logout()
    // The pause wakes ten seconds late in awake time.
    let clock = RetryClock(overshoot: .seconds(10))
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: logicalUnitFailure)) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(clock.sleeps == [.milliseconds(500)])
    #expect(await commandOpcodes(transport) == [0x28])
    #expect(await disk.connectionState() == .connected)
    #expect(disk.mutationEvidence.incident == nil)
    await disk.close()
    #expect(await session.state == .closed)
}

private struct ReadFailure: Sendable, CustomStringConvertible {
    let sense: Data
    let deferred: Bool
    var description: String { Array(sense.prefix(4)).description }
    static let all = [
        // Other HARDWARE ERRORs: internal target failure, and 3Eh with other qualifiers.
        Self(sense: Data([0x72, 4, 0x44, 0, 0, 0, 0, 0]), deferred: false),
        Self(sense: Data([0x72, 4, 0x3E, 0, 0, 0, 0, 0]), deferred: false),
        Self(sense: Data([0x72, 4, 0x3E, 2, 0, 0, 0, 0]), deferred: false),
        // The same code under another key.
        Self(sense: Data([0x72, 3, 0x3E, 1, 0, 0, 0, 0]), deferred: false),
        // Deferred: it reports an earlier command, in fixed and descriptor format.
        Self(
            sense: Data([0xF1, 0, 4, 0, 0, 0, 0, 0x0A, 0, 0, 0, 0, 0x3E, 1, 0, 0, 0, 0]),
            deferred: true),
        Self(sense: Data([0x73, 4, 0x3E, 1, 0, 0, 0, 0]), deferred: true),
    ]
}

@Test(arguments: ReadFailure.all)
private func otherHardwareErrorsOfAReadAreNeverRetried(_ failure: ReadFailure) async throws {
    var script = RetryScript()
    try script.status(2, sense: failure.sense)
    if !failure.deferred { try script.logout() }
    let clock = RetryClock()
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: failure.sense)) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(clock.sleeps.isEmpty)
    #expect(await commandOpcodes(transport) == [0x28])
    #expect(disk.mutationEvidence.incident == nil)
    // A deferred error retires the session, as before; a current one leaves it usable.
    #expect(await disk.connectionState() == (failure.deferred ? .interrupted : .connected))
    await disk.close()
    #expect(await session.state != .ready)
}

@Test(arguments: [DiskOperation.write, .synchronize])
private func aLogicalUnitFailureOfAWriteOrFlushStillLatchesWithoutARetry(
    _ operation: DiskOperation
) async throws {
    var script = RetryScript()
    try script.status(2, sense: logicalUnitFailure)
    try script.logout()
    let clock = RetryClock()
    let (disk, session, transport) = try await retryDisk(script, clock: clock)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: logicalUnitFailure)) {
        try await disk.perform(operation)
    }
    #expect(clock.sleeps.isEmpty)
    #expect(await commandOpcodes(transport) == [opcode(operation)])
    #expect(await disk.connectionState() == .interrupted)
    #expect(
        disk.mutationEvidence.incident?.operation == (operation == .write ? .write : .synchronize))
    for next in DiskOperation.allCases {
        await #expect(throws: ProtocolError.invalidState) { try await disk.perform(next) }
    }
    #expect(await commandOpcodes(transport) == [opcode(operation)])
    await disk.close()
    #expect(await session.state == .closed)
}

@Test func onlyAReadIsSentAgainAfterALogicalUnitFailure() throws {
    let current = try SCSISense(data: logicalUnitFailure)
    let deferred = try SCSISense(data: Data([0x73, 4, 0x3E, 1, 0, 0, 0, 0]))
    let other = try SCSISense(data: Data([0x72, 4, 0x3E, 2, 0, 0, 0, 0]))
    let reads = [
        try SCSICommand.read10(lba: 0, blocks: 1, blockSize: 512),
        try SCSICommand.read16(lba: 0, blocks: 1, blockSize: 512),
    ]
    let others = [
        try SCSICommand.write10(lba: 0, blocks: 1, blockSize: 512),
        try SCSICommand.write16(lba: 0, blocks: 1, blockSize: 512),
        SCSICommand.synchronizeCache10(), .synchronizeCache16(), .inquiry(), .readCapacity16(),
    ]
    for command in reads {
        #expect(RemoteDisk.resendsAfterLogicalUnitFailure(command, sense: current))
        #expect(!RemoteDisk.resendsAfterLogicalUnitFailure(command, sense: deferred))
        #expect(!RemoteDisk.resendsAfterLogicalUnitFailure(command, sense: other))
    }
    for command in others {
        #expect(!RemoteDisk.resendsAfterLogicalUnitFailure(command, sense: current))
    }
}

@Test func theShippingDiskRetainsNoWritePayloadButKeepsItsIncidentLatch() async throws {
    let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    var script = RetryScript()
    try script.written()
    try script.status(2, sense: sense)
    try script.logout()
    let transport = ScriptedTransport(script.responses)
    let session = try ISCSISession(transport: transport, configuration: configuration(normal: true))
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(7), at: 0)
    capacity.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        writeProtection: false, diagnostics: nil)
    try await session.login()
    try await disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
    #expect(disk.mutationEvidence.intents.isEmpty)
    #expect(!disk.mutationEvidence.coverageComplete)
    await #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try await disk.synchronize()
    }
    #expect(disk.mutationEvidence.incident?.operation == .synchronize)
    #expect(disk.mutationEvidence.intents.isEmpty)
    #expect(await disk.connectionState() == .interrupted)
    await #expect(throws: ProtocolError.invalidState) {
        try await disk.write(offset: 0, data: Data(repeating: 0xCC, count: 512))
    }
    await disk.close()
    #expect(await session.state == .closed)
}
