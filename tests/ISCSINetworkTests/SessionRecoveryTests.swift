import FSKit
import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge
@testable import ISCSINetwork

private let original = Data(repeating: 0x11, count: 1024)

private func count(_ opcode: UInt8, in opcodes: some Sequence<UInt8>) -> Int {
    opcodes.filter { $0 == opcode }.count
}

/// Waits until no recovery task runs, so a later change can't race an attempt in progress.
private func waitForRecoveryToStop(_ f: RecoveryFixture) async throws {
    let recovering = f.recovering
    try await recoveryPhase("recovery to stop") { await !recovering.isRecoveryTaskRunning }
}

/// Waits for the recovery task's next sleep, makes `change`, then wakes it.
private func wakeNextAttempt(_ f: RecoveryFixture, after change: () -> Void) async throws {
    let time = f.time
    let now = time.now
    try await recoveryPhase("the next attempt") { time.deadlines.contains { $0 > now } }
    change()
    try await f.advanceToNextSleeper()
}

@Test func aDroppedReadWaitsForARevalidatedSessionThenRunsAgain() async throws {
    let f = try await RecoveryFixture()
    let start = f.opcodes.count
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    try await f.waitForBlockedCommands()
    #expect(await f.disk.connectionState() == .reconnecting)
    #expect(await f.recovering.epoch == 0)
    try await f.releaseNextAttempt()
    #expect(try await read.value == original)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    #expect(f.backing.acceptedLogins == 2)
    // The interrupted READ, the opening's own queries on the new session, then the READ again.
    #expect(Array(f.opcodes[start...]) == [0x28, 0x12, 0x9E, 0x5A, 0x12, 0x28])
    await f.disk.close()
    #expect(await f.recovering.health() == .closed)
}

private enum RestartPoint: String, CaseIterable { case dataOut, synchronization }

@Test(arguments: RestartPoint.allCases)
private func aWriteSpanningARestartIsSentAgainAndFlushedWithinOneEpoch(_ point: RestartPoint)
    async throws
{
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let payload = Data((0..<3072).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 1) })
    switch point {
    // The first 1 KiB chunk is acknowledged, then the target restarts during the second.
    case .dataOut: f.backing.arm(.restart, on: 0x2A, phase: .dataOut, skipping: 1)
    // Every chunk is acknowledged, then the target restarts before answering the flush.
    case .synchronization: f.backing.arm(.restart, on: 0x35)
    }
    let start = f.opcodes.count
    let write = Task { try await volume.write(contents: payload, to: volume.imageItem, at: 4096) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    #expect(try await write.value == payload.count)
    // The restart discarded acknowledged chunks with its cache. They are on stable media only
    // because the whole callback was sent again and flushed in the new epoch.
    #expect(f.backing.resets == 1)
    #expect(f.backing.stableMedia[4096..<(4096 + 3072)] == payload)
    #expect(await f.recovering.epoch == 1)
    let issued = f.opcodes[start...]
    #expect(count(0x2A, in: issued) == (point == .dataOut ? 2 + 2 + 3 : 3 + 3))
    #expect(count(0x35, in: issued) == (point == .dataOut ? 2 : 3))
    #expect(issued.last == 0x35)
    await volume.shutdown()
}

@Test func aResetReportedWithoutALostConnectionBeginsAnEpochAndRedoesTheWrite() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let payload = Data((0..<3072).map { UInt8(truncatingIfNeeded: $0 &+ 3) })
    f.backing.arm(.reset, on: 0x2A, skipping: 1)
    let start = f.opcodes.count
    #expect(try await volume.write(contents: payload, to: volume.imageItem, at: 0) == 3072)
    #expect(f.backing.stableMedia.prefix(3072) == payload)
    #expect(await f.recovering.epoch == 1)
    #expect(f.backing.acceptedLogins == 1)
    // The unit attention, the shared revalidation, the retried chunk, then the whole redo.
    #expect(
        Array(f.opcodes[start...]) == [
            0x2A, 0x2A, 0x12, 0x9E, 0x5A, 0x12, 0x2A, 0x2A, 0x35, 0x2A, 0x2A, 0x2A, 0x35,
        ])
    await volume.shutdown()
}

@Test func aWriteThatNeverCompletesWithinOneEpochIsBoundedAndLatchesTheDisk() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    // Every pass's WRITE reports another reset, then runs once more, so every pass ends in
    // a new epoch. Each reset is reported only once, within the unit-attention retry limit.
    f.backing.arm(.reset, on: 0x2A)
    for _ in 0..<SessionRecovery.maximumRedoPasses { f.backing.arm(.reset, on: 0x2A, skipping: 1) }
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(
            contents: Data(repeating: 0x5C, count: 1024), to: volume.imageItem, at: 0)
    }
    // The original pass and its redos, each a reported reset and the retried WRITE.
    #expect(count(0x2A, in: f.opcodes) == 2 * (SessionRecovery.maximumRedoPasses + 1))
    #expect(await f.recovering.epoch == UInt64(SessionRecovery.maximumRedoPasses + 1))
    #expect(await f.disk.connectionState() == .interrupted)
    await #expect(throws: SessionRecoveryError.writeRedoLimitExceeded) {
        try await f.disk.read(offset: 0, length: 1024)
    }
    await volume.shutdown()
}

@Test func anUnansweredHeartbeatReconnectsWithoutWaitingIO() async throws {
    let sessionTime = ManualSessionTime()
    let f = try await RecoveryFixture(sessionTime: sessionTime)
    f.backing.change { $0.answersHeartbeats = false }
    let recovering = f.recovering
    // The idle session pings after the default ten-second interval and gives up after five.
    try await recoveryPhase("the heartbeat interval") {
        sessionTime.hasSleeper(after: .seconds(10))
    }
    sessionTime.advance(by: .seconds(10), wakeTimers: true)
    try await recoveryPhase("the heartbeat timeout") { sessionTime.hasSleeper(after: .seconds(15)) }
    #expect(await !recovering.isRecovering)
    sessionTime.advance(by: .seconds(5), wakeTimers: true)
    // The session's termination starts recovery itself; nothing reads its state.
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    #expect(await f.disk.connectionState() == .reconnecting)
    #expect(await f.first.heartbeatsIgnored > 0)
    f.backing.change { $0.answersHeartbeats = true }
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(await f.disk.connectionState() == .connected)
    #expect(await f.recovering.epoch == 1)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await f.disk.close()
}

@Test(arguments: [(UInt8(2), UInt16(5)), (3, 5), (1, 0)])
private func aTargetRequestToEndTheConnectionWaitsItsTime2WaitThenReconnects(
    _ event: (UInt8, UInt16)
) async throws {
    let f = try await RecoveryFixture()
    try await f.first.sendAsyncEvent(event.0, parameter2: event.1)
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    // A dropped connection, or all of them, waits the event's Time2Wait; a requested Logout
    // first completes, then waits the negotiated DefaultTime2Wait.
    try await f.releaseNextAttempt(
        after: event.0 == 1 ? RecoveryFixture.initialDelay : .seconds(Int64(event.1)))
    try await f.waitForHealth(.ready)
    #expect(await f.recovering.epoch == 1)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await f.disk.close()
}

@Test func loginFailuresThatCanClearAreRetriedWithBackoff() async throws {
    let f = try await RecoveryFixture()
    f.backing.scriptLogins([.refuse, .reject(2, 3), .reject(3, 1)])
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    // DefaultTime2Wait, then 2, 4 and 8 seconds after a refused connection, a target that
    // wasn't found (0203) and a target error (0300).
    for delay in [Duration.seconds(2), .seconds(2), .seconds(4), .seconds(8)] {
        try await f.releaseNextAttempt(after: delay)
    }
    #expect(try await read.value == original)
    #expect(await f.recovering.loginAttempts == 4)
    #expect(f.backing.acceptedLogins == 2)
    await f.disk.close()
}

// 0201 and 0202 are retried for a while; see the authorization tests below.
@Test(arguments: [(UInt8(2), UInt8(7)), (2, 0)])
private func loginRejectionsThatCannotClearStopTheDisk(_ status: (UInt8, UInt8)) async throws {
    let f = try await RecoveryFixture()
    f.backing.scriptLogins([.reject(status.0, status.1)])
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    let rejection = ProtocolError.loginRejected(statusClass: status.0, detail: status.1)
    await #expect(throws: rejection) { try await read.value }
    #expect(await f.recovering.health() == .failed)
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    let connections = f.backing.connections.count
    await #expect(throws: rejection) { try await f.disk.read(offset: 0, length: 1024) }
    f.time.advance(by: .seconds(600))
    #expect(f.backing.connections.count == connections)
    #expect(await f.recovering.loginAttempts == 1)
    await f.disk.close()
}

private struct DeviceChange: Sendable, CustomStringConvertible {
    let description: String
    let apply: @Sendable (RecoveryBacking) -> Void
    let error: SessionRecoveryError

    static let all = [
        Self(description: "capacity", apply: { $0.lastBlock = 2047 }, error: .deviceChanged),
        Self(
            description: "block size",
            apply: {
                $0.blockSize = 4096
                $0.lastBlock = 127
            }, error: .deviceChanged),
        Self(
            description: "write protection", apply: { $0.writeProtected = true },
            error: .deviceChanged),
        Self(
            description: "logical unit name",
            apply: { $0.designator = [1, 3, 0, 8, 0x50, 0, 0, 0, 0, 0, 0, 2] },
            error: .deviceChanged),
        Self(
            description: "no logical unit name", apply: { $0.designator = nil },
            error: .deviceChanged),
        Self(description: "device type", apply: { $0.deviceType = 5 }, error: .deviceChanged),
        Self(
            description: "portal group", apply: { $0.portalGroupTag = 2 },
            error: .portalGroupChanged),
    ]
}

@Test(arguments: DeviceChange.all)
private func aDifferentDeviceAfterLoggingInAgainStopsTheDisk(_ change: DeviceChange) async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    f.backing.change(change.apply)
    try await f.releaseNextAttempt()
    await #expect(throws: change.error) { try await read.value }
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    // No command reaches the other device, including the interrupted READ.
    #expect(count(0x28, in: f.opcodes) == 1)
    await #expect(throws: change.error) {
        try await f.disk.write(offset: 0, data: Data(repeating: 1, count: 512))
    }
    #expect(count(0x2A, in: f.opcodes) == 0)
    #expect(f.backing.connections.count == 2)
    await f.disk.close()
}

@Test func theConnectorsPortalGroupCheckAlsoStopsTheDisk() async throws {
    let f = try await RecoveryFixture(expectsPortalGroup: true)
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    f.backing.change { $0.portalGroupTag = 2 }
    try await f.releaseNextAttempt()
    await #expect(throws: ProtocolError.malformed("target portal group")) { try await read.value }
    #expect(await f.disk.connectionState() == .interrupted)
    await f.disk.close()
}

@Test func anIdentityQueryThatFailsAfterLoggingInAgainIsAskedAgainLater() async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.drop, on: 0x28)
    f.backing.change { $0.abortedIdentityQueries = 1 }
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    // The device matches, but its names are unknown: not a different device. Log in again.
    try await f.releaseNextAttempt()
    try await f.releaseNextAttempt(after: SessionRecovery.backoff[0])
    #expect(try await read.value == original)
    #expect(f.backing.acceptedLogins == 3)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    await f.disk.close()
}

@Test func onlyARejectedIdentityPageMeansTheDeviceHasNoNames() async throws {
    let f = try await RecoveryFixture()
    let session = f.recovering.initialSession
    let lun = try LogicalUnit(0)
    f.backing.change { $0.abortedIdentityQueries = 1 }
    await #expect(throws: DiskProbeIssue.commandFailed(status: 2)) {
        try await DiskProbe.logicalUnitDesignator(session: session, lun: lun)
    }
    #expect(try await DiskProbe.logicalUnitDesignator(session: session, lun: lun) != nil)
    f.backing.change { $0.designator = nil }
    #expect(try await DiskProbe.logicalUnitDesignator(session: session, lun: lun) == nil)
    await f.disk.close()
}

@Test func aBlockedReadFailsAfterItsWindowAndRecoveryContinues() async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    await #expect(throws: SessionRecoveryError.recoveryWindowExpired) { try await read.value }
    #expect(await f.recovering.isRecovering)
    #expect(await f.disk.connectionState() == .reconnecting)
    try await wakeNextAttempt(f) { f.backing.change { $0.refusing = false } }
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    #expect(await f.recovering.epoch == 1)
    await f.disk.close()
}

@Test(arguments: [UInt8(0x2A), 0x35])
private func aBlockedWriteOrFlushFailsAfterItsWindowAndLatchesTheDisk(_ opcode: UInt8)
    async throws
{
    let f = try await RecoveryFixture()
    if opcode == 0x35 {
        // An acknowledged write not yet flushed: the flush has something to make durable.
        try await f.disk.write(offset: 0, data: Data(repeating: 0x5A, count: 512))
        #expect(!f.disk.coverage.isClean)
    }
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: opcode)
    let operation = Task {
        if opcode == 0x2A {
            try await f.disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        } else {
            try await f.disk.synchronize()
        }
    }
    try await f.waitForBlockedCommands()
    #expect(count(opcode, in: f.opcodes) == 1)
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    await #expect(throws: SessionRecoveryError.recoveryWindowExpired) { try await operation.value }
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    f.backing.change { $0.refusing = false }
    f.time.advance(by: .seconds(600))
    await #expect(throws: SessionRecoveryError.recoveryWindowExpired) {
        try await f.disk.read(offset: 0, length: 1024)
    }
    #expect(f.backing.acceptedLogins == 1)
    await f.disk.close()
}

@Test func aPartialWriteWhoseReadExpiresLatchesTheDisk() async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: 0x28)
    // An unaligned write first reads its blocks; that read waits for the write's window.
    let write = Task { try await f.disk.write(offset: 10, data: Data(repeating: 0xA5, count: 100)) }
    try await f.waitForBlockedCommands()
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    await #expect(throws: SessionRecoveryError.recoveryWindowExpired) { try await write.value }
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    #expect(count(0x2A, in: f.opcodes) == 0)
    #expect(f.backing.acceptedLogins == 1)
    await f.disk.close()
}

@Test func anIdleOutageLongerThanTheWindowKeepsRetryingAndRecovers() async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    await f.first.drop()
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    var slept: [Duration] = []
    while f.time.now < .seconds(600) { slept.append(try await f.advanceToNextSleeper()) }
    #expect(slept.prefix(5) == [.seconds(2), .seconds(2), .seconds(4), .seconds(8), .seconds(15)])
    #expect(slept.dropFirst(4).allSatisfy { $0 == .seconds(15) })
    // The last advance only resumes the recovery loop; it counts that wake's attempt after an
    // executor hop. Once it sleeps for the next backoff the attempt has been counted and the
    // count can't change, so compare there: one attempt for every backoff, none extra.
    let time = f.time
    let woken = time.now
    try await recoveryPhase("the backoff after the last attempt") {
        time.hasSleeper(until: woken + .seconds(15))
    }
    #expect(await f.recovering.health() == .reconnecting)
    #expect(await f.recovering.loginAttempts == slept.count)
    try await wakeNextAttempt(f) { f.backing.change { $0.refusing = false } }
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    #expect(await f.recovering.epoch == 1)
    await f.disk.close()
}

private enum Abandonment: String, CaseIterable { case unmount, deactivate, unload, control }

@Test(arguments: Abandonment.allCases)
private func abandoningRecoveryFailsBlockedIOAtOnceAndStopsLoggingIn(_ how: Abandonment)
    async throws
{
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    f.backing.arm(.drop, on: 0x28)
    let read = Task {
        try await volume.readChunks(
            from: volume.imageItem, at: 0, length: 1024, bufferLength: 1024,
            consume: { _, _ in })
    }
    try await f.waitForBlockedCommands()
    switch how {
    case .unmount: await volume.unmount()
    case .deactivate: try await volume.deactivate()
    case .unload: await volume.shutdown()
    case .control:
        try await volume.setXattr(
            named: FSFileName(string: ConnectionDescriptor.connectionControlAttributeName),
            to: ConnectionDescriptor.abandonRecoveryControlValue, on: volume.rootItem,
            policy: .alwaysSet)
    }
    // No time passes: the waiting callback is released by the request itself.
    await #expect(throws: POSIXError(.EIO)) { try await read.value }
    try await waitForRecoveryToStop(f)
    f.time.advance(by: .seconds(600))
    #expect(await f.recovering.loginAttempts == 0)
    #expect(f.backing.connections.count == 1)
    #expect(await f.disk.connectionState() == (how == .control ? .interrupted : .closed))
    await volume.shutdown()
}

@Test func theConnectionControlIsWriteOnlyAndAcceptsOnlyAbandon() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let name = FSFileName(string: ConnectionDescriptor.connectionControlAttributeName)
    for item in [volume.rootItem, volume.imageItem] {
        await #expect(throws: POSIXError(.ENOATTR)) {
            try await volume.xattr(named: name, of: item)
        }
        #expect(try await !volume.xattrs(of: item).contains(name))
        for value: Data? in [nil, Data(), Data("Abandon".utf8), Data("abandon\n".utf8)] {
            await #expect(throws: POSIXError(.EINVAL)) {
                try await volume.setXattr(named: name, to: value, on: item, policy: .alwaysSet)
            }
        }
    }
    #expect(await f.disk.connectionState() == .connected)
    // A healthy connection keeps working; only a later loss is no longer recovered.
    try await volume.setXattr(
        named: name, to: ConnectionDescriptor.abandonRecoveryControlValue, on: volume.imageItem,
        policy: .alwaysSet)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    f.backing.arm(.drop, on: 0x28)
    await #expect(throws: ProtocolError.connectionClosed) {
        try await f.disk.read(offset: 0, length: 1024)
    }
    #expect(await f.disk.connectionState() == .interrupted)
    #expect(await f.recovering.loginAttempts == 0)
    await volume.shutdown()
}

@Test(arguments: [false, true])
private func cancellingABlockedCallbackReturnsAtOnceAndRecoveryContinues(_ write: Bool)
    async throws
{
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    f.backing.arm(.drop, on: write ? 0x2A : 0x28)
    let blocked = Task {
        if write {
            _ = try await volume.write(
                contents: Data(repeating: 0xEE, count: 1024), to: volume.imageItem, at: 0)
        } else {
            _ = try await volume.readChunks(
                from: volume.imageItem, at: 0, length: 1024, bufferLength: 1024,
                consume: { _, _ in })
        }
    }
    try await f.waitForBlockedCommands()
    blocked.cancel()
    await #expect(throws: POSIXError(.ECANCELED)) { try await blocked.value }
    #expect(await f.recovering.waitingCount == 0)
    guard !write else {
        // The dropped WRITE was sent: the target may have applied it. The callback that is
        // told it failed can't be resumed later, so the disk stops.
        #expect(await f.disk.connectionState() == .interrupted)
        try await expectLatched(f, .mutationInterrupted)
        try await waitForRecoveryToStop(f)
        #expect(f.backing.acceptedLogins == 1)
        await volume.shutdown()
        return
    }
    // A read changes nothing: recovery continues.
    #expect(await f.recovering.isRecovering)
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await volume.shutdown()
}

@Test func cancellingAWriteBlockedBeforeSendingAnythingDoesNotLatch() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    await f.first.drop()
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    let issued = count(0x2A, in: f.opcodes)
    let blocked = Task {
        _ = try await volume.write(
            contents: Data(repeating: 0xEE, count: 2048), to: volume.imageItem, at: 0)
    }
    try await f.waitForBlockedCommands()
    blocked.cancel()
    await #expect(throws: POSIXError(.ECANCELED)) { try await blocked.value }
    // Nothing of the callback reached the target: nothing is latched.
    #expect(count(0x2A, in: f.opcodes) == issued)
    #expect(await f.recovering.isRecovering)
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await volume.shutdown()
}

@Test func cancellingAWriteBlockedAfterPartOfItWasSentLatchesTheDisk() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    // The first 1 KiB chunk is acknowledged; the connection is lost on the second.
    f.backing.arm(.drop, on: 0x2A, skipping: 1)
    let blocked = Task {
        _ = try await volume.write(
            contents: Data(repeating: 0xEE, count: 2048), to: volume.imageItem, at: 0)
    }
    try await f.waitForBlockedCommands()
    blocked.cancel()
    await #expect(throws: POSIXError(.ECANCELED)) { try await blocked.value }
    #expect(await f.disk.connectionState() == .interrupted)
    try await expectLatched(f, .mutationInterrupted)
    try await waitForRecoveryToStop(f)
    #expect(f.backing.acceptedLogins == 1)
    await volume.shutdown()
}

@Test func cancellingAReadTheTargetHoldsEndsTheSessionAndRecoveryContinues() async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.hold, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    let backing = f.backing
    try await recoveryPhase("the held read") { backing.held == 1 }
    read.cancel()
    await #expect(throws: CancellationError.self) { try await read.value }
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    #expect(await f.recovering.epoch == 1)
    await f.disk.close()
}

@Test(arguments: [(UInt8(0x2A), RecoveryBacking.Phase.command), (0x2A, .dataOut), (0x35, .command)])
private func cancellingAWriteOrFlushTheTargetHoldsLatchesTheDisk(
    _ opcode: UInt8, _ phase: RecoveryBacking.Phase
) async throws {
    let f = try await RecoveryFixture()
    if opcode == 0x35 {
        // A flush with nothing to make durable isn't sent; give this one something.
        try await f.disk.write(offset: 0, data: Data(repeating: 0x5A, count: 512))
    }
    f.backing.arm(.hold, on: opcode, phase: phase)
    let operation = Task {
        if opcode == 0x2A {
            try await f.disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        } else {
            try await f.disk.synchronize()
        }
    }
    let backing = f.backing
    try await recoveryPhase("the held command") { backing.held == 1 }
    operation.cancel()
    await #expect(throws: CancellationError.self) { try await operation.value }
    // Whether the target applied it is unknown, so no later I/O is admitted.
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    await #expect(throws: SessionRecoveryError.mutationInterrupted) {
        try await f.disk.read(offset: 0, length: 1024)
    }
    #expect(f.backing.acceptedLogins == 1)
    await f.disk.close()
}

@Test func aReconnectingVolumeReportsItsStateAndStillAdmitsOpens() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    // Acknowledged but not yet flushed, so closing the last writer has a flush to send.
    try await f.disk.write(offset: 0, data: Data(repeating: 0x5A, count: 512))
    await f.first.drop()
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    let state = FSFileName(string: ConnectionDescriptor.connectionStateAttributeName)
    #expect(
        try await volume.xattr(named: state, of: volume.rootItem)
            == DiskConnectionState.reconnecting.encoded)
    try await volume.openItem(volume.imageItem, modes: [.read, .write])
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(
        try await volume.xattr(named: state, of: volume.rootItem)
            == DiskConnectionState.connected.encoded)
    // The last writer's flush runs on the new session.
    try await volume.closeItem(volume.imageItem, modes: [])
    #expect(f.opcodes.last == 0x35)
    await volume.shutdown()
}

@Test func aDeferredErrorStopsTheDiskInsteadOfReconnecting() async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.deferred, on: 0x28)
    await #expect(throws: ProtocolError.self) { try await f.disk.read(offset: 0, length: 1024) }
    #expect(await f.disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    f.time.advance(by: .seconds(600))
    #expect(await f.recovering.loginAttempts == 0)
    #expect(f.backing.connections.count == 1)
    await f.disk.close()
}

@Test func aDiskWithoutAConnectorNeverReconnects() async throws {
    let backing = RecoveryBacking()
    let connection = backing.makeConnection()
    try await connection.connect()
    let session = try ISCSISession(
        transport: connection, configuration: configuration(normal: true))
    try await session.login()
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(1023), at: 0)
    capacity.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        writeProtection: false, diagnostics: nil)
    backing.arm(.drop, on: 0x28)
    await #expect(throws: ProtocolError.connectionClosed) {
        try await disk.read(offset: 0, length: 512)
    }
    #expect(await disk.connectionState() == .interrupted)
    #expect(await disk.connectionEpoch() == 0)
    #expect(backing.connections.count == 1)
    await disk.close()
}

/// A task's outcome, polled, so a task that never finishes fails within two seconds of real
/// time instead of hanging the test run.
private final class Completion<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, any Error>?
    var value: Result<Value, any Error>? { lock.withLock { result } }
    func finish(_ value: Result<Value, any Error>) { lock.withLock { result = value } }
}

private func finished<Value: Sendable>(
    _ task: Task<Value, any Error>, _ description: String = "the operation"
) async throws -> Result<Value, any Error> {
    let completion = Completion<Value>()
    Task { completion.finish(await task.result) }
    try await recoveryPhase(description) { completion.value != nil }
    return try #require(completion.value)
}

private func failure<Value>(_ result: Result<Value, any Error>) -> (any Error)? {
    if case .failure(let error) = result { return error }
    return nil
}

/// What a device reports while asked whether it is still the disk that was opened.
private enum TransientStatus: String, CaseIterable {
    case notReady, busy, aborted, threeAttentions

    var fault: RecoveryBacking.Fault {
        switch self {
        case .notReady: .status(2, key: 2, asc: 4)
        case .busy: .status(8)
        case .aborted: .status(2, key: 0x0B, asc: 0x47)
        // More than the query's own unit attention retries take.
        case .threeAttentions: .attentions([0x29, 0x29, 0x29], losingCache: false)
        }
    }
}

@Test(arguments: TransientStatus.allCases)
private func aResetFollowedByATransientStatusIsAskedAgainWithoutLatching(
    _ status: TransientStatus
) async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.reset, on: 0x28)
    f.backing.arm(status.fault, on: 0x9E)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    // The revalidation found the device busy or not ready, and waits before asking again.
    try await f.releaseNextAttempt(after: SessionRecovery.revalidationBackoff[0])
    #expect(try await finished(read).get() == original)
    #expect(await f.disk.connectionState() == .connected)
    #expect(await f.recovering.epoch == 1)
    #expect(f.disk.mutationEvidence.incident == nil)
    #expect(await f.recovering.loginAttempts == 0)
    await f.disk.close()
}

@Test(arguments: TransientStatus.allCases)
private func aTransientStatusAfterLoggingInAgainIsAskedAgainLater(_ status: TransientStatus)
    async throws
{
    let f = try await RecoveryFixture()
    f.backing.arm(.drop, on: 0x28)
    f.backing.arm(status.fault, on: 0x9E)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    try await f.releaseNextAttempt(after: SessionRecovery.backoff[0])
    #expect(try await finished(read).get() == original)
    #expect(f.backing.acceptedLogins == 3)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    await f.disk.close()
}

@Test(arguments: [false, true])
private func aDeviceNotReadyForTheWholeWindowIsNeverUsedUnchecked(_ write: Bool) async throws {
    let f = try await RecoveryFixture()
    f.backing.arm(.reset, on: write ? 0x2A : 0x28)
    f.backing.change { $0.notReady = true }
    let operation = Task {
        if write {
            try await f.disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512))
        } else {
            _ = try await f.disk.read(offset: 0, length: 1024)
        }
    }
    // Asked again after each wait, as long as the next answer could come within the window.
    var waited = Duration.zero
    var attempt = 0
    while true {
        let backoff = SessionRecovery.revalidationBackoff
        let wait = backoff[min(attempt, backoff.count - 1)]
        guard waited + wait < SessionRecovery.defaultRecoveryWindow else { break }
        try await f.releaseNextAttempt(after: wait)
        waited += wait
        attempt += 1
    }
    let error = failure(try await finished(operation))
    #expect(error as? SessionRecoveryError == .recoveryWindowExpired)
    #expect(f.time.now == waited)
    #expect(count(0x2A, in: f.opcodes) == (write ? 1 : 0))
    f.backing.change { $0.notReady = false }
    if write {
        // A write that couldn't run latches the disk, as after a reconnection too slow.
        #expect(await f.disk.connectionState() == .interrupted)
        await #expect(throws: SessionRecoveryError.recoveryWindowExpired) {
            try await f.disk.read(offset: 0, length: 1024)
        }
        #expect(f.backing.acceptedLogins == 1)
    } else {
        // The unconfirmed device is replaced by a new login, which revalidates it first.
        #expect(await f.disk.connectionState() == .reconnecting)
        try await f.releaseNextAttempt()
        try await f.waitForHealth(.ready)
        #expect(f.backing.acceptedLogins == 2)
        #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    }
    await f.disk.close()
}

@Test(arguments: [RecoveryBacking.Fault.status(8), .status(2, key: 6, asc: 0x2F)])
private func anUnexecutedFirstCommandAfterALongReconnectionIsRetried(
    _ refusal: RecoveryBacking.Fault
) async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: 0x2A)
    f.backing.arm(refusal, on: 0x2A)
    let write = Task { try await f.disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512)) }
    try await f.waitForBlockedCommands()
    // Logging in again takes 16 seconds, longer than the ten-second retry window.
    try await f.releaseNextAttempt()
    try await f.releaseNextAttempt(after: .seconds(2))
    try await f.releaseNextAttempt(after: .seconds(4))
    let time = f.time
    try await recoveryPhase("the fourth attempt") { time.hasSleeper(until: .seconds(16)) }
    f.backing.change { $0.refusing = false }
    time.advance(by: .seconds(8))
    if refusal == .status(8) {
        try await f.releaseNextAttempt(after: RemoteDisk.busyBackoff[0])
    }
    try await finished(write).get()
    #expect(await f.disk.connectionState() == .connected)
    #expect(f.disk.mutationEvidence.incident == nil)
    #expect(count(0x2A, in: f.opcodes) == 3)
    await f.disk.close()
}

@Test func queuedReadsShareTheirOutagesWindow() async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: 0x28)
    let reads = (0..<3).map { _ in Task { try await f.disk.read(offset: 0, length: 1024) } }
    try await f.waitForBlockedCommands()
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    // The first read waited the window; the others, queued behind it, fail at once.
    for read in reads {
        let error = failure(try await finished(read, "every queued read"))
        #expect(error as? SessionRecoveryError == .recoveryWindowExpired)
    }
    #expect(f.time.now == SessionRecovery.defaultRecoveryWindow)
    #expect(await f.disk.connectionState() == .reconnecting)
    // A new read still fails at once, until a session is adopted again.
    await #expect(throws: SessionRecoveryError.recoveryWindowExpired) {
        try await f.disk.read(offset: 0, length: 1024)
    }
    try await wakeNextAttempt(f) { f.backing.change { $0.refusing = false } }
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await f.disk.close()
}

@Test(arguments: [false, true])
private func aStatusDeliveredWhileTheSessionEndsIsNeverSentAgain(_ deferred: Bool)
    async throws
{
    let f = try await RecoveryFixture()
    // A medium error on this read, or a deferred error for an earlier write.
    let sense: [UInt8] =
        deferred ? [0x73, 3, 0x0C, 0, 0, 0, 0, 0] : [0x72, 3, 0x11, 0, 0, 0, 0, 0]
    f.backing.arm(.statusThenLogoutRequest(sense: sense), on: 0x28)
    let issued = count(0x28, in: f.opcodes)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    let error = failure(try await finished(read))
    #expect(error as? ProtocolError == .scsiFailure(status: 2, sense: Data(sense)))
    #expect(count(0x28, in: f.opcodes) == issued + 1)
    if deferred {
        // Data already acknowledged may be lost: the disk stops instead of reconnecting.
        #expect(await f.disk.connectionState() == .interrupted)
        try await waitForRecoveryToStop(f)
        f.time.advance(by: .seconds(600))
        #expect(await f.recovering.loginAttempts == 0)
    } else {
        // The session ended at the target's request; the next one serves later reads.
        try await f.releaseNextAttempt()
        try await f.waitForHealth(.ready)
        #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    }
    await f.disk.close()
}

// REC024: a Windows Server 2025 target whose service stops answers the READ in flight with
// LOGICAL UNIT FAILURE, announces 20-35 µs later that it drops all connections (event 3,
// Time2Wait 5, Time2Retain 0), and closes the connection about 2 ms after that.

@Test func aReadFailedByAStoppingTargetIsSentAgainAfterTheReconnection() async throws {
    let f = try await RecoveryFixture()
    let time = f.time
    let recovering = f.recovering
    f.backing.arm(.sense(windowsLogicalUnitFailure), on: 0x28)
    let start = f.opcodes.count
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    // The status reaches the disk before the lost connection does: it pauses before sending
    // the READ again, while the session still looks ready.
    try await recoveryPhase("the pause") { time.hasSleeper(until: .milliseconds(500)) }
    #expect(await recovering.health() == .ready)
    try await f.first.sendAsyncEvent(3, parameter2: 5, closing: true)
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    try await recoveryPhase("the target's Time2Wait") { time.hasSleeper(until: .seconds(5)) }
    time.advance(by: .milliseconds(500))
    // Sent again, the READ waits for the new session instead of landing on the old one.
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt(after: .milliseconds(4_500))
    #expect(try await finished(read).get() == original)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    #expect(f.disk.mutationEvidence.incident == nil)
    #expect(Array(f.opcodes[start...]) == [0x28, 0x12, 0x9E, 0x5A, 0x12, 0x28])
    await f.disk.close()
}

@Test func aReadFailedJustBeforeTheTargetDropsItsConnectionsGetsItsData() async throws {
    let f = try await RecoveryFixture()
    let time = f.time
    let recovering = f.recovering
    f.backing.arm(.senseThenDropAll(sense: windowsLogicalUnitFailure, time2Wait: 5), on: 0x28)
    let start = f.opcodes.count
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    // Whether the READ sees its status or the lost connection first depends on scheduling.
    // Either way it is sent again only on the new session.
    try await recoveryPhase("the pause or a blocked command") {
        if time.hasSleeper(until: .milliseconds(500)) { return true }
        return await recovering.waitingCount == 1
    }
    try await recoveryPhase("the target's Time2Wait") { time.hasSleeper(until: .seconds(5)) }
    time.advance(by: .seconds(5))
    #expect(try await finished(read).get() == original)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    #expect(Array(f.opcodes[start...]) == [0x28, 0x12, 0x9E, 0x5A, 0x12, 0x28])
    await f.disk.close()
}

@Test func aReadSentAgainOnAConnectionThatDropsIsRedoneAfterTheReconnection() async throws {
    let f = try await RecoveryFixture()
    let time = f.time
    f.backing.arm(.sense(windowsLogicalUnitFailure), on: 0x28)
    f.backing.arm(.drop, on: 0x28)
    let start = f.opcodes.count
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    try await recoveryPhase("the pause") { time.hasSleeper(until: .milliseconds(500)) }
    time.advance(by: .milliseconds(500))
    // The READ sent again is cut off with the connection; the lost connection's own recovery
    // sends it once more on the new session.
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    #expect(try await finished(read).get() == original)
    #expect(await f.recovering.epoch == 1)
    #expect(Array(f.opcodes[start...]) == [0x28, 0x28, 0x12, 0x9E, 0x5A, 0x12, 0x28])
    await f.disk.close()
}

@Test func aReadTheLogicalUnitKeepsFailingFailsWithinTheAttemptLimit() async throws {
    let f = try await RecoveryFixture()
    let time = f.time
    for _ in 0..<RemoteDisk.unexecutedAttemptLimit {
        f.backing.arm(.sense(windowsLogicalUnitFailure), on: 0x28)
    }
    let start = f.opcodes.count
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    try await recoveryPhase("the first pause") { time.hasSleeper(until: .milliseconds(500)) }
    time.advance(by: .milliseconds(500))
    try await recoveryPhase("the second pause") { time.hasSleeper(until: .milliseconds(2_500)) }
    time.advance(by: .seconds(2))
    // The original failure, after BUSY's backoff, not after the recovery window.
    let error = failure(try await finished(read))
    #expect(
        error as? ProtocolError
            == .scsiFailure(status: 2, sense: Data(windowsLogicalUnitFailure)))
    #expect(time.now == .milliseconds(2_500))
    #expect(Array(f.opcodes[start...]) == [0x28, 0x28, 0x28])
    #expect(await f.recovering.loginAttempts == 0)
    #expect(await f.recovering.epoch == 0)
    // A failed read alone leaves the disk usable.
    #expect(await f.disk.connectionState() == .connected)
    #expect(f.disk.mutationEvidence.incident == nil)
    #expect(try await f.disk.read(offset: 0, length: 1024) == original)
    await f.disk.close()
}

@Test func aReadPausedWhileTheMacSleepsIsSentAgainAfterWaking() async throws {
    let f = try await RecoveryFixture()
    let time = f.time
    let recovering = f.recovering
    f.backing.arm(.sense(windowsLogicalUnitFailure), on: 0x28)
    let start = f.opcodes.count
    let read = Task { try await f.disk.read(offset: 1024, length: 1024) }
    // The pause before sending the READ again counts the connection's awake time.
    try await recoveryPhase("the pause") { time.hasSleeper(until: .milliseconds(500)) }
    // The Mac sleeps: real time passes beyond the pause and the connection is lost, but no
    // awake time passes. The READ is neither sent again nor failed.
    await f.first.drop()
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    try await recoveryPhase("the reconnection delay") {
        time.hasSleeper(until: RecoveryFixture.initialDelay)
    }
    try await Task.sleep(for: .milliseconds(600))
    #expect(time.hasSleeper(until: .milliseconds(500)))
    #expect(await recovering.waitingCount == 0)
    #expect(Array(f.opcodes[start...]) == [0x28])
    // Awake again, the READ waits for the reconnection and is sent on the new session.
    time.advance(by: .milliseconds(500))
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt(after: RecoveryFixture.initialDelay - .milliseconds(500))
    #expect(try await finished(read).get() == original)
    #expect(await recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    #expect(f.disk.mutationEvidence.incident == nil)
    #expect(Array(f.opcodes[start...]) == [0x28, 0x12, 0x9E, 0x5A, 0x12, 0x28])
    await f.disk.close()
}

@Test func aResetConsumedWhileRevalidatingAnotherAttentionRedoesTheWrite() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let payload = Data((0..<2048).map { UInt8(truncatingIfNeeded: $0 &* 5 &+ 9) })
    // The target loses its cache, holding the first chunk, then reports changed parameters
    // (2Ah) on the second; its reset (29h) is only reported to the revalidation's query.
    f.backing.arm(.attentions([0x2A, 0x29], losingCache: true), on: 0x2A, skipping: 1)
    #expect(try await volume.write(contents: payload, to: volume.imageItem, at: 0) == 2048)
    #expect(f.backing.stableMedia.prefix(2048) == payload)
    #expect(await f.recovering.epoch == 1)
    await volume.shutdown()
}

@Test func aResetReportedOnTheFlushRedoesTheWrite() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let payload = Data((0..<2048).map { UInt8(truncatingIfNeeded: $0 &* 3 &+ 1) })
    f.backing.arm(.reset, on: 0x35)
    #expect(try await volume.write(contents: payload, to: volume.imageItem, at: 0) == 2048)
    #expect(f.backing.stableMedia.prefix(2048) == payload)
    #expect(await f.recovering.epoch == 1)
    #expect(count(0x35, in: f.opcodes) == 3)
    await volume.shutdown()
}

@Test func anAuthorizationRejectionThatClearsWithinItsLimitRecovers() async throws {
    let f = try await RecoveryFixture()
    // A restored portal group whose ACLs aren't restored yet.
    f.backing.scriptLogins([.reject(2, 2)])
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    try await f.releaseNextAttempt(after: SessionRecovery.backoff[0])
    #expect(try await finished(read).get() == original)
    #expect(await f.recovering.loginAttempts == 2)
    #expect(await f.recovering.epoch == 1)
    await f.disk.close()
}

@Test func aPersistentAuthenticationRejectionStopsTheDiskAfterItsLimit() async throws {
    let f = try await RecoveryFixture()
    f.backing.scriptLogins(Array(repeating: .reject(2, 1), count: 8))
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    // The first rejection comes after DefaultTime2Wait; the later ones 2, 6, 14 and 29
    // seconds after it are retried, and the one 44 seconds after it stops the disk.
    for delay in [Duration.seconds(2), .seconds(2), .seconds(4), .seconds(8), .seconds(15)] {
        try await f.releaseNextAttempt(after: delay)
    }
    #expect(await f.recovering.health() == .reconnecting)
    try await f.releaseNextAttempt(after: .seconds(15))
    let error = failure(try await finished(read))
    #expect(error as? ProtocolError == .loginRejected(statusClass: 2, detail: 1))
    #expect(await f.recovering.loginAttempts == 6)
    #expect(await f.disk.connectionState() == .interrupted)
    await f.disk.close()
}

/// A later read fails at once with the latch's error, instead of waiting for a session.
private func expectLatched(_ f: RecoveryFixture, _ expected: SessionRecoveryError) async throws {
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    #expect(
        failure(try await finished(read, "a latched read")) as? SessionRecoveryError == expected)
}

@Test(arguments: Abandonment.allCases)
private func abandoningWhileAskingAResetDeviceAgainStopsTheDiskAtOnce(_ how: Abandonment)
    async throws
{
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    f.backing.arm(.reset, on: 0x28)
    f.backing.change { $0.notReady = true }
    let read = Task {
        try await volume.readChunks(
            from: volume.imageItem, at: 0, length: 1024, bufferLength: 1024,
            consume: { _, _ in })
    }
    // The session stays ready while the device is asked again after a pause.
    let time = f.time
    try await recoveryPhase("a pause before asking again") {
        time.hasSleeper(until: SessionRecovery.revalidationBackoff[0])
    }
    let issued = f.opcodes.count
    switch how {
    case .unmount: await volume.unmount()
    case .deactivate: try await volume.deactivate()
    case .unload: await volume.shutdown()
    case .control:
        try await volume.setXattr(
            named: FSFileName(string: ConnectionDescriptor.connectionControlAttributeName),
            to: ConnectionDescriptor.abandonRecoveryControlValue, on: volume.rootItem,
            policy: .alwaysSet)
    }
    // No time passes, and the unconfirmed device never receives the read again.
    let error = failure(try await finished(read, "the abandoned read"))
    #expect(error as? POSIXError == POSIXError(.EIO))
    #expect(count(0x28, in: f.opcodes[issued...]) == 0)
    #expect(await f.recovering.loginAttempts == 0)
    #expect(await f.disk.connectionState() == (how == .control ? .interrupted : .closed))
    await volume.shutdown()
}

@Test func aWriteAfterTheOutagesWindowExpiredLatchesTheDiskAtOnce() async throws {
    let f = try await RecoveryFixture()
    f.backing.change { $0.refusing = true }
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    #expect(failure(try await finished(read)) as? SessionRecoveryError == .recoveryWindowExpired)
    // The write fails without waiting, and like any write whose window expired, it latches.
    let write = Task { try await f.disk.write(offset: 0, data: Data(repeating: 0xA5, count: 512)) }
    #expect(failure(try await finished(write)) as? SessionRecoveryError == .recoveryWindowExpired)
    #expect(await f.disk.connectionState() == .interrupted)
    #expect(count(0x2A, in: f.opcodes) == 0)
    await f.disk.close()
}

// MARK: Flushes with nothing to make durable

@Test func aFlushOfADiskThatWroteNothingIsNotSent() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    // Opening read the device but sent nothing that could sit in the target's cache.
    #expect(f.disk.coverage.isClean)
    let start = f.opcodes.count
    try await f.disk.synchronize()
    try await volume.synchronize(flags: .wait)
    #expect(Array(f.opcodes[start...]).isEmpty)
    await volume.shutdown()
}

@Test func aDirtyFlushIsSentOnceAndALaterOneIsNot() async throws {
    let f = try await RecoveryFixture()
    try await f.disk.write(offset: 512, data: Data(repeating: 0x3C, count: 512))
    #expect(!f.disk.coverage.isClean)
    // The acknowledged write is only in the target's volatile cache until the flush.
    #expect(f.backing.stableMedia[512..<1024] == Data(repeating: 0x11, count: 512))
    let start = f.opcodes.count
    try await f.disk.synchronize()
    #expect(Array(f.opcodes[start...]) == [0x35])
    #expect(f.backing.stableMedia[512..<1024] == Data(repeating: 0x3C, count: 512))
    #expect(f.disk.coverage.isClean)
    try await f.disk.synchronize()
    #expect(Array(f.opcodes[start...]) == [0x35])
    await f.disk.close()
}

@Test func aCleanFlushDuringAnOutageSucceedsAtOnceAndNeverStopsTheDisk() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    #expect(
        try await volume.write(
            contents: Data(repeating: 0x6B, count: 1024), to: volume.imageItem, at: 0) == 1024)
    #expect(f.disk.coverage.isClean)
    let flushes = count(0x35, in: f.opcodes)
    f.backing.change { $0.refusing = true }
    await f.first.drop()
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    // FSKit's periodic flush, as during an idle outage: answered at once, nothing waits.
    try await volume.synchronize(flags: .wait)
    try await f.disk.synchronize()
    #expect(await f.recovering.waitingCount == 0)
    // Long past the recovery window, still nothing to flush and nothing latched.
    for _ in 0..<40 { try await f.advanceToNextSleeper() }
    #expect(f.time.now > SessionRecovery.defaultRecoveryWindow * 2)
    try await volume.synchronize(flags: .wait)
    try await f.disk.synchronize()
    #expect(await f.disk.connectionState() == .reconnecting)
    #expect(count(0x35, in: f.opcodes) == flushes)
    try await wakeNextAttempt(f) { f.backing.change { $0.refusing = false } }
    try await f.waitForHealth(.ready)
    #expect(try await f.disk.read(offset: 0, length: 1024) == Data(repeating: 0x6B, count: 1024))
    #expect(await f.disk.connectionState() == .connected)
    await volume.shutdown()
}

@Test func aFlushWhoseAnswerCameAfterAReconnectionProvesNothing() async throws {
    let f = try await RecoveryFixture()
    try await f.disk.write(offset: 0, data: Data(repeating: 0x4D, count: 512))
    f.backing.arm(.drop, on: 0x35)
    let flush = Task { try await f.disk.synchronize() }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    try await finished(flush).get()
    #expect(await f.recovering.epoch == 1)
    // A target that restarted may have lost the write before this GOOD: still dirty, and a
    // later flush in the new epoch doesn't cover a write sent in the earlier one either.
    #expect(!f.disk.coverage.isClean)
    let start = f.opcodes.count
    try await f.disk.synchronize()
    #expect(Array(f.opcodes[start...]) == [0x35])
    #expect(!f.disk.coverage.isClean)
    await f.disk.close()
}

@Test func aWriteRedoneAfterARestartIsCleanOnlyAfterItsOwnFlush() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let payload = Data((0..<2048).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 2) })
    // Every chunk is acknowledged, then the target restarts before answering the flush.
    f.backing.arm(.restart, on: 0x35)
    let start = f.opcodes.count
    let write = Task { try await volume.write(contents: payload, to: volume.imageItem, at: 0) }
    try await f.waitForBlockedCommands()
    // The interrupted flush is still waiting: what the first pass sent isn't covered.
    #expect(!f.disk.coverage.isClean)
    try await f.releaseNextAttempt()
    #expect(try await finished(write).get() == 2048)
    #expect(f.backing.stableMedia.prefix(2048) == payload)
    // The reissued flush, the redone chunks and their own flush, all in the new epoch.
    #expect(count(0x35, in: f.opcodes[start...]) == 3)
    #expect(f.disk.coverage.isClean)
    let after = f.opcodes.count
    try await volume.synchronize(flags: .wait)
    #expect(f.opcodes.count == after)
    await volume.shutdown()
}

@Test func aFlushSentWhileAWriteIsInFlightDoesNotCoverIt() {
    let coverage = SynchronizationCoverage()
    #expect(coverage.isClean)
    let first = coverage.beginMutation(epoch: 0)
    coverage.endMutation(first)
    let second = coverage.beginMutation(epoch: 0)
    // Sent before `second` completed: covers only `first`.
    let captured = coverage.capture()
    #expect(captured == first)
    let third = coverage.beginMutation(epoch: 0)
    coverage.synchronized(through: captured, epoch: 0)
    #expect(coverage.cleanGeneration == first && !coverage.isClean)
    coverage.endMutation(second)
    coverage.endMutation(third)
    #expect(!coverage.isClean)
    // A capture never runs ahead of what was issued, and never moves the mark back.
    coverage.synchronized(through: coverage.issuedGeneration + 5, epoch: 0)
    #expect(!coverage.isClean)
    coverage.synchronized(through: coverage.capture(), epoch: 0)
    #expect(coverage.isClean && coverage.cleanGeneration == third)
    coverage.synchronized(through: first, epoch: 0)
    #expect(coverage.isClean)
}

/// A write acknowledged in epoch N may be lost when the target restarts; a GOOD flush in N + 1
/// doesn't bring it back. Only the callback sending it again in N + 1, then a GOOD flush, does.
@Test func aFlushInALaterEpochCoversOnlyWhatWasSentAgainInIt() {
    let coverage = SynchronizationCoverage()
    let early = coverage.beginMutation(epoch: 4)
    coverage.endMutation(early)
    coverage.synchronized(through: coverage.capture(), epoch: 5)
    #expect(!coverage.isClean && coverage.cleanGeneration == 0)
    // The redo in epoch 5, and its own flush: the earlier write still isn't covered...
    let redo = coverage.beginMutation(epoch: 5)
    coverage.endMutation(redo)
    coverage.synchronized(through: coverage.capture(), epoch: 5)
    #expect(!coverage.isClean && coverage.cleanGeneration == 0)
    // ...until the callback that sent it reports that it sent everything again.
    coverage.supersede([early])
    #expect(coverage.isClean && coverage.cleanGeneration == redo)
}

@Test func aWriteAcknowledgedBeforeAReconnectionStaysDirtyAfterALaterFlush() async throws {
    let f = try await RecoveryFixture()
    // Acknowledged in epoch 0, not flushed.
    try await f.disk.write(offset: 0, data: Data(repeating: 0x4E, count: 512))
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 1024, length: 512) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    _ = try await finished(read).get()
    #expect(await f.recovering.epoch == 1)
    // GOOD in epoch 1, but the write may have been lost with the target's cache.
    let start = f.opcodes.count
    try await f.disk.synchronize()
    #expect(!f.disk.coverage.isClean)
    try await f.disk.synchronize()
    #expect(Array(f.opcodes[start...]) == [0x35, 0x35])
    await f.disk.close()
}

/// Up to 65,536 generations may wait for one flush. One more and the disk stays dirty for as
/// long as it is open, even after a flush that covers all of them. A volume flushes at the end
/// of every write callback, so unless an earlier generation is held (see the next test), only
/// one callback's commands, at most nine passes of them, count towards the limit.
@Test func generationsBeyondTheLimitLeaveTheDiskDirtyForGood() {
    let limit = 65_536
    let coverage = SynchronizationCoverage()
    for _ in 0..<limit { coverage.endMutation(coverage.beginMutation(epoch: 0)) }
    coverage.synchronized(through: coverage.capture(), epoch: 0)
    #expect(coverage.isClean && coverage.cleanGeneration == UInt64(limit))
    // A covering flush empties the list: the limit counts what one flush has to cover.
    for _ in 0...limit { coverage.endMutation(coverage.beginMutation(epoch: 0)) }
    coverage.synchronized(through: coverage.capture(), epoch: 0)
    #expect(!coverage.isClean && coverage.cleanGeneration == UInt64(limit))
    for _ in 0..<3 {
        coverage.endMutation(coverage.beginMutation(epoch: 0))
        coverage.synchronized(through: coverage.capture(), epoch: 0)
    }
    #expect(!coverage.isClean && coverage.cleanGeneration == UInt64(limit))
}

/// One generation of an earlier epoch that is never superseded holds every later one: no
/// later GOOD flush cleans the disk, and each later write adds to the list. The stall alone
/// keeps the disk dirty; reaching the limit only makes that permanent even for `supersede`.
@Test(arguments: [false, true])
func anUnsupersededGenerationOfAnEarlierEpochHoldsTheDiskDirty(_ pastTheLimit: Bool) {
    let limit = 65_536
    let coverage = SynchronizationCoverage()
    let stuck = coverage.beginMutation(epoch: 0)
    coverage.endMutation(stuck)
    // With `stuck`, exactly the limit, or one more.
    let later = pastTheLimit ? limit : limit - 1
    for _ in 0..<later { coverage.endMutation(coverage.beginMutation(epoch: 1)) }
    coverage.synchronized(through: coverage.capture(), epoch: 1)
    coverage.synchronized(through: coverage.capture(), epoch: 1)
    #expect(!coverage.isClean && coverage.cleanGeneration == 0)
    coverage.supersede([stuck])
    #expect(coverage.isClean == !pastTheLimit)
    #expect(coverage.cleanGeneration == (pastTheLimit ? 0 : UInt64(limit)))
}

/// A cancelled write that never reached a session has nothing to flush on a later connection.
@Test func cancellingBeforeWriteAdmissionKeepsTheDiskClean() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    await f.first.drop()
    let recovering = f.recovering
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    let blocked = Task {
        _ = try await volume.write(
            contents: Data(repeating: 0xEE, count: 1024), to: volume.imageItem, at: 0)
    }
    try await f.waitForBlockedCommands()
    blocked.cancel()
    await #expect(throws: POSIXError(.ECANCELED)) { try await blocked.value }
    try await f.releaseNextAttempt()
    try await f.waitForHealth(.ready)
    #expect(await f.disk.connectionState() == .connected)
    #expect(count(0x2A, in: f.opcodes) == 0)
    #expect(f.disk.coverage.issuedGeneration == 0 && f.disk.coverage.isClean)
    let start = f.opcodes.count
    try await volume.synchronize(flags: .wait)
    #expect(f.opcodes.count == start)
    let payload = Data(repeating: 0x6B, count: 1024)
    #expect(try await volume.write(contents: payload, to: volume.imageItem, at: 0) == 1024)
    #expect(f.backing.stableMedia.prefix(1024) == payload)
    #expect(f.disk.coverage.isClean)
    f.backing.change { $0.refusing = true }
    let current = try #require(f.backing.connections.last)
    await current.drop()
    try await recoveryPhase("eager recovery") { await recovering.isRecovering }
    f.time.advance(by: SessionRecovery.defaultRecoveryWindow)
    let flushes = count(0x35, in: f.opcodes)
    let flush = Task { try await volume.synchronize(flags: .wait) }
    try await finished(flush).get()
    #expect(await recovering.isRecovering)
    #expect(count(0x35, in: f.opcodes) == flushes)
    await volume.shutdown()
}

/// A failed pre-read during a redo leaves the earlier writes unconfirmed.
@Test func aFailedReadWhileRedoingAnIssuedWriteStopsTheDisk() async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    // 1 KiB at 256: each pass reads 0..<1536 (two READs), writes it (two WRITEs), flushes.
    f.backing.arm(.restart, on: 0x35)
    f.backing.arm(.status(2, key: 3, asc: 0x11), on: 0x28, skipping: 2)
    let issued = f.opcodes.count
    let write = Task {
        try await volume.write(
            contents: Data(repeating: 0xC3, count: 1024), to: volume.imageItem, at: 256)
    }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    #expect(failure(try await finished(write)) as? POSIXError == POSIXError(.EIO))
    #expect(await f.recovering.epoch == 1)
    // The first pass, the revalidation (whose first READ CAPACITY reports the reset), the
    // reissued flush, and the redo's first READ.
    #expect(
        Array(f.opcodes[issued...]) == [
            0x28, 0x28, 0x2A, 0x2A, 0x35, 0x12, 0x9E, 0x9E, 0x5A, 0x12, 0x35, 0x28,
        ])
    #expect(await f.disk.connectionState() == .interrupted)
    #expect(!f.disk.coverage.isClean)
    let afterFailure = f.opcodes.count
    await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
    await #expect(throws: POSIXError(.EIO)) {
        try await volume.write(
            contents: Data(repeating: 0xBE, count: 512), to: volume.imageItem, at: 0)
    }
    #expect(f.opcodes.count == afterFailure)
    #expect(f.backing.stableMedia.prefix(1536) == Data(repeating: 0x11, count: 1536))
    await volume.shutdown()
}

private enum CleanLatch: String, CaseIterable { case abandoned, deviceChanged, deferred, closed }

@Test(arguments: CleanLatch.allCases)
private func aStoppedDiskWithNothingToFlushStillReportsItsError(_ latch: CleanLatch) async throws {
    let f = try await RecoveryFixture()
    let volume = LUNImageVolume(disk: f.disk, identifier: UUID())
    let matches: @Sendable (any Error) -> Bool
    switch latch {
    case .abandoned:
        await f.first.drop()
        let recovering = f.recovering
        try await recoveryPhase("eager recovery") { await recovering.isRecovering }
        await f.disk.abandonConnectionRecovery()
        matches = { $0 as? SessionRecoveryError == .abandoned }
    case .deviceChanged:
        f.backing.arm(.drop, on: 0x28)
        let read = Task { try await f.disk.read(offset: 0, length: 1024) }
        try await f.waitForBlockedCommands()
        f.backing.change { $0.lastBlock = 2047 }
        try await f.releaseNextAttempt()
        _ = try? await read.value
        matches = { $0 as? SessionRecoveryError == .deviceChanged }
    case .deferred:
        f.backing.arm(.deferred, on: 0x28)
        _ = try? await f.disk.read(offset: 0, length: 1024)
        matches = {
            guard case ProtocolError.scsiFailure(let status, let data) = $0,
                let sense = try? SCSISense(data: data)
            else { return false }
            return status == 2 && sense.isDeferred
        }
    case .closed:
        await f.disk.close()
        matches = { $0 as? SessionRecoveryError == .abandoned }
    }
    #expect(f.disk.coverage.isClean)
    let start = f.opcodes.count
    let error = failure(try await finished(Task { try await f.disk.synchronize() }))
    #expect(error.map(matches) == true)
    if latch != .closed {
        await #expect(throws: POSIXError(.EIO)) { try await volume.synchronize(flags: .wait) }
    }
    #expect(count(0x35, in: f.opcodes[start...]) == 0)
    await volume.shutdown()
}

@Test func aSingleSessionDiskWhoseConnectionEndedStillFailsItsFlush() async throws {
    let backing = RecoveryBacking()
    let connection = backing.makeConnection()
    try await connection.connect()
    let session = try ISCSISession(
        transport: connection, configuration: configuration(normal: true))
    try await session.login()
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(1023), at: 0)
    capacity.put(UInt32(512), at: 4)
    let disk = RemoteDisk(
        session: session, lun: try LogicalUnit(0),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), readOnly: false,
        writeProtection: false, diagnostics: nil)
    try await disk.synchronize()
    #expect(!backing.commands.contains(0x35))
    backing.arm(.drop, on: 0x28)
    await #expect(throws: ProtocolError.connectionClosed) {
        try await disk.read(offset: 0, length: 512)
    }
    // Nothing to flush, but the session can't confirm that now: the flush isn't skipped.
    await #expect(throws: (any Error).self) { try await disk.synchronize() }
    await disk.close()
}

@Test func aDiskWithoutAnIdentificationPageOpensAndReconnects() async throws {
    let backing = RecoveryBacking()
    // INQUIRY VPD 83h answers CHECK CONDITION, ILLEGAL REQUEST, from the first login on.
    backing.change { $0.designator = nil }
    let f = try await RecoveryFixture(backing: backing)
    #expect(f.recovering.fingerprint.designator == .absent)
    f.backing.arm(.drop, on: 0x28)
    let read = Task { try await f.disk.read(offset: 0, length: 1024) }
    try await f.waitForBlockedCommands()
    try await f.releaseNextAttempt()
    // Still no names after logging in again: the same device, so the read runs again.
    #expect(try await finished(read).get() == original)
    #expect(await f.recovering.epoch == 1)
    #expect(await f.disk.connectionState() == .connected)
    await f.disk.close()
}

/// Reading the read-only control on a healthy read-only disk does what writing the writable
/// control does on a writable one: the connection keeps working, and only a later loss is no
/// longer recovered.
@Test func theReadOnlyControlOnAHealthyDiskStopsOnlyALaterReconnection() async throws {
    let f = try await RecoveryFixture()
    let disk = RemoteDisk(connection: f.recovering, readOnly: true, diagnostics: nil)
    let volume = LUNImageVolume(disk: disk, identifier: UUID())
    let name = FSFileName(string: ConnectionDescriptor.readOnlyConnectionControlAttributeName)
    #expect(
        try await volume.xattr(named: name, of: volume.imageItem)
            == ConnectionDescriptor.abandonRecoveryControlValue)
    #expect(await disk.connectionState() == .connected)
    #expect(try await disk.read(offset: 0, length: 1024) == original)
    f.backing.arm(.drop, on: 0x28)
    await #expect(throws: ProtocolError.connectionClosed) {
        try await disk.read(offset: 0, length: 1024)
    }
    #expect(await disk.connectionState() == .interrupted)
    try await waitForRecoveryToStop(f)
    f.time.advance(by: .seconds(600))
    #expect(await f.recovering.loginAttempts == 0)
    await volume.shutdown()
}
