import Foundation
import ISCSICore
import Network
import Testing

@testable import ISCSINetwork

/// A manual awake-time clock. Sleepers wake only when the test advances past their deadline.
final class ManualRecoveryTime: @unchecked Sendable {
    private struct Sleeper {
        let deadline: Duration
        let continuation: CheckedContinuation<Void, any Error>
    }
    private let lock = NSLock()
    private var instant = Duration.zero
    private var sleepers: [UUID: Sleeper] = [:]

    var clock: RecoveryClock {
        RecoveryClock(elapsed: { self.now }, sleepUntil: { try await self.sleep(until: $0) })
    }
    var now: Duration { lock.withLock { instant } }
    var deadlines: [Duration] { lock.withLock { sleepers.values.map(\.deadline).sorted() } }

    func hasSleeper(until deadline: Duration) -> Bool {
        lock.withLock { sleepers.values.contains { $0.deadline == deadline } }
    }

    func advance(by duration: Duration) {
        let due: [Sleeper] = lock.withLock {
            instant += duration
            let due = sleepers.filter { $0.value.deadline <= instant }
            for id in due.keys { sleepers.removeValue(forKey: id) }
            return Array(due.values)
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    private func sleep(until deadline: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let ready = lock.withLock { () -> Bool? in
                    if Task.isCancelled { return nil }
                    if deadline <= instant { return true }
                    sleepers[id] = Sleeper(deadline: deadline, continuation: continuation)
                    return false
                }
                switch ready {
                case nil: continuation.resume(throwing: CancellationError())
                case true?: continuation.resume()
                case false?: break
                }
            }
        } onCancel: {
            let sleeper = self.lock.withLock { self.sleepers.removeValue(forKey: id) }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }
}

/// Polls a condition across actor hops, failing after two seconds of real time.
func recoveryPhase(
    _ description: String = "condition", _ condition: @Sendable () async -> Bool
) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else {
            Issue.record("Timed out waiting for \(description)")
            throw ProtocolError.timedOut
        }
        try await Task.sleep(for: .milliseconds(1))
    }
}

/// The persistent state of one simulated target, shared by every connection to it. Writes
/// land in a volatile cache until SYNCHRONIZE CACHE; a restart loses the cache and reports a
/// power-on reset (29h) once to every connection, including later ones.
final class RecoveryBacking: @unchecked Sendable {
    enum Login: Sendable, Equatable {
        case accept
        case refuse
        case reject(UInt8, UInt8)
    }
    enum Fault: Sendable, Equatable {
        /// Close the connection without answering.
        case drop
        /// Lose the volatile cache, then close the connection without answering.
        case restart
        /// Lose the volatile cache and report a reset on this command, keeping the connection.
        case reset
        /// Report a deferred medium error for an earlier, already acknowledged write.
        case deferred
        /// Accept the command, or its data, and never answer it.
        case hold
        /// Answer with this status without running the command: CHECK CONDITION (2) carries a
        /// current sense key and additional sense code; BUSY is 8.
        case status(UInt8, key: UInt8 = 0, asc: UInt8 = 0)
        /// Optionally lose the volatile cache, then report these unit attentions in order, on
        /// this command and the following ones other than INQUIRY.
        case attentions([UInt8], losingCache: Bool)
        /// Answer with CHECK CONDITION and this sense, then at once ask to log out (event 1),
        /// both in one segment, so the session is ending when the status arrives.
        case statusThenLogoutRequest(sense: [UInt8])
        /// Answer with CHECK CONDITION and these sense bytes without running the command.
        case sense([UInt8])
        /// Answer with CHECK CONDITION and this sense, then announce that the target drops all
        /// connections (event 3) with this Time2Wait, each in its own segment, then close the
        /// connection once both were read: a Windows Server target whose service stops.
        case senseThenDropAll(sense: [UInt8], time2Wait: UInt16)
    }
    enum Phase: Sendable, Equatable { case command, dataOut }
    private struct Trigger {
        let opcode: UInt8
        let phase: Phase
        var skip: Int
        let fault: Fault
    }

    static let blockSize = 512
    static let naa: [UInt8] = [1, 3, 0, 8, 0x50, 0, 0, 0, 0, 0, 0, 1]

    private let lock = NSLock()
    private var cache: Data
    private var stable: Data
    private var resetCount = 0
    private var holdCount = 0
    private var attentionQueue: [UInt8] = []
    private var triggers: [Trigger] = []
    private var logins: [Login] = []
    private var made: [RecoveryConnection] = []
    private var log: [UInt8] = []
    private var accepted = 0
    var lastBlock: UInt64 = 1023
    var blockSize: UInt32 = 512
    var writeProtected = false
    var deviceType: UInt8 = 0
    var designator: [UInt8]? = RecoveryBacking.naa
    var portalGroupTag: UInt16 = 1
    var answersHeartbeats = true
    /// How many of the next identification queries (VPD 83h) end as ABORTED COMMAND.
    var abortedIdentityQueries = 0
    /// While set, every new connection is refused.
    var refusing = false
    /// While set, every command other than INQUIRY reports NOT READY (02h/04h), after any
    /// fault or pending unit attention.
    var notReady = false

    init(fill: UInt8 = 0x11) {
        cache = Data(repeating: fill, count: 524_288)
        stable = cache
    }

    var stableMedia: Data { lock.withLock { stable } }
    var commands: [UInt8] { lock.withLock { log } }
    var acceptedLogins: Int { lock.withLock { accepted } }
    var connections: [RecoveryConnection] { lock.withLock { made } }
    var resets: Int { lock.withLock { resetCount } }
    /// How many commands, or Data-Out frames, were held without an answer.
    var held: Int { lock.withLock { holdCount } }

    func change(_ body: (RecoveryBacking) -> Void) { lock.withLock { body(self) } }

    /// Outcomes for the next connections, in order. Afterwards every login is accepted.
    func scriptLogins(_ outcomes: [Login]) { lock.withLock { logins += outcomes } }

    func arm(_ fault: Fault, on opcode: UInt8, phase: Phase = .command, skipping skip: Int = 0) {
        lock.withLock {
            triggers.append(Trigger(opcode: opcode, phase: phase, skip: skip, fault: fault))
        }
    }

    func makeConnection() -> RecoveryConnection {
        let connection = RecoveryConnection(backing: self)
        lock.withLock { made.append(connection) }
        return connection
    }

    func nextLogin() -> Login {
        lock.withLock {
            if refusing { return .refuse }
            return logins.isEmpty ? .accept : logins.removeFirst()
        }
    }

    func noteLogin() { lock.withLock { accepted += 1 } }

    func record(_ opcode: UInt8) { lock.withLock { log.append(opcode) } }

    func fault(for opcode: UInt8, phase: Phase) -> Fault? {
        lock.withLock {
            guard
                let index = triggers.firstIndex(where: { $0.opcode == opcode && $0.phase == phase })
            else { return nil }
            if triggers[index].skip > 0 {
                triggers[index].skip -= 1
                return nil
            }
            let fault = triggers.remove(at: index).fault
            if fault == .restart || fault == .reset {
                cache = stable
                resetCount += 1
            }
            if fault == .hold { holdCount += 1 }
            if case .attentions(let codes, let losingCache) = fault {
                if losingCache { cache = stable }
                attentionQueue += codes
            }
            return fault
        }
    }

    func reportedResets() -> Int { lock.withLock { resetCount } }

    /// The next queued unit attention, removed when reported.
    func nextAttention() -> UInt8? {
        lock.withLock { attentionQueue.isEmpty ? nil : attentionQueue.removeFirst() }
    }

    func read(offset: Int, count: Int) -> Data {
        lock.withLock { Data(cache[offset..<(offset + count)]) }
    }

    func write(_ data: Data, at offset: Int) {
        lock.withLock { cache.replaceSubrange(offset..<(offset + data.count), with: data) }
    }

    func synchronize() { lock.withLock { stable = cache } }

    var geometry: (lastBlock: UInt64, blockSize: UInt32, protected: Bool, type: UInt8) {
        lock.withLock { (lastBlock, blockSize, writeProtected, deviceType) }
    }
    var names: [UInt8]? { lock.withLock { designator } }
    var group: UInt16 { lock.withLock { portalGroupTag } }
    var heartbeats: Bool { lock.withLock { answersHeartbeats } }
    var becomingReady: Bool { lock.withLock { notReady } }

    func abortIdentityQuery() -> Bool {
        lock.withLock {
            guard abortedIdentityQueries > 0 else { return false }
            abortedIdentityQueries -= 1
            return true
        }
    }
}

/// One TCP connection to `RecoveryBacking`: a minimal ERL 0 target for one logical unit.
actor RecoveryConnection: ConnectableByteTransport {
    private let backing: RecoveryBacking
    private var queue: [Data] = []
    private var waiter: CheckedContinuation<Void, Never>?
    private var login: RecoveryBacking.Login = .accept
    private var loginStep = 0
    private var stat: UInt32 = 2
    private var acknowledgedResets = 0
    private var expected: UInt32 = 1
    private var pendingWrite: (cdb: [UInt8], tag: UInt32, exp: UInt32)?
    /// The connection ends once everything queued was read.
    private var closesWhenDrained = false
    private(set) var isClosed = false
    private(set) var heartbeatsIgnored = 0

    init(backing: RecoveryBacking) { self.backing = backing }

    func connect() async throws {
        login = backing.nextLogin()
        if login == .refuse { throw NWError.posix(.ECONNREFUSED) }
    }

    /// Sends an asynchronous message, such as 2 (drop this connection) with its Time2Wait.
    /// With `closing`, the connection then ends once the message was read.
    func sendAsyncEvent(
        _ event: UInt8, parameter2: UInt16 = 0, parameter3: UInt16 = 0, closing: Bool = false
    ) throws {
        var header = base(opcode: 0x32, tag: UInt32.max, exp: expected)
        header[36] = event
        header.put(parameter2, at: 40)
        header.put(parameter3, at: 42)
        queue.append(try PDU(header: header).encoded())
        stat += 1
        if closing { closesWhenDrained = true }
        waiter?.resume()
        waiter = nil
    }

    /// Ends the connection from the target's side, as a network failure would.
    func drop() {
        isClosed = true
        waiter?.resume()
        waiter = nil
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { throw ProtocolError.connectionClosed }
        let bytes = Array(data)
        switch bytes[0] & 0x3F {
        case 0x03: try answerLogin(bytes)
        case 0x01: try command(bytes)
        case 0x05: try dataOut(bytes)
        case 0x00: try heartbeat(bytes)
        case 0x06:
            try respond(opcode: 0x26, tag: bytes.uint32(at: 16), exp: bytes.uint32(at: 24))
        default: throw ProtocolError.invalidState
        }
        waiter?.resume()
        waiter = nil
    }

    func receive(maximumLength: Int) async throws -> Data {
        while queue.isEmpty && !isClosed { await withCheckedContinuation { waiter = $0 } }
        guard !isClosed, !queue.isEmpty else { throw ProtocolError.connectionClosed }
        let data = Data(queue[0].prefix(maximumLength))
        queue[0].removeFirst(data.count)
        if queue[0].isEmpty { queue.removeFirst() }
        if queue.isEmpty, closesWhenDrained { isClosed = true }
        return data
    }

    func close() {
        isClosed = true
        waiter?.resume()
        waiter = nil
    }

    private func answerLogin(_ bytes: [UInt8]) throws {
        if case .reject(let statusClass, let detail) = login {
            var header = [UInt8](repeating: 0, count: 48)
            header[0] = 0x23
            header.replaceSubrange(8..<14, with: bytes[8..<14])
            header.put(UInt32(1), at: 16)
            header[36] = statusClass
            header[37] = detail
            queue.append(try PDU(header: header).encoded())
            return
        }
        var responses = try loginFixtures(normal: true)
        if loginStep == 0 {
            var decoder = try PDUDecoder()
            let original = try #require(decoder.append(responses[0]).first)
            var entries = try TextParameters(data: original.data).entries
            entries.removeAll { $0.key == "TargetPortalGroupTag" }
            entries.append(.init("TargetPortalGroupTag", String(backing.group)))
            responses[0] = try PDU(header: original.header, data: TextParameters(entries).encoded())
                .encoded()
        } else {
            backing.noteLogin()
        }
        queue.append(responses[min(loginStep, 1)])
        loginStep += 1
    }

    private func command(_ bytes: [UInt8]) throws {
        let cdb = Array(bytes[32..<48])
        let tag = bytes.uint32(at: 16)
        let exp = bytes.uint32(at: 24) &+ 1
        expected = exp
        backing.record(cdb[0])
        switch backing.fault(for: cdb[0], phase: .command) {
        case .drop?, .restart?:
            drop()
            return
        case .deferred?:
            try respond(
                opcode: 0x21, tag: tag, exp: exp,
                data: Data([0, 8, 0x73, 3, 0x0C, 0, 0, 0, 0, 0]), status: 2)
            return
        case .hold?: return
        case .status(let status, let key, let asc)?:
            let sense = status == 2 ? Data([0, 8, 0x72, key, asc, 0, 0, 0, 0, 0]) : Data()
            try respond(opcode: 0x21, tag: tag, exp: exp, data: sense, status: status)
            return
        case .statusThenLogoutRequest(let sense)?:
            try respondEndingSession(tag: tag, exp: exp, sense: sense)
            return
        case .sense(let sense)?:
            try respond(
                opcode: 0x21, tag: tag, exp: exp, data: Data([0, UInt8(sense.count)] + sense),
                status: 2)
            return
        case .senseThenDropAll(let sense, let time2Wait)?:
            try respond(
                opcode: 0x21, tag: tag, exp: exp, data: Data([0, UInt8(sense.count)] + sense),
                status: 2)
            try sendAsyncEvent(3, parameter2: time2Wait, closing: true)
            return
        case .attentions?, .reset?, nil: break
        }
        if cdb[0] != 0x12, cdb[0] != 0xA0, let asc = backing.nextAttention() {
            try respond(
                opcode: 0x21, tag: tag, exp: exp,
                data: Data([0, 8, 0x72, 6, asc, 0, 0, 0, 0, 0]), status: 2)
            return
        }
        if acknowledgedResets < backing.reportedResets(), cdb[0] != 0x12, cdb[0] != 0xA0 {
            acknowledgedResets = backing.reportedResets()
            try respond(
                opcode: 0x21, tag: tag, exp: exp,
                data: Data([0, 8, 0x72, 6, 0x29, 0, 0, 0, 0, 0]), status: 2)
            return
        }
        if backing.becomingReady, cdb[0] != 0x12 {
            try checkCondition(tag, exp, key: 2, asc: 4)
            return
        }
        let geometry = backing.geometry
        let blockSize = Int(geometry.blockSize)
        switch cdb[0] {
        case 0x12 where cdb[1] & 1 == 0:
            var inquiry = [UInt8](repeating: 0, count: 36)
            inquiry[0] = geometry.type
            inquiry[2] = 6
            inquiry[3] = 2
            inquiry[4] = 31
            try respond(data: Data(inquiry), allocation: UInt32(cdb.uint16(at: 3)), tag, exp)
        case 0x12 where cdb[2] == 0x83:
            if backing.abortIdentityQuery() {
                try checkCondition(tag, exp, key: 0x0B, asc: 0x47)
                return
            }
            guard let names = backing.names else {
                try checkCondition(tag, exp, key: 5, asc: 0x24)
                return
            }
            let page = [0, 0x83, UInt8(names.count >> 8), UInt8(names.count & 255)] + names
            try respond(data: Data(page), allocation: UInt32(cdb.uint16(at: 3)), tag, exp)
        case 0x9E:
            var capacity = [UInt8](repeating: 0, count: 32)
            capacity.put(geometry.lastBlock, at: 0)
            capacity.put(geometry.blockSize, at: 8)
            try respond(data: Data(capacity), allocation: cdb.uint32(at: 10), tag, exp)
        case 0x5A:
            let mode = Data([0, 6, 0, geometry.protected ? 0x80 : 0, 0, 0, 0, 0])
            try respond(data: mode, allocation: UInt32(cdb.uint16(at: 7)), tag, exp)
        case 0x28, 0x88:
            let lba = cdb[0] == 0x28 ? UInt64(cdb.uint32(at: 2)) : cdb.uint64(at: 2)
            let count = Int(bytes.uint32(at: 20))
            let data = backing.read(offset: Int(lba) * blockSize, count: count)
            try respond(data: data, allocation: UInt32(count), tag, exp)
        case 0x2A, 0x8A:
            pendingWrite = (cdb, tag, exp)
            var header = base(opcode: 0x31, tag: tag, exp: exp)
            header.put(UInt32(9), at: 20)
            header.put(bytes.uint32(at: 20), at: 44)
            queue.append(try PDU(header: header).encoded())
        case 0x35, 0x91:
            backing.synchronize()
            try respond(opcode: 0x21, tag: tag, exp: exp)
        default:
            try checkCondition(tag, exp, key: 5, asc: 0x20)
        }
    }

    private func dataOut(_ bytes: [UInt8]) throws {
        guard let pending = pendingWrite else { throw ProtocolError.invalidState }
        let cdb = pending.cdb
        switch backing.fault(for: cdb[0], phase: .dataOut) {
        case .drop?, .restart?:
            drop()
            return
        case .hold?: return
        case .reset?, .deferred?, .status?, .attentions?, .statusThenLogoutRequest?, .sense?,
            .senseThenDropAll?, nil:
            break
        }
        let lba = cdb[0] == 0x2A ? UInt64(cdb.uint32(at: 2)) : cdb.uint64(at: 2)
        let offset = Int(lba) * Int(backing.geometry.blockSize) + Int(bytes.uint32(at: 40))
        let length = Int(UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7]))
        backing.write(Data(bytes[48..<(48 + length)]), at: offset)
        if bytes[1] & 0x80 != 0 {
            pendingWrite = nil
            try respond(opcode: 0x21, tag: pending.tag, exp: pending.exp)
        }
    }

    private func heartbeat(_ bytes: [UInt8]) throws {
        let tag = bytes.uint32(at: 16)
        guard tag != UInt32.max else { return }
        guard backing.heartbeats else {
            heartbeatsIgnored += 1
            return
        }
        var header = base(opcode: 0x20, tag: tag, exp: bytes.uint32(at: 24))
        header.put(UInt32.max, at: 20)
        let length = Int(UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7]))
        queue.append(try PDU(header: header, data: Data(bytes[48..<(48 + length)])).encoded())
        stat += 1
    }

    /// The status and a request to log out within Time2Wait 2 and Time2Retain 0, in one
    /// segment, as a target restarting its service right after answering might send them.
    private func respondEndingSession(tag: UInt32, exp: UInt32, sense: [UInt8]) throws {
        var status = base(opcode: 0x21, tag: tag, exp: exp)
        status[3] = 2
        let data = Data([0, UInt8(sense.count)] + sense)
        let answer = try PDU(header: status, data: data).encoded()
        stat += 1
        var event = base(opcode: 0x32, tag: UInt32.max, exp: exp)
        event[36] = 1
        event.put(UInt16(2), at: 40)
        let request = try PDU(header: event).encoded()
        stat += 1
        queue.append(answer + request)
    }

    private func checkCondition(_ tag: UInt32, _ exp: UInt32, key: UInt8, asc: UInt8) throws {
        try respond(
            opcode: 0x21, tag: tag, exp: exp, data: Data([0, 8, 0x72, key, asc, 0, 0, 0, 0, 0]),
            status: 2)
    }

    private func base(opcode: UInt8, tag: UInt32, exp: UInt32) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 48)
        bytes[0] = opcode
        bytes[1] = 0x80
        bytes.put(tag, at: 16)
        bytes.put(stat, at: 24)
        bytes.put(exp, at: 28)
        bytes.put(exp &+ 1024, at: 32)
        return bytes
    }

    private func respond(data: Data, allocation: UInt32, _ tag: UInt32, _ exp: UInt32) throws {
        let sent = data.prefix(Int(allocation))
        var bytes = base(opcode: 0x25, tag: tag, exp: exp)
        bytes[1] = sent.count < allocation ? 0x83 : 0x81
        bytes.put(allocation - UInt32(sent.count), at: 44)
        queue.append(try PDU(header: bytes, data: Data(sent)).encoded())
        stat += 1
    }

    private func respond(
        opcode: UInt8, tag: UInt32, exp: UInt32, data: Data = Data(), status: UInt8 = 0
    ) throws {
        var bytes = base(opcode: opcode, tag: tag, exp: exp)
        bytes[3] = status
        queue.append(try PDU(header: bytes, data: data).encoded())
        stat += 1
    }
}

/// A logged-in disk whose session recovers through `backing`, using a manual awake clock.
struct RecoveryFixture {
    let backing: RecoveryBacking
    let time: ManualRecoveryTime
    let recovering: RecoveringSession
    let disk: RemoteDisk
    let first: RecoveryConnection

    /// Every reconnection begins with the negotiated DefaultTime2Wait of two seconds.
    static let initialDelay = Duration.seconds(2)

    init(
        window: Duration = SessionRecovery.defaultRecoveryWindow, expectsPortalGroup: Bool = false,
        sessionTime: ManualSessionTime? = nil, backing: RecoveryBacking = RecoveryBacking()
    ) async throws {
        self.backing = backing
        let first = backing.makeConnection()
        self.first = first
        try await first.connect()
        let login = try configuration(normal: true)
        // The first session's timers run on `sessionTime` when given, with the default
        // heartbeat interval and timeout; later sessions use real time.
        let session =
            try sessionTime.map {
                try ISCSISession(transport: first, configuration: login, clock: $0.source)
            } ?? ISCSISession(transport: first, configuration: login)
        try await session.login()
        let lun = try LogicalUnit(0)
        let information = try await DiskProbe.diskInformation(session: session, lun: lun)
        let designator = try await DiskProbe.logicalUnitDesignator(session: session, lun: lun)
        let time = ManualRecoveryTime()
        self.time = time
        let portal = try Portal("recovery.local")
        let address = TargetAddress(portal: portal, portalGroupTag: expectsPortalGroup ? 1 : nil)
        recovering = try await RecoveringSession.recovering(
            session: session, lun: lun,
            fingerprint: LogicalUnitFingerprint(information: information, designator: designator),
            recoveryWindow: window, clock: time.clock,
            connect: { timeout in
                try await SessionConnector.connect(
                    addresses: [address], configuration: login, timeout: timeout,
                    clock: .continuous, factory: { _, _ in backing.makeConnection() }
                ).session
            })
        // Opened as `LUNVolumeFactory` opens it. Retries of unexecuted commands count the
        // connection's clock, here the manual one, so time spent reconnecting counts there too.
        disk = RemoteDisk(
            connection: recovering, readOnly: false, maximumTransferBlocks: 2, diagnostics: nil)
    }

    /// Waits for the recovery task to sleep before its next login attempt, then wakes it.
    func releaseNextAttempt(after delay: Duration = Self.initialDelay) async throws {
        let time = time
        let deadline = time.now + delay
        try await recoveryPhase("a login attempt to be scheduled") {
            time.hasSleeper(until: deadline)
        }
        time.advance(by: delay)
    }

    /// Wakes the earliest sleeper, which is the recovery task's next attempt when no command
    /// waits, and returns how long it slept.
    @discardableResult
    func advanceToNextSleeper() async throws -> Duration {
        let time = time
        let now = time.now
        try await recoveryPhase("a sleeper") { time.deadlines.contains { $0 > now } }
        let next = try #require(time.deadlines.first { $0 > now })
        time.advance(by: next - now)
        return next - now
    }

    func waitForBlockedCommands(_ count: Int = 1) async throws {
        let recovering = recovering
        try await recoveryPhase("\(count) blocked command(s)") {
            await recovering.waitingCount == count
        }
    }

    func waitForHealth(_ health: RecoveringSession.Health) async throws {
        let recovering = recovering
        try await recoveryPhase("health \(health)") { await recovering.health() == health }
    }

    var opcodes: [UInt8] { backing.commands }
}

/// The sense a Windows Server 2025 target returned for a READ in flight when its iSCSI Target
/// service stopped (captured 2026-11-12): current, fixed format, HARDWARE ERROR, LOGICAL UNIT
/// FAILURE (3Eh/01h).
let windowsLogicalUnitFailure: [UInt8] = [
    0xF0, 0, 4, 0, 0, 0, 0, 0x0A, 0, 0, 0, 0, 0x3E, 0x01, 0, 0, 0, 0,
]

/// Counts one write as sent and completed without sending it, so the next flush has something
/// to make durable and is sent. A disk that wrote nothing since the last GOOD flush doesn't
/// send one (see SynchronizationCoverage). Tests of a flush's own outcome start from here
/// instead of scripting a WRITE before every flush.
func markUnsynchronizedWrite(_ disk: RemoteDisk) {
    disk.coverage.endMutation(disk.coverage.beginMutation(epoch: 0))
}
