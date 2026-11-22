import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

/// This store/lease and target are simulations, not durability or external drain evidence.
final class IntentFixture: OwnedReservationIntentStore, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [OwnedReservationIntent] = []
    let failPhase: OwnedReservationIntent.Phase?
    let commitThenFail: Bool
    init(failPhase: OwnedReservationIntent.Phase? = nil, commitThenFail: Bool = false) {
        self.failPhase = failPhase
        self.commitThenFail = commitThenFail
    }
    func load() -> [OwnedReservationIntent] { lock.withLock { entries } }
    func insert(_ intent: OwnedReservationIntent) throws {
        try lock.withLock {
            if intent.phase != failPhase || commitThenFail { entries.append(intent) }
            if intent.phase == failPhase { throw POSIXError(.EIO) }
        }
    }
    func advance(_ expected: OwnedReservationIntent, to next: OwnedReservationIntent) throws {
        try lock.withLock {
            guard entries == [expected] else { throw ProtocolError.invalidState }
            if next.phase != failPhase || commitThenFail { entries = [next] }
            if next.phase == failPhase { throw POSIXError(.EIO) }
        }
    }
}

actor QuiescenceFixture: StorageQuiescenceLease {
    nonisolated let id = UUID()
    nonisolated let relativeTargetPort: UInt16 = 12
    private var calls = 0
    private let failCall: Int?
    private let cancelCall: Int?
    init(failCall: Int? = nil, cancelCall: Int? = nil) {
        self.failCall = failCall
        self.cancelCall = cancelCall
    }
    func assertHeld(for binding: OwnedReservationBinding) async throws {
        calls += 1
        #expect(binding.quiescenceID == id && binding.relativeTargetPort == relativeTargetPort)
        if calls == cancelCall { withUnsafeCurrentTask { $0?.cancel() } }
        if calls == failCall { throw POSIXError(.EBUSY) }
    }
}

actor ReservationTarget: SendAdmissionTransport {
    enum SynchronizationReplyFault: Sendable { case body, underflow }
    enum Fault: Sendable {
        case none, ownISID, targetPort, allPorts, foreignKey, identity, unitAttention, t10Identity
    }
    private let store: IntentFixture
    private let fault: Fault
    private var login = 0
    private var stat: UInt32 = 2
    private var queue: [Data] = []
    private var waiter: CheckedContinuation<Void, Never>?
    private var key: UInt64 = 0
    private var holder = false
    private var generation: UInt32 = 7
    private var control: (cdb: [UInt8], tag: UInt32, exp: UInt32)?
    private var nextStatus: UInt8?
    private var nextSyncFailure = false
    private var nextSyncCommunicationFailure = false
    private var nextSyncRejection: (status: UInt8, sense: Data)?
    private var nextWriteFailure = false
    private let maximumTransferBlocks: UInt32
    private let writeProtected: Bool
    private let changeCapacity: Bool
    private var capacityQueries = 0
    private var media = Data(repeating: 0x11, count: 524_288)
    let dataPause = ReservationLeasePause()
    let synchronizationPause = ReservationLeasePause()
    let logoutPause = ReservationLeasePause()
    let logoutAdmissionPause = ReservationLeasePause()
    private var pauseDataOut = false
    private var pauseSynchronization = false
    private var pauseLogout = false
    private var dropLogout = false
    private var pauseLogoutAdmission = false
    private var synchronizationReplyFault: SynchronizationReplyFault?
    private(set) var admittedFrames: [Data] = []
    private var externalFenceReleased: (@Sendable () -> Bool)?
    private(set) var writesAfterFenceRelease = 0
    private(set) var dataCommands: [UInt8] = []
    private(set) var blockTransfers: [(opcode: UInt8, blocks: UInt32)] = []
    private(set) var loginRequests: [Data] = []
    private(set) var commandLUNs: [Data] = []
    private let dropAction: UInt8?
    private(set) var actions: [UInt8] = []
    private(set) var logoutRequests = 0
    private(set) var isClosed = false
    private(set) var closeCalls = 0

    init(
        store: IntentFixture, fault: Fault = .none, dropAction: UInt8? = nil,
        maximumTransferBlocks: UInt32 = 0, writeProtected: Bool = false,
        changeCapacity: Bool = false
    ) {
        self.store = store
        self.fault = fault
        self.dropAction = dropAction
        self.maximumTransferBlocks = maximumTransferBlocks
        self.writeProtected = writeProtected
        self.changeCapacity = changeCapacity
    }
    func injectStatus(_ status: UInt8) { nextStatus = status }
    func failNextSynchronization(communication: Bool = false) {
        nextSyncFailure = true
        nextSyncCommunicationFailure = communication
    }
    func failNextWrite() { nextWriteFailure = true }
    /// Reply to the next synchronization with this status, for example BUSY.
    func rejectNextSynchronization(status: UInt8, sense: Data = Data()) {
        nextSyncRejection = (status, sense)
    }
    func pauseNextSynchronization() { pauseSynchronization = true }
    func pauseNextLogout() { pauseLogout = true }
    func dropNextLogout() { dropLogout = true }
    func pauseNextLogoutAdmission() { pauseLogoutAdmission = true }
    func malformNextSynchronization(_ fault: SynchronizationReplyFault) {
        synchronizationReplyFault = fault
    }
    func corruptMedia() { media[0] ^= 1 }
    func pauseNextDataOut(fence: @escaping @Sendable () -> Bool) {
        pauseDataOut = true
        externalFenceReleased = fence
    }
    func hasReservation() -> Bool { holder }

    func send(
        _ data: Data, whileAdmitted: @escaping @Sendable (_ submit: () -> Void) throws -> Void
    ) async throws {
        if data.first.map({ $0 & 0x3F }) == 6, pauseLogoutAdmission {
            pauseLogoutAdmission = false
            await logoutAdmissionPause.wait()
        }
        guard !isClosed else { throw ProtocolError.connectionClosed }
        var submitted = false
        try whileAdmitted {
            admittedFrames.append(data)  // The simulated peer accepts this exact frame inline.
            submitted = true
        }
        guard submitted else { throw ProtocolError.invalidState }
        try await send(data)
    }

    func send(_ data: Data) async throws {
        let bytes = Array(data)
        let opcode = bytes[0] & 0x3F
        if opcode == 3 {
            loginRequests.append(Data(bytes.dropFirst(48)))
            queue.append(try loginFixtures(normal: true)[login])
            login += 1
        } else if opcode == 1 {
            let cdb = Array(bytes[32..<48])
            commandLUNs.append(Data(bytes[8..<16]))
            if [UInt8(0x28), 0x2A, 0x88, 0x8A].contains(cdb[0]) {
                blockTransfers.append(
                    (cdb[0], cdb[0] < 0x80 ? UInt32(cdb.uint16(at: 7)) : cdb.uint32(at: 10)))
            }
            let tag = bytes.uint32(at: 16)
            let exp = bytes.uint32(at: 24) + 1
            if [UInt8(0x28), 0x88, 0x2A, 0x8A, 0x35, 0x91].contains(cdb[0]) {
                dataCommands.append(cdb[0])
            }
            if cdb[0] == 0x5F {
                actions.append(cdb[1])
                // Intent must already be visible before the first mutation reaches this peer.
                #expect(store.load().count == 1)
                if cdb[1] == 1 && fault == .unitAttention {
                    try response(
                        opcode: 0x21, tag: tag, exp: exp,
                        data: Data([0, 8, 0x72, 6, 0x29, 0, 0, 0, 0, 0]), status: 2)
                } else {
                    control = (cdb, tag, exp)
                    var header = base(opcode: 0x31, tag: tag, exp: exp)
                    header.replaceSubrange(8..<16, with: bytes[8..<16])
                    header.put(UInt32(9), at: 20)
                    header.put(UInt32(24), at: 44)
                    queue.append(try PDU(header: header).encoded())
                }
            } else if cdb[0] == 0x2A || cdb[0] == 0x8A {
                control = (cdb, tag, exp)
                var header = base(opcode: 0x31, tag: tag, exp: exp)
                header.replaceSubrange(8..<16, with: bytes[8..<16])
                header.put(UInt32(9), at: 20)
                header.put(bytes.uint32(at: 20), at: 44)
                queue.append(try PDU(header: header).encoded())
            } else if cdb[0] == 0x35 || cdb[0] == 0x91 {
                if pauseSynchronization {
                    pauseSynchronization = false
                    await synchronizationPause.wait()
                    guard !isClosed else { throw ProtocolError.connectionClosed }
                }
                if let fault = synchronizationReplyFault {
                    synchronizationReplyFault = nil
                    switch fault {
                    case .body:
                        try response(opcode: 0x21, tag: tag, exp: exp, data: Data([0xA5]))
                    case .underflow:
                        var header = base(opcode: 0x21, tag: tag, exp: exp)
                        header[1] = 0x82
                        header.put(UInt32(1), at: 44)
                        queue.append(try PDU(header: header).encoded())
                    }
                    waiter?.resume()
                    waiter = nil
                    return
                }
                if let rejection = nextSyncRejection {
                    nextSyncRejection = nil
                    try response(
                        opcode: 0x21, tag: tag, exp: exp,
                        data: rejection.sense.isEmpty
                            ? Data() : Data([0, UInt8(rejection.sense.count)]) + rejection.sense,
                        status: rejection.status)
                    waiter?.resume()
                    waiter = nil
                    return
                }
                let failed = nextSyncFailure
                nextSyncFailure = false
                let key: UInt8 = nextSyncCommunicationFailure ? 2 : 3
                let asc: UInt8 = nextSyncCommunicationFailure ? 8 : 0x0C
                nextSyncCommunicationFailure = false
                try response(
                    opcode: 0x21, tag: tag, exp: exp,
                    data: failed ? Data([0, 8, 0x72, key, asc, 0, 0, 0, 0, 0]) : Data(),
                    status: failed ? 2 : 0)
            } else if cdb[0] == 0x28 || cdb[0] == 0x88 {
                let offset =
                    Int(cdb[0] == 0x28 ? UInt64(cdb.uint32(at: 2)) : cdb.uint64(at: 2)) * 512
                let count = Int(bytes.uint32(at: 20))
                try response(
                    opcode: 0x25, tag: tag, exp: exp,
                    data: Data(media[offset..<(offset + count)]), allocation: UInt32(count))
            } else {
                if let status = nextStatus {
                    nextStatus = nil
                    try response(opcode: 0x21, tag: tag, exp: exp, status: status)
                } else {
                    let result = try query(cdb)
                    try response(
                        opcode: 0x25, tag: tag, exp: exp, data: result,
                        allocation: cdb[0] == 0x1A
                            ? UInt32(cdb[4])
                            : cdb[0] == 0x9E
                                ? 32
                                : cdb[0] == 0x12
                                    ? (cdb[1] == 0 ? 96 : UInt32(cdb.uint16(at: 3)))
                                    : UInt32(cdb.uint16(at: 7)))
                }
            }
        } else if opcode == 5 {
            let pending = try #require(control)
            let parameters = Array(bytes[48...])
            if pending.cdb[0] == 0x2A || pending.cdb[0] == 0x8A {
                if pauseDataOut {
                    pauseDataOut = false
                    await dataPause.wait()
                }
                if externalFenceReleased?() == true { writesAfterFenceRelease += 1 }
                let cdb = pending.cdb
                let start =
                    Int(cdb[0] == 0x2A ? UInt64(cdb.uint32(at: 2)) : cdb.uint64(at: 2)) * 512
                    + Int(bytes.uint32(at: 40))
                media.replaceSubrange(start..<(start + parameters.count), with: parameters)
                if bytes[1] & 0x80 != 0 {
                    control = nil
                    let failed = nextWriteFailure
                    nextWriteFailure = false
                    try response(
                        opcode: 0x21, tag: pending.tag, exp: pending.exp,
                        data: failed ? Data([0, 8, 0x72, 3, 0x0C, 0, 0, 0, 0, 0]) : Data(),
                        status: failed ? 2 : 0)
                }
                waiter?.resume()
                waiter = nil
                return
            }
            if pending.cdb[1] == 0 {
                #expect(parameters.uint64(at: 0) == key)
                key = parameters.uint64(at: 8)
                generation += 1
            } else if pending.cdb[1] == 1 {
                holder = true
            } else if pending.cdb[1] == 2 {
                holder = false
            }
            control = nil
            if pending.cdb[1] == dropAction {
                close()
                return
            }
            try response(opcode: 0x21, tag: pending.tag, exp: pending.exp)
        } else if opcode == 6 {
            logoutRequests += 1
            if pauseLogout {
                pauseLogout = false
                await logoutPause.wait()
                guard !isClosed else { throw ProtocolError.connectionClosed }
            }
            if dropLogout {
                dropLogout = false
                close()
                return
            }
            try response(opcode: 0x26, tag: bytes.uint32(at: 16), exp: bytes.uint32(at: 24))
        } else {
            throw ProtocolError.invalidState
        }
        waiter?.resume()
        waiter = nil
    }

    private func base(opcode: UInt8, tag: UInt32, exp: UInt32) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 48)
        bytes[0] = opcode
        bytes[1] = 0x80
        bytes.put(tag, at: 16)
        bytes.put(stat, at: 24)
        bytes.put(exp, at: 28)
        bytes.put(UInt32(1024), at: 32)
        return bytes
    }
    private func response(
        opcode: UInt8, tag: UInt32, exp: UInt32, data: Data = Data(),
        allocation: UInt32 = 0, status: UInt8 = 0
    ) throws {
        var bytes = base(opcode: opcode, tag: tag, exp: exp)
        if opcode == 0x25 {
            bytes[1] = data.count < allocation ? 0x83 : 0x81
            bytes.put(allocation - UInt32(data.count), at: 44)
        }
        bytes[3] = status
        queue.append(try PDU(header: bytes, data: data).encoded())
        stat += 1
    }
    private func query(_ cdb: [UInt8]) throws -> Data {
        if cdb[0] == 0x5A { return Data([0, 6, 0, writeProtected ? 0x80 : 0, 0, 0, 0, 0]) }
        if cdb[0] == 0x1A { return Data([3, 0, writeProtected ? 0x80 : 0, 0]) }
        if cdb[0] == 0x12 && cdb[1] == 0 {
            var bytes = [UInt8](repeating: 0, count: 36)
            bytes[2] = 6
            bytes[3] = 2
            bytes[4] = 31
            return Data(bytes)
        }
        if cdb[0] == 0x9E {
            capacityQueries += 1
            var bytes = [UInt8](repeating: 0, count: 32)
            bytes.put(UInt64(changeCapacity && capacityQueries > 1 ? 1022 : 1023), at: 0)
            bytes.put(UInt32(512), at: 8)
            return Data(bytes)
        }
        if cdb[0] == 0x12 {
            if cdb[2] == 0xB0 {
                var bytes = [UInt8](repeating: 0, count: 64)
                bytes[1] = 0xB0
                bytes[3] = 60
                bytes.put(maximumTransferBlocks, at: 8)
                return Data(bytes)
            }
            if fault == .t10Identity {
                let suffix = key == 0 ? "4" : "5"
                let raw =
                    Array(("LIO-ORG FILEIO:00000000-1111-2222-3333-44444444444" + suffix).utf8) + [
                        UInt8(0)
                    ]
                let naa: [UInt8] = [1, 3, 0, 16, 0x60] + Array(repeating: 0x23, count: 15)
                let body = naa + [2, 1, 0, UInt8(raw.count)] + raw
                return Data([0, 0x83, UInt8(body.count >> 8), UInt8(body.count & 255)] + body)
            }
            return Data([
                0, 0x83, 0, 12, 1, 3, 0, 8, 0x50, 0, 0, 0, 0, 0, 0,
                key != 0 && fault == .identity ? 2 : 1,
            ])
        }
        if cdb[1] == 2 { return Data([0, 8, 1, 0x80, 2, 0, 0, 0]) }
        let present = key != 0
        var body: [UInt8] = []
        if cdb[1] == 0 && present {
            body = [UInt8](repeating: 0, count: 8)
            body.put(fault == .foreignKey ? key ^ 1 : key, at: 0)
        } else if cdb[1] == 1 && holder {
            body = [UInt8](repeating: 0, count: 16)
            body.put(key, at: 0)
            body[13] = 1
        } else if cdb[1] == 3 && present {
            var text =
                Array(
                    ("iqn.2026-10.test:initiator,i,0x80010203040"
                        + (fault == .ownISID ? "6" : "5")).utf8) + [0]
            while text.count % 4 != 0 { text.append(0) }
            let port = [UInt8(0x45), 0, 0, UInt8(text.count)] + text
            body = [UInt8](repeating: 0, count: 24)
            body.put(key, at: 0)
            body[12] = (holder ? 1 : 0) | (fault == .allPorts ? 2 : 0)
            body[13] = holder ? 1 : 0
            body.put(UInt16(fault == .targetPort ? 13 : 12), at: 18)
            body.put(UInt32(port.count), at: 20)
            body += port
        }
        var header = [UInt8](repeating: 0, count: 8)
        header.put(generation, at: 0)
        header.put(UInt32(body.count), at: 4)
        return Data(header + body)
    }
    func receive(maximumLength: Int) async throws -> Data {
        while queue.isEmpty && !isClosed { await withCheckedContinuation { waiter = $0 } }
        guard !isClosed, !queue.isEmpty else { throw ProtocolError.connectionClosed }
        let data = Data(queue[0].prefix(maximumLength))
        queue[0].removeFirst(data.count)
        if queue[0].isEmpty { queue.removeFirst() }
        return data
    }
    func close() {
        closeCalls += 1
        isClosed = true
        waiter?.resume()
        waiter = nil
    }
}

func reservedSession(_ store: IntentFixture, fault: ReservationTarget.Fault = .none)
    async throws -> (ISCSISession, ReservationTarget)
{
    let target = ReservationTarget(store: store, fault: fault)
    let session = try ISCSISession(transport: target, configuration: configuration(normal: true))
    try await session.login()
    return (session, target)
}

actor ReservationLeasePause {
    var isWaiting = false
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async {
        isWaiting = true
        await withCheckedContinuation { continuation = $0 }
    }
    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

final class ContinuousLeaseFixture: ContinuousStorageQuiescenceLease, @unchecked Sendable {
    let id = UUID()
    let relativeTargetPort: UInt16 = 12
    let pause = ReservationLeasePause()
    private let lock = NSLock()
    private var revoked = false
    private var assertionsUntilPause: Int?
    private var backingWasReplaced = false
    private var pins: Set<UUID> = []
    private var afterCriticalBody: (@Sendable () -> Void)?
    func setAfterCriticalBody(_ body: (@Sendable () -> Void)?) {
        lock.withLock { afterCriticalBody = body }
    }
    var externalWritersAdmitted: Bool { lock.withLock { revoked && pins.isEmpty } }
    var outstandingPins: Int { lock.withLock { pins.count } }
    private final class Pin: StorageCommandFencePin, Sendable {
        let id: UUID
        let lease: ContinuousLeaseFixture
        init(id: UUID, lease: ContinuousLeaseFixture) {
            self.id = id
            self.lease = lease
        }
        func complete() { lease.completePin(id) }
    }
    private func completePin(_ id: UUID) { _ = lock.withLock { pins.remove(id) } }
    func pinCommand(for binding: OwnedReservationBinding) throws -> any StorageCommandFencePin {
        try lock.withLock {
            guard !revoked, !backingWasReplaced, binding.quiescenceID == id else {
                throw POSIXError(.EBUSY)
            }
            let token = UUID()
            pins.insert(token)
            return Pin(id: token, lease: self)
        }
    }

    func revoke() { lock.withLock { revoked = true } }
    func replaceBackingWithoutChangingSCSIIdentity() { lock.withLock { backingWasReplaced = true } }
    func pauseAssertion(after count: Int = 1) { lock.withLock { assertionsUntilPause = count } }
    func assertHeld(for binding: OwnedReservationBinding) async throws {
        let suspend = try lock.withLock {
            guard !revoked, !backingWasReplaced, binding.quiescenceID == id else {
                throw POSIXError(.EBUSY)
            }
            guard let remaining = assertionsUntilPause else { return false }
            assertionsUntilPause = remaining == 1 ? nil : remaining - 1
            return remaining == 1
        }
        if suspend { await pause.wait() }
    }
    func whileHeld(for binding: OwnedReservationBinding, _ body: () throws -> Void) throws {
        try lock.withLock {
            guard !revoked, !backingWasReplaced, binding.quiescenceID == id else {
                throw POSIXError(.EBUSY)
            }
            try body()
            afterCriticalBody?()
        }
    }
}

func recoverableReservedDisk(
    diagnostics: IODiagnostics.Recorder? = nil
) async throws -> (ReservedRemoteDisk, ISCSISession, ReservationTarget, ContinuousLeaseFixture) {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store, diagnostics: diagnostics)
    try await reserved.disk.write(offset: 7, data: Data([0xAB, 0xCD]))
    await target.failNextSynchronization()
    await #expect(throws: ProtocolError.self) { try await reserved.disk.synchronize() }
    #expect(reserved.disk.mutationEvidence.incident != nil)
    return (reserved, session, target, lease)
}
