import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

/// An independent, small target: acknowledge the first chunk and hold the second status.
/// A rejected chunk changes no media here; that is a fixture rule, not a SCSI guarantee.
private actor SplitWriteTarget: ByteTransport {
    static let sense = Data([0x72, 3, 0x0C, 0, 0, 0, 0, 0])
    private let logins: [Data]
    private let blockSize: Int
    private let failure: UInt8?
    private var input = Data()
    private var reader: CheckedContinuation<Void, Never>?
    private var status: UInt32 = 2
    private var commandSequence: UInt32 = 1
    private var pending: (pdu: PDU, offset: Int, length: Int)?
    private var held: PDU?
    private var fullFeature = false
    private var closed = false
    private(set) var media: Data
    private(set) var writeCommands = 0
    private(set) var reads = 0
    private(set) var commandsAfterFailure = 0
    private(set) var logouts = 0
    private(set) var failureReturned = false
    var secondStatusIsHeld: Bool { held != nil }

    init(blockSize: Int, failure: UInt8?) throws {
        self.blockSize = blockSize
        self.failure = failure
        media = Data(repeating: 0x11, count: 16 * blockSize)
        logins = try loginFixtures(normal: true)
    }

    func send(_ bytes: Data) throws {
        guard !closed else { throw ProtocolError.connectionClosed }
        var decoder = try PDUDecoder(maximumDataLength: 8192)
        let pdus = try decoder.append(bytes)
        guard pdus.count == 1, decoder.isAtFrameBoundary, let pdu = pdus.first else {
            throw ProtocolError.malformed("split-write fixture frame")
        }
        switch pdu.opcode {
        case 0x03:
            let stage = Int((pdu.flags >> 2) & 3)
            guard !fullFeature, stage < logins.count else { throw ProtocolError.invalidState }
            enqueue(logins[stage])
            if stage == 1 { fullFeature = true }
        case 0x01:
            guard !failureReturned else {
                commandsAfterFailure += 1
                throw ProtocolError.malformed("command after rejected split write")
            }
            guard fullFeature, pending == nil, held == nil,
                pdu.header.uint32(at: 24) == commandSequence
            else { throw ProtocolError.invalidState }
            commandSequence &+= 1
            let cdb = Array(pdu.header[32..<48])
            let offset = Int(cdb.uint32(at: 2)) * blockSize
            let length = Int(cdb.uint16(at: 7)) * blockSize
            guard [UInt8(0x28), 0x2A].contains(cdb[0]), length > 0,
                length <= 2 * blockSize, offset <= media.count - length,
                pdu.header.uint32(at: 20) == UInt32(length)
            else { throw ProtocolError.malformed("split-write fixture command") }
            if cdb[0] == 0x28 {
                reads += 1
                var header = response(opcode: 0x25, tag: pdu.taskTag)
                header[1] = 0x81
                enqueue(try PDU(header: header, data: media[offset..<(offset + length)]).encoded())
                status &+= 1
            } else {
                writeCommands += 1
                pending = (pdu, offset, length)
                var header = response(opcode: 0x31, tag: pdu.taskTag)
                header.replaceSubrange(8..<16, with: pdu.header[8..<16])
                header.put(UInt32(73), at: 20)
                header.put(UInt32(length), at: 44)
                enqueue(try PDU(header: header).encoded())
            }
        case 0x05:
            guard let command = pending, pdu.taskTag == command.pdu.taskTag,
                pdu.transferTag == 73, pdu.flags == 0x80,
                pdu.header.uint32(at: 36) == 0, pdu.header.uint32(at: 40) == 0,
                pdu.data.count == command.length
            else { throw ProtocolError.malformed("split-write fixture Data-Out") }
            pending = nil
            if writeCommands == 2 {
                held = pdu
                pending = command
            } else {
                media.replaceSubrange(
                    command.offset..<(command.offset + command.length), with: pdu.data)
                try completeWrite(tag: pdu.taskTag, failure: nil)
            }
        case 0x06:
            guard pending == nil, held == nil else { throw ProtocolError.invalidState }
            logouts += 1
            enqueue(try PDU(header: response(opcode: 0x26, tag: pdu.taskTag)).encoded())
            status &+= 1
        default: throw ProtocolError.malformed("unexpected split-write fixture PDU")
        }
    }

    func releaseSecondStatus() throws {
        guard let held, let command = pending else { throw ProtocolError.invalidState }
        self.held = nil
        pending = nil
        if failure == nil {
            media.replaceSubrange(
                command.offset..<(command.offset + command.length), with: held.data)
        }
        try completeWrite(tag: held.taskTag, failure: failure)
    }

    func receive(maximumLength: Int) async throws -> Data {
        while input.isEmpty, !closed { await withCheckedContinuation { reader = $0 } }
        guard !closed else { throw ProtocolError.connectionClosed }
        let bytes = Data(input.prefix(maximumLength))
        input.removeFirst(bytes.count)
        return bytes
    }

    func close() {
        closed = true
        reader?.resume()
        reader = nil
    }

    private func completeWrite(tag: UInt32, failure: UInt8?) throws {
        var header = response(opcode: 0x21, tag: tag)
        header[3] = failure ?? 0
        let sense = failure == 2 ? Data([0, UInt8(Self.sense.count)]) + Self.sense : Data()
        enqueue(try PDU(header: header, data: sense).encoded())
        status &+= 1
        failureReturned = failure != nil
    }

    private func response(opcode: UInt8, tag: UInt32) -> [UInt8] {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = opcode
        header[1] = 0x80
        header.put(tag, at: 16)
        header.put(UInt32.max, at: 20)
        header.put(status, at: 24)
        header.put(commandSequence, at: 28)
        header.put(UInt32(32), at: 32)
        return header
    }

    private func enqueue(_ bytes: Data) {
        input.append(bytes)
        reader?.resume()
        reader = nil
    }
}

private actor SplitWriteCallers {
    private(set) var started = 0
    func start() { started += 1 }
}

private func awaitSplitWritePhase(_ predicate: @Sendable () async -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        await Task.yield()
    }
}

private func awaitSecondWrite(
    _ target: SplitWriteTarget, session: ISCSISession, write: Task<Void, any Error>
) async throws {
    try await awaitSplitWritePhase {
        if await target.secondStatusIsHeld { return true }
        return await session.state != .ready
    }
    guard await target.secondStatusIsHeld else {
        // Preserve an earlier transport/protocol error instead of masking it as a phase timeout.
        try await write.value
        throw ProtocolError.invalidState
    }
}

private func splitWriteDisk(
    _ target: SplitWriteTarget, blockSize: Int, diagnostics: IODiagnostics.Recorder? = nil
) async throws
    -> (RemoteDisk, ISCSISession)
{
    let session = try ISCSISession(
        transport: target, configuration: configuration(normal: true),
        commandTimeout: .seconds(5))
    var capacity = Array(repeating: UInt8(0), count: 8)
    capacity.put(UInt32(15), at: 0)
    capacity.put(UInt32(blockSize), at: 4)
    let disk = try RemoteDisk(
        session: session, lun: LogicalUnit(0),
        capacity: DiskCapacity(readCapacity10: Data(capacity)),
        readOnly: false, maximumTransferBlocks: 2, diagnostics: diagnostics)
    try await session.login()
    return (disk, session)
}

@Test(arguments: [512, 4096], [false, true])
private func splitWriteHealthyControl(_ blockSize: Int, _ unaligned: Bool) async throws {
    let target = try SplitWriteTarget(blockSize: blockSize, failure: nil)
    let (disk, session) = try await splitWriteDisk(target, blockSize: blockSize)
    let offset = unaligned ? 1 : 0
    let data = Data(repeating: 0xA5, count: 5 * blockSize)
    let write = Task { try await disk.write(offset: Int64(offset), data: data) }
    do {
        try await awaitSecondWrite(target, session: session, write: write)
        try await target.releaseSecondStatus()
        try await write.value
        var expected = Data(repeating: 0x11, count: 16 * blockSize)
        expected.replaceSubrange(offset..<(offset + data.count), with: data)
        #expect(await target.media == expected)
        #expect(await target.writeCommands == 3)
        #expect(await target.reads == (unaligned ? 3 : 0))
        #expect(await disk.connectionState() == .connected)
        await disk.close()
        #expect(await session.state == .closed)
        #expect(await target.logouts == 1)
    } catch {
        write.cancel()
        await session.close()
        _ = try? await write.value
        throw error
    }
}

// BUSY reports an unexecuted command and is retried first; RemoteDiskRetryTests covers it.
@Test(arguments: [512, 4096], [UInt8(2), 0x18])
private func rejectedSecondWriteStopsConcurrentDiskIO(_ blockSize: Int, _ status: UInt8)
    async throws
{
    let target = try SplitWriteTarget(blockSize: blockSize, failure: status)
    let diagnostics = IODiagnostics.Recorder(layer: .remoteDisk, capacity: 4096)
    let (disk, session) = try await splitWriteDisk(
        target, blockSize: blockSize, diagnostics: diagnostics)
    let write = Task {
        try await disk.write(offset: 1, data: Data(repeating: 0xA5, count: 5 * blockSize))
    }
    do {
        try await awaitSecondWrite(target, session: session, write: write)
        let callers = SplitWriteCallers()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for operation in 0..<3 {
                group.addTask {
                    await callers.start()
                    await #expect(throws: ProtocolError.invalidState) {
                        switch operation {
                        case 0: _ = try await disk.read(offset: 0, length: blockSize)
                        case 1: try await disk.write(offset: 0, data: Data([0xCC]))
                        default: try await disk.synchronize()
                        }
                    }
                }
            }
            // All callers have started; their exact scheduling at the gate is unspecified.
            try await awaitSplitWritePhase { await callers.started == 3 }
            try await awaitSplitWritePhase { await disk.queuedIOCount == 3 }
            try await target.releaseSecondStatus()
            await #expect(
                throws: ProtocolError.scsiFailure(
                    status: status, sense: status == 2 ? SplitWriteTarget.sense : Data())
            ) { try await write.value }
            try await group.waitForAll()
        }
        var expected = Data(repeating: 0x11, count: 16 * blockSize)
        expected.replaceSubrange(
            1..<(2 * blockSize), with: repeatElement(UInt8(0xA5), count: 2 * blockSize - 1))
        #expect(await target.media == expected)
        #expect(await target.writeCommands == 2)
        #expect(await target.reads == 3)
        #expect(await target.commandsAfterFailure == 0)
        let snapshot = diagnostics.snapshot()
        let cause = try #require(snapshot.summary.retainedMutationCause)
        let writes = snapshot.events.filter { $0.stage == .backendBegin && $0.detail == .write }
        #expect(writes.count == 2 && writes.last?.backendAttemptID == cause.backendAttemptID)
        let retained = try #require(snapshot.events.first { $0.stage == .mutationFailureRetained })
        let refusals = snapshot.events.filter { $0.stage == .retainedMutationRejected }
        #expect(refusals.count == 3 && refusals.allSatisfy { $0.retainedCauseID == cause.id })
        for refusal in refusals {
            let acquired = try #require(
                snapshot.events.first {
                    $0.operationID == refusal.operationID && $0.stage == .gateAcquired
                })
            #expect(acquired.sequence > retained.sequence)
        }
        #expect(snapshot.summary.activeOperations == 0 && snapshot.summary.integrityValid)

        #expect(await session.state == .ready)
        #expect(await disk.connectionState() == .interrupted)
        await disk.close()
        #expect(await target.logouts == 1)
        #expect(await session.state == .closed)
    } catch {
        write.cancel()
        await session.close()
        _ = try? await write.value
        throw error
    }
}
