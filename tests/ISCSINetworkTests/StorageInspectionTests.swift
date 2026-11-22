import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

private struct InspectionScript {
    var responses = try! loginFixtures(normal: true)
    var tag: UInt32 = 2
    var stat: UInt32 = 2

    mutating func data(_ data: Data, allocation: UInt32) throws {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x25
        header[1] = data.count < allocation ? 0x83 : 0x81
        header.put(tag, at: 16)
        header.put(stat, at: 24)
        header.put(tag, at: 28)
        header.put(UInt32(64), at: 32)
        header.put(allocation - UInt32(data.count), at: 44)
        responses.append(try PDU(header: header, data: data).encoded())
        tag += 1
        stat += 1
    }

    mutating func status(
        _ status: UInt8 = 0, key: UInt8 = 0, asc: UInt8 = 0,
        ascq: UInt8 = 0, response: UInt8 = 0x72
    ) throws {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x21
        header[1] = 0x80
        header[3] = status
        header.put(tag, at: 16)
        header.put(stat, at: 24)
        header.put(tag, at: 28)
        header.put(UInt32(64), at: 32)
        let data: [UInt8] = status == 2 ? [0, 8, response, key, asc, ascq, 0, 0, 0, 0] : []
        responses.append(try PDU(header: header, data: Data(data)).encoded())
        tag += 1
        stat += 1
    }

    mutating func base(capacityFallback: Bool = false, invalidIdentity: Bool = false) throws {
        var inquiry = Array(repeating: UInt8(0), count: 36)
        inquiry[2] = 6
        inquiry[3] = 2
        inquiry[4] = 31
        try data(Data(inquiry), allocation: 96)
        if capacityFallback {
            try status(2, key: 5, asc: 0x20)
            var capacity = Array(repeating: UInt8(0), count: 8)
            capacity.put(UInt32(1023), at: 0)
            capacity.put(UInt32(512), at: 4)
            try data(Data(capacity), allocation: 8)
        } else {
            var capacity = Array(repeating: UInt8(0), count: 32)
            capacity.put(UInt64(1023), at: 0)
            capacity.put(UInt32(512), at: 8)
            try data(Data(capacity), allocation: 32)
        }
        let identity: [UInt8] =
            [
                0, 0x83, 0, 20, 1, invalidIdentity ? 0x13 : 3, 0, 16,
                0x60,
            ] + Array(repeating: 0x24, count: 15)
        try data(Data(identity), allocation: 65_535)
    }

    mutating func reservations(
        generations: [UInt32] = [7, 7, 7],
        registered: [UInt64] = [], holder: UInt64? = nil, inconsistentHolder: Bool = false,
        holderType: UInt8 = 1, typeMaskValid: Bool = true
    ) throws {
        try data(Data([0, 8, 1, typeMaskValid ? 0x80 : 0, 2, 0, 0, 0]), allocation: 8)
        var keys = header(generations[0], UInt32(registered.count * 8))
        for key in registered {
            keys += Array(repeating: 0, count: 8)
            keys.put(key, at: keys.count - 8)
        }
        try data(Data(keys), allocation: 65_535)
        var reservation = header(generations[1], holder == nil ? 0 : 16)
        if let holder {
            reservation += Array(repeating: 0, count: 16)
            reservation.put(holder, at: 8)
            reservation[21] = holderType
        }
        try data(Data(reservation), allocation: 24)
        var descriptors: [UInt8] = []
        var holderAdded = false
        for key in registered {
            var row = Array(repeating: UInt8(0), count: 48)
            row.put(key, at: 0)
            let isHolder = key == holder && !holderAdded
            row[12] = isHolder && !inconsistentHolder ? 1 : 0
            row[13] = isHolder ? holderType : 0xFF
            row.put(UInt16(12), at: 18)
            row.put(UInt32(24), at: 20)
            // An opaque transport name is data, never ownership of this iSCSI connection.
            row[24] = 0
            if isHolder { holderAdded = true }
            descriptors += row
        }
        try data(
            Data(header(generations[2], UInt32(descriptors.count)) + descriptors),
            allocation: 65_535)
    }

    private func header(_ generation: UInt32, _ length: UInt32) -> [UInt8] {
        var bytes = Array(repeating: UInt8(0), count: 8)
        bytes.put(generation, at: 0)
        bytes.put(length, at: 4)
        return bytes
    }

    func open() async throws -> (ISCSISession, ScriptedTransport) {
        let transport = ScriptedTransport(responses)
        let session = try ISCSISession(
            transport: transport, configuration: configuration(normal: true))
        try await session.login()
        return (session, transport)
    }
}

@Test(arguments: [false, true])
func storageInspectionReadsActualProtocolMetadataWithoutWritesOrAuthority(_ fallback: Bool)
    async throws
{
    var script = InspectionScript()
    try script.base(capacityFallback: fallback)
    try script.reservations()
    let (session, transport) = try await script.open()
    do {
        let result = try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
        #expect(result.capacity.byteCount == 524_288)
        #expect(result.identity.designators.count == 1)
        #expect(result.capabilities.supportedTypes == [.writeExclusive])
        #expect(result.keys.generation == 7 && result.keys.keys.isEmpty)
        #expect(result.reservation.holder == nil && result.fullStatus.registrations.isEmpty)
        #expect(!result.establishesRecoveryAuthority)
        #expect(result.finalContinuity.continues(result.initialContinuity))
        #expect(!result.finalContinuity.hasAdmittedDataAccess)
        #expect(result.finalContinuity.admittedCommands == (fallback ? 8 : 7))
        let writes = await transport.writes.map { Array($0) }.filter { $0[0] & 0x3F == 1 }
        #expect(writes.allSatisfy { $0[1] & 0x20 == 0 && $0.count == 48 })
        #expect(
            writes.map { $0[32] }
                == (fallback
                    ? [0x12, 0x9E, 0x25, 0x12, 0x5E, 0x5E, 0x5E, 0x5E]
                    : [0x12, 0x9E, 0x12, 0x5E, 0x5E, 0x5E, 0x5E]))
        #expect(writes.filter { $0[32] == 0x5E }.map { $0[33] } == [2, 0, 1, 3])
    } catch {
        await session.close()
        throw error
    }
    await session.close()
}

@Test func storageInspectionPreservesOtherNexusesAndDuplicateKeysWithoutClaimingOwnership()
    async throws
{
    var script = InspectionScript()
    try script.base()
    try script.reservations(registered: [0x11, 0x22, 0x11], holder: 0x22)
    let (session, _) = try await script.open()
    do {
        let result = try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
        #expect(result.keys.keys == [0x11, 0x22, 0x11])
        #expect(result.fullStatus.registrations.map(\.isHolder) == [false, true, false])
        #expect(result.reservation.holder?.key == 0x22)
        #expect(result.fullStatus.registrations[1].relativeTargetPort == 12)
        #expect(!result.establishesRecoveryAuthority)
    } catch {
        await session.close()
        throw error
    }
    await session.close()
}

@Test func storageInspectionRejectsGenerationAndHolderInconsistency() async throws {
    for mismatch in 0..<3 {
        var script = InspectionScript()
        try script.base()
        try script.reservations(
            generations: mismatch == 0 ? [7, 8, 7] : [7, 7, mismatch == 1 ? 8 : 7],
            registered: [0x11], holder: 0x11, inconsistentHolder: mismatch == 2)
        let (session, _) = try await script.open()
        await #expect(throws: ProtocolError.self) {
            try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
        }
        #expect(await session.state == .ready)
        await session.close()
    }
}

@Test func storageInspectionReleasesItsTransactionAfterInvalidIdentity() async throws {
    var script = InspectionScript()
    try script.base(invalidIdentity: true)
    try script.status()
    let (session, transport) = try await script.open()
    await #expect(throws: ProtocolError.self) {
        try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
    }
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(1))
    #expect(await session.state == .ready)
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.count == 4)
    await session.close()
}

@Test func storageInspectionTicketRejectsDirectDataSyncForeignAndStaleCalls() async throws {
    let script = InspectionScript()
    let (session, transport) = try await script.open()
    let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
    await #expect(throws: ProtocolError.busy) {
        try await session.execute(.testUnitReady(), lun: LogicalUnit(1))
    }
    await #expect(throws: ProtocolError.busy) {
        try await session.beginStorageInspection(lun: LogicalUnit(2))
    }
    for command in [
        SCSICommand.synchronizeCache10(), try .read(lba: 0, blocks: 1, blockSize: 512),
        try .write(lba: 0, blocks: 1, blockSize: 512),
    ] {
        await #expect(throws: ProtocolError.invalidState) {
            try await session.executeForStorageInspection(command, ticket: ticket)
        }
    }
    let foreign = StorageInspectionTicket(id: UUID(), lun: ticket.lun, initial: ticket.initial)
    await #expect(throws: ProtocolError.busy) {
        try await session.executeForStorageInspection(.inquiry(), ticket: foreign)
    }
    #expect(await session.finishStorageInspection(ticket))
    await #expect(throws: ProtocolError.invalidState) {
        try await session.executeForStorageInspection(.inquiry(), ticket: ticket)
    }
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.isEmpty)
    await session.close()
}

@Test func storageContinuityRecordsAttentionBeforeProbeConsumesAndRetriesIt() async throws {
    var script = InspectionScript()
    try script.status(2, key: 6, asc: 0x29)
    try script.data(Data([0, 0, 6, 2, 0]), allocation: 96)
    let (session, _) = try await script.open()
    let before = try #require(await session.storageContinuity)
    _ = try await DiskProbe.readOnly(.inquiry(), session: session, lun: LogicalUnit(1))
    let after = try #require(await session.storageContinuity)
    #expect(after.isReady && after.admittedCommands == 2)
    #expect(after.disruptionEpoch > before.disruptionEpoch)
    #expect(!after.continues(before))
    await session.close()
}

@Test func storageContinuityDistinguishesDefiniteSyncRefusalFromReservationLoss() async throws {
    for conflict in [false, true] {
        var script = InspectionScript()
        try script.status(conflict ? 0x18 : 2, key: 3, asc: 0x0C)
        let (session, _) = try await script.open()
        let before = try #require(await session.storageContinuity)
        await #expect(throws: ProtocolError.self) {
            try await session.execute(.synchronizeCache10(), lun: LogicalUnit(1))
        }
        let after = try #require(await session.storageContinuity)
        #expect(after.isReady)
        #expect(after.continues(before) == !conflict)
        #expect(after.hasAdmittedDataAccess)
        let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
        await #expect(throws: ProtocolError.invalidState) {
            try await session.ownUnexposedReservation(ticket)
        }
        #expect(await session.finishStorageInspection(ticket))
        await session.close()
    }
}

@Test func storageContinuityDoesNotForgetEarlierAdmittedDataAccess() async throws {
    var script = InspectionScript()
    try script.data(Data(repeating: 0xA7, count: 512), allocation: 512)
    try script.base()
    try script.reservations()
    let (session, _) = try await script.open()
    _ = try await session.execute(.read(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(1))
    do {
        let result = try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
        #expect(result.initialContinuity.hasAdmittedDataAccess)
        #expect(result.finalContinuity.hasAdmittedDataAccess)
        #expect(!result.establishesRecoveryAuthority)
    } catch {
        await session.close()
        throw error
    }
    await session.close()
}

@Test func storageInspectionCannotCommitObservationAfterConcurrentClose() async throws {
    let (session, _) = try await InspectionScript().open()
    let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
    let before = try #require(await session.storageContinuity)
    await session.close()
    #expect(!(await session.finishStorageInspection(ticket, validating: before)))
    let after = try #require(await session.storageContinuity)
    #expect(after.disruptionEpoch > before.disruptionEpoch)
    #expect(!after.isReady && !after.continues(before))
}

@Test func storageInspectionCancellationBeforeAdmissionLeavesConnectionAvailable() async throws {
    var script = InspectionScript()
    try script.status()
    let (session, transport) = try await script.open()
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(1))
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.count == 1)
    await session.close()
}

@Test func storageContinuityBindsAnActualSessionInstanceRatherThanOnlyConfiguredNames() async throws
{
    let (one, _) = try await InspectionScript().open()
    let (two, _) = try await InspectionScript().open()
    let a = try #require(await one.storageContinuity)
    let b = try #require(await two.storageContinuity)
    #expect(a.instanceID != b.instanceID)
    #expect(!a.continues(b) && !b.continues(a))
    await one.close()
    await two.close()
}

@Test func storageReviewRejectsHolderContradictingAValidCapabilityMask() async throws {
    var script = InspectionScript()
    try script.base()
    try script.reservations(registered: [0x11], holder: 0x11, holderType: 3)
    let (session, _) = try await script.open()
    await #expect(throws: ProtocolError.self) {
        try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
    }
    await session.close()
}

@Test func storageReviewRejectsCancellationAtTheAtomicCommit() async throws {
    let (session, _) = try await InspectionScript().open()
    let ticket = try await session.beginStorageInspection(lun: LogicalUnit(1))
    let observed = try #require(await session.storageContinuity)
    let commit = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await session.finishStorageInspection(ticket, validating: observed)
    }
    #expect(!(await commit.value))
    let next = try await session.beginStorageInspection(lun: LogicalUnit(1))
    #expect(await session.finishStorageInspection(next))
    await session.close()
}

@Test func storageInspectionKeepsAnUnvalidatedTypeMaskUnknown() async throws {
    var script = InspectionScript()
    try script.base()
    try script.reservations(registered: [0x11], holder: 0x11, holderType: 3, typeMaskValid: false)
    let (session, _) = try await script.open()
    do {
        let result = try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
        #expect(result.capabilities.supportedTypes == nil)
        #expect(result.reservation.holder?.type == .exclusiveAccess)
        #expect(!result.establishesRecoveryAuthority)
    } catch {
        await session.close()
        throw error
    }
    await session.close()
}

@Test func storageInspectionRefusesAttentionInsteadOfSilentlyRetryingItsSnapshot() async throws {
    var script = InspectionScript()
    try script.status(2, key: 6, asc: 0x29)
    try script.status()
    let (session, transport) = try await script.open()
    let before = try #require(await session.storageContinuity)
    await #expect(throws: ProtocolError.self) {
        try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
    }
    let after = try #require(await session.storageContinuity)
    #expect(after.disruptionEpoch > before.disruptionEpoch && after.isReady)
    _ = try await session.execute(.testUnitReady(), lun: LogicalUnit(1))
    #expect(await transport.writes.filter { Array($0)[0] & 0x3F == 1 }.count == 2)
    await session.close()
}

@Test func storageInspectionRejectsWireFailureWithoutLeavingAUsableObservation() async throws {
    var script = InspectionScript()
    try script.data(Data([0, 0, 6, 2, 0]), allocation: 96)
    var wrong = Array(try #require(script.responses.last))
    wrong.put(UInt32(99), at: 16)
    script.responses[script.responses.count - 1] = Data(wrong)
    let (session, _) = try await script.open()
    let before = try #require(await session.storageContinuity)
    await #expect(throws: ProtocolError.self) {
        try await DiskProbe.inspectStorage(session: session, lun: LogicalUnit(1))
    }
    let after = try #require(await session.storageContinuity)
    #expect(!after.isReady && after.disruptionEpoch > before.disruptionEpoch)
    await session.close()
}

@Test(arguments: [UInt8(0x73), 0x75])
func storageContinuityRevokesOnDeferredOrUnknownSense(_ response: UInt8) async throws {
    var script = InspectionScript()
    try script.status(2, key: 3, asc: 0x0C, response: response)
    let (session, _) = try await script.open()
    let before = try #require(await session.storageContinuity)
    await #expect(throws: ProtocolError.self) {
        try await session.execute(.synchronizeCache10(), lun: LogicalUnit(1))
    }
    let after = try #require(await session.storageContinuity)
    #expect(after.disruptionEpoch > before.disruptionEpoch)
    #expect(!after.continues(before))
    await session.close()
}
