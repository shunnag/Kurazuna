import Foundation
import Testing

@testable import ISCSICore

private func reservationHeader(generation: UInt32 = .max, length: UInt32) -> [UInt8] {
    var data = Array(repeating: UInt8(0), count: 8)
    data.put(generation, at: 0)
    data.put(length, at: 4)
    return data
}

private func reservationStatusRow(
    key: UInt64, flags: UInt8, scopeAndType: UInt8,
    port: UInt16 = 12, transportLength: UInt32 = 24
) -> [UInt8] {
    var data = Array(repeating: UInt8(0), count: 24)
    data.put(key, at: 0)
    data[12] = flags
    data[13] = scopeAndType
    data.put(port, at: 18)
    data.put(transportLength, at: 20)
    return data + Array(repeating: 0x34, count: Int(transportLength))
}

@Test func reservationQueriesHaveCorrectCDBFieldsAndNeverTransferOutput() throws {
    let identity = try SCSICommand.deviceIdentification()
    #expect(identity.cdb == [0x12, 1, 0x83, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    #expect(identity.transferLength == 65_535 && identity.direction == .read)
    for (query, action) in [
        (SCSIReservationQuery.keys, UInt8(0)), (.reservation, 1), (.capabilities, 2),
        (.fullStatus, 3),
    ] {
        let command = try SCSICommand.persistentReservation(query, allocationLength: 0x1234)
        #expect(command.cdb == [0x5E, action, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0])
        #expect(command.direction == .read && command.transferLength == 0x1234)
    }
    #expect(throws: ProtocolError.self) {
        try SCSICommand.deviceIdentification(allocationLength: 3)
    }
    #expect(throws: ProtocolError.self) {
        try SCSICommand.persistentReservation(.keys, allocationLength: 7)
    }
}

@Test func reservationKeysPreserveDuplicateRegistrationsAndUnsignedGeneration() throws {
    var bytes = reservationHeader(length: 24)
    for key: UInt64 in [0x1234, 0x2345, 0x1234] {
        bytes += Array(repeating: 0, count: 8)
        bytes.put(key, at: bytes.count - 8)
    }
    let value = try SCSIReservationKeys(data: Data(bytes))
    #expect(value.generation == UInt32.max)
    #expect(value.keys == [0x1234, 0x2345, 0x1234])
    #expect(try SCSIReservationKeys(data: Data(reservationHeader(length: 0))).keys.isEmpty)
}

@Test func reservationKeysRejectTruncationMisalignmentAndUnboundedLength() throws {
    for bytes in [
        [], [0, 0, 0], reservationHeader(length: 9) + Array(repeating: 1, count: 9),
        reservationHeader(length: 8), reservationHeader(length: .max),
        reservationHeader(length: 8) + Array(repeating: 0, count: 8),
    ] {
        #expect(throws: ProtocolError.self) { try SCSIReservationKeys(data: Data(bytes)) }
    }
    #expect(throws: ProtocolError.self) {
        try SCSIReservationKeys(data: Data(repeating: 0, count: 65_536))
    }
}

@Test(arguments: SCSIReservationType.allCases)
func reservationHolderParsesAllValidTypesWithoutGrantingAccess(_ type: SCSIReservationType) throws {
    let all = type == .writeExclusiveAllRegistrants || type == .exclusiveAccessAllRegistrants
    var bytes = reservationHeader(length: 16) + Array(repeating: UInt8(0), count: 16)
    bytes.put(all ? UInt64(0) : 0x0123_4567_89AB_CDEF, at: 8)
    bytes[21] = type.rawValue
    let value = try SCSIReservation(data: Data(bytes))
    #expect(value.holder?.type == type)
    #expect(value.holder?.key == (all ? 0 : 0x0123_4567_89AB_CDEF))
    #expect(try SCSIReservation(data: Data(reservationHeader(length: 0))).holder == nil)
}

@Test func reservationHolderRejectsInvalidScopeTypeKeyAndLengths() throws {
    for (length, scopeType, key): (UInt32, UInt8, UInt64) in [
        (15, 1, 1), (17, 1, 1),
        (16, 0x11, 1), (16, 2, 1), (16, 1, 0), (16, 7, 1),
    ] {
        var bytes = reservationHeader(length: length) + Array(repeating: UInt8(0), count: 24)
        bytes[21] = scopeType
        bytes.put(key, at: 8)
        #expect(throws: ProtocolError.self) { try SCSIReservation(data: Data(bytes)) }
    }
}

@Test func reservationCapabilitiesDoNotInferTypesWhenMaskIsNotValid() throws {
    let unknown = try SCSIReservationCapabilities(data: Data([0, 8, 5, 1, 0xEA, 1, 0, 0]))
    #expect(unknown.supportedTypes == nil)
    #expect(unknown.persistThroughPowerLossCapable && unknown.persistThroughPowerLossActive)
    #expect(unknown.allTargetPortsCapable)
    let all = try SCSIReservationCapabilities(data: Data([0, 8, 0, 0x80, 0xEA, 1, 0, 0]))
    #expect(all.supportedTypes == Set(SCSIReservationType.allCases))
    let onlyHolder = try SCSIReservationCapabilities(data: Data([0, 8, 0, 0x80, 2, 0, 0, 0]))
    #expect(onlyHolder.supportedTypes == [.writeExclusive])
    for bad in [
        Data([0, 8, 0]), Data([0, 6, 0, 0, 0, 0, 0, 0]), Data([0, 10, 0, 0, 0, 0, 0, 0]),
    ] {
        #expect(throws: ProtocolError.self) { try SCSIReservationCapabilities(data: bad) }
    }
}

@Test func reservationFullStatusKeepsNexusesAndUndefinedNonHolderTypeSeparate() throws {
    let a = reservationStatusRow(key: 0x1234, flags: 1, scopeAndType: 1)
    let b = reservationStatusRow(key: 0x1234, flags: 2, scopeAndType: 0xFF)
    let value = try SCSIReservationFullStatus(
        data: Data(reservationHeader(length: UInt32(a.count + b.count)) + a + b))
    #expect(value.registrations.count == 2)
    #expect(value.registrations.map(\.key) == [0x1234, 0x1234])
    #expect(value.registrations[0].type == .writeExclusive)
    #expect(value.registrations[0].relativeTargetPort == 12)
    #expect(value.registrations[1].type == nil && value.registrations[1].relativeTargetPort == nil)
    #expect(value.registrations[0].transportID == Data(repeating: 0x34, count: 24))
}

@Test func reservationFullStatusRejectsEveryTruncationAndForgedDescriptorLength() throws {
    let row = reservationStatusRow(key: 8, flags: 1, scopeAndType: 3)
    let full = Data(reservationHeader(length: UInt32(row.count)) + row)
    for count in 0..<full.count {
        #expect(throws: ProtocolError.self) {
            try SCSIReservationFullStatus(data: full.prefix(count))
        }
    }
    for length: UInt32 in [0, 1, 23, 25, .max] {
        var bytes = Array(full)
        bytes.put(length, at: 28)
        #expect(throws: ProtocolError.self) { try SCSIReservationFullStatus(data: Data(bytes)) }
    }
    var unknown = Array(full)
    unknown[21] = 0x11
    #expect(throws: ProtocolError.self) { try SCSIReservationFullStatus(data: Data(unknown)) }
}

@Test func reservationResponsesAcceptSlicedDataAndIgnoreUnreportedAllocationTail() throws {
    let page = Data(reservationHeader(length: 0))
    let wrapped = Data(repeating: 0xFA, count: 21) + page
    let slice = wrapped.dropFirst(21)
    #expect(slice.startIndex != 0)
    #expect(try SCSIReservationKeys(data: slice).keys.isEmpty)
    #expect(try SCSIReservation(data: slice).holder == nil)
    #expect(try SCSIReservationFullStatus(data: slice).registrations.isEmpty)
    #expect(try SCSIReservationKeys(data: page + Data(repeating: 0xFF, count: 12)).keys.isEmpty)
}
