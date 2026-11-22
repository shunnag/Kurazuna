import Foundation
import Testing

@testable import ISCSICore

private func response(
    opcode: UInt8, flags: UInt8 = 0x80, dataSN: UInt32 = 0, offset: UInt32 = 0,
    residual: UInt32 = 0, status: UInt8 = 0, data: Data = Data()
) throws -> PDU {
    var header = Array(repeating: UInt8(0), count: 48)
    header[0] = opcode
    header[1] = flags
    header[3] = status
    header.put(UInt32(7), at: 16)
    header.put(UInt32(77), at: 20)
    header.put(dataSN, at: 36)
    header.put(offset, at: 40)
    header.put(residual, at: 44)
    return try PDU(header: header, data: data)
}

@Test func orderedReadWithSeparateStatus() throws {
    var task = try CommandTransfer(
        command: .read16(lba: 4, blocks: 2, blockSize: 512), lun: LogicalUnit(0), taskTag: 7)
    let request = try task.request(commandSequenceNumber: 9, expectedStatusSequenceNumber: 3)
    #expect(request.flags == 0xC1)
    #expect(request.header.uint64(at: 34) == 4)
    #expect(
        try task.accept(
            response(opcode: 0x25, flags: 0, data: Data(repeating: 1, count: 512)),
            expectedStatusSequenceNumber: 3) == .waiting)
    #expect(
        try task.accept(
            response(opcode: 0x25, dataSN: 1, offset: 512, data: Data(repeating: 2, count: 512)),
            expectedStatusSequenceNumber: 3) == .waiting)
    let result = try task.accept(response(opcode: 0x21, dataSN: 2), expectedStatusSequenceNumber: 4)
    guard case .complete(let completed) = result else {
        Issue.record("Read did not complete")
        return
    }
    #expect(completed.data == Data(repeating: 1, count: 512) + Data(repeating: 2, count: 512))
}

@Test func checkConditionWithZeroExpDataSNDiscardsPreviouslyReceivedData() throws {
    // TGT 1.0.85 sends 32 bytes before a Unit Attention with ExpDataSN = 0.
    let sense = Data([0x70, 0, 6, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x29, 0, 0, 0, 0, 0])
    var task = try CommandTransfer(command: .readCapacity16(), lun: LogicalUnit(1), taskTag: 7)
    #expect(
        try task.accept(
            response(opcode: 0x25, data: Data(repeating: 0xA5, count: 32)),
            expectedStatusSequenceNumber: 0) == .waiting)
    #expect(throws: ProtocolError.scsiFailure(status: 2, sense: sense)) {
        try task.accept(
            response(opcode: 0x21, status: 2, data: Data([0, 18]) + sense),
            expectedStatusSequenceNumber: 0)
    }
    #expect(throws: ProtocolError.invalidState) {
        try task.accept(response(opcode: 0x21, dataSN: 1), expectedStatusSequenceNumber: 0)
    }
}

@Test func zeroErrorDataSNExceptionDoesNotAllowSuccessOrOtherMismatches() throws {
    for (status, dataSN): (UInt8, UInt32) in [(0, 0), (2, 2), (8, 0)] {
        var task = try CommandTransfer(command: .readCapacity16(), lun: LogicalUnit(1), taskTag: 7)
        _ = try task.accept(
            response(opcode: 0x25, data: Data(repeating: 0xA5, count: 32)),
            expectedStatusSequenceNumber: 0)
        #expect(throws: ProtocolError.malformed("SCSI response")) {
            try task.accept(
                response(opcode: 0x21, dataSN: dataSN, status: status),
                expectedStatusSequenceNumber: 0)
        }
    }
}

@Test func zeroErrorDataSNExceptionStillValidatesResidualsAndSense() throws {
    for malformedSense in [false, true] {
        var task = try CommandTransfer(command: .readCapacity16(), lun: LogicalUnit(1), taskTag: 7)
        _ = try task.accept(
            response(opcode: 0x25, data: Data(repeating: 0xA5, count: 32)),
            expectedStatusSequenceNumber: 0)
        #expect(
            throws: ProtocolError.malformed(
                malformedSense ? "SCSI sense length" : "SCSI residual count")
        ) {
            try task.accept(
                response(
                    opcode: 0x21, flags: malformedSense ? 0x80 : 0x86,
                    residual: 1, status: 2, data: malformedSense ? Data([0, 18]) : Data()),
                expectedStatusSequenceNumber: 0)
        }
    }
}

@Test(arguments: [UInt32(0), 1, .max])
func successfulStatusCannotHideShortRead(_ unusedResidual: UInt32) throws {
    var task = try CommandTransfer(
        command: .read16(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0), taskTag: 7)
    #expect(throws: ProtocolError.self) {
        try task.accept(
            response(
                opcode: 0x25, flags: 0x81, residual: unusedResidual,
                data: Data(repeating: 1, count: 511)),
            expectedStatusSequenceNumber: 0)
    }
}

@Test(arguments: [UInt8(0x28), 0x88, 0x2A, 0x8A])
func underflowCannotCompleteAnExactBlockCommand(_ opcode: UInt8) throws {
    let command: SCSICommand
    switch opcode {
    case 0x28: command = try .read10(lba: 0, blocks: 1, blockSize: 512)
    case 0x88: command = try .read16(lba: 0, blocks: 1, blockSize: 512)
    case 0x2A: command = try .write10(lba: 0, blocks: 1, blockSize: 512)
    default: command = try .write16(lba: 0, blocks: 1, blockSize: 512)
    }
    var task = try CommandTransfer(
        command: command, lun: LogicalUnit(0), taskTag: 7,
        output: command.direction == .write ? Data(repeating: 1, count: 512) : Data())
    if command.direction == .write {
        _ = try task.accept(response(opcode: 0x31, residual: 256), expectedStatusSequenceNumber: 0)
    }
    #expect(throws: ProtocolError.malformed("short block transfer")) {
        try task.accept(
            response(
                opcode: command.direction == .read ? 0x25 : 0x21,
                flags: command.direction == .read ? 0x83 : 0x82, residual: 256,
                data: command.direction == .read ? Data(repeating: 1, count: 256) : Data()),
            expectedStatusSequenceNumber: 0)
    }
}

@Test func anUnusedResidualFieldIsIgnoredForCompletedDataAndCacheSynchronization() throws {
    for command in [
        try SCSICommand.read10(lba: 0, blocks: 1, blockSize: 512),
        try SCSICommand.read16(lba: 0, blocks: 1, blockSize: 512),
        SCSICommand.inquiry(),
    ] {
        let data = Data(repeating: 0xA5, count: Int(command.transferLength))
        var task = try CommandTransfer(command: command, lun: LogicalUnit(0), taskTag: 7)
        let result = try task.accept(
            response(opcode: 0x25, flags: 0x81, residual: .max, data: data),
            expectedStatusSequenceNumber: 0)
        #expect(result == .complete(SCSIResult(data: data, residualCount: 0)))
    }
    for command in [
        try SCSICommand.write10(lba: 0, blocks: 1, blockSize: 512),
        try SCSICommand.write16(lba: 0, blocks: 1, blockSize: 512),
        SCSICommand.synchronizeCache10(), SCSICommand.synchronizeCache16(),
    ] {
        var task = try CommandTransfer(
            command: command, lun: LogicalUnit(0), taskTag: 7,
            output: Data(repeating: 1, count: Int(command.transferLength)))
        if command.direction == .write {
            _ = try task.accept(
                response(opcode: 0x31, residual: 512), expectedStatusSequenceNumber: 0)
        }
        let result = try task.accept(
            response(opcode: 0x21, residual: .max), expectedStatusSequenceNumber: 0)
        #expect(result == .complete(SCSIResult(data: Data(), residualCount: 0)))
    }
}

@Test func explicitUnderflowRetainsResidual() throws {
    var task = try CommandTransfer(
        command: .inquiry(allocationLength: 96), lun: LogicalUnit(0), taskTag: 7)
    let result = try task.accept(
        response(opcode: 0x25, flags: 0x83, residual: 60, data: Data(repeating: 0, count: 36)),
        expectedStatusSequenceNumber: 0)
    guard case .complete(let completed) = result else {
        Issue.record("Inquiry did not complete")
        return
    }
    #expect(completed.residualCount == 60)
    #expect(completed.data.count == 36)
}

@Test func r2tSplitsAndResetsDataSNPerBurst() throws {
    let output = Data((0..<2048).map { UInt8(truncatingIfNeeded: $0) })
    var task = try CommandTransfer(
        command: .write16(lba: 0, blocks: 4, blockSize: 512), lun: LogicalUnit(0), taskTag: 7,
        output: output, maximumSegmentLength: 512)
    for burst: UInt32 in 0..<2 {
        let result = try task.accept(
            response(opcode: 0x31, dataSN: burst, offset: burst * 1024, residual: 1024),
            expectedStatusSequenceNumber: 8)
        guard case .send(let pdus) = result else {
            Issue.record("No Data-Out")
            return
        }
        #expect(pdus.count == 2)
        #expect(pdus.map(\.dataSequenceNumber) == [0, 1])
        #expect(pdus.map(\.flags) == [0, 0x80])
        #expect(pdus.map(\.bufferOffset) == [burst * 1024, burst * 1024 + 512])
        #expect(pdus.allSatisfy { $0.transferTag == 77 })
    }
    #expect(
        try task.accept(response(opcode: 0x21), expectedStatusSequenceNumber: 9)
            == .complete(SCSIResult(data: Data(), residualCount: 0)))
}

@Test func writeRequiresAcknowledgmentAndRejectsOverlappingR2T() throws {
    var task = try CommandTransfer(
        command: .write16(lba: 0, blocks: 2, blockSize: 512), lun: LogicalUnit(0), taskTag: 7,
        output: Data(repeating: 1, count: 1024))
    #expect(throws: ProtocolError.self) {
        try task.accept(response(opcode: 0x21), expectedStatusSequenceNumber: 0)
    }
    _ = try task.accept(response(opcode: 0x31, residual: 512), expectedStatusSequenceNumber: 0)
    #expect(throws: ProtocolError.self) {
        try task.accept(
            response(opcode: 0x31, dataSN: 1, offset: 0, residual: 512),
            expectedStatusSequenceNumber: 0)
    }
}

@Test(arguments: [UInt8(0), 2, 8, 0x18])
func invalidResidualsCannotHideBehindADeviceStatus(_ status: UInt8) throws {
    for (flags, count): (UInt8, UInt32) in [(0x86, 1), (0x82, 0), (0x82, 97), (0x84, 0)] {
        var task = try CommandTransfer(command: .inquiry(), lun: LogicalUnit(0), taskTag: 7)
        #expect(throws: ProtocolError.malformed("SCSI residual count")) {
            try task.accept(
                response(opcode: 0x21, flags: flags, residual: count, status: status),
                expectedStatusSequenceNumber: 0)
        }
    }
}

@Test(arguments: [UInt8(2), 8, 0x18])
func validResidualsDoNotReplaceADeviceErrorWithASuccessOrTransportFailure(_ status: UInt8) throws {
    for command in [
        SCSICommand.inquiry(), try .read10(lba: 0, blocks: 1, blockSize: 512),
        try .write16(lba: 0, blocks: 1, blockSize: 512), .synchronizeCache10(),
    ] {
        let residuals: [(UInt8, UInt32)] =
            [(0x80, .max), (0x84, 1)]
            + (command.transferLength == 0 ? [] : [(UInt8(0x82), command.transferLength)])
        for (flags, count) in residuals {
            var task = try CommandTransfer(
                command: command, lun: LogicalUnit(0), taskTag: 7,
                output: command.direction == .write
                    ? Data(repeating: 0, count: Int(command.transferLength)) : Data())
            #expect(throws: ProtocolError.scsiFailure(status: status, sense: Data())) {
                try task.accept(
                    response(opcode: 0x21, flags: flags, residual: count, status: status),
                    expectedStatusSequenceNumber: 0)
            }
        }
    }
}

@Test func dataInWithoutStatusDoesNotInterpretStatusOrResidualFields() throws {
    var task = try CommandTransfer(command: .inquiry(), lun: LogicalUnit(0), taskTag: 7)
    let data = Data(repeating: 0xA5, count: 96)
    #expect(
        try task.accept(
            response(opcode: 0x25, flags: 0x86, residual: .max, status: 2, data: data),
            expectedStatusSequenceNumber: 0) == .waiting)
    #expect(
        try task.accept(response(opcode: 0x21, dataSN: 1), expectedStatusSequenceNumber: 0)
            == .complete(SCSIResult(data: data, residualCount: 0)))
}

@Test(arguments: [false, true])
func erlZeroIgnoresDataAcknowledgmentRequestsWithoutSendingASnack(_ statusInData: Bool) throws {
    var task = try CommandTransfer(
        command: .read10(lba: 0, blocks: 1, blockSize: 512), lun: LogicalUnit(0), taskTag: 7)
    let data = Data(repeating: 0xA5, count: 512)
    let progress = try task.accept(
        response(opcode: 0x25, flags: statusInData ? 0xC1 : 0xC0, data: data),
        expectedStatusSequenceNumber: 0)
    let completion = TransferProgress.complete(SCSIResult(data: data, residualCount: 0))
    if statusInData {
        #expect(progress == completion)
    } else {
        #expect(progress == .waiting)
        #expect(
            try task.accept(response(opcode: 0x21, dataSN: 1), expectedStatusSequenceNumber: 0)
                == completion)
    }
}
