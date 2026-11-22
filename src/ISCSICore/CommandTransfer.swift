import Foundation

public struct SCSIResult: Sendable, Equatable {
    public let data: Data
    public let residualCount: UInt32
}

public enum TransferProgress: Sendable, Equatable {
    case waiting
    case send([PDU])
    case complete(SCSIResult)
}

/// One ordered ERL-0 task. A write is acknowledged only by a successful SCSI status.
public struct CommandTransfer: Sendable {
    private let command: SCSICommand
    private let lun: LogicalUnit
    private let taskTag: UInt32
    private let output: Data
    private let maximumSegmentLength: Int
    private let maximumBurstLength: Int
    private var received = Data()
    private var sent = 0
    private var nextDataSN: UInt32 = 0
    private var nextR2TSN: UInt32 = 0
    private var finished = false

    public init(
        command: SCSICommand, lun: LogicalUnit, taskTag: UInt32, output: Data = Data(),
        maximumSegmentLength: Int = 8192, maximumBurstLength: Int = 262_144
    ) throws {
        guard taskTag != UInt32.max,
            (512...PDU.maximumDataLength).contains(maximumSegmentLength),
            (512...PDU.maximumDataLength).contains(maximumBurstLength),
            command.direction == .write
                ? output.count == Int(command.transferLength) : output.isEmpty
        else { throw ProtocolError.malformed("SCSI transfer configuration") }
        self.command = command
        self.lun = lun
        self.taskTag = taskTag
        self.output = output
        self.maximumSegmentLength = maximumSegmentLength
        self.maximumBurstLength = maximumBurstLength
    }

    public func request(commandSequenceNumber: UInt32, expectedStatusSequenceNumber: UInt32) throws
        -> PDU
    {
        var header = Array(repeating: UInt8(0), count: 48)
        header[0] = 0x01
        header[1] = 0x81  // Final; SIMPLE task attribute.
        if command.direction == .read { header[1] |= 0x40 }
        if command.direction == .write { header[1] |= 0x20 }
        header.replaceSubrange(8..<16, with: lun.wireBytes)
        header.put(taskTag, at: 16)
        header.put(command.transferLength, at: 20)
        header.put(commandSequenceNumber, at: 24)
        header.put(expectedStatusSequenceNumber, at: 28)
        header.replaceSubrange(32..<48, with: command.cdb)
        return try PDU(header: header)
    }

    public mutating func accept(_ response: PDU, expectedStatusSequenceNumber: UInt32) throws
        -> TransferProgress
    {
        guard !finished else { throw ProtocolError.invalidState }
        guard response.taskTag == taskTag else { throw ProtocolError.malformed("SCSI task tag") }
        switch response.opcode {
        case 0x25: return try acceptData(response)
        case 0x31:
            return try acceptR2T(
                response, expectedStatusSequenceNumber: expectedStatusSequenceNumber)
        case 0x21:
            // TGT 1.0.85 leaves ExpDataSN zero on CHECK CONDITION even after
            // sending Data-In. In ERL 0 that data is discarded with the error;
            // accepting this exception cannot complete a read or write successfully.
            let missingErrorDataSN = response.header[3] == 2 && response.dataSequenceNumber == 0
            guard response.flags & 0x80 != 0, response.header[2] == 0,
                response.dataSequenceNumber == nextDataSN || missingErrorDataSN
            else { throw ProtocolError.malformed("SCSI response") }
            // Residual semantics apply to CHECK CONDITION, BUSY and other device statuses
            // too. A malformed response must not become a recoverable SCSI error.
            _ = try validatedResidual(response)
            if response.header[3] != 0 {
                finished = true
                var sense = Data()
                if !response.data.isEmpty {
                    let bytes = [UInt8](response.data)
                    guard bytes.count >= 2, Int(bytes.uint16(at: 0)) <= bytes.count - 2 else {
                        throw ProtocolError.malformed("SCSI sense length")
                    }
                    sense = Data(bytes[2..<(2 + Int(bytes.uint16(at: 0)))])
                }
                throw ProtocolError.scsiFailure(status: response.header[3], sense: sense)
            }
            guard response.data.isEmpty else {
                throw ProtocolError.malformed("unexpected SCSI response data")
            }
            return try complete(response)
        default: throw ProtocolError.malformed("unexpected SCSI opcode")
        }
    }

    private mutating func acceptData(_ response: PDU) throws -> TransferProgress {
        // ERL 0 ignores the A bit; it does not request a DataACK SNACK from this initiator.
        guard command.direction == .read,
            response.dataSequenceNumber == nextDataSN,
            response.bufferOffset == UInt32(received.count),
            response.data.count <= Int(command.transferLength) - received.count
        else { throw ProtocolError.malformed("Data-In ordering or bounds") }
        let hasStatus = response.flags & 1 != 0
        guard !hasStatus || (response.flags & 0x80 != 0 && response.header[3] == 0) else {
            throw ProtocolError.malformed("Data-In status")
        }
        received.append(response.data)
        nextDataSN &+= 1
        return hasStatus ? try complete(response) : .waiting
    }

    private mutating func acceptR2T(_ response: PDU, expectedStatusSequenceNumber: UInt32) throws
        -> TransferProgress
    {
        // DesiredDataTransferLength occupies bytes 44...47.
        let length = Int(response.residualCount)
        guard command.direction == .write, response.flags == 0x80, response.data.isEmpty,
            response.transferTag != UInt32.max,
            Array(response.header[8..<16]) == lun.wireBytes,
            response.dataSequenceNumber == nextR2TSN, response.bufferOffset == UInt32(sent),
            length > 0, length <= maximumBurstLength, length <= output.count - sent
        else { throw ProtocolError.malformed("R2T ordering or bounds") }
        nextR2TSN &+= 1
        let end = sent + length
        var sequence: UInt32 = 0  // DataSN restarts for every R2T sequence.
        var pdus: [PDU] = []
        while sent < end {
            let count = min(maximumSegmentLength, end - sent)
            var header = Array(repeating: UInt8(0), count: 48)
            header[0] = 0x05
            header[1] = sent + count == end ? 0x80 : 0
            header.replaceSubrange(8..<16, with: lun.wireBytes)
            header.put(taskTag, at: 16)
            header.put(response.transferTag, at: 20)
            header.put(expectedStatusSequenceNumber, at: 28)
            header.put(sequence, at: 36)
            header.put(UInt32(sent), at: 40)
            let start = output.startIndex + sent
            pdus.append(try PDU(header: header, data: Data(output[start..<(start + count)])))
            sent += count
            sequence &+= 1
        }
        return .send(pdus)
    }

    private func validatedResidual(_ response: PDU) throws -> UInt32 {
        let underflow = response.flags & 0x02 != 0
        let overflow = response.flags & 0x04 != 0
        guard !(underflow && overflow),
            !(underflow || overflow) || response.residualCount > 0,
            !underflow || response.residualCount <= command.transferLength
        else { throw ProtocolError.malformed("SCSI residual count") }
        // RFC 7143: without U/O, the residual field is ignored on reception.
        return underflow ? response.residualCount : 0
    }

    private mutating func complete(_ response: PDU) throws -> TransferProgress {
        let residual = try validatedResidual(response)
        guard response.flags & 0x04 == 0 else {
            throw ProtocolError.malformed("SCSI residual count")
        }
        guard !command.requiresExactTransfer || residual == 0 else {
            throw ProtocolError.malformed("short block transfer")
        }
        let transferred = command.direction == .read ? received.count : sent
        guard transferred == Int(command.transferLength - residual)
        else {
            throw ProtocolError.malformed("incomplete SCSI transfer")
        }
        finished = true
        return .complete(SCSIResult(data: received, residualCount: residual))
    }
}
