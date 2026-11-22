import Foundation

/// Unsolicited, StatSN-consuming notification defined by RFC 7143 section 11.9.
public struct AsynchronousMessage: Sendable, Equatable {
    public let event: UInt8
    public let vendorCode: UInt8
    public let parameter1: UInt16
    public let parameter2: UInt16
    public let parameter3: UInt16
    public let lun: LogicalUnit
    public let sense: Data

    public init(_ pdu: PDU) throws {
        guard pdu.opcode == 0x32, pdu.flags & 0x80 != 0, pdu.taskTag == UInt32.max else {
            throw ProtocolError.malformed("asynchronous message header")
        }
        event = pdu.header[36]
        vendorCode = pdu.header[37]
        parameter1 = pdu.header.uint16(at: 38)
        parameter2 = pdu.header.uint16(at: 40)
        parameter3 = pdu.header.uint16(at: 42)
        lun = try LogicalUnit(wireBytes: Array(pdu.header[8..<16]))
        if pdu.data.isEmpty {
            sense = Data()
        } else {
            guard pdu.data.count >= 2 else {
                throw ProtocolError.malformed("asynchronous sense length")
            }
            let bytes = Array(pdu.data)
            let count = Int(bytes.uint16(at: 0))
            guard count <= pdu.data.count - 2 else {
                throw ProtocolError.malformed("asynchronous sense length")
            }
            sense = Data(bytes[2..<(2 + count)])
        }
        if event == 0 {
            _ = try SCSISense(data: sense)
        }
    }
}
