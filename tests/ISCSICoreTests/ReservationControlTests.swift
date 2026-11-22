import Foundation
import Testing

@testable import ISCSICore

@Test func reservationControlsHaveExactCDBAndNexusOnlyParameters() throws {
    for action in [SCSIReservationAction.register, .reserve, .release] {
        let control = try SCSIReservationControl(
            action: action, key: action == .register ? 0 : 0x1234,
            newKey: action == .register ? 0x1234 : 0)
        let cdb = control.command.cdb
        #expect(cdb[0] == 0x5F && cdb[1] == action.rawValue)
        #expect(cdb[2] == (action == .register ? 0 : 1))
        #expect(cdb.uint32(at: 5) == 24 && cdb.count == 16)
        #expect(control.command.direction == .write && control.command.requiresExactTransfer)
        #expect(control.command.transferLength == 24 && control.parameters.count == 24)
        #expect(control.parameters.dropFirst(16).allSatisfy { $0 == 0 })
        #expect(Array(control.parameters).uint64(at: action == .register ? 8 : 0) == 0x1234)
    }
    let unregister = try SCSIReservationControl(action: .register, key: 0x1234)
    #expect(Array(unregister.parameters).uint64(at: 8) == 0)
    #expect(throws: ProtocolError.self) {
        try SCSIReservationControl(action: .register, key: 0)
    }
    #expect(throws: ProtocolError.self) {
        try SCSIReservationControl(action: .register, key: 1, newKey: 2)
    }
    #expect(throws: ProtocolError.self) {
        try SCSIReservationControl(action: .reserve, key: 0)
    }
}

private func portBytes(_ name: String = "iqn.2026-10.dev.soba:initiator", format: UInt8 = 0x45)
    -> Data
{
    var payload = Array((name + ",i,0x800102030405").utf8) + [0]
    while payload.count < 20 || payload.count % 4 != 0 { payload.append(0) }
    return Data([format, 0, UInt8(payload.count >> 8), UInt8(payload.count & 255)] + payload)
}

@Test func reservationPortBindsExactNameAndSixByteISID() throws {
    let data = portBytes()
    let port = try ISCSIReservationPort(data: data)
    #expect(port.initiatorName == "iqn.2026-10.dev.soba:initiator")
    #expect(port.isid == [0x80, 1, 2, 3, 4, 5])
    #expect(try ISCSIReservationPort(data: (Data([99]) + data).dropFirst()) == port)
    for length in 0..<data.count {
        #expect(throws: ProtocolError.self) {
            try ISCSIReservationPort(data: data.prefix(length))
        }
    }
    for index in [0, 1, 2, 3, data.count - 1] {
        var wrong = data
        wrong[index] ^= 0x10
        #expect(throws: ProtocolError.self) { try ISCSIReservationPort(data: wrong) }
    }
    #expect(throws: ProtocolError.self) { try ISCSIReservationPort(data: portBytes(format: 5)) }
}

@Test func reservationPortRejectsMalformedPortSuffix() {
    for suffix in [",i,0x80010203040", ",i,0x8001020304050", ",i,0x80010203040z", ""] {
        var payload = Array(("iqn.2026-10.dev.soba:initiator" + suffix).utf8) + [0]
        while payload.count % 4 != 0 { payload.append(0) }
        let data = Data([0x45, 0, 0, UInt8(payload.count)] + payload)
        #expect(throws: ProtocolError.self) { try ISCSIReservationPort(data: data) }
    }
}

@Test func reservationIntentHasImmutableIdentityAndMonotonicPhases() throws {
    let binding = try OwnedReservationBinding(
        sessionID: UUID(), initiatorName: "iqn.2026-10.dev.soba:initiator",
        targetName: "iqn.2026-10.dev.soba:target", isid: [0x80, 1, 2, 3, 4, 5],
        tsih: 1, portalGroup: 1, relativeTargetPort: 12, lun: LogicalUnit(1),
        logicalUnitNames: Data([1, 2, 3]), blockCount: 1024, blockSize: 512,
        quiescenceID: UUID())
    var intent = try OwnedReservationIntent(key: 7, binding: binding)
    #expect(throws: ProtocolError.self) { try intent.advancing(to: .reserved) }
    for phase in [
        OwnedReservationIntent.Phase.registered, .reserving, .reserved, .releasing,
        .unregistering, .released,
    ] {
        let next = try intent.advancing(to: phase)
        #expect(next.id == intent.id && next.key == intent.key && next.binding == intent.binding)
        #expect(next.revision == intent.revision + 1)
        #expect(
            try JSONDecoder().decode(OwnedReservationIntent.self, from: JSONEncoder().encode(next))
                == next)
        try next.validate()
        intent = next
    }
    #expect(throws: ProtocolError.self) { try intent.advancing(to: .prepared) }
    #expect(throws: ProtocolError.self) { try OwnedReservationIntent(key: 0, binding: binding) }
}
