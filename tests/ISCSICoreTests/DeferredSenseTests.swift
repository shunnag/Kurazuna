import Foundation
import Testing

@testable import ISCSICore

@Test(arguments: [UInt8(0x70), 0xF0, 0x71, 0xF1, 0x72, 0x73])
func senseTimingSurvivesBothFormatsAndTheFixedValidBit(_ response: UInt8) throws {
    let fixed = response & 0x7F == 0x70 || response & 0x7F == 0x71
    let data =
        fixed
        ? Data([response, 0, 6, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x29, 0])
        : Data([response, 6, 0x29, 0, 0, 0, 0, 0])
    let sense = try SCSISense(data: data)
    #expect(sense.isDeferred == [UInt8(0x71), 0xF1, 0x73].contains(response))
    #expect(sense.key == 6 && sense.additionalSenseCode == 0x29 && sense.qualifier == 0)
    #expect(sense.isUnitAttention)
    #expect(throws: ProtocolError.self) { try SCSISense(data: data.dropLast()) }
}
