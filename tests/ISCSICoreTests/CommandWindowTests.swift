import Foundation
import Testing

@testable import ISCSICore

@Test(arguments: [UInt32(1), UInt32.max - 1])
func commandWindowUpdatesAdvanceEachBoundaryAndIgnoreOldOrInvalidPairs(_ start: UInt32) throws {
    var parameters = SessionParameters()
    parameters.commandSequenceNumber = start &+ 2
    parameters.expectedCommandSequenceNumber = start
    parameters.maximumCommandSequenceNumber = start &+ 31
    try parameters.updateCommandWindow(expected: start &+ 1, maximum: start &+ 32)
    #expect(parameters.expectedCommandSequenceNumber == start &+ 1)
    #expect(parameters.maximumCommandSequenceNumber == start &+ 32)
    let advanced = parameters
    try parameters.updateCommandWindow(expected: start, maximum: start &+ 30)
    #expect(parameters == advanced)
    try parameters.updateCommandWindow(expected: start &+ 2, maximum: start &- 1)
    #expect(parameters == advanced)
    // Ignore both fields before considering an impossible acknowledgment in the invalid pair.
    try parameters.updateCommandWindow(expected: start &+ 4, maximum: start &+ 2)
    #expect(parameters == advanced)
    try parameters.updateCommandWindow(expected: start &+ 2, maximum: start &+ 33)
    #expect(parameters.expectedCommandSequenceNumber == start &+ 2)
    #expect(parameters.maximumCommandSequenceNumber == start &+ 33)
    // One boundary may advance even when the other is an older snapshot.
    try parameters.updateCommandWindow(expected: start &+ 1, maximum: start &+ 34)
    #expect(parameters.expectedCommandSequenceNumber == start &+ 2)
    #expect(parameters.maximumCommandSequenceNumber == start &+ 34)
    parameters.commandSequenceNumber &+= 1
    try parameters.updateCommandWindow(expected: start &+ 3, maximum: start &+ 33)
    #expect(parameters.expectedCommandSequenceNumber == start &+ 3)
    #expect(parameters.maximumCommandSequenceNumber == start &+ 34)
}

@Test(arguments: [UInt32(1), UInt32.max - 1])
func aValidWindowCannotAcknowledgeBeyondTheLocalNextCommand(_ start: UInt32) throws {
    var parameters = SessionParameters()
    parameters.commandSequenceNumber = start &+ 1
    parameters.expectedCommandSequenceNumber = start
    parameters.maximumCommandSequenceNumber = start &+ 31
    let original = parameters
    for expected in [start &+ 2, parameters.commandSequenceNumber &+ 0x8000_0000] {
        #expect(throws: ProtocolError.malformed("command window")) {
            try parameters.updateCommandWindow(expected: expected, maximum: expected &+ 31)
        }
        #expect(parameters == original)
    }
}

@Test(arguments: [UInt32(1), .max])
func aConsumedCommandCreditRequiresANewerLimitToReopen(_ start: UInt32) throws {
    var parameters = SessionParameters()
    parameters.commandSequenceNumber = start
    parameters.expectedCommandSequenceNumber = start
    parameters.maximumCommandSequenceNumber = start &- 1
    func open(_ parameters: SessionParameters) -> Bool {
        SerialNumber.isWithin(
            parameters.commandSequenceNumber, first: parameters.expectedCommandSequenceNumber,
            last: parameters.maximumCommandSequenceNumber)
    }
    #expect(!open(parameters))
    try parameters.updateCommandWindow(expected: start &- 1, maximum: start &- 2)
    #expect(!open(parameters))
    try parameters.updateCommandWindow(expected: start, maximum: start)
    #expect(open(parameters))
    parameters.commandSequenceNumber &+= 1
    #expect(!open(parameters))
    try parameters.updateCommandWindow(expected: start &+ 1, maximum: start)
    #expect(!open(parameters))
    try parameters.updateCommandWindow(expected: start &+ 1, maximum: start &+ 1)
    #expect(open(parameters))
}
