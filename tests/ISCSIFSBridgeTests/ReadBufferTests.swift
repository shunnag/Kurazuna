import Foundation
import Testing

@testable import ISCSIFSBridge

@Test(arguments: [0, 1, 511, 1536, 4095, 4096])
func readBufferClearsOnlyUnusedBytes(_ returnedCount: Int) throws {
    let capacity = 4096
    let canary: UInt8 = 0xAD
    let contents = (0..<capacity).map { UInt8(truncatingIfNeeded: $0 * 37) }
    var storage = [UInt8](repeating: canary, count: capacity + 32)
    storage.replaceSubrange(16..<(16 + capacity), with: contents)
    try storage.withUnsafeMutableBytes { allocation in
        let buffer = UnsafeMutableRawBufferPointer(rebasing: allocation[16..<(16 + capacity)])
        try clearImageReadTail(buffer, after: returnedCount)
    }
    #expect(storage.prefix(16).allSatisfy { $0 == canary })
    #expect(Array(storage[16..<(16 + returnedCount)]) == Array(contents.prefix(returnedCount)))
    #expect(storage[(16 + returnedCount)..<(16 + capacity)].allSatisfy { $0 == 0 })
    #expect(storage.suffix(16).allSatisfy { $0 == canary })
}

@Test func emptyReadBufferNeedsNoStorage() throws {
    try clearImageReadTail(UnsafeMutableRawBufferPointer(start: nil, count: 0), after: 0)
}

@Test(arguments: [-1, 17, Int.max])
func invalidReadBufferCountsFailWithoutChangingMemory(_ returnedCount: Int) throws {
    let original = [UInt8](repeating: 0xAD, count: 16)
    var storage = original
    storage.withUnsafeMutableBytes { buffer in
        #expect(throws: POSIXError(.EFAULT)) {
            try clearImageReadTail(buffer, after: returnedCount)
        }
    }
    #expect(storage == original)
}
