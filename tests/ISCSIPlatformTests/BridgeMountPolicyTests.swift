import Darwin
import Testing

@testable import ISCSIPlatform

@Test(
    arguments: [UInt32(0), UInt32(MNT_SYNCHRONOUS), UInt32(MNT_RDONLY), UInt32(MNT_ASYNC)],
    [false, true])
func anOwnedBlockMountRequiresCompatibleKernelWriteFlags(_ flags: UInt32, _ readOnly: Bool) throws {
    if flags & UInt32(MNT_ASYNC) != 0 || (!readOnly && flags & UInt32(MNT_RDONLY) != 0) {
        #expect(throws: AttachmentError.writeCompletionUnavailable) {
            try SystemAttachmentBackend.validateBlockMountPolicy(flags: flags, readOnly: readOnly)
        }
    } else {
        try SystemAttachmentBackend.validateBlockMountPolicy(flags: flags, readOnly: readOnly)
    }
}

@Test(arguments: [
    UInt32(0), UInt32(MNT_NODEV), 270_532_608,
    UInt32(MNT_SYNCHRONOUS | MNT_RDONLY),
    UInt32(MNT_SYNCHRONOUS | MNT_ASYNC),
])
private func writableMountRequiresEffectiveSynchronousWrites(_ flags: UInt32) {
    #expect(throws: AttachmentError.writeCompletionUnavailable) {
        try SystemAttachmentBackend.validateWritableMountPolicy(flags: flags, readOnly: false)
    }
}

@Test(arguments: [UInt32(MNT_SYNCHRONOUS), 271_581_214])
private func synchronousWritableMountCanProceed(_ flags: UInt32) throws {
    try SystemAttachmentBackend.validateWritableMountPolicy(flags: flags, readOnly: false)
}

@Test(arguments: [UInt32(0), UInt32(MNT_RDONLY), 270_532_608, 271_581_213])
private func readOnlyBridgeDoesNotRequireWriteSynchronization(_ flags: UInt32) throws {
    try SystemAttachmentBackend.validateWritableMountPolicy(flags: flags, readOnly: true)
}
