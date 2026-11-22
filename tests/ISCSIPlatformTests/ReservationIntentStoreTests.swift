import Darwin
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private func reservationIntent(_ key: UInt64 = 0x1234) throws -> OwnedReservationIntent {
    let binding = try OwnedReservationBinding(
        sessionID: UUID(), initiatorName: "iqn.2026-10.dev.soba:initiator",
        targetName: "iqn.2026-10.dev.soba:target", isid: [0x80, 1, 2, 3, 4, 5],
        tsih: 1, portalGroup: 1, relativeTargetPort: 12, lun: LogicalUnit(1),
        logicalUnitNames: Data([1, 2, 3]), blockCount: 1024, blockSize: 512,
        quiescenceID: UUID())
    return try OwnedReservationIntent(key: key, binding: binding)
}

private func intentDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true
    )
    .resolvingSymlinksInPath()
}

@Test func reservationIntentStoreFullSyncRoundTripCASAndKernelLease() throws {
    let directory = intentDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    var store: FileReservationIntentStore? = try FileReservationIntentStore(directory: directory)
    let original = try reservationIntent()
    #expect(try store?.load() == [])
    try store?.insert(original)
    #expect(try store?.load() == [original])
    #expect(throws: POSIXError.self) { try FileReservationIntentStore(directory: directory) }
    #expect(throws: ProtocolError.self) { try store?.insert(original) }
    #expect(throws: ProtocolError.self) { try store?.insert(reservationIntent(0x3456)) }
    let registered = try original.advancing(to: .registered)
    try store?.advance(original, to: registered)
    #expect(throws: ProtocolError.self) { try store?.advance(original, to: registered) }
    store = nil
    let reopened = try FileReservationIntentStore(directory: directory)
    #expect(try reopened.load() == [registered])
    let path = directory.appendingPathComponent("ReservationIntents.json")
    let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test(arguments: [
    "symlink", "hardlink", "permissions", "malformed", "oversize", "lockReplacement",
    "directoryReplacement", "removed", "validReplacement",
])
func reservationIntentStoreRejectsUnsafeOrReplacedOwnership(_ fault: String) throws {
    let directory = intentDirectory()
    let other = intentDirectory()
    defer {
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.removeItem(at: other)
    }
    let store = try FileReservationIntentStore(directory: directory)
    let original = try reservationIntent()
    try store.insert(original)
    let path = directory.appendingPathComponent("ReservationIntents.json")
    switch fault {
    case "removed": try FileManager.default.removeItem(at: path)
    case "validReplacement":
        let replacement = try reservationIntent(0x3456)
        let document = try JSONSerialization.jsonObject(with: JSONEncoder().encode(replacement))
        let data = try JSONSerialization.data(
            withJSONObject: ["version": 1, "intents": [document]])
        try data.write(to: path)
    case "symlink":
        try FileManager.default.moveItem(at: path, to: other)
        try FileManager.default.createSymbolicLink(at: path, withDestinationURL: other)
    case "hardlink": try FileManager.default.linkItem(at: path, to: other)
    case "permissions":
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
    case "malformed": try Data("malformed".utf8).write(to: path)
    case "oversize":
        let file = try FileHandle(forWritingTo: path)
        try file.truncate(atOffset: 16 * 1024 * 1024 + 1)
        try file.close()
    case "lockReplacement":
        let lock = directory.appendingPathComponent("ReservationIntents.lock")
        try FileManager.default.removeItem(at: lock)
        #expect(
            FileManager.default.createFile(
                atPath: lock.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
    default:
        try FileManager.default.moveItem(at: directory, to: other)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
    }
    #expect(throws: (any Error).self) { try store.load() }
    #expect(throws: (any Error).self) {
        try store.advance(original, to: original.advancing(to: .registered))
    }
}

private final class SyncFailure: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    let failedCall: Int
    init(_ failedCall: Int) { self.failedCall = failedCall }
    func synchronize(_ fd: Int32) throws {
        let count = lock.withLock {
            calls += 1
            return calls
        }
        if count == failedCall { throw POSIXError(.EIO) }
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
    }
}

@Test(arguments: [1, 2])
func reservationIntentStorePublicationFailureLatchesAndPreservesPossibleOrphan(_ failedCall: Int)
    throws
{
    let directory = intentDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let injection = SyncFailure(failedCall)
    var store: FileReservationIntentStore? = try FileReservationIntentStore(
        directory: directory, synchronize: injection.synchronize)
    let original = try reservationIntent()
    #expect(throws: POSIXError.self) { try store?.insert(original) }
    #expect(throws: ProtocolError.self) { try store?.load() }
    #expect(throws: ProtocolError.self) { try store?.insert(original) }
    let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
    #expect(
        names.contains {
            $0.hasPrefix(failedCall == 1 ? ".ReservationIntents-" : "ReservationIntents.json")
        })
    store = nil
    let reopened = try FileReservationIntentStore(directory: directory)
    // Readback of a possibly renamed record is not authority or proof its failed save was durable.
    #expect(try reopened.load() == (failedCall == 1 ? [] : [original]))
}

private final class FileSwapOnSync: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = false
    let path: URL
    let removeOnly: Bool
    init(path: URL, removeOnly: Bool) {
        self.path = path
        self.removeOnly = removeOnly
    }
    func arm() { lock.withLock { armed = true } }
    func synchronize(_ fd: Int32) throws {
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw POSIXError(.EIO) }
        let change = lock.withLock {
            let value = armed
            armed = false
            return value
        }
        if change {
            let bytes = try Data(contentsOf: path)
            try FileManager.default.removeItem(at: path)
            if !removeOnly {
                #expect(
                    FileManager.default.createFile(
                        atPath: path.path, contents: bytes, attributes: [.posixPermissions: 0o600]))
            }
        }
    }
}

@Test(arguments: [false, true])
func reservationIntentStoreRejectsReplacementDuringPublication(_ removed: Bool) throws {
    let directory = intentDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let hook = FileSwapOnSync(
        path: directory.appendingPathComponent("ReservationIntents.json"), removeOnly: removed)
    let store = try FileReservationIntentStore(directory: directory, synchronize: hook.synchronize)
    let intent = try reservationIntent()
    try store.insert(intent)
    hook.arm()
    #expect(throws: (any Error).self) {
        try store.advance(intent, to: intent.advancing(to: .registered))
    }
    #expect(throws: ProtocolError.self) { try store.load() }
}
