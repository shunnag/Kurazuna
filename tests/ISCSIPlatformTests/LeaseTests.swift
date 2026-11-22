import Darwin
import Foundation
import Testing

@testable import ISCSIPlatform

private final class WeakLeaseOwner {
    weak var value: AnyObject?
    init(_ value: AnyObject?) { self.value = value }
}

private func leaseOwner(_ kind: String, directory: URL) throws -> AnyObject {
    if kind == "connections" {
        return try FileAttachmentJournal(
            directory: directory,
            bridgeRoot: directory.appendingPathComponent("Mounts"))
    }
    return try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
}

/// A duplicated descriptor shares the same flock, just as an inherited descriptor before exec.
/// Inspect only the path in this test's private directory; no production descriptor is touched.
private func duplicateLease(at url: URL) throws -> Int32 {
    var expected = stat()
    guard lstat(url.path, &expected) == 0 else { throw POSIXError(.ENOENT) }
    for descriptor in 0..<getdtablesize() {
        var info = stat()
        if fstat(descriptor, &info) == 0, info.st_dev == expected.st_dev,
            info.st_ino == expected.st_ino
        {
            let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
            guard copy >= 0 else { throw POSIXError(.EIO) }
            return copy
        }
    }
    throw POSIXError(.EBADF)
}

@Test(arguments: ["connections", "settings"])
func releasingOwnerUnlocksLeaseEvenWhileDuplicateDescriptorSurvives(kind: String) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: directory) }
    var owner: AnyObject? = try leaseOwner(kind, directory: directory)
    let released = WeakLeaseOwner(owner)
    let name = kind == "connections" ? "Connections.lock" : "Servers.json.lock"
    var duplicate = try duplicateLease(at: directory.appendingPathComponent(name))
    defer { if duplicate >= 0 { close(duplicate) } }
    #expect(fcntl(duplicate, F_GETFD) & FD_CLOEXEC != 0)
    owner = nil
    #expect(released.value == nil)
    let replacement = try leaseOwner(kind, directory: directory)
    #expect(throws: POSIXError(.EWOULDBLOCK)) { try leaseOwner(kind, directory: directory) }
    close(duplicate)
    duplicate = -1
    // Closing a stale duplicate must not release the new owner's distinct lock.
    #expect(throws: POSIXError(.EWOULDBLOCK)) { try leaseOwner(kind, directory: directory) }
    withExtendedLifetime(replacement) {}
}

@Test func connectionJournalRejectsHardLinksBeforeReadingOrChangingTheFile() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let journal = try FileAttachmentJournal(
        directory: directory, bridgeRoot: directory.appendingPathComponent("Mounts"))
    try journal.save([])
    let url = directory.appendingPathComponent("Connections.json")
    let original = try Data(contentsOf: url)
    #expect(link(url.path, directory.appendingPathComponent("Other.json").path) == 0)
    #expect(throws: POSIXError(.EACCES)) { try journal.load() }
    #expect(try Data(contentsOf: url) == original)
}
