import Darwin
import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return url
}

@Test func settingsLeaseIsKernelHeldAndReleasedWithoutRemovingLockFile() throws {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("Servers.json")
    var first: ProfileStore? = try ProfileStore(url: url)
    let document = try #require(first).loadOrCreate()
    #expect(throws: POSIXError(.EWOULDBLOCK)) { try ProfileStore(url: url) }
    first = nil
    let second = try ProfileStore(url: url)
    #expect(try second.load() == document)
    let permissions =
        try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
    #expect(permissions?.intValue == 0o600)
}

@Test(arguments: ["symlink", "fifo", "hardlink", "permissions", "oversize"])
func invalidSettingsFilesAreRejectedWithoutReplacingEvidence(kind: String) throws {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
    let document = try store.loadOrCreate()
    let original = try Data(contentsOf: store.url)
    let outside = directory.appendingPathComponent("Original.json")
    switch kind {
    case "symlink":
        try FileManager.default.moveItem(at: store.url, to: outside)
        try FileManager.default.createSymbolicLink(at: store.url, withDestinationURL: outside)
    case "fifo":
        try FileManager.default.removeItem(at: store.url)
        #expect(mkfifo(store.url.path, 0o600) == 0)
    case "hardlink":
        #expect(link(store.url.path, outside.path) == 0)
    case "permissions":
        #expect(chmod(store.url.path, 0o644) == 0)
    default:
        let file = try FileHandle(forWritingTo: store.url)
        try file.truncate(atOffset: 1_048_577)
        try file.close()
    }
    #expect(throws: (any Error).self) { try store.loadOrCreate() }
    if kind == "symlink" || kind == "hardlink" {
        #expect(try Data(contentsOf: outside) == original)
    }
    if kind == "permissions" { #expect(try Data(contentsOf: store.url) == original) }
    #expect(document.servers.isEmpty)
}

@Test func replacedOrPublicSettingsDirectoryStopsReadsAndWrites() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = root.appendingPathComponent("Settings", isDirectory: true)
    let store = try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
    let original = try store.loadOrCreate()
    try FileManager.default.moveItem(at: directory, to: root.appendingPathComponent("Moved"))
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    #expect(throws: POSIXError(.ESTALE)) { try store.load() }
    #expect(throws: POSIXError(.ESTALE)) { try store.save(original) }
    #expect(
        !FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("Servers.json").path))
    #expect(chmod(directory.path, 0o755) == 0)
    #expect(throws: POSIXError(.EACCES)) {
        try ProfileStore(url: directory.appendingPathComponent("Other.json"))
    }
}

@Test func nonregularSettingsLeaseIsRejectedWithoutWaitingForAnotherProcess() throws {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    #expect(mkfifo(directory.appendingPathComponent("Servers.json.lock").path, 0o600) == 0)
    #expect(throws: POSIXError(.EACCES)) {
        try ProfileStore(url: directory.appendingPathComponent("Servers.json"))
    }
}
