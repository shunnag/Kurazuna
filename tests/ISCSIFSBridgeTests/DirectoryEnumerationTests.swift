import FSKit
import Foundation
import Testing

@testable import ISCSIFSBridge

private struct PackedDirectoryEntry {
    let name: String?
    let type: FSItem.ItemType
    let identifier: FSItem.Identifier
    let nextCookie: FSDirectoryCookie
    let attributes: FSItem.Attributes?
}

private struct DirectoryPage {
    let entries: [PackedDirectoryEntry]
    let attempts: Int
    let verifier: FSDirectoryVerifier
}

private func directoryPage(
    _ volume: LUNImageVolume, cookie: UInt64 = 0, verifier: UInt64 = 0,
    attributes: FSItem.GetAttributesRequest? = nil, capacity: Int = .max
) throws -> DirectoryPage {
    var entries: [PackedDirectoryEntry] = []
    var attempts = 0
    let current = try volume.enumerateDirectoryEntries(
        volume.rootItem, startingAt: FSDirectoryCookie(rawValue: cookie),
        verifier: FSDirectoryVerifier(rawValue: verifier), attributes: attributes
    ) { name, type, identifier, nextCookie, values in
        attempts += 1
        guard entries.count < capacity else { return false }
        entries.append(
            PackedDirectoryEntry(
                name: name.string, type: type, identifier: identifier,
                nextCookie: nextCookie, attributes: values))
        return true
    }
    return DirectoryPage(entries: entries, attempts: attempts, verifier: current)
}

@Test func ordinaryDirectoryEnumerationIncludesBothRootAliases() async throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    let page = try directoryPage(volume)
    #expect(page.entries.map(\.name) == [".", "..", "Disk.img"])
    #expect(page.entries.map(\.type) == [.directory, .directory, .file])
    #expect(
        page.entries.map(\.identifier) == [.rootDirectory, .rootDirectory, FSItem.Identifier(3)])
    #expect(page.entries.map { $0.nextCookie.rawValue } == [1, 2, 3])
    #expect(page.entries.allSatisfy { $0.attributes == nil })
    #expect(page.verifier.rawValue == 1)
    for entry in page.entries {
        let (item, name) = try await (volume as any FSVolume.Operations).lookupItem(
            named: FSFileName(string: try #require(entry.name)), inDirectory: volume.rootItem)
        let values = try volume.makeAttributes(of: item)
        #expect(name.string == entry.name)
        #expect(values.fileID == entry.identifier)
        #expect(values.type == entry.type)
    }
}

@Test(arguments: [false, true])
func attributeDirectoryEnumerationContainsOnlyTheImage(readOnly: Bool) throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(readOnly: readOnly), identifier: UUID())
    let page = try directoryPage(volume, attributes: FSItem.GetAttributesRequest())
    #expect(page.entries.map(\.name) == ["Disk.img"])
    #expect(page.entries.map { $0.nextCookie.rawValue } == [3])
    let entry = try #require(page.entries.first)
    let values = try #require(entry.attributes)
    #expect(entry.identifier == FSItem.Identifier(3))
    #expect(values.fileID == entry.identifier)
    #expect(values.type == .file)
    #expect(values.size == 4096)
    #expect(values.mode == (readOnly ? 0o400 : 0o600))
}

@Test(arguments: [false, true])
func directoryEnumerationResumesAfterEveryBufferBoundary(withAttributes: Bool) throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    let request = withAttributes ? FSItem.GetAttributesRequest() : nil
    let expected = withAttributes ? ["Disk.img"] : [".", "..", "Disk.img"]
    for capacity in 1...3 {
        var names: [String?] = []
        var cookie: UInt64 = 0
        var verifier: UInt64 = 0
        var reachedEnd = false
        for _ in 0..<5 {
            let empty = try directoryPage(
                volume, cookie: cookie, verifier: verifier, attributes: request, capacity: 0)
            #expect(empty.entries.isEmpty)
            #expect(empty.attempts <= 1)
            verifier = empty.verifier.rawValue
            let page = try directoryPage(
                volume, cookie: cookie, verifier: verifier, attributes: request, capacity: capacity)
            #expect(page.attempts <= capacity + 1)
            #expect(page.verifier.rawValue == verifier)
            if page.entries.isEmpty {
                reachedEnd = true
                #expect(page.attempts == 0)
                break
            }
            names += page.entries.map(\.name)
            cookie = try #require(page.entries.last).nextCookie.rawValue
        }
        #expect(reachedEnd)
        #expect(names == expected)
        #expect(cookie == 3)
    }
}

@Test(arguments: [false, true])
func directoryCookiesHaveTheSameMeaningAcrossAttributeModes(withAttributes: Bool) throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    let request = withAttributes ? FSItem.GetAttributesRequest() : nil
    let afterFirst = try directoryPage(volume, cookie: 1, verifier: 1, attributes: request)
    #expect(afterFirst.entries.map(\.name) == (withAttributes ? ["Disk.img"] : ["..", "Disk.img"]))
    let beforeImage = try directoryPage(volume, cookie: 2, verifier: 1, attributes: request)
    #expect(beforeImage.entries.map(\.name) == ["Disk.img"])
    let end = try directoryPage(volume, cookie: 3, verifier: 1, attributes: request)
    #expect(end.entries.isEmpty)
    #expect(end.attempts == 0)
    #expect(end.verifier.rawValue == 1)
}

@Test(arguments: [UInt64(4), 0x8000_0000_0000_0000, UInt64.max])
func invalidDirectoryCookiesUseTheDocumentedError(cookie: UInt64) throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    var called = false
    do {
        _ = try volume.enumerateDirectoryEntries(
            volume.rootItem, startingAt: FSDirectoryCookie(rawValue: cookie),
            verifier: FSDirectoryVerifier(rawValue: 1), attributes: nil
        ) { _, _, _, _, _ in
            called = true
            return true
        }
        Issue.record("An invalid directory cookie was accepted")
    } catch {
        let error = error as NSError
        #expect(error.domain == NSPOSIXErrorDomain)
        #expect(error.code == FSError.Code.invalidDirectoryCookie.rawValue)
    }
    #expect(!called)
}

@Test func directoryEnumerationRejectsStaleVerifiersAndForeignItemsBeforePacking() throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    let other = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    var called = false
    for (item, verifier, error) in [
        (volume.rootItem, UInt64(2), POSIXError(.ESTALE)),
        (volume.rootItem, UInt64.max, POSIXError(.ESTALE)),
        (other.rootItem, UInt64(0), POSIXError(.ESTALE)),
        (volume.imageItem, UInt64(0), POSIXError(.ENOTDIR)),
    ] {
        #expect(throws: error) {
            try volume.enumerateDirectoryEntries(
                item, startingAt: .initial, verifier: FSDirectoryVerifier(rawValue: verifier),
                attributes: nil
            ) { _, _, _, _, _ in
                called = true
                return true
            }
        }
    }
    #expect(!called)
}

@Test func interleavedDirectoryReadersDoNotShareAPosition() throws {
    let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
    let first = try directoryPage(volume, capacity: 1)
    #expect(first.entries.map(\.name) == ["."])
    let bulk = try directoryPage(volume, attributes: FSItem.GetAttributesRequest(), capacity: 1)
    #expect(bulk.entries.map(\.name) == ["Disk.img"])
    let second = try directoryPage(
        volume, cookie: try #require(first.entries.last).nextCookie.rawValue,
        verifier: first.verifier.rawValue, capacity: 1)
    #expect(second.entries.map(\.name) == [".."])
    let third = try directoryPage(
        volume, cookie: try #require(second.entries.last).nextCookie.rawValue,
        verifier: second.verifier.rawValue, capacity: 1)
    #expect(third.entries.map(\.name) == ["Disk.img"])
}
