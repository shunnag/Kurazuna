import Foundation
import ISCSICore
import Security
import Testing

@testable import ISCSIPlatform

private final class BridgeCommandCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var observed: Bool { lock.withLock { value } }
    func record() { lock.withLock { value = true } }
}

private actor HeldBridgeCommand {
    private let cancellation = BridgeCommandCancellation()
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var calls: [(String, [String], TimeInterval)] = []
    var isPaused: Bool { waiter != nil }
    var cancellationObserved: Bool { cancellation.observed }

    func run(_ program: String, _ arguments: [String], _ timeout: TimeInterval) async throws -> Data
    {
        calls.append((program, arguments, timeout))
        let cancellation = cancellation
        await withTaskCancellationHandler {
            await withCheckedContinuation { waiter = $0 }
        } onCancel: {
            cancellation.record()
        }
        try Task.checkCancellation()
        return Data()
    }
    func release() {
        waiter?.resume()
        waiter = nil
    }
}

private actor BridgeMetadata: MountResourceStore {
    private(set) var values: [String: ConnectionDescriptor] = [:]
    private(set) var removalAttempts = 0
    private var removalFailure: (any Error)?

    init(removalFailure: (any Error)? = nil) { self.removalFailure = removalFailure }
    func allowRemoval() { removalFailure = nil }
    func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        let reference = try ConnectionResourceReference(descriptor: descriptor)
        values[reference.account] = descriptor
        return reference
    }
    func resolve(_ reference: ConnectionResourceReference) throws -> ConnectionDescriptor {
        guard let value = values[reference.account] else { throw POSIXError(.ENOENT) }
        return value
    }
    func remove(_ reference: ConnectionResourceReference) throws {
        removalAttempts += 1
        if let removalFailure { throw removalFailure }
        values.removeValue(forKey: reference.account)
    }
}

@Test(arguments: [false, true])
private func cancellingABridgeMountWaitsForItsBoundedCommand(_ readOnly: Bool) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:bridge", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: readOnly, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let command = HeldBridgeCommand()
    let backend = SystemAttachmentBackend(root: root, mountCommand: command.run)
    let bridge = try await backend.bridgeURL(for: id)
    let task = Task { try await backend.mountBridge(descriptor, at: bridge) }
    while !(await command.isPaused) { await Task.yield() }
    task.cancel()
    for _ in 0..<20 { await Task.yield() }
    let propagatedCancellation = await command.cancellationObserved
    await command.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(!propagatedCancellation)
    let calls = await command.calls
    #expect(calls.count == 1 && calls[0].0 == "/sbin/mount" && calls[0].2 == 60)
    #expect(calls[0].1.last == bridge.path)
    #expect(calls[0].1.prefix(3) == ["-F", "-t", ApplicationIdentity.current.fileSystemType])
    #expect(calls[0].1.contains(try descriptor.resourceURL.absoluteString))
}

@Test func cancelledMountRetainsItsBoundedResourceUntilEmptyBridgeCleanup() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: root) }
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:bridge", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let store = BridgeMetadata()
    let command = HeldBridgeCommand()
    let backend = SystemAttachmentBackend(root: root, resources: store, mountCommand: command.run)
    let bridge = try await backend.bridgeURL(for: #require(descriptor.mountID))
    let task = Task { try await backend.mountBridge(descriptor, at: bridge) }
    while !(await command.isPaused) { await Task.yield() }
    let reference = try ConnectionResourceReference(descriptor: descriptor)
    #expect(await store.values[reference.account] == descriptor)
    #expect(await command.calls[0].1.contains(reference.url.absoluteString))
    task.cancel()
    await command.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await store.values[reference.account] == descriptor)
    // An unexpected file prevents deletion of both the directory and its metadata.
    let unexpected = bridge.appendingPathComponent("unexpected")
    try Data([1]).write(to: unexpected)
    await #expect(throws: POSIXError.self) {
        try await backend.discardEmptyBridge(descriptor, at: bridge)
    }
    #expect(await store.values[reference.account] == descriptor)
    #expect(await store.removalAttempts == 0)
    try FileManager.default.removeItem(at: unexpected)
    try await backend.discardEmptyBridge(descriptor, at: bridge)
    #expect(await store.values.isEmpty)
    try await backend.discardEmptyBridge(descriptor, at: bridge)
}

@Test(arguments: [Int(errSecInteractionNotAllowed), Int(errSecMissingEntitlement), -50])
private func unmountedBridgeRetainsMetadataAndDistinguishesItsCleanupFailure(_ status: Int)
    async throws
{
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: root) }
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:bridge", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0), readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: UUID())
    let store = BridgeMetadata(removalFailure: NSError(domain: NSOSStatusErrorDomain, code: status))
    let command = HeldBridgeCommand()
    let backend = SystemAttachmentBackend(root: root, resources: store, mountCommand: command.run)
    let bridge = try await backend.bridgeURL(for: #require(descriptor.mountID))
    try FileManager.default.createDirectory(at: bridge, withIntermediateDirectories: true)
    let reference = try await store.save(descriptor)
    do {
        try await backend.unmountBridge(descriptor, at: bridge)
        Issue.record("Metadata removal failure must not be reported as successful ejection")
    } catch {
        let cleanup = try #require(error as? MountResourceCleanupError)
        let underlying = cleanup.underlying as NSError
        #expect(underlying.domain == NSOSStatusErrorDomain && underlying.code == status)
    }
    #expect(!FileManager.default.fileExists(atPath: bridge.path))
    #expect(await store.values[reference.account] == descriptor)
    #expect(await store.removalAttempts == 1)
    // The same production backend retries after the directory has already gone.
    await store.allowRemoval()
    try await backend.unmountBridge(descriptor, at: bridge)
    #expect(await store.values.isEmpty)
    #expect(await store.removalAttempts == 2)
    #expect(await command.calls.isEmpty)
}

private let launchFailure = SystemCommandError.failed(
    program: "mount", status: 69,
    detail:
        "mount: Loading resource: Operation failed. (com.apple.extensionKit.errorDomain error 2.)\nmount: File system named \(ApplicationIdentity.current.fileSystemType) not found\n"
)

@Test
private func onlyInitialExtensionLoadingErrorsQualifyForAMountRetry() {
    guard case .failed(let program, let status, let detail) = launchFailure else { return }
    #expect(SystemAttachmentBackend.isInitialExtensionLaunchFailure(launchFailure))
    for error in [
        SystemCommandError.timedOut(program: program),
        .failed(program: "umount", status: status, detail: detail),
        .failed(program: program, status: 1, detail: detail),
        .failed(
            program: program, status: status,
            detail: detail.replacingOccurrences(of: " error 2.", with: " error 20.")),
        .failed(
            program: program, status: status,
            detail: detail.replacingOccurrences(
                of: "File system named", with: "File system named other-")),
        .failed(
            program: program, status: status,
            detail: detail + "mount: a different failure occurred\n"),
        .failed(program: program, status: status, detail: "write failed"),
    ] {
        #expect(!SystemAttachmentBackend.isInitialExtensionLaunchFailure(error))
    }
}

private actor FailingExtensionLaunch {
    private(set) var arguments: [[String]] = []
    private let change: String
    init(_ change: String) { self.change = change }
    func run(_ program: String, _ args: [String], _ timeout: TimeInterval) async throws -> Data {
        arguments.append(args)
        if arguments.count == 1 {
            let path = URL(fileURLWithPath: try #require(args.last), isDirectory: true)
            if change == "file" { try Data().write(to: path.appendingPathComponent(".hidden")) }
            if change == "directory" {
                try FileManager.default.moveItem(
                    at: path, to: path.appendingPathExtension("previous"))
                try FileManager.default.createDirectory(
                    at: path, withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700])
            }
        }
        throw launchFailure
    }
}

@Test(arguments: ["none", "file", "directory", "nested mount"])
private func extensionLoadRetriesAtMostOnceAndRequiresTheOriginalUnusedBridge(_ change: String)
    async throws
{
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:bridge", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0),
        readOnly: false, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let reply = try PropertyListSerialization.data(
        fromPropertyList: ["images": []], format: .binary, options: 0)
    let images = DiskImages(run: { _, _, _ in reply }, fileSize: { _ in 0 })
    let recorder = FailingExtensionLaunch(change)
    let bridge = root.appendingPathComponent(id.uuidString, isDirectory: true)
    let store = BridgeMetadata()
    let backend = SystemAttachmentBackend(
        root: root, resources: store, diskImages: images, mountCommand: recorder.run,
        mounts: {
            guard change == "nested mount" else { return [] }
            return [
                .init(
                    type: "apfs", source: "/dev/disk-test",
                    path: bridge.appendingPathComponent("inner").path, owner: getuid(), flags: 0)
            ]
        })
    if change == "none" {
        await #expect(throws: launchFailure) {
            try await backend.mountBridge(descriptor, at: bridge)
        }
    } else {
        await #expect(throws: AttachmentError.ownershipUnverified) {
            try await backend.mountBridge(descriptor, at: bridge)
        }
    }
    let calls = await recorder.arguments
    #expect(calls.count == (change == "none" ? 2 : 1))
    #expect(calls.first == calls.last)
    #expect(await store.values.count == 1)
}

@Test
private func cancellingTheInitialMountDoesNotRetryAnExtensionLaunchFailure() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        .resolvingSymlinksInPath()
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("example.invalid"),
        initiatorName: "iqn.2026-10.test:bridge", targetName: "iqn.2026-10.test:disk",
        lun: LogicalUnit(0),
        readOnly: true, isid: [0x80, 1, 2, 3, 4, 5], mountID: id)
    let command = HeldBridgeCommand()
    let backend = SystemAttachmentBackend(
        root: root,
        mountCommand: { path, arguments, timeout in
            _ = try await command.run(path, arguments, timeout)
            throw launchFailure
        })
    let bridge = try await backend.bridgeURL(for: id)
    let task = Task { try await backend.mountBridge(descriptor, at: bridge) }
    while !(await command.isPaused) { await Task.yield() }
    task.cancel()
    await command.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await command.calls.count == 1)
}
