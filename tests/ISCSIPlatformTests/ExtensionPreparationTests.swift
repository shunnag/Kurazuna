import CryptoKit
import Darwin
import Foundation
import Testing

@testable import ISCSIPlatform

private func registrationRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return root
}

private let registrationTestVolume = UUID(
    uuid: (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))

private func installedIdentity(
    _ code: UInt8 = 1, inode: UInt64 = 10, device: Int32 = 1,
    volume: UUID = registrationTestVolume, path: String = "/Applications/Kurazuna.app"
)
    -> ExtensionRegistrationIdentity
{
    ExtensionRegistrationIdentity(
        uid: geteuid(),
        application: .init(
            path: path, device: device, volumeUUID: volume, inode: inode,
            identifier: "dev.soba.iscsi.kurazuna", team: "FQTM2788K5", codeHash: Data([code])),
        module: .init(
            path: path + "/Contents/Extensions/ISCSIFSExtension.appex",
            device: device, volumeUUID: volume, inode: inode + 1,
            identifier: "dev.soba.iscsi.kurazuna.FileSystem",
            team: "FQTM2788K5", codeHash: Data([code, 2])))
}

private actor RegistrationCommands {
    private(set) var stages: [FileSystemExtensionPreparation.Stage] = []
    func record(_ stage: FileSystemExtensionPreparation.Stage) { stages.append(stage) }
}

@Test(arguments: [false, true])
private func rebootDeviceRenumberingDoesNotRepeatRegistration(failed: Bool) async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    do {
        _ = try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { installedIdentity(device: 16_777_234) },
            permitted: { true },
            run: { stage, _ in
                await commands.record(stage)
                if failed { throw POSIXError(.EIO) }
            })
        #expect(!failed)
    } catch { #expect(failed && error as? POSIXError == POSIXError(.EIO)) }
    let again = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity(device: 16_777_229) },
        permitted: { true }, run: { stage, _ in await commands.record(stage) })
    #expect(again == .alreadyAttempted)
    #expect(await commands.stages == (failed ? [.application] : [.application, .module]))
    #expect(
        try FileManager.default.contentsOfDirectory(
            atPath: root.appendingPathComponent("ExtensionRegistration").path
        ).count == 1)
}

@Test private func concurrentDeviceNumbersShareOneRegistrationAttempt() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    let submitted = await withTaskGroup(of: Bool.self) { group in
        for device in Int32(1)...8 {
            group.addTask {
                let outcome = try? await FileSystemExtensionPreparation.prepare(
                    supportURL: root, capture: { installedIdentity(device: device) },
                    permitted: { true }, run: { stage, _ in await commands.record(stage) })
                return outcome == .submitted
            }
        }
        var count = 0
        for await value in group { if value { count += 1 } }
        return count
    }
    #expect(submitted == 1)
    #expect(await commands.stages.count == 2)
}

private final class RegistrationDeviceCaptures: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let changeAt: Int
    init(changeAt: Int) { self.changeAt = changeAt }
    func capture() -> ExtensionRegistrationIdentity {
        lock.withLock {
            count += 1
            return installedIdentity(device: count >= changeAt ? 2 : 1)
        }
    }
}

@Test(arguments: [2, 3, 4])
private func deviceChangesDuringRegistrationStillInvalidateTheLiveCapture(changeAt: Int)
    async throws
{
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let captures = RegistrationDeviceCaptures(changeAt: changeAt)
    let commands = RegistrationCommands()
    await #expect(throws: POSIXError(.ESTALE)) {
        try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { captures.capture() }, permitted: { true },
            run: { stage, _ in await commands.record(stage) })
    }
    #expect(await commands.stages.count == changeAt - 2)
    let again = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity(device: 2) }, permitted: { true },
        run: { _, _ in Issue.record("Device renumbering released a failed live claim") })
    #expect(again == .alreadyAttempted)
}

@Test(arguments: [
    "uid", "application.path", "application.volumeUUID", "application.inode",
    "application.identifier", "application.team", "application.codeHash",
    "module.path", "module.volumeUUID", "module.inode", "module.identifier",
    "module.team", "module.codeHash",
])
private func persistentRegistrationKeyKeepsEveryNonDeviceIdentityField(field: String) throws {
    let original = installedIdentity()
    var object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
    let parts = field.split(separator: ".").map(String.init)
    if field == "uid" {
        object[field] = geteuid() + 1
    } else {
        var bundle = try #require(object[parts[0]] as? [String: Any])
        switch parts[1] {
        case "volumeUUID": bundle[parts[1]] = UUID().uuidString
        case "inode": bundle[parts[1]] = 100
        case "codeHash": bundle[parts[1]] = Data([99]).base64EncodedString()
        default: bundle[parts[1]] = "different"
        }
        object[parts[0]] = bundle
    }
    let changed = try JSONDecoder().decode(
        ExtensionRegistrationIdentity.self, from: JSONSerialization.data(withJSONObject: object))
    #expect(changed.persistent != original.persistent)
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    #expect(try ExtensionRegistrationAttempt.claim(original, in: root) != nil)
    #expect(try ExtensionRegistrationAttempt.claim(changed, in: root) != nil)
    #expect(try ExtensionRegistrationAttempt.claim(changed, in: root) == nil)
}

@Test private func persistentClaimRetainsItsOriginalLiveDeviceEvidence() throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    _ = try ExtensionRegistrationAttempt.claim(installedIdentity(device: 16_777_234), in: root)
    let directory = root.appendingPathComponent("ExtensionRegistration")
    let file = try #require(
        FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first)
    let before = try Data(contentsOf: file)
    let record = try #require(
        JSONSerialization.jsonObject(with: before) as? [String: Any])
    #expect(file.lastPathComponent.hasPrefix("v2-") && record["version"] as? Int == 2)
    let saved = try #require(record["identity"] as? [String: Any])
    #expect((saved["application"] as? [String: Any])?["device"] as? Int == 16_777_234)
    #expect(
        try ExtensionRegistrationAttempt.claim(installedIdentity(device: 16_777_229), in: root)
            == nil)
    #expect(try Data(contentsOf: file) == before)
}

@Test(arguments: ["application", "module"])
private func unknownVolumeIdentityNeverAuthorizesRegistration(bundle: String) throws {
    var object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(installedIdentity()))
            as? [String: Any])
    var value = try #require(object[bundle] as? [String: Any])
    value["volumeUUID"] = "00000000-0000-0000-0000-000000000000"
    object[bundle] = value
    let identity = try JSONDecoder().decode(
        ExtensionRegistrationIdentity.self, from: JSONSerialization.data(withJSONObject: object))
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    #expect(throws: POSIXError(.EINVAL)) {
        try ExtensionRegistrationAttempt.claim(identity, in: root)
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
}

@Test private func legacyRegistrationReceiptsArePreservedWithoutReinterpretation() throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = root.appendingPathComponent("ExtensionRegistration")
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    var oldIdentity = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(installedIdentity()))
            as? [String: Any])
    for key in ["application", "module"] {
        var bundle = try #require(oldIdentity[key] as? [String: Any])
        bundle.removeValue(forKey: "volumeUUID")
        oldIdentity[key] = bundle
    }
    let oldKey = try JSONSerialization.data(withJSONObject: oldIdentity, options: [.sortedKeys])
    let legacy = directory.appendingPathComponent(
        SHA256.hash(data: oldKey).map { String(format: "%02x", $0) }.joined() + ".jsonl")
    var old = try JSONSerialization.data(
        withJSONObject: ["version": 1, "event": "claimed", "identity": oldIdentity])
    old.append(0x0a)
    try old.write(to: legacy)
    #expect(chmod(legacy.path, 0o600) == 0)
    _ = try ExtensionRegistrationAttempt.claim(installedIdentity(2), in: root)
    #expect(
        try ExtensionRegistrationAttempt.claim(installedIdentity(2, device: 2), in: root) == nil)
    #expect(try Data(contentsOf: legacy) == old)
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count == 2)
}

@Test private func registrationDirectoryVolumeIdentityMatchesIndependentFoundation() throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    #expect(fd >= 0)
    defer { close(fd) }
    let values = try root.resourceValues(forKeys: [.volumeUUIDStringKey])
    let expected = try #require(values.volumeUUIDString.flatMap { UUID(uuidString: $0) })
    #expect(try OwnedBlockResourceFiles.readVolumeUUID(fd) == expected)
}

private final class RegistrationCaptures: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let changeAt: Int
    init(changeAt: Int) { self.changeAt = changeAt }
    func capture() -> ExtensionRegistrationIdentity {
        lock.withLock {
            count += 1
            return installedIdentity(count >= changeAt ? 2 : 1)
        }
    }
}

@Test(arguments: [FileSystemExtensionPreparation.Stage.application, .module])
private func failedRegistrationIsNotRepeatedOnTheSameInstallation(
    failureStage: FileSystemExtensionPreparation.Stage
) async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    await #expect(throws: POSIXError(.EIO)) {
        try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { installedIdentity() }, permitted: { true },
            run: { stage, _ in
                await commands.record(stage)
                if stage == failureStage { throw POSIXError(.EIO) }
            })
    }
    let again = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity() }, permitted: { true },
        run: { stage, _ in await commands.record(stage) })
    #expect(again == .alreadyAttempted)
    #expect(
        await commands.stages
            == (failureStage == .application ? [.application] : [.application, .module]))
}

@Test private func unsafeRecoveryDoesNotCaptureOrRegisterAnyBundle() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let result = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { throw POSIXError(.EACCES) }, permitted: { false },
        run: { _, _ in Issue.record("An unsafe registration was submitted") })
    #expect(result == .deferred)
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
}

@Test(arguments: [3, 4])
private func bundleReplacementStopsTheNextRegistrationOrCompletion(changeAt: Int) async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let captures = RegistrationCaptures(changeAt: changeAt)
    let commands = RegistrationCommands()
    await #expect(throws: POSIXError(.ESTALE)) {
        try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { captures.capture() }, permitted: { true },
            run: { stage, _ in await commands.record(stage) })
    }
    #expect(await commands.stages == (changeAt == 3 ? [.application] : [.application, .module]))
    let retryOldIdentity = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity() }, permitted: { true },
        run: { _, _ in Issue.record("A changed bundle released its old attempt claim") })
    #expect(retryOldIdentity == .alreadyAttempted)
}

@Test private func aNewCodeIdentityOrPlacementGetsItsOwnSingleAttempt() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    for snapshot in [installedIdentity(), installedIdentity(2), installedIdentity(2, inode: 20)] {
        for expected in [FileSystemExtensionPreparation.Outcome.submitted, .alreadyAttempted] {
            let outcome = try await FileSystemExtensionPreparation.prepare(
                supportURL: root, capture: { snapshot }, permitted: { true },
                run: { stage, _ in await commands.record(stage) })
            #expect(outcome == expected)
        }
    }
    #expect(await commands.stages.count == 6)
    let rollback = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity() }, permitted: { true },
        run: { _, _ in Issue.record("Rollback repeated an old attempt") })
    #expect(rollback == .alreadyAttempted)
}

@Test(arguments: ["corrupt", "symlink", "permissions"])
private func invalidAttemptStorageNeverAuthorizesRegistration(damage: String) async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    _ = try ExtensionRegistrationAttempt.claim(installedIdentity(), in: root)
    let directory = root.appendingPathComponent("ExtensionRegistration")
    let file = try #require(
        FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first)
    if damage == "corrupt" {
        try Data("{}\n".utf8).write(to: file)
    } else if damage == "symlink" {
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createSymbolicLink(
            at: file, withDestinationURL: root.appendingPathComponent("absent"))
    } else {
        #expect(chmod(file.path, 0o644) == 0)
    }
    await #expect(throws: (any Error).self) {
        try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { installedIdentity() }, permitted: { true },
            run: { _, _ in Issue.record("Invalid attempt storage authorized a command") })
    }
}

@Test private func concurrentClaimantsSubmitAtMostOneCommandPair() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    let submitted = await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<8 {
            group.addTask {
                let outcome = try? await FileSystemExtensionPreparation.prepare(
                    supportURL: root, capture: { installedIdentity() }, permitted: { true },
                    run: { stage, _ in await commands.record(stage) })
                return outcome == .submitted
            }
        }
        var count = 0
        for await didSubmit in group { if didSubmit { count += 1 } }
        return count
    }
    #expect(submitted == 1)
    #expect(await commands.stages == [.application, .module])
}

private final class RegistrationPermission: @unchecked Sendable {
    private let lock = NSLock()
    private var allowed = true
    private var captures = 0
    func permits() -> Bool { lock.withLock { allowed } }
    func capture() -> ExtensionRegistrationIdentity {
        lock.withLock {
            captures += 1
            if captures == 2 { allowed = false }
            return installedIdentity()
        }
    }
}

@Test private func recoveryChangesDuringSignatureValidationPreventTheCommand() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let permission = RegistrationPermission()
    let commands = RegistrationCommands()
    await #expect(throws: POSIXError(.EBUSY)) {
        try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { permission.capture() },
            permitted: { permission.permits() },
            run: { stage, _ in await commands.record(stage) })
    }
    #expect(await commands.stages.isEmpty)
}

private actor RegistrationCancellationGate {
    private var entered = false
    private var entryWaiter: CheckedContinuation<Void, Never>?
    private var cleanup: CheckedContinuation<Void, Never>?
    private(set) var finished = false

    func run() async throws {
        entered = true
        entryWaiter?.resume()
        entryWaiter = nil
        do { try await Task.sleep(for: .seconds(60)) } catch {
            await withCheckedContinuation { cleanup = $0 }
            throw error
        }
    }
    func waitForEntry() async {
        if !entered { await withCheckedContinuation { entryWaiter = $0 } }
    }
    func waitForCleanup() async {
        while cleanup == nil { await Task.yield() }
    }
    func releaseCleanup() {
        cleanup?.resume()
        cleanup = nil
    }
    func didFinish() { finished = true }
}

@Test private func cancellationWaitsForCommandCleanupAndKeepsTheAttemptClaim() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let gate = RegistrationCancellationGate()
    let commands = RegistrationCommands()
    let task = Task {
        do {
            _ = try await FileSystemExtensionPreparation.prepare(
                supportURL: root, capture: { installedIdentity() }, permitted: { true },
                run: { stage, _ in
                    await commands.record(stage)
                    try await gate.run()
                })
            Issue.record("A cancelled registration succeeded")
        } catch { #expect(error is CancellationError) }
        await gate.didFinish()
    }
    await gate.waitForEntry()
    task.cancel()
    await gate.waitForCleanup()
    let other = try await FileSystemExtensionPreparation.prepare(
        supportURL: root, capture: { installedIdentity() }, permitted: { true },
        run: { _, _ in Issue.record("A second registration bypassed pending cleanup") })
    let finishedBeforeCleanup = await gate.finished
    #expect(other == .alreadyAttempted && !finishedBeforeCleanup)
    #expect(await commands.stages == [.application])
    await gate.releaseCleanup()
    await task.value
    #expect(await gate.finished)
}

@Test
private func aMoveOfTheSameSignedAppRegistersTheNewPathOnce() async throws {
    let root = try registrationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let commands = RegistrationCommands()
    let previous = installedIdentity(path: "/Users/test/Applications/Kurazuna.app")
    let current = installedIdentity()
    var outcomes: [FileSystemExtensionPreparation.Outcome] = []
    for location in [previous, current, current] {
        let result = try await FileSystemExtensionPreparation.prepare(
            supportURL: root, capture: { location }, permitted: { true },
            run: { stage, _ in await commands.record(stage) })
        outcomes.append(result)
    }
    #expect(outcomes == [.submitted, .submitted, .alreadyAttempted])
    #expect(await commands.stages.count == 4)
}
