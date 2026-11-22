import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

private actor ExtensionReplies {
    private var count = 0
    private var pending: [Int: CheckedContinuation<AppModel.ExtensionState, any Error>] = [:]
    private var observers: [(Int, CheckedContinuation<Void, Never>)] = []

    var requestCount: Int { count }

    func check() async throws -> AppModel.ExtensionState {
        count += 1
        let id = count
        return try await withCheckedThrowingContinuation { reply in
            pending[id] = reply
            let ready = observers.filter { $0.0 <= count }
            observers.removeAll { $0.0 <= count }
            for (_, observer) in ready { observer.resume() }
        }
    }
    func waitForCount(_ expected: Int) async {
        if count >= expected { return }
        await withCheckedContinuation { observers.append((expected, $0)) }
    }
    func finish(_ id: Int, with state: AppModel.ExtensionState) {
        pending.removeValue(forKey: id)!.resume(returning: state)
    }
}

/// The model doesn't ask the provider once a check's deadline has passed. A 20 ms deadline
/// could pass before the query first ran under load; the request then never came and an
/// unbounded waitForCount hung the whole bundle. Tests with a deadline use 250 ms, which leaves
/// the query time to start, and wait for the request with a bound so a missing one fails.
private func waitForTimedRequest(_ replies: ExtensionReplies, _ count: Int) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while await replies.requestCount < count, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(1))
    }
    try #require(
        await replies.requestCount >= count, "the extension check never reached the provider")
}

@MainActor private func extensionModel(
    check: @escaping @MainActor @Sendable () async throws -> AppModel.ExtensionState
) throws -> AppModel {
    let model = AppModel(extensionCheck: check)
    model.document = try ProfileDocument(identity: .makeNew())
    model.recoveryComplete = true
    model.extensionState = .ready
    return model
}

@Test @MainActor
private func anOlderReadyResultCannotOverwriteANewerDisabledResult() async throws {
    let replies = ExtensionReplies()
    let model = try extensionModel { try await replies.check() }
    let older = Task { await model.refreshExtension() }
    await replies.waitForCount(1)
    #expect(model.isCheckingExtension)
    #expect(!model.canConnect)
    let newer = Task { await model.refreshExtension() }
    await replies.waitForCount(2)
    await replies.finish(2, with: .disabled)
    await newer.value
    #expect(model.extensionState == .disabled)
    #expect(!model.isCheckingExtension)
    await replies.finish(1, with: .ready)
    await older.value
    #expect(model.extensionState == .disabled)
    #expect(!model.canConnect)
}

@Test @MainActor
private func anOlderReplyCannotFinishTheLatestExtensionCheck() async throws {
    let replies = ExtensionReplies()
    let model = try extensionModel { try await replies.check() }
    let older = Task { await model.refreshExtension() }
    await replies.waitForCount(1)
    let newer = Task { await model.refreshExtension() }
    await replies.waitForCount(2)
    await replies.finish(1, with: .ready)
    await older.value
    #expect(model.isCheckingExtension)
    #expect(!model.canConnect)
    await replies.finish(2, with: .ready)
    await newer.value
    #expect(!model.isCheckingExtension)
    #expect(model.canConnect)
}

@Test @MainActor
private func aCancelledExtensionCheckCannotRestoreAReadyState() async throws {
    let replies = ExtensionReplies()
    let model = try extensionModel { try await replies.check() }
    let task = Task { await model.refreshExtension() }
    await replies.waitForCount(1)
    task.cancel()
    await replies.finish(1, with: .ready)
    await task.value
    #expect(model.extensionState == .unavailable)
    #expect(!model.isCheckingExtension)
    #expect(!model.canConnect)
}

@Test @MainActor
private func cancellingAnOlderCheckDoesNotFinishANewerCheck() async throws {
    let replies = ExtensionReplies()
    let model = try extensionModel { try await replies.check() }
    let older = Task { await model.refreshExtension() }
    await replies.waitForCount(1)
    let newer = Task { await model.refreshExtension() }
    await replies.waitForCount(2)
    older.cancel()
    await older.value
    #expect(model.isCheckingExtension)
    #expect(!model.canConnect)
    await replies.finish(2, with: .disabled)
    await newer.value
    await replies.finish(1, with: .ready)
    #expect(model.extensionState == .disabled)
    #expect(!model.isCheckingExtension)
}

@Test @MainActor
private func unresponsiveExtensionQueriesAreBoundedAndCanRecover() async throws {
    let replies = ExtensionReplies()
    var responses = 0
    let model = try extensionModel {
        let state = try await replies.check()
        responses += 1
        return state
    }
    for index in 1...8 {
        let task = Task { await model.refreshExtension() }
        await replies.waitForCount(index)
        task.cancel()
        await task.value
        #expect(!model.isCheckingExtension)
    }
    await model.refreshExtension()
    #expect(await replies.requestCount == 8)
    #expect(model.extensionState == .unavailable)
    #expect(!model.canConnect)
    // Free one SDK query and let its task finish before retrying.
    await replies.finish(1, with: .ready)
    while responses < 1 { await Task.yield() }
    let retry = Task { await model.refreshExtension() }
    await replies.waitForCount(9)
    await replies.finish(9, with: .ready)
    await retry.value
    #expect(model.canConnect)
    for index in 2...8 { await replies.finish(index, with: .disabled) }
    while responses < 9 { await Task.yield() }
    #expect(model.extensionState == .ready)
}

@Test @MainActor
private func aFailedExtensionCheckDisablesConnectionAndFinishesChecking() async throws {
    let model = try extensionModel { throw POSIXError(.EACCES) }
    await model.refreshExtension()
    #expect(model.extensionState == .unavailable)
    #expect(!model.isCheckingExtension)
    #expect(!model.canConnect)
}

@Test @MainActor
private func aStalledExtensionCheckTimesOutAndIgnoresItsLateReadyReply() async throws {
    let replies = ExtensionReplies()
    let model = AppModel(
        extensionCheck: { try await replies.check() },
        extensionCheckTimeout: .milliseconds(250))
    model.document = try ProfileDocument(identity: .makeNew())
    model.recoveryComplete = true
    model.extensionState = .ready
    let task = Task { await model.refreshExtension() }
    try await waitForTimedRequest(replies, 1)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.isCheckingExtension, clock.now < deadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    let finishedWhileProviderWasPending = !model.isCheckingExtension
    let stateBeforeLateReply = model.extensionState
    await replies.finish(1, with: .ready)
    await task.value
    #expect(finishedWhileProviderWasPending)
    #expect(stateBeforeLateReply == .unavailable)
    #expect(model.extensionState == .unavailable)
    #expect(!model.canConnect)
    #expect(model.issue == nil)
}

@Test @MainActor
private func anExtensionRetryCanSucceedWhileTheTimedOutQueryIsPending() async throws {
    let replies = ExtensionReplies()
    var responses = 0
    let model = AppModel(
        extensionCheck: {
            let state = try await replies.check()
            responses += 1
            return state
        }, extensionCheckTimeout: .milliseconds(250))
    model.document = try ProfileDocument(identity: .makeNew())
    model.recoveryComplete = true
    let first = Task { await model.refreshExtension() }
    try await waitForTimedRequest(replies, 1)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.isCheckingExtension, clock.now < deadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    let finishedWhileProviderWasPending = !model.isCheckingExtension
    if !finishedWhileProviderWasPending { await replies.finish(1, with: .disabled) }
    await first.value
    #expect(finishedWhileProviderWasPending)
    let retry = Task { await model.refreshExtension() }
    try await waitForTimedRequest(replies, 2)
    await replies.finish(2, with: .ready)
    await retry.value
    #expect(model.canConnect)
    if finishedWhileProviderWasPending { await replies.finish(1, with: .disabled) }
    while responses < 2 { await Task.yield() }
    #expect(model.extensionState == .ready)
    #expect(model.canConnect)
}

private actor ExtensionMounts: AttachmentBackend {
    private(set) var mounts = 0
    let mountFailure: SystemCommandError?
    init(mountFailure: SystemCommandError? = nil) { self.mountFailure = mountFailure }
    func bridgeURL(for id: UUID) -> URL { URL(fileURLWithPath: "/unused/\(id)") }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        mounts += 1
        if let mountFailure { throw mountFailure }
        throw ProtocolError.invalidState
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL)
        -> AttachmentInspection
    {
        AttachmentInspection(ownership: .absent, attachment: nil)
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        throw ProtocolError.invalidState
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
    {}
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

@Test(arguments: [false, true]) @MainActor
private func extensionLaunchFailurePreservesDetailsAndRecoversItsJournal(_ readOnly: Bool)
    async throws
{
    let detail =
        "mount: Loading resource: The operation couldn’t be completed. (com.apple.extensionKit.errorDomain error 2.)\nmount: File system named iscsifs not found\n"
    let backend = ExtensionMounts(
        mountFailure: .failed(program: "mount", status: 69, detail: detail))
    let journal = MemoryAttachmentJournal()
    let coordinator = try AttachmentCoordinator(backend: backend, journal: journal)
    try await coordinator.restore()
    let model = AppModel(coordinator: coordinator, extensionCheck: { .ready })
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.connect(try extensionDisk(), server: server, readOnly: readOnly)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(3))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(1))
    }
    let issue = try #require(model.issue)
    #expect(
        issue.title
            == String(
                localized:
                    "The \(ApplicationIdentity.current.applicationName) Extension Couldn’t Be Started"
            ))
    #expect(
        issue.message
            == String(
                localized:
                    "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then check that \(ApplicationIdentity.current.applicationName) is enabled. If it’s already enabled, eject any connected iSCSI disks and restart your Mac, then try again."
            ))
    #expect(issue.detail == "mount (69): \(detail)")
    #expect(issue.recoveryAction == .openExtensionSettings && issue.forceEjectionDiskID == nil)
    #expect(model.attached.isEmpty && model.recoveryComplete && journal.load().isEmpty)
    #expect(await backend.mounts == 1)
}

private func extensionDisk() throws -> FoundDisk {
    var inquiry = [UInt8](repeating: 0x20, count: 36)
    inquiry[0] = 0
    inquiry[1] = 0
    inquiry[2] = 6
    inquiry[3] = 2
    inquiry[4] = 31
    var capacity = [UInt8](repeating: 0, count: 32)
    capacity.put(UInt64(7), at: 0)
    capacity.put(UInt32(512), at: 8)
    return FoundDisk(
        targetName: "iqn.2026-10.test:extension-state",
        inspection: LogicalUnitInspection(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: Data(inquiry)),
                    capacity: try DiskCapacity(readCapacity16: Data(capacity))))))
}

private enum CheckResult: CaseIterable { case ready, disabled, unavailable, failure }

@Test(arguments: CheckResult.allCases) @MainActor
private func connectionRechecksExtensionBeforeAnyMount(_ result: CheckResult) async throws {
    let mounts = ExtensionMounts()
    let coordinator = try AttachmentCoordinator(backend: mounts)
    try await coordinator.restore()
    let model = AppModel(
        coordinator: coordinator,
        extensionCheck: {
            switch result {
            case .ready: .ready
            case .disabled: .disabled
            case .unavailable: .unavailable
            case .failure: throw POSIXError(.EACCES)
            }
        })
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.connect(try extensionDisk(), server: server)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(1))
    }
    #expect(await mounts.mounts == (result == .ready ? 1 : 0))
    if result != .ready { #expect(model.issue == nil) }
    #expect(!model.isCheckingExtension)
    #expect(model.extensionState == result.state)
}

@Test(arguments: [AppModel.ExtensionState.checking, .disabled, .unavailable, .differentCopy])
@MainActor
private func anUnreadyConnectActionCannotBypassTheModelGate(_ state: AppModel.ExtensionState)
    async throws
{
    let mounts = ExtensionMounts()
    let coordinator = try AttachmentCoordinator(backend: mounts)
    try await coordinator.restore()
    var checks = 0
    let model = AppModel(
        coordinator: coordinator,
        extensionCheck: {
            checks += 1
            return .ready
        })
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = state
    model.connect(try extensionDisk(), server: server)
    #expect(!model.busy)
    await Task.yield()
    #expect(checks == 0)
    #expect(await mounts.mounts == 0)
    #expect(model.issue == nil)
}

extension CheckResult {
    var state: AppModel.ExtensionState {
        switch self {
        case .ready: .ready
        case .disabled: .disabled
        case .unavailable, .failure: .unavailable
        }
    }
}

@Test @MainActor
private func cancellingBeforeMountDoesNotWaitForAnUncooperativeExtensionCheck() async throws {
    let replies = ExtensionReplies()
    let mounts = ExtensionMounts()
    let coordinator = try AttachmentCoordinator(backend: mounts)
    try await coordinator.restore()
    let model = AppModel(
        coordinator: coordinator, extensionCheck: { try await replies.check() })
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.connect(try extensionDisk(), server: server)
    await replies.waitForCount(1)
    model.cancel()
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy, clock.now < deadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    let finishedWhileProviderWasPending = !model.busy && !model.isCheckingExtension
    // Release the deliberately noncooperative provider even when the assertion fails.
    await replies.finish(1, with: .ready)
    let cleanupDeadline = clock.now.advanced(by: .seconds(2))
    while model.busy, clock.now < cleanupDeadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    #expect(finishedWhileProviderWasPending)
    #expect(await mounts.mounts == 0)
    #expect(model.issue == nil)
    #expect(model.extensionState == .unavailable)
}

@Test @MainActor
private func connectingCannotMountAfterTheExtensionCheckTimesOut() async throws {
    let replies = ExtensionReplies()
    let mounts = ExtensionMounts()
    let coordinator = try AttachmentCoordinator(backend: mounts)
    try await coordinator.restore()
    let model = AppModel(
        coordinator: coordinator, extensionCheck: { try await replies.check() },
        extensionCheckTimeout: .milliseconds(250))
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    model.connect(try extensionDisk(), server: server)
    try await waitForTimedRequest(replies, 1)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy, clock.now < deadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    let finishedWhileProviderWasPending = !model.busy && !model.isCheckingExtension
    await replies.finish(1, with: .ready)
    let cleanupDeadline = clock.now.advanced(by: .seconds(2))
    while model.busy, clock.now < cleanupDeadline {
        try await clock.sleep(for: .milliseconds(1))
    }
    #expect(finishedWhileProviderWasPending)
    #expect(await mounts.mounts == 0)
    #expect(model.issue == nil)
    #expect(model.extensionState == .unavailable)
}
