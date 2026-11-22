import Foundation
import ISCSICore
import ISCSINetwork
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

private actor UnmountedBackend: AttachmentBackend {
    let volumeURLs: [URL]
    let hasMountIssue: Bool
    private var bridges: Set<UUID> = []
    private var images: Set<UUID> = []

    init(partiallyMounted: Bool, hasMountIssue: Bool) {
        volumeURLs = partiallyMounted ? [URL(fileURLWithPath: "/Volumes/Archive")] : []
        self.hasMountIssue = hasMountIssue
    }
    func bridgeURL(for id: UUID) -> URL { URL(fileURLWithPath: "/unused/\(id)") }
    func untrackedBridges(excluding trackedURLs: [URL]) -> [URL] { [] }
    func mountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        bridges.insert(try #require(descriptor.mountID))
    }
    func attachImage(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws -> DiskAttachment
    {
        images.insert(try #require(descriptor.mountID))
        return DiskAttachment(
            device: "/dev/disk900000", volumeURLs: volumeURLs,
            volumeMountIssue: hasMountIssue
                ? VolumeMountIssue(status: 1, detail: "Not mounted") : nil)
    }
    func inspectBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws
        -> AttachmentInspection
    {
        let id = try #require(descriptor.mountID)
        return AttachmentInspection(
            ownership: bridges.contains(id) ? .verified : .absent,
            attachment: images.contains(id)
                ? DiskAttachment(device: "/dev/disk900000", volumeURLs: volumeURLs) : nil,
            connectionState: .connected)
    }
    func detachImage(_ attachment: DiskAttachment, descriptor: ConnectionDescriptor, bridgeURL: URL)
        throws
    {
        images.remove(try #require(descriptor.mountID))
    }
    func unmountBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) throws {
        bridges.remove(try #require(descriptor.mountID))
    }
    func discardEmptyBridge(_ descriptor: ConnectionDescriptor, at bridgeURL: URL) {}
}

@Test(arguments: [false, true], [false, true]) @MainActor
private func connectedDisksOfferDiskUtilityAfterAVolumeMountFailure(
    _ partiallyMounted: Bool, _ hasMountIssue: Bool
) async throws {
    let backend = UnmountedBackend(partiallyMounted: partiallyMounted, hasMountIssue: hasMountIssue)
    let journal = MemoryAttachmentJournal()
    let owner = try AttachmentCoordinator(backend: backend, journal: journal)
    try await owner.restore()
    let model = AppModel(coordinator: owner, extensionCheck: { .ready })
    let server = try ServerProfile(name: "Server", portal: Portal("example.invalid"))
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    var inquiry = Data(repeating: 0, count: 36)
    inquiry[2] = 6
    inquiry[3] = 2
    inquiry[4] = 31
    var capacity = Data(repeating: 0, count: 32)
    capacity[7] = 7
    capacity[10] = 2
    let disk = FoundDisk(
        targetName: "iqn.2026-10.test:unmounted",
        inspection: .init(
            lun: try LogicalUnit(0),
            result: .success(
                DiskInformation(
                    device: try SCSIInquiry(data: inquiry),
                    capacity: try DiskCapacity(readCapacity16: capacity)))))
    model.connect(disk, server: server)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(3))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(1))
    }
    let connected = try #require(model.attached.first)
    #expect(model.attached.count == 1 && connected.phase == .connected)
    #expect(connected.connectionState == .connected && !connected.needsCleanup)
    #expect(model.recoveryComplete && journal.load().count == 1)
    #expect(connected.attachment?.volumeURLs.count == (partiallyMounted ? 1 : 0))
    if hasMountIssue {
        #expect(model.issue?.title == String(localized: "Volumes Couldn’t Be Mounted"))
        #expect(model.issue?.recoveryAction == .openDiskUtility)
        #expect(model.issue?.detail == "diskutil (1): Not mounted")
    } else {
        #expect(model.issue == nil)
    }
    await model.refreshConnectionHealth()
    #expect(model.attached.first?.phase == .connected && model.recoveryComplete)
    model.issue = nil  // Dismiss the notice before choosing the next operation.
    model.eject(try #require(model.attached.first))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(1))
    }
    #expect(model.attached.isEmpty && journal.load().isEmpty && model.issue == nil)
}

private func connectedDisk(target: String, volume: String?) throws -> AttachedDisk {
    let id = UUID()
    let identity = try InitiatorIdentity.makeNew()
    let descriptor = try ConnectionDescriptor(
        profileID: UUID(), portal: Portal("storage.invalid"), initiatorName: identity.name,
        targetName: target, lun: LogicalUnit(0), readOnly: false, isid: identity.seed,
        mountID: id)
    var disk = AttachedDisk(
        entry: try AttachmentJournalEntry(
            id: id, descriptor: descriptor,
            bridgeURL: URL(fileURLWithPath: "/unused-unmounted-test/\(id.uuidString)"),
            phase: .connected))
    disk.verificationFailed = false
    disk.attachment = DiskAttachment(
        device: "/dev/disk900000",
        volumeURLs: volume.map { [URL(fileURLWithPath: "/Volumes/\($0)")] } ?? [])
    disk.connectionState = .connected
    return disk
}

/// A connected disk without a mounted volume is named like its row under Available Disks,
/// with its LUN and target on the line below, like a disk with a volume.
@Test func aDiskWithoutVolumesIsNamedByItsLUN() throws {
    let target = "iqn.2026-11.dev.soba:realapp-84dd2e643998"
    let blank = try connectedDisk(target: target, volume: nil)
    #expect(blank.hasNoMountedVolumes)
    #expect(blank.displayName == String(localized: "Disk 0"))
    #expect(ConnectedDiskRow.facts(for: blank) == "LUN 0 · \(target)")
    let formatted = try connectedDisk(target: target, volume: "RealAppRW")
    #expect(formatted.displayName == "RealAppRW")
    #expect(ConnectedDiskRow.facts(for: formatted) == "LUN 0 · \(target)")
    #expect(ConnectedDiskRow.message(for: formatted) == nil)
    // The disk may be new, or its volumes unreadable or unmounted: only a new disk is told
    // to be initialized, and Open Disk Utility stays beside it.
    #expect(
        ConnectedDiskRow.message(for: blank)
            == "No volumes are mounted on this disk. To use a new disk with this Mac, initialize it in Disk Utility."
    )
    // Without a known attachment, as for a connection that couldn't be verified, the disk
    // is still named by its LUN rather than by the target's full name.
    var unverified = blank
    unverified.attachment = nil
    #expect(unverified.displayName == String(localized: "Disk 0"))
    // Alerts about the disk use the same name as its row, kept on one line in the title.
    let issue = AppIssue(
        POSIXError(.EBUSY), context: .ejectingDisk(blank.displayName, connectionState: .connected))
    #expect(issue.title == String(localized: "“Disk\u{00A0}0” Is in Use"))
}
