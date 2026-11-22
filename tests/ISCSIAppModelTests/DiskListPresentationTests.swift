import Foundation
import ISCSICore
import ISCSINetwork
import Testing

@testable import ISCSIAppModel
@testable import ISCSIPlatform

@MainActor private func listModel() throws -> (AppModel, ServerProfile) {
    let server = try ServerProfile(name: "Storage", portal: Portal("storage.invalid"))
    let model = AppModel(extensionCheck: { .ready })
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.recoveryComplete = true
    model.extensionState = .ready
    return (model, server)
}

private func foundDisk(_ target: String, _ lun: LogicalUnit) -> FoundDisk {
    FoundDisk(
        targetName: target, inspection: LogicalUnitInspection(lun: lun, result: .failure(.notReady))
    )
}

@MainActor private func attachedDisk(
    _ model: AppModel, _ server: ServerProfile, target: String, lun: UInt16,
    volume: String? = nil, state: DiskConnectionState = .connected
) throws -> AttachedDisk {
    let id = UUID()
    let identity = try #require(model.document).identity
    let descriptor = try ConnectionDescriptor(
        profileID: server.id, portal: server.portal, initiatorName: identity.name,
        targetName: target, lun: LogicalUnit(lun), readOnly: false, isid: identity.seed,
        mountID: id)
    var disk = AttachedDisk(
        entry: try AttachmentJournalEntry(
            id: id, descriptor: descriptor,
            bridgeURL: URL(fileURLWithPath: "/unused-list-test/\(id.uuidString)"),
            phase: .connected))
    disk.verificationFailed = false
    disk.attachment = DiskAttachment(
        device: "/dev/disk900000",
        volumeURLs: volume.map { [URL(fileURLWithPath: "/Volumes/\($0)")] } ?? [])
    disk.connectionState = state
    return disk
}

/// The server may report its disks and targets in any order, and in a different order on
/// each search. The lists show them by LUN and by name, the same way every time.
@Test @MainActor func availableDisksAreListedByLUNInAStableOrder() throws {
    let (model, server) = try listModel()
    #expect(model.availableTargets(on: server) == nil)
    let names = [
        "iqn.2026-10.example:target-10", "iqn.2026-10.example:target-2",
        "iqn.2026-10.example:Archive",
    ]
    let sortedNames = [names[2], names[1], names[0]]
    let target = DiscoveredTarget(name: names[0])
    #expect(model.availableDisks(target, on: server) == nil)
    let luns = [
        try LogicalUnit(1), try LogicalUnit(300), try LogicalUnit(0), try LogicalUnit(17),
        try LogicalUnit(wireBytes: [0, 2, 0, 0, 0, 0, 0, 1]),
    ]
    let expected = ["0", "1", "0x0002000000000001", "17", "300"]
    for order in [names, names.reversed(), [names[1], names[0], names[2]]] {
        model.targets[server.id] = order.map { DiscoveredTarget(name: $0) }
        #expect(model.availableTargets(on: server)?.map(\.name) == sortedNames)
    }
    for order in [luns, luns.reversed(), [luns[2], luns[4], luns[0], luns[3], luns[1]]] {
        model.choices[model.choiceKey(server, target.name)] = order.map {
            foundDisk(target.name, $0)
        }
        #expect(
            model.availableDisks(target, on: server)?.map(\.lun.displayIdentifier) == expected)
    }
    model.choices[model.choiceKey(server, target.name)] = []
    #expect(model.availableDisks(target, on: server) == [])
}

/// Connected disks are listed like Available Disks, without reordering the model's own list.
@Test @MainActor func connectedDisksAreListedByTargetAndLUN() throws {
    let (model, server) = try listModel()
    let other = try ServerProfile(name: "Other", portal: Portal("other.invalid"))
    let disks = [
        try attachedDisk(model, server, target: "iqn.2026-10.example:b", lun: 1, volume: "B1"),
        try attachedDisk(model, server, target: "iqn.2026-10.example:a", lun: 1, volume: "A1"),
        try attachedDisk(model, other, target: "iqn.2026-10.example:a", lun: 0, volume: "X"),
        try attachedDisk(model, server, target: "iqn.2026-10.example:b", lun: 0, volume: "B0"),
        try attachedDisk(model, server, target: "iqn.2026-10.example:a", lun: 0, volume: "A0"),
    ]
    model.attached = disks
    #expect(model.connectedDisks(on: server).map(\.displayName) == ["A0", "A1", "B0", "B1"])
    #expect(model.connectedDisks(on: other).map(\.displayName) == ["X"])
    #expect(model.attached.map(\.id) == disks.map(\.id))
    model.attached = disks.reversed()
    #expect(model.connectedDisks(on: server).map(\.displayName) == ["A0", "A1", "B0", "B1"])
}

/// The Available Disks row of a connected disk shows the live state of that connection, so
/// it never reads as connected while its Connected Disks row is reconnecting.
@Test(arguments: [
    DiskConnectionState.connected, .reconnecting, .interrupted, .closed, .unknown,
])
@MainActor func anAlreadyConnectedDiskMirrorsItsConnection(_ state: DiskConnectionState) throws {
    let (model, server) = try listModel()
    let target = "iqn.2026-10.example:mirror"
    let disk = try attachedDisk(model, server, target: target, lun: 0, volume: "Work", state: state)
    model.attached = [disk]
    let found = foundDisk(target, try LogicalUnit(0))
    let existing = try #require(model.existingConnection(for: found))
    let tone: DiskStatusTone
    switch state {
    case .connected: tone = .normal
    case .reconnecting: tone = .progress
    case .interrupted, .closed: tone = .failure
    case .unknown: tone = .inactive
    }
    #expect(existing.statusTone == tone)
    #expect(model.diskStatus(existing) == model.diskStatus(disk))
    #expect(
        (model.diskStatus(existing) == String(localized: "Reconnecting…"))
            == (state == .reconnecting))
    #expect(model.existingConnection(for: foundDisk(target, try LogicalUnit(1))) == nil)
}

/// A disk without a volume keeps the short name its Available Disks row has, when no other
/// disk of the server has that name: not the same disk listed under Available Disks, not a
/// disk with a volume, and not a disk of another server.
@Test @MainActor func aDiskWithoutAVolumeKeepsItsShortNameWhenNoOtherDiskHasIt() throws {
    let (model, server) = try listModel()
    let other = try ServerProfile(name: "Other", portal: Portal("other.invalid"))
    let target = "iqn.2026-10.example:a"
    let blank = try attachedDisk(model, server, target: target, lun: 0)
    model.attached = [
        blank,
        try attachedDisk(model, server, target: "iqn.2026-10.example:b", lun: 0, volume: "B0"),
        try attachedDisk(model, other, target: "iqn.2026-10.example:c", lun: 0),
    ]
    model.targets[server.id] = [DiscoveredTarget(name: target)]
    model.choices[model.choiceKey(server, target)] = [
        foundDisk(target, try LogicalUnit(0)), foundDisk(target, try LogicalUnit(1)),
    ]
    let name = String(localized: "Disk 0")
    #expect(model.name(of: blank) == name)
    #expect(model.name(of: model.attached[1]) == "B0")
    #expect(model.name(of: model.attached[2]) == name)
}

/// Two targets of a server can both have LUN 0. Like Finder with items of the same name,
/// each disk then adds the short name of its target, under either list, in its row, its
/// VoiceOver labels and its alerts. Targets of the same short name add their full names.
@Test @MainActor func disksOfTheSameNameAddTheirTargets() async throws {
    let (model, server) = try listModel()
    let a = "iqn.2026-10.example:a"
    let b = "iqn.2026-10.example:b"
    let first = try attachedDisk(model, server, target: a, lun: 0)
    let second = try attachedDisk(model, server, target: b, lun: 0)
    model.attached = [first, second]
    let short = String(localized: "Disk 0")
    #expect(model.name(of: first) == "\(short) — a")
    #expect(model.name(of: second) == "\(short) — b")
    // A disk listed under Available Disks with the same name counts too, but only from
    // another target: the same target and LUN is the disk itself.
    model.attached = [first]
    #expect(model.name(of: first) == short)
    let c = "iqn.2026-10.example:c"
    model.targets[server.id] = [DiscoveredTarget(name: a), DiscoveredTarget(name: c)]
    model.choices[model.choiceKey(server, a)] = [foundDisk(a, try LogicalUnit(0))]
    #expect(model.name(of: first) == short)
    model.choices[model.choiceKey(server, c)] = [foundDisk(c, try LogicalUnit(0))]
    #expect(model.name(of: first) == "\(short) — a")
    // Disks of different LUNs keep their short names.
    model.choices[model.choiceKey(server, c)] = [foundDisk(c, try LogicalUnit(1))]
    #expect(model.name(of: first) == short)
    // Targets whose short names are the same add their full names.
    let one = "iqn.2026-10.one:disk"
    let two = "iqn.2026-10.two:disk"
    let left = try attachedDisk(model, server, target: one, lun: 0)
    let right = try attachedDisk(model, server, target: two, lun: 0)
    model.targets[server.id] = nil
    model.attached = [left, right]
    #expect(model.name(of: left) == "\(short) — \(one)")
    #expect(model.name(of: right) == "\(short) — \(two)")
    // A disk with a volume keeps the volume's name.
    var mounted = first
    mounted.attachment = DiskAttachment(
        device: "/dev/disk900000", volumeURLs: [URL(fileURLWithPath: "/Volumes/A0")])
    model.attached = [mounted, second]
    #expect(model.name(of: mounted) == "A0")
    #expect(model.name(of: second) == short)

    // Ejection alerts use the same name. Without a coordinator, every ejection fails.
    model.attached = [first, second]
    model.eject(second)
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while model.busy {
        guard clock.now < deadline else { throw ProtocolError.timedOut }
        try await clock.sleep(for: .milliseconds(2))
    }
    // The title keeps the name on one line.
    let unbroken = AppName.inSentence("\(short) — b")
    #expect(unbroken.contains("\u{00A0}—\u{00A0}") && !unbroken.contains(" "))
    #expect(model.issue?.title == String(localized: "“\(unbroken)” Couldn’t Be Ejected"))
    // So does Force Eject's confirmation, when the request knows no volume name.
    let request = ForceEjectionRequest(
        id: UUID(), diskID: second.id, displayName: b, reportsLostConnection: true,
        descriptor: second.descriptor, bridgeURL: second.bridgeURL,
        release: ForcedReleaseIdentity(image: nil))
    #expect(model.forceEjectionName(request) == "\(short) — b")
}
