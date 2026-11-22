import Foundation
import ISCSICore
import ISCSINetwork
import ISCSIPlatform
import Testing

@testable import ISCSIAppModel

@Test(arguments: [
    ("iqn.2026-10.example:available", "available"),
    ("iqn.2005-10.org.freenas.ctl:archive", "archive"),
    ("IQN.2026-10.EXAMPLE:Projects", "Projects"),
    ("iqn.2026-10.example:a:b", "b"),
    ("iqn.2026-10.example", "iqn.2026-10.example"),
    ("iqn.2026-10.example:", "iqn.2026-10.example:"),
    ("eui.02004567A425678D", "eui.02004567A425678D"),
    ("naa.52004567BA64678D", "naa.52004567BA64678D"),
])
func targetRowsUseTheLastIQNComponentAsTheirName(_ name: String, _ expected: String) {
    #expect(DiscoveredTarget(name: name).friendlyName == expected)
}

@MainActor private func noticeModel() throws -> AppModel {
    let model = AppModel(extensionCheck: { .ready })
    model.document = try ProfileDocument(identity: .makeNew(), servers: [])
    model.recoveryComplete = true
    model.extensionState = .ready
    return model
}

@Test @MainActor func onlyTheMostSevereNoticeIsShown() throws {
    let model = try noticeModel()
    #expect(model.notice == nil)
    model.credentialCleanupNeeded = true
    #expect(model.notice == .credentialCleanup)
    model.extensionState = .disabled
    #expect(model.notice == .extensionSetup)
    model.extensionState = .checking
    #expect(model.notice == .credentialCleanup)
    model.extensionState = .unavailable
    model.document = nil
    #expect(model.notice == .settingsUnavailable)
    model.recoveryComplete = false
    #expect(model.notice == .connectionRecovery)
}

@Test @MainActor func busyWorkDefersConnectionAndSettingsNotices() throws {
    let model = try noticeModel()
    model.recoveryComplete = false
    model.document = nil
    model.extensionState = .differentCopy
    model.busy = true
    // The connection and settings notices describe a finished check; the setup notice remains.
    #expect(model.notice == .extensionSetup)
    model.extensionState = .ready
    #expect(model.notice == nil)
    model.busy = false
    #expect(model.notice == .connectionRecovery)
}

@Test @MainActor func targetCapacityIsShownOnlyForASingleReadableDisk() throws {
    let model = try noticeModel()
    let server = try ServerProfile(name: "Storage", portal: Portal("storage.invalid"))
    let target = DiscoveredTarget(name: "iqn.2026-10.example:capacity")
    #expect(model.knownCapacity(of: target, on: server) == nil)
    var capacity = [UInt8](repeating: 0, count: 8)
    capacity.put(UInt32(2047), at: 0)
    capacity.put(UInt32(512), at: 4)
    let information = DiskInformation(
        device: try SCSIInquiry(data: Data([0, 0, 6, 2, 0])),
        capacity: try DiskCapacity(readCapacity10: Data(capacity)), isWriteProtected: false)
    func disk(_ lun: UInt16, _ result: Result<DiskInformation, DiskProbeIssue>) throws -> FoundDisk
    {
        FoundDisk(
            targetName: target.name,
            inspection: LogicalUnitInspection(lun: try LogicalUnit(lun), result: result))
    }
    let key = model.choiceKey(server, target.name)
    model.choices[key] = []
    #expect(model.knownCapacity(of: target, on: server) == nil)
    model.choices[key] = [try disk(0, .success(information)), try disk(1, .failure(.notReady))]
    #expect(model.knownCapacity(of: target, on: server) == 1_048_576)
    model.choices[key]?.append(try disk(2, .success(information)))
    #expect(model.knownCapacity(of: target, on: server) == nil)
}

@Test @MainActor func findingDisksFromTheMenuNeedsAnIdleSelectedServer() throws {
    let model = try noticeModel()
    let server = try ServerProfile(name: "Storage", portal: Portal("storage.invalid"))
    #expect(!model.canFindDisksOnSelectedServer)
    model.document = try ProfileDocument(identity: .makeNew(), servers: [server])
    model.selectedServerID = server.id
    #expect(model.canFindDisksOnSelectedServer)
    model.busy = true
    #expect(!model.canFindDisksOnSelectedServer && !model.canRunMenuCommand)
    model.busy = false
    // The editor sheet and pending alerts must not be replaced by menu-started work.
    model.showingServerEditor = true
    #expect(!model.canFindDisksOnSelectedServer && !model.canRunMenuCommand)
    model.showingServerEditor = false
    model.issue = AppIssue(ProtocolError.invalidState)
    #expect(!model.canFindDisksOnSelectedServer && !model.canRunMenuCommand)
    model.issue = nil
    model.removeServer(server)
    #expect(!model.canFindDisksOnSelectedServer && !model.canRunMenuCommand)
    let request = try #require(model.serverRemovalRequest)
    model.cancelServerRemoval(request)
    #expect(model.canFindDisksOnSelectedServer && model.canRunMenuCommand)
}
