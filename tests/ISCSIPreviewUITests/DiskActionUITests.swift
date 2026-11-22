import XCTest

/// Per-disk actions in the production views, with the memory-only preview backend.
/// No disk is mounted, no NAS is contacted, and no Keychain item is used.
final class DiskActionUITests: XCTestCase {
    @MainActor func testEnglishConnectMenuConnectsReadOnly() { checkConnectMenu(japanese: false) }
    @MainActor func testJapaneseConnectMenuConnectsReadOnly() { checkConnectMenu(japanese: true) }
    @MainActor func testEnglishForceEjectNeedsConfirmation() { checkForceEject(japanese: false) }
    @MainActor func testJapaneseForceEjectNeedsConfirmation() { checkForceEject(japanese: true) }
    @MainActor func testEnglishDiskInUseForceEjectKeepsGeneralWarning() {
        checkInUseForceEject(japanese: false)
    }
    @MainActor func testJapaneseDiskInUseForceEjectKeepsGeneralWarning() {
        checkInUseForceEject(japanese: true)
    }
    @MainActor func testEnglishUnverifiedDiskOffersForceEject() {
        checkUnverifiedForceEject(japanese: false)
    }
    @MainActor func testJapaneseUnverifiedDiskOffersForceEject() {
        checkUnverifiedForceEject(japanese: true)
    }
    @MainActor func testEnglishReconnectingDiskShowsStatus() { checkReconnecting(japanese: false) }
    @MainActor func testJapaneseReconnectingDiskShowsStatus() { checkReconnecting(japanese: true) }
    @MainActor func testEnglishFoundDiskMirrorsItsReconnectingConnection() {
        checkFoundDiskMirrorsConnection(japanese: false)
    }
    @MainActor func testJapaneseFoundDiskMirrorsItsReconnectingConnection() {
        checkFoundDiskMirrorsConnection(japanese: true)
    }
    @MainActor func testEnglishUnformattedDiskIsNamedByItsLUN() {
        checkUnformattedDisk(japanese: false)
    }
    @MainActor func testJapaneseUnformattedDiskIsNamedByItsLUN() {
        checkUnformattedDisk(japanese: true)
    }
    @MainActor func testEnglishReconnectingDiskOffersForceEjectWhenItsDelayEnds() {
        checkReconnectingOffer(japanese: false)
    }
    @MainActor func testJapaneseReconnectingDiskOffersForceEjectWhenItsDelayEnds() {
        checkReconnectingOffer(japanese: true)
    }
    @MainActor func testEnglishDisksOfTheSameNameAddTheirTargets() {
        checkSameLUNDisks(japanese: false)
    }
    @MainActor func testJapaneseDisksOfTheSameNameAddTheirTargets() {
        checkSameLUNDisks(japanese: true)
    }

    @MainActor private func launch(
        japanese: Bool, fixture: String, _ arguments: [String] = []
    ) -> XCUIApplication {
        continueAfterFailure = false
        executionTimeAllowance = 90
        let app = XCUIApplication()
        app.launchArguments =
            [
                "-AppleLanguages", japanese ? "(ja)" : "(en)",
                "-AppleLocale", japanese ? "ja_JP" : "en_US", fixture,
            ] + arguments
        launchPreview(app)
        return app
    }

    /// Connect Read-Only in a writable disk's Connect menu connects that disk read-only
    /// directly, even when a writable connection would need the read-only confirmation.
    @MainActor private func checkConnectMenu(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--write-completion-unavailable")
        defer { app.terminate() }
        let target = "iqn.2026-10.example:available"
        let connect = app.descendants(matching: .any).matching(identifier: "connect-\(target)-0")
            .firstMatch
        XCTAssertTrue(connect.waitForExistence(timeout: 10) && connect.isEnabled)
        XCTAssertEqual(connect.elementType, .popUpButton)
        let arrow = connect.menuButtons.firstMatch
        XCTAssertTrue(arrow.exists && arrow.isHittable)
        arrow.click()
        let readOnly = app.menuItems[japanese ? "読み出し専用で接続" : "Connect Read-Only"]
        XCTAssertTrue(readOnly.waitForExistence(timeout: 5) && readOnly.isEnabled)
        record(japanese ? "Japanese Connect menu" : "English Connect menu", app: app, screen: true)
        readOnly.click()
        XCTAssertTrue(app.staticTexts["Read-only Archive"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts[japanese ? "読み出し専用" : "Read-only"].exists)
        XCTAssertTrue(app.staticTexts[japanese ? "接続済み" : "Connected"].exists)
        // The read-only choice was explicit, so no confirmation is shown.
        XCTAssertEqual(app.windows["preview"].sheets.count, 0)
        XCTAssertFalse(connect.isEnabled)
        // The found disk's row shows the state of its connection, like its connected row.
        let connected = japanese ? "接続済み" : "Connected"
        XCTAssertEqual(
            app.staticTexts.matching(
                NSPredicate(format: "value == %@ OR label == %@", connected, connected)
            ).count, 2)
        XCTAssertFalse(
            app.staticTexts[
                japanese
                    ? "このディスクはすでにこのMacに接続されています。"
                    : "This disk is already connected to this Mac."
            ].exists)
        record(japanese ? "Japanese read-only from menu" : "English read-only from menu", app: app)
    }

    /// An interrupted disk that can't be ejected offers Force Eject in the error. Its
    /// confirmation explains that the connection was lost and keeps Cancel as the Return
    /// default.
    @MainActor private func checkForceEject(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--force-ejection")
        defer { app.terminate() }
        let eject = app.buttons[japanese ? "Archiveを取り出す" : "Eject Archive"]
        let window = app.windows["preview"]
        let sheet = window.sheets.firstMatch
        let failure = japanese ? "“Archive”を取り出せませんでした" : "“Archive” Couldn’t Be Ejected"
        let confirmation = japanese ? "“Archive”を\n強制的に取り出しますか?" : "Force Eject “Archive”?"
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        XCTAssertTrue(text(japanese ? "接続が中断されました" : "Connection interrupted", in: app).exists)
        func requestForceEject() {
            XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
            eject.click()
            XCTAssertTrue(sheet.waitForExistence(timeout: 10))
            XCTAssertTrue(text(failure, in: sheet).exists)
            XCTAssertTrue(
                sheet.buttons[japanese ? "ディスクユーティリティを開く" : "Open Disk Utility"].exists)
            let force = sheet.buttons[japanese ? "強制的に取り出す…" : "Force Eject…"]
            XCTAssertTrue(force.isEnabled)
            force.click()
            XCTAssertTrue(text(confirmation, in: window).waitForExistence(timeout: 10))
        }
        requestForceEject()
        let message =
            japanese
            ? "サーバとの接続が切れました。ディスクに保存されていない変更内容は失われます。"
            : "The connection to the server was lost. Changes that haven’t been saved to the disk will be lost."
        XCTAssertTrue(text(message, in: window).exists)
        let confirm = window.buttons[japanese ? "強制的に取り出す" : "Force Eject"]
        XCTAssertTrue(confirm.exists && confirm.isEnabled)
        record(
            japanese ? "Japanese force eject confirmation" : "English force eject confirmation",
            app: app)
        // Cancel is the default button: Return must never force the ejection.
        app.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(text(confirmation, in: window).waitForNonExistence(timeout: 5))
        XCTAssertTrue(eject.waitForExistence(timeout: 5))
        requestForceEject()
        // Escape also cancels.
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(text(confirmation, in: window).waitForNonExistence(timeout: 5))
        XCTAssertTrue(eject.exists)
        requestForceEject()
        window.buttons[japanese ? "強制的に取り出す" : "Force Eject"].click()
        XCTAssertTrue(eject.waitForNonExistence(timeout: 10))
        XCTAssertFalse(text(confirmation, in: window).exists)
        record(japanese ? "Japanese force ejected" : "English force ejected", app: app)
    }

    /// A connected disk that is in use keeps the general warning: nothing showed that its
    /// connection was lost.
    @MainActor private func checkInUseForceEject(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--force-ejection-in-use")
        defer { app.terminate() }
        let eject = app.buttons[japanese ? "Archiveを取り出す" : "Eject Archive"]
        let window = app.windows["preview"]
        let sheet = window.sheets.firstMatch
        XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
        // A healthy disk offers Force Eject only after a normal eject has failed.
        XCTAssertFalse(app.buttons[japanese ? "Archiveを強制的に取り出す" : "Force Eject Archive"].exists)
        eject.click()
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        XCTAssertTrue(text(japanese ? "“Archive”は使用中です" : "“Archive” Is in Use", in: sheet).exists)
        record(japanese ? "Japanese disk in use" : "English disk in use", app: app)
        let force = sheet.buttons[japanese ? "強制的に取り出す…" : "Force Eject…"]
        // Escape dismisses the error without forcing anything.
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        XCTAssertTrue(eject.isEnabled)
        eject.click()
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        force.click()
        let confirmation = japanese ? "“Archive”を\n強制的に取り出しますか?" : "Force Eject “Archive”?"
        XCTAssertTrue(text(confirmation, in: window).waitForExistence(timeout: 10))
        let message =
            japanese
            ? "このディスクの未保存の変更内容は失われる可能性があります。"
            : "Unsaved changes on this disk may be lost."
        XCTAssertTrue(text(message, in: window).exists)
        record(
            japanese
                ? "Japanese in-use force eject confirmation"
                : "English in-use force eject confirmation",
            app: app)
        window.buttons[japanese ? "キャンセル" : "Cancel"].click()
        XCTAssertTrue(text(confirmation, in: window).waitForNonExistence(timeout: 5))
        XCTAssertTrue(eject.exists && eject.isEnabled)
    }

    /// A disk whose connection couldn't be verified offers Force Eject in its row, without a
    /// failed normal eject first.
    @MainActor private func checkUnverifiedForceEject(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--unverified-connection")
        defer { app.terminate() }
        // Without a known volume, the disk is named by its LUN, as under Available Disks.
        // A found disk of another target there is also LUN 0, so the name adds its target.
        let name = japanese ? "ディスク0 — preview-0" : "Disk 0 — preview-0"
        let force = app.buttons[japanese ? "\(name)を強制的に取り出す" : "Force Eject \(name)"]
        XCTAssertTrue(force.waitForExistence(timeout: 10) && force.isEnabled)
        XCTAssertTrue(app.buttons[japanese ? "\(name)を取り出す" : "Eject \(name)"].exists)
        XCTAssertTrue(
            text(japanese ? "接続を確認してください" : "Check this connection", in: app).exists)
        let notice = app.descendants(matching: .any).matching(
            identifier: "connection-recovery-notice"
        ).firstMatch
        XCTAssertTrue(notice.exists)
        XCTAssertTrue(
            notice.staticTexts[japanese ? "接続中のディスクを確認" : "Check Connected Disks"].exists)
        record(japanese ? "Japanese unverified disk" : "English unverified disk", app: app)
        force.click()
        let window = app.windows["preview"]
        let confirmation = japanese ? "“Archive”を\n強制的に取り出しますか?" : "Force Eject “Archive”?"
        XCTAssertTrue(text(confirmation, in: window).waitForExistence(timeout: 10))
        let message =
            japanese
            ? "サーバとの接続が切れました。ディスクに保存されていない変更内容は失われます。"
            : "The connection to the server was lost. Changes that haven’t been saved to the disk will be lost."
        XCTAssertTrue(text(message, in: window).exists)
        record(
            japanese
                ? "Japanese unverified force eject confirmation"
                : "English unverified force eject confirmation", app: app)
        window.buttons[japanese ? "強制的に取り出す" : "Force Eject"].click()
        XCTAssertTrue(force.waitForNonExistence(timeout: 10))
        XCTAssertFalse(text(confirmation, in: window).exists)
    }

    /// A reconnecting disk shows its status in words and can still be ejected normally.
    @MainActor private func checkReconnecting(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--reconnecting")
        defer { app.terminate() }
        let eject = app.buttons[japanese ? "Workを取り出す" : "Eject Work"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
        XCTAssertTrue(text(japanese ? "再接続中…" : "Reconnecting…", in: app).exists)
        XCTAssertTrue(text(japanese ? "接続済み" : "Connected", in: app).exists)
        // Force Eject is offered only after the disk has kept reconnecting for a while
        // (AttachedDisk.forcedReleaseReconnectingDelay), so a short blip never shows it.
        XCTAssertFalse(app.buttons[japanese ? "Workを強制的に取り出す" : "Force Eject Work"].exists)
        // Its volume waits for the server, so it isn't opened in Finder until it reconnects.
        XCTAssertFalse(app.buttons[japanese ? "WorkをFinderに表示" : "Show Work in Finder"].exists)
        XCTAssertTrue(app.buttons[japanese ? "ArchiveをFinderに表示" : "Show Archive in Finder"].exists)
        record(japanese ? "Japanese reconnecting disk" : "English reconnecting disk", app: app)
    }

    /// A found disk that is already connected shows that connection's state, so it never
    /// reads as connected while its connected row is reconnecting.
    @MainActor private func checkFoundDiskMirrorsConnection(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--reconnecting", ["--shared-target"])
        defer { app.terminate() }
        let eject = app.buttons[japanese ? "Workを取り出す" : "Eject Work"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        for state in [japanese ? "再接続中…" : "Reconnecting…", japanese ? "接続済み" : "Connected"] {
            XCTAssertEqual(
                app.staticTexts.matching(
                    NSPredicate(format: "value == %@ OR label == %@", state, state)
                ).count, 2,
                state)
        }
        XCTAssertFalse(
            app.staticTexts[
                japanese
                    ? "このディスクはすでにこのMacに接続されています。"
                    : "This disk is already connected to this Mac."
            ].exists)
        let target = "iqn.2026-10.example:available"
        for lun in 0...1 {
            let connect = app.descendants(matching: .any)
                .matching(identifier: "connect-\(target)-\(lun)").firstMatch
            XCTAssertTrue(connect.exists && !connect.isEnabled)
        }
        record(
            japanese
                ? "Japanese found disk mirrors reconnecting"
                : "English found disk mirrors reconnecting", app: app)
    }

    /// A connected disk without a volume is named like its Available Disks row, with its LUN
    /// and target below, and says how a new disk is prepared, beside Open Disk Utility.
    @MainActor private func checkUnformattedDisk(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--unformatted-disk")
        defer { app.terminate() }
        let name = japanese ? "ディスク0" : "Disk 0"
        let eject = app.buttons[japanese ? "\(name)を取り出す" : "Eject \(name)"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
        XCTAssertTrue(text("LUN 0 · iqn.2026-10.example:available", in: app).exists)
        let message =
            japanese
            ? "このディスクには、マウントされているボリュームがありません。新しいディスクをこのMacで使用するには、ディスクユーティリティで初期化してください。"
            : "No volumes are mounted on this disk. To use a new disk with this Mac, initialize it in Disk Utility."
        XCTAssertTrue(text(message, in: app).exists)
        let utility = app.buttons[
            japanese ? "ディスクユーティリティで\(name)を確認" : "Check \(name) in Disk Utility"]
        XCTAssertTrue(utility.isHittable)
        // The connected row and the found row have the same title.
        XCTAssertEqual(
            app.staticTexts.matching(NSPredicate(format: "value == %@ OR label == %@", name, name))
                .count, 2)
        record(japanese ? "Japanese unformatted disk" : "English unformatted disk", app: app)
    }

    /// Two connected disks without volumes are both LUN 0, of different targets, beside a found
    /// LUN 0 of a third. Each row, VoiceOver label and alert adds the disk's target to its name.
    @MainActor private func checkSameLUNDisks(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--same-lun-disks", ["--eject-fails"])
        defer { app.terminate() }
        let disk = japanese ? "ディスク0" : "Disk 0"
        let names = ["preview-0", "preview-1"].map { "\(disk) — \($0)" }
        for name in names {
            let eject = app.buttons[japanese ? "\(name)を取り出す" : "Eject \(name)"]
            XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled, name)
            XCTAssertTrue(text(name, in: app).exists, name)
            XCTAssertTrue(
                app.buttons[
                    japanese ? "ディスクユーティリティで\(name)を確認" : "Check \(name) in Disk Utility"
                ].exists, name)
            XCTAssertTrue(
                app.buttons[japanese ? "\(name)の情報を表示" : "Show Info for \(name)"].exists, name)
        }
        // The found disk keeps its own title, under its target.
        XCTAssertEqual(
            app.staticTexts.matching(NSPredicate(format: "value == %@ OR label == %@", disk, disk))
                .count, 1)
        XCTAssertFalse(app.buttons[japanese ? "\(disk)を取り出す" : "Eject \(disk)"].exists)
        record(
            japanese ? "Japanese disks of the same name" : "English disks of the same name",
            app: app)
        app.buttons[japanese ? "\(names[1])を取り出す" : "Eject \(names[1])"].click()
        let sheet = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        // The alert's title keeps the name on one line with no-break spaces.
        let titleName = names[1].replacingOccurrences(of: " ", with: "\u{00A0}")
        let failure =
            japanese ? "“\(titleName)”を取り出せませんでした" : "“\(titleName)” Couldn’t Be Ejected"
        XCTAssertTrue(text(failure, in: sheet).exists)
        record(
            japanese
                ? "Japanese ejection alert names its target"
                : "English ejection alert names its target", app: app)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
    }

    /// The disk starts reconnecting at launch, and its clock runs. When the delay before Force
    /// Eject ends, the row offers it at once, without a click, a refresh, or reactivation.
    @MainActor private func checkReconnectingOffer(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--reconnecting", ["--reconnecting-for=0"])
        defer { app.terminate() }
        let eject = app.buttons[japanese ? "Workを取り出す" : "Eject Work"]
        let force = app.buttons[japanese ? "Workを強制的に取り出す" : "Force Eject Work"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        let launched = Date()
        XCTAssertFalse(force.exists)
        XCTAssertTrue(text(japanese ? "再接続中…" : "Reconnecting…", in: app).exists)
        // The delay is 10 seconds; the next periodic check would come much later.
        XCTAssertTrue(force.waitForExistence(timeout: 20))
        let waited = XCTAttachment(
            string: "Force Eject appeared \(Date().timeIntervalSince(launched)) s after the row")
        waited.name = "Force Eject offer timing"
        waited.lifetime = .keepAlways
        add(waited)
        XCTAssertTrue(force.isEnabled && eject.isEnabled)
        XCTAssertTrue(text(japanese ? "再接続中…" : "Reconnecting…", in: app).exists)
        record(
            japanese
                ? "Japanese reconnecting disk offers Force Eject"
                : "English reconnecting disk offers Force Eject", app: app)
    }

    @MainActor private func text(_ value: String, in element: XCUIElement) -> XCUIElement {
        element.staticTexts.matching(
            NSPredicate(format: "value == %@ OR label == %@", value, value)
        ).firstMatch
    }

    @MainActor private func record(_ name: String, app: XCUIApplication, screen: Bool = false) {
        // An open menu is a separate window, so capture the whole screen for it.
        let window = app.windows["preview"]
        let image =
            screen || !window.exists ? XCUIScreen.main.screenshot() : window.screenshot()
        let screenshot = XCTAttachment(screenshot: image)
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = name + " accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
    }
}
