import XCTest

/// Uses the production eject, error presentation, and recovery flow with memory stores.
/// Actual locked-Keychain and FSKit behavior is a separate native integration test.
final class MetadataCleanupUITests: XCTestCase {
    @MainActor func testEnglishCleanupFailureCanBeRetried() { check(japanese: false) }
    @MainActor func testJapaneseCleanupFailureCanBeRetried() { check(japanese: true) }
    @MainActor func testEnglishCleanupRowCanBeRetried() { check(japanese: false, rowRetry: true) }
    @MainActor func testJapaneseCleanupRowCanBeRetried() { check(japanese: true, rowRetry: true) }
    @MainActor func testEnglishUnlockRemovesTheConnectionInformation() {
        checkUnlock(japanese: false)
    }
    @MainActor func testJapaneseUnlockRemovesTheConnectionInformation() {
        checkUnlock(japanese: true)
    }
    @MainActor func testEnglishUnlockClosesTheCleanupAlert() {
        checkUnlock(japanese: false, alertShown: true)
    }
    @MainActor func testJapaneseUnlockClosesTheCleanupAlert() {
        checkUnlock(japanese: true, alertShown: true)
    }

    @MainActor private func check(japanese: Bool, rowRetry: Bool = false) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US", "--metadata-cleanup-failure",
        ]
        if rowRetry { app.launchArguments.append("--metadata-cleanup-delay") }
        launchPreview(app)
        let eject = app.buttons[japanese ? "Archiveを取り出す" : "Eject Archive"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
        eject.click()
        let sheet = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title = japanese ? "接続情報を削除できませんでした" : "Connection Information Couldn’t Be Removed"
        let message =
            japanese
            ? "ディスクの接続は解除されています。Macのロックを解除してから、“接続を確認”をクリックして接続情報を削除してください。"
            : "The disk is disconnected. Unlock your Mac, then click Check Connections to remove its connection information."
        XCTAssertTrue(sheet.staticTexts[title].exists)
        XCTAssertTrue(sheet.staticTexts[message].exists)
        XCTAssertFalse(sheet.buttons[japanese ? "強制的に取り出す…" : "Force Eject…"].exists)
        XCTAssertFalse(sheet.buttons[japanese ? "ディスクユーティリティを開く" : "Open Disk Utility"].exists)
        record(japanese ? "Japanese cleanup failure" : "English cleanup failure", app: app)
        sheet.buttons["OK"].click()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        // Once ejected, the disk has no volume and is named by its LUN.
        let name = japanese ? "ディスク0" : "Disk 0"
        let cleanup = app.buttons[
            japanese ? "\(name)の接続情報を削除" : "Remove connection information for \(name)"]
        XCTAssertTrue(cleanup.waitForExistence(timeout: 5) && cleanup.isEnabled)
        XCTAssertFalse(app.buttons[japanese ? "\(name)を取り出す" : "Eject \(name)"].exists)
        XCTAssertTrue(app.staticTexts[japanese ? "接続解除済み" : "Disconnected"].exists)
        let notice = app.descendants(matching: .any).matching(
            identifier: "connection-recovery-notice"
        ).firstMatch
        XCTAssertTrue(notice.exists)
        XCTAssertTrue(
            notice.staticTexts[japanese ? "接続情報が残っています" : "Connection Information Remains"].exists)
        let guidance =
            japanese
            ? "接続情報を削除できませんでした。Macのロックを解除してから、“接続を確認”をクリックしてやり直してください。"
            : "Connection information couldn’t be removed. Unlock your Mac, then click Check Connections to try again."
        XCTAssertTrue(notice.staticTexts[guidance].exists)
        XCTAssertFalse(app.buttons[japanese ? "ディスクユーティリティを開く" : "Open Disk Utility"].exists)
        record(japanese ? "Japanese cleanup pending" : "English cleanup pending", app: app)
        if rowRetry {
            cleanup.click()
            // The activity text is the progress indicator's accessibility label, not a
            // separate text element.
            let progress = japanese ? "接続情報を削除中…" : "Removing connection information…"
            XCTAssertTrue(app.activityIndicators[progress].waitForExistence(timeout: 2))
            let ejecting = japanese ? "ディスクを取り出し中…" : "Ejecting disk…"
            XCTAssertEqual(
                app.descendants(matching: .any).matching(
                    NSPredicate(format: "label == %@ OR value == %@", ejecting, ejecting)
                ).count, 0)
            record(japanese ? "Japanese cleanup progress" : "English cleanup progress", app: app)
        } else {
            let action = notice.buttons[japanese ? "接続を確認" : "Check Connections"]
            XCTAssertTrue(action.exists && action.isEnabled)
            action.click()
        }
        XCTAssertTrue(cleanup.waitForNonExistence(timeout: 10))
        XCTAssertFalse(notice.exists)
        XCTAssertFalse(sheet.exists)
        record(japanese ? "Japanese cleanup completed" : "English cleanup completed", app: app)
    }

    /// The disk is ejected while the preview's screen is locked, and its connection information
    /// is removed when Unlock Screen in the Preview menu stands in for the Mac being unlocked,
    /// without Check Connections and without a new alert. If the eject's alert, which asks to
    /// do this, is still shown, it closes by itself.
    @MainActor private func checkUnlock(japanese: Bool, alertShown: Bool = false) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US", "--metadata-cleanup-while-locked",
        ]
        launchPreview(app)
        let language = japanese ? "Japanese" : "English"
        let eject = app.buttons[japanese ? "Archiveを取り出す" : "Eject Archive"]
        XCTAssertTrue(eject.waitForExistence(timeout: 10) && eject.isEnabled)
        eject.click()
        let sheet = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title = japanese ? "接続情報を削除できませんでした" : "Connection Information Couldn’t Be Removed"
        XCTAssertTrue(sheet.staticTexts[title].exists)
        let name = japanese ? "ディスク0" : "Disk 0"
        let cleanup = app.buttons[
            japanese ? "\(name)の接続情報を削除" : "Remove connection information for \(name)"]
        let notice = app.descendants(matching: .any).matching(
            identifier: "connection-recovery-notice"
        ).firstMatch
        if !alertShown {
            sheet.buttons["OK"].click()
            XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        }
        XCTAssertTrue(cleanup.waitForExistence(timeout: 5))
        XCTAssertTrue(notice.exists)
        XCTAssertTrue(
            notice.staticTexts[japanese ? "接続情報が残っています" : "Connection Information Remains"].exists)
        record("\(language) cleanup pending while locked", app: app)

        let menu = app.menuBars.menuBarItems["Preview"]
        XCTAssertTrue(menu.waitForExistence(timeout: 5))
        menu.click()
        let unlock = app.menuBars.menuItems["Unlock Screen"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 5) && unlock.isEnabled)
        unlock.click()
        if alertShown {
            // The alert asked for what is now done, so it closes without a click.
            XCTAssertTrue(sheet.waitForNonExistence(timeout: 10))
        }
        XCTAssertTrue(cleanup.waitForNonExistence(timeout: 10))
        XCTAssertTrue(notice.waitForNonExistence(timeout: 5))
        // Nothing reports the removal, and nothing else needs attention.
        XCTAssertFalse(sheet.waitForExistence(timeout: 2))
        XCTAssertFalse(app.buttons[japanese ? "ディスクユーティリティを開く" : "Open Disk Utility"].exists)
        XCTAssertFalse(app.staticTexts[japanese ? "接続解除済み" : "Disconnected"].exists)
        record("\(language) cleanup removed after unlock", app: app)
    }

    @MainActor private func record(_ name: String, app: XCUIApplication) {
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = name + " accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
    }
}
