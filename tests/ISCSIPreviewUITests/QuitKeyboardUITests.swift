import XCTest

/// Uses the production application delegate with opt-in memory-only fixtures.
/// The search fixture ends with an authentication error; it opens no connection.
/// The application's name is joined by a no-break space in the alerts, so it never wraps.
final class QuitKeyboardUITests: XCTestCase {
    @MainActor func testEnglishBusyQuitReturn() { checkBusy(japanese: false, key: .return) }
    @MainActor func testJapaneseBusyQuitReturn() { checkBusy(japanese: true, key: .return) }
    @MainActor func testEnglishBusyQuitEscape() { checkBusy(japanese: false, key: .escape) }
    @MainActor func testJapaneseBusyQuitEscape() { checkBusy(japanese: true, key: .escape) }
    @MainActor func testEnglishBusyQuitCommandPeriod() {
        checkBusy(japanese: false, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testJapaneseBusyQuitCommandPeriod() {
        checkBusy(japanese: true, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testEnglishConnectedQuitReturn() {
        checkConnected(japanese: false, key: .return)
    }
    @MainActor func testJapaneseConnectedQuitReturn() {
        checkConnected(japanese: true, key: .return)
    }
    @MainActor func testEnglishConnectedQuitEscape() {
        checkConnected(japanese: false, key: .escape)
    }
    @MainActor func testJapaneseConnectedQuitEscape() {
        checkConnected(japanese: true, key: .escape)
    }
    @MainActor func testEnglishConnectedQuitCommandPeriod() {
        checkConnected(japanese: false, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testJapaneseConnectedQuitCommandPeriod() {
        checkConnected(japanese: true, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }

    @MainActor private func launch(japanese: Bool, fixture: String) -> XCUIApplication {
        continueAfterFailure = false
        executionTimeAllowance = 90
        let app = XCUIApplication()
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US", fixture,
        ]
        launchPreview(app)
        return app
    }

    @MainActor private func text(_ title: String, in element: XCUIElement) -> XCUIElement {
        element.staticTexts.matching(
            NSPredicate(format: "value == %@ OR label == %@", title, title)
        ).firstMatch
    }

    @MainActor private func checkBusy(
        japanese: Bool, key: XCUIKeyboardKey, modifiers: XCUIElement.KeyModifierFlags = []
    ) {
        let app = launch(japanese: japanese, fixture: "--quit-during-search")
        defer { app.terminate() }
        let search = app.findDisksToolbarButton(japanese: japanese)
        XCTAssertTrue(search.waitForExistence(timeout: 10) && search.isEnabled)
        search.click()
        XCTAssertFalse(search.isEnabled)
        app.typeKey("q", modifierFlags: .command)
        let dialog = app.dialogs.firstMatch
        XCTAssertTrue(dialog.waitForExistence(timeout: 5))
        XCTAssertEqual(app.dialogs.count, 1)
        let title = japanese ? "操作を実行中です" : "An Operation Is in Progress"
        let message =
            japanese
            ? "現在の操作が完了してから、Kurazuna\u{00A0}Previewを終了してください。"
            : "Wait for the current operation to finish before quitting Kurazuna\u{00A0}Preview."
        XCTAssertTrue(text(title, in: dialog).exists && text(message, in: dialog).exists)
        XCTAssertTrue(dialog.buttons["OK"].isEnabled)
        record("Busy quit before safe key", app: app)
        dialog.typeKey(key, modifierFlags: modifiers)
        XCTAssertTrue(dialog.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 5))
        record("Busy quit dismissed; application continues", app: app)

        // Let the memory search finish, then acknowledge its separate error.
        let searchError = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(searchError.waitForExistence(timeout: 20))
        let errorTitle =
            japanese
            ? "“Test\u{00A0}Storage”でディスクを検索できませんでした"
            : "Couldn’t Find Disks on “Test\u{00A0}Storage”"
        XCTAssertTrue(text(errorTitle, in: searchError).exists)
        // Return would open the server editor; Escape cancels the alert.
        searchError.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(searchError.waitForNonExistence(timeout: 5))
        XCTAssertTrue(search.isEnabled)
        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 5))
    }

    @MainActor private func checkConnected(
        japanese: Bool, key: XCUIKeyboardKey, modifiers: XCUIElement.KeyModifierFlags = []
    ) {
        let app = launch(japanese: japanese, fixture: "--quit-with-connected-disk")
        defer { app.terminate() }
        let disk = text("Archive", in: app)
        XCTAssertTrue(disk.waitForExistence(timeout: 10))
        app.typeKey("q", modifierFlags: .command)
        let dialog = app.dialogs.firstMatch
        XCTAssertTrue(dialog.waitForExistence(timeout: 5))
        XCTAssertEqual(app.dialogs.count, 1)
        let title =
            japanese
            ? "すべてのディスクを取り出してKurazuna\u{00A0}Previewを終了しますか?"
            : "Eject all disks and quit Kurazuna\u{00A0}Preview?"
        let message =
            japanese
            ? "終了する前に、接続中のディスクを取り出す必要があります。"
            : "Connected disks must be ejected before quitting."
        XCTAssertTrue(text(title, in: dialog).exists && text(message, in: dialog).exists)
        record("Connected quit before keyboard choice", app: app)
        dialog.typeKey(key, modifierFlags: modifiers)
        if key == .return {
            // Eject and Quit is the default: the memory disk is ejected, then the app quits.
            XCTAssertTrue(app.wait(for: .notRunning, timeout: 10))
            return
        }
        XCTAssertTrue(dialog.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 5))
        XCTAssertTrue(disk.exists)
        record("Safe key keeps the memory disk connected", app: app)

        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(dialog.waitForExistence(timeout: 5))
        dialog.buttons[japanese ? "取り出して終了" : "Eject and Quit"].click()
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 10))
    }

    @MainActor private func record(_ name: String, app: XCUIApplication) {
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
        // The quit alert is its own window; keep a crop of it for design review.
        let dialog = app.dialogs.firstMatch
        if dialog.exists {
            let crop = XCTAttachment(screenshot: dialog.screenshot())
            crop.name = name + " dialog"
            crop.lifetime = .keepAlways
            add(crop)
        }
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = name + " accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
    }
}
