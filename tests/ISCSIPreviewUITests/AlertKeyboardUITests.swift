import XCTest

/// Exercises the production search/error flow with memory-only login failures.
final class AlertKeyboardUITests: XCTestCase {
    @MainActor func testEnglishErrorDismissesWithReturn() { check(japanese: false, key: .return) }
    @MainActor func testJapaneseErrorDismissesWithReturn() { check(japanese: true, key: .return) }
    @MainActor func testEnglishErrorDismissesWithEscape() { check(japanese: false, key: .escape) }
    @MainActor func testJapaneseErrorDismissesWithEscape() { check(japanese: true, key: .escape) }

    @MainActor func testEnglishErrorDismissesWithCommandPeriod() {
        check(japanese: false, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testJapaneseErrorDismissesWithCommandPeriod() {
        check(japanese: true, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }

    @MainActor func testEnglishSearchAuthenticationReturnEditsServer() {
        checkAuthentication(japanese: false, key: .return)
    }
    @MainActor func testJapaneseSearchAuthenticationReturnEditsServer() {
        checkAuthentication(japanese: true, key: .return)
    }
    @MainActor func testEnglishSearchAuthenticationEscapeCancels() {
        checkAuthentication(japanese: false, key: .escape)
    }
    @MainActor func testJapaneseSearchAuthenticationEscapeCancels() {
        checkAuthentication(japanese: true, key: .escape)
    }
    @MainActor func testEnglishSearchAuthenticationCommandPeriodCancels() {
        checkAuthentication(
            japanese: false, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testJapaneseSearchAuthenticationCommandPeriodCancels() {
        checkAuthentication(
            japanese: true, key: XCUIKeyboardKey(rawValue: "."), modifiers: .command)
    }
    @MainActor func testEnglishSearchFailureWithConnectedDiskSaysToEjectFirst() {
        checkAuthenticationWithConnectedDisk(japanese: false)
    }
    @MainActor func testJapaneseSearchFailureWithConnectedDiskSaysToEjectFirst() {
        checkAuthenticationWithConnectedDisk(japanese: true)
    }
    @MainActor func testEnglishClosedLoginReturnEditsServer() {
        checkClosedLogin(japanese: false)
    }
    @MainActor func testJapaneseClosedLoginReturnEditsServer() {
        checkClosedLogin(japanese: true)
    }

    @MainActor private func launch(japanese: Bool, fixture: String) -> XCUIApplication {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US", fixture,
        ]
        launchPreview(app)
        return app
    }

    @MainActor private func text(_ value: String, in element: XCUIElement) -> XCUIElement {
        element.staticTexts.matching(
            NSPredicate(format: "value == %@ OR label == %@", value, value)
        ).firstMatch
    }

    /// An error with a single safe response: OK takes Return, Escape and Command–Period.
    @MainActor private func check(
        japanese: Bool, key: XCUIKeyboardKey, modifiers: XCUIElement.KeyModifierFlags = []
    ) {
        let app = launch(japanese: japanese, fixture: "--search-network-failure")
        defer { app.terminate() }
        let search = app.findDisksToolbarButton(japanese: japanese)
        XCTAssertTrue(search.waitForExistence(timeout: 10) && search.isEnabled)
        search.click()
        let sheet = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title = japanese ? "操作を完了できませんでした" : "The Operation Couldn’t Be Completed"
        let titles = sheet.staticTexts.matching(
            NSPredicate(format: "value == %@ OR label == %@", title, title))
        XCTAssertEqual(titles.count, 1)
        XCTAssertTrue(sheet.buttons["OK"].isEnabled)
        XCTAssertFalse(sheet.buttons[japanese ? "サーバを編集…" : "Edit Server…"].exists)
        record("Before keyboard dismissal", app: app)
        app.typeKey(key, modifierFlags: modifiers)
        let dismissed = sheet.waitForNonExistence(timeout: 5)
        record("After keyboard dismissal", app: app)
        XCTAssertTrue(dismissed)
        XCTAssertTrue(search.isEnabled)
    }

    /// A refused search names what to change and offers Edit Server… as the Return default.
    /// Escape and Command–Period cancel; neither opens the editor.
    @MainActor private func checkAuthentication(
        japanese: Bool, key: XCUIKeyboardKey, modifiers: XCUIElement.KeyModifierFlags = []
    ) {
        let app = launch(japanese: japanese, fixture: "--search-authentication-failure")
        defer { app.terminate() }
        let search = app.findDisksToolbarButton(japanese: japanese)
        XCTAssertTrue(search.waitForExistence(timeout: 10) && search.isEnabled)
        search.click()
        let window = app.windows["preview"]
        let sheet = window.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title =
            japanese
            ? "“Test\u{00A0}Storage”でディスクを検索できませんでした"
            : "Couldn’t Find Disks on “Test\u{00A0}Storage”"
        let message =
            japanese
            ? "このサーバでディスクを検索するには、ユーザ名とパスワードが必要です。このサーバを編集して、“ディスクの検索”で認証方法を選択してから、やり直してください。"
            : "This server requires a user name and password to find disks. Edit this server and choose an authentication method under Finding Disks, then try again."
        XCTAssertTrue(text(title, in: sheet).exists)
        XCTAssertTrue(text(message, in: sheet).exists)
        let edit = sheet.buttons[japanese ? "サーバを編集…" : "Edit Server…"]
        let cancel = sheet.buttons[japanese ? "キャンセル" : "Cancel"]
        XCTAssertTrue(edit.isEnabled && cancel.isEnabled)
        XCTAssertFalse(sheet.buttons["OK"].exists)
        // The action is at the trailing edge, or on top when the buttons are stacked.
        XCTAssertTrue(
            edit.frame.minX > cancel.frame.maxX || edit.frame.maxY < cancel.frame.minY)
        record("Search authentication alert", app: app)
        app.typeKey(key, modifierFlags: modifiers)
        XCTAssertTrue(text(title, in: window).waitForNonExistence(timeout: 5))
        // Find the editor's heading by its label within the sheet, as the other editor tests
        // do; a value-or-label predicate over the whole application didn't find it.
        let editor = app.sheets.firstMatch
        let heading = editor.staticTexts[japanese ? "サーバを編集" : "Edit Server"]
        if key == .return {
            XCTAssertTrue(heading.waitForExistence(timeout: 5))
            XCTAssertEqual(
                editor.textFields[japanese ? "名前" : "Name"].value as? String, "Test Storage")
            record("Server editor opened from the alert", app: app)
            editor.buttons[japanese ? "キャンセル" : "Cancel"].click()
            XCTAssertTrue(heading.waitForNonExistence(timeout: 5))
        } else {
            XCTAssertFalse(heading.waitForExistence(timeout: 2))
            XCTAssertEqual(window.sheets.count, 0)
        }
        XCTAssertTrue(search.isEnabled)
    }

    /// A server with a connected disk can't be edited, so a refused search says to eject its
    /// disks first. The alert offers only OK, and Return dismisses it without the editor.
    @MainActor private func checkAuthenticationWithConnectedDisk(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--search-failure-with-connected-disk")
        defer { app.terminate() }
        let search = app.findDisksToolbarButton(japanese: japanese)
        XCTAssertTrue(search.waitForExistence(timeout: 10) && search.isEnabled)
        XCTAssertTrue(app.buttons[japanese ? "Archiveを取り出す" : "Eject Archive"].exists)
        search.click()
        let window = app.windows["preview"]
        let sheet = window.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title =
            japanese
            ? "“Test\u{00A0}Storage”でディスクを検索できませんでした"
            : "Couldn’t Find Disks on “Test\u{00A0}Storage”"
        let message =
            japanese
            ? "このサーバでディスクを検索するには、ユーザ名とパスワードが必要です。“ディスクの検索”で認証方法を選択するには、このサーバのディスクを取り出してから、サーバを編集してください。"
            : "This server requires a user name and password to find disks. To choose an authentication method under Finding Disks, eject this server’s disks, then edit the server."
        XCTAssertTrue(text(title, in: sheet).exists)
        XCTAssertTrue(text(message, in: sheet).exists)
        XCTAssertTrue(sheet.buttons["OK"].isEnabled)
        XCTAssertFalse(sheet.buttons[japanese ? "サーバを編集…" : "Edit Server…"].exists)
        XCTAssertFalse(sheet.buttons[japanese ? "キャンセル" : "Cancel"].exists)
        record("Search refused with a connected disk", app: app)
        app.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(text(title, in: window).waitForNonExistence(timeout: 5))
        XCTAssertFalse(
            app.sheets.firstMatch.staticTexts[japanese ? "サーバを編集" : "Edit Server"]
                .waitForExistence(timeout: 2))
        XCTAssertEqual(window.sheets.count, 0)
        XCTAssertTrue(search.isEnabled)
    }

    /// The server closed the connection during the login without a user name and password,
    /// as Linux LIO does when it requires CHAP to find disks. The alert names the server, says
    /// what happened and what to check, and Edit Server… is the Return default.
    @MainActor private func checkClosedLogin(japanese: Bool) {
        let app = launch(japanese: japanese, fixture: "--server-closes-login")
        defer { app.terminate() }
        let search = app.findDisksToolbarButton(japanese: japanese)
        XCTAssertTrue(search.waitForExistence(timeout: 10) && search.isEnabled)
        search.click()
        let window = app.windows["preview"]
        let sheet = window.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        let title =
            japanese
            ? "“Test\u{00A0}Storage”でディスクを検索できませんでした"
            : "Couldn’t Find Disks on “Test\u{00A0}Storage”"
        let message =
            japanese
            ? "サーバが接続を閉じました。このサーバでディスクを検索するのにユーザ名とパスワードが必要な場合は、このサーバを編集して、“ディスクの検索”で認証方法を選択してから、やり直してください。"
            : "The server closed the connection. If it requires a user name and password to find disks, edit this server and choose an authentication method under Finding Disks, then try again."
        XCTAssertTrue(text(title, in: sheet).exists)
        XCTAssertTrue(text(message, in: sheet).exists)
        // Not the general network message it showed before.
        XCTAssertFalse(
            text(japanese ? "操作を完了できませんでした" : "The Operation Couldn’t Be Completed", in: sheet)
                .exists)
        let edit = sheet.buttons[japanese ? "サーバを編集…" : "Edit Server…"]
        let cancel = sheet.buttons[japanese ? "キャンセル" : "Cancel"]
        XCTAssertTrue(edit.isEnabled && cancel.isEnabled)
        XCTAssertFalse(sheet.buttons["OK"].exists)
        XCTAssertTrue(
            edit.frame.minX > cancel.frame.maxX || edit.frame.maxY < cancel.frame.minY)
        record("Closed login alert", app: app)
        app.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(text(title, in: window).waitForNonExistence(timeout: 5))
        let editor = app.sheets.firstMatch
        let heading = editor.staticTexts[japanese ? "サーバを編集" : "Edit Server"]
        XCTAssertTrue(heading.waitForExistence(timeout: 5))
        XCTAssertEqual(
            editor.textFields[japanese ? "名前" : "Name"].value as? String, "Test Storage")
        record("Server editor opened from the closed login alert", app: app)
        editor.buttons[japanese ? "キャンセル" : "Cancel"].click()
        XCTAssertTrue(heading.waitForNonExistence(timeout: 5))
        XCTAssertTrue(search.isEnabled)
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
