import XCTest

/// Exercises the production loading and selection views with memory-only settings and attachments.
final class ServerSelectionUITests: XCTestCase {
    @MainActor func testEnglishLaunchShowsSavedServer() { check(.saved, language: .english) }
    @MainActor func testJapaneseLaunchShowsSavedServer() { check(.saved, language: .japanese) }
    @MainActor func testEnglishUnselectedServerExplainsSelection() {
        check(.unselected, language: .english)
    }
    @MainActor func testJapaneseUnselectedServerExplainsSelection() {
        check(.unselected, language: .japanese)
    }
    @MainActor func testEnglishFirstRunOffersServerSetup() { check(.empty, language: .english) }
    @MainActor func testJapaneseFirstRunOffersServerSetup() { check(.empty, language: .japanese) }

    @MainActor func testEnglishSettingsReadFailureCanBeRetried() {
        check(.settingsFailure, language: .english)
    }
    @MainActor func testJapaneseSettingsReadFailureCanBeRetried() {
        check(.settingsFailure, language: .japanese)
    }

    private enum Scenario { case saved, unselected, empty, settingsFailure }
    private enum Language: String {
        case english = "en"
        case japanese = "ja"
        var locale: String { self == .english ? "en_US" : "ja_JP" }
        func text(_ key: String) -> String {
            guard self == .japanese else { return key }
            return [
                "Find Disks": "ディスクを検索", "Select a Server": "サーバを選択",
                "Click Find Disks to see the disks available on this server.":
                    "“ディスクを検索”をクリックすると、このサーバで利用できるディスクが表示されます。",
                "Choose a server in the sidebar to find and connect its disks.":
                    "サイドバーでサーバを選択すると、ディスクを検索して接続できます。",
                "No Servers": "サーバがありません",
                "Add Server…": "サーバを追加…", "Add Server": "サーバを追加",
                "Cancel": "キャンセル", "OK": "OK", "Check Connections": "接続を確認",
                "Server Settings Are Unavailable": "サーバ設定を確認できません",
                "Saved Passwords Need Attention": "保存済みのパスワードを確認してください",
                "Kurazuna couldn’t read its saved server settings. Click Check Connections to try again.":
                    "保存済みのサーバ設定を読み込めませんでした。“接続を確認”をクリックして、やり直してください。",

            ][key]!
        }
    }

    @MainActor private func check(_ scenario: Scenario, language: Language) {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", "(\(language.rawValue))", "-AppleLocale", language.locale,
            "--server-selection",
        ]
        if scenario == .unselected { app.launchArguments.append("--no-server-selection") }
        if scenario == .empty { app.launchArguments.append("--empty-servers") }
        if scenario == .settingsFailure { app.launchArguments.append("--settings-load-failure") }
        launchPreview(app)
        let row = app.outlines.staticTexts["Test Storage"].firstMatch
        let find = app.findDisksToolbarButton(japanese: language == .japanese)
        switch scenario {
        case .settingsFailure:
            let alert = app.windows["preview"].sheets.firstMatch
            XCTAssertTrue(alert.waitForExistence(timeout: 10))
            XCTAssertTrue(
                alert.staticTexts[language.text("Server Settings Are Unavailable")].exists)
            XCTAssertTrue(
                alert.staticTexts[
                    language.text(
                        "Kurazuna couldn’t read its saved server settings. Click Check Connections to try again."
                    )
                ].exists)
            XCTAssertFalse(row.exists)
            XCTAssertFalse(app.staticTexts[language.text("Saved Passwords Need Attention")].exists)
            record("\(language.rawValue) settings read failure", app: app)
            alert.buttons[language.text("OK")].click()
            XCTAssertTrue(alert.waitForNonExistence(timeout: 5))
            let retry = app.buttons[language.text("Check Connections")].firstMatch
            XCTAssertTrue(retry.isEnabled && retry.isHittable)
            retry.click()
            XCTAssertTrue(row.waitForExistence(timeout: 5))
            row.click()
            XCTAssertTrue(find.waitForExistence(timeout: 5) && find.isEnabled)
            XCTAssertEqual(app.sheets.count, 0)
            record("\(language.rawValue) settings reloaded", app: app)
        case .saved:
            XCTAssertTrue(row.waitForExistence(timeout: 10))
            XCTAssertTrue(find.waitForExistence(timeout: 5) && find.isEnabled)
            // Before a search, the text names the labeled button right beside it.
            let placeholder = app.findDisksPlaceholderButton
            XCTAssertTrue(placeholder.isHittable && placeholder.isEnabled)
            XCTAssertEqual(placeholder.label, language.text("Find Disks"))
            XCTAssertTrue(
                app.staticTexts[
                    language.text("Click Find Disks to see the disks available on this server.")
                ].exists)
            XCTAssertFalse(app.staticTexts[language.text("No Servers")].exists)
            XCTAssertFalse(app.staticTexts[language.text("Select a Server")].exists)
            record("\(language.rawValue) saved server after loading", app: app)
        case .unselected:
            XCTAssertTrue(row.waitForExistence(timeout: 10))
            XCTAssertTrue(
                app.staticTexts[language.text("Select a Server")].waitForExistence(timeout: 5))
            XCTAssertTrue(
                app.staticTexts[
                    language.text("Choose a server in the sidebar to find and connect its disks.")
                ].exists)
            XCTAssertFalse(app.buttons[language.text("Add Server…")].exists)
            XCTAssertFalse(find.exists)
            record("\(language.rawValue) choose existing server", app: app)
            row.click()
            XCTAssertTrue(find.waitForExistence(timeout: 5) && find.isEnabled)
            XCTAssertFalse(app.staticTexts[language.text("Select a Server")].exists)
            record("\(language.rawValue) existing server selected", app: app)
        case .empty:
            let title = app.staticTexts[language.text("No Servers")]
            XCTAssertTrue(title.waitForExistence(timeout: 10))
            XCTAssertFalse(row.exists)
            XCTAssertFalse(app.staticTexts[language.text("Select a Server")].exists)
            let add = app.buttons[language.text("Add Server…")]
            XCTAssertTrue(add.isHittable && add.isEnabled)
            record("\(language.rawValue) first run", app: app)
            add.click()
            let editor = app.sheets.firstMatch
            XCTAssertTrue(
                editor.staticTexts[language.text("Add Server")].waitForExistence(
                    timeout: 5))
            editor.buttons[language.text("Cancel")].click()
            XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
            XCTAssertTrue(title.exists)
        }
        XCTAssertEqual(app.alerts.count, 0)
    }

    @MainActor private func record(_ name: String, app: XCUIApplication) {
        let image = XCTAttachment(screenshot: app.screenshot())
        image.name = name
        image.lifetime = .keepAlways
        add(image)
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = name + " accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
    }
}
