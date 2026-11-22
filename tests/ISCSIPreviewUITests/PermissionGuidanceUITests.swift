import XCTest

final class PermissionGuidanceUITests: XCTestCase {
    @MainActor func testEnglishGuidanceNamesTheDevelopmentPermission() { check(japanese: false) }
    @MainActor func testJapaneseGuidanceNamesTheDevelopmentPermission() { check(japanese: true) }

    @MainActor private func check(japanese: Bool) {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US",
        ]
        defer { app.terminate() }
        launchPreview(app)
        let title =
            japanese
            ? "Kurazuna Developmentのディスク接続を許可"
            : "Allow Kurazuna Development to Connect Disks"
        let message =
            japanese
            ? "“システム設定”＞“一般”＞“ログイン項目と機能拡張”で“カテゴリ別”をクリックし、“ファイルシステム機能拡張”でKurazuna Developmentをオンにしてください。"
            : "In System Settings > General > Login Items & Extensions, click By Category, click File System Extensions, then turn on Kurazuna Development."
        XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 10))
        // A subscript query is limited to 128 characters; the guidance is longer.
        XCTAssertTrue(
            app.staticTexts.matching(
                NSPredicate(format: "value == %@ OR label == %@", message, message)
            ).firstMatch.exists)
        XCTAssertFalse(
            app.staticTexts[japanese ? "Kurazunaのディスク接続を許可" : "Allow Kurazuna to Connect Disks"]
                .exists)
        XCTAssertTrue(app.buttons[japanese ? "システム設定を開く" : "Open System Settings"].isEnabled)
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name =
            japanese ? "Japanese development permission" : "English development permission"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
