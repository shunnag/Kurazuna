import XCTest

/// Uses the production editor with memory-only settings and no target connection.
final class ServerEditorKeyboardUITests: XCTestCase {
    @MainActor func testEnglishEditorSupportsKeyboardSaveAndCancel() {
        check(japanese: false)
    }

    @MainActor func testJapaneseEditorSupportsKeyboardSaveAndCancel() {
        check(japanese: true)
    }

    @MainActor private func check(japanese: Bool) {
        continueAfterFailure = false
        executionTimeAllowance = 90
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", japanese ? "(ja)" : "(en)",
            "-AppleLocale", japanese ? "ja_JP" : "en_US",
            "--server-selection", "--empty-servers",
        ]
        launchPreview(app)

        let openEditor = app.buttons[japanese ? "サーバを追加…" : "Add Server…"]
        XCTAssertTrue(openEditor.waitForExistence(timeout: 10))
        openEditor.click()
        let editor = app.sheets.firstMatch
        XCTAssertTrue(editor.waitForExistence(timeout: 5))
        let name = editor.textFields[japanese ? "名前" : "Name"]
        let address = editor.textFields[japanese ? "サーバアドレス" : "Server Address"]
        let add = editor.buttons[japanese ? "追加" : "Add"]
        record("Editor before typing without a field click", app: app)

        // Typing into the application, rather than a queried field, observes the actual focus.
        app.typeText("Discarded Keyboard Storage")
        XCTAssertEqual(name.value as? String, "Discarded Keyboard Storage")
        XCTAssertFalse(add.isEnabled)
        app.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(editor.exists)
        XCTAssertFalse(add.isEnabled)
        app.typeKey(.tab, modifierFlags: [])
        app.typeText("192.0.2.60")
        XCTAssertEqual(address.value as? String, "192.0.2.60")
        XCTAssertTrue(add.isEnabled)
        record("Tab reached the address; valid draft can be cancelled", app: app)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        XCTAssertFalse(app.outlines.staticTexts["Discarded Keyboard Storage"].exists)

        XCTAssertTrue(openEditor.isEnabled)
        openEditor.click()
        XCTAssertTrue(editor.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, "")
        XCTAssertEqual(address.value as? String, "")
        app.typeText("Keyboard Storage")
        XCTAssertEqual(name.value as? String, "Keyboard Storage")
        app.typeKey(.tab, modifierFlags: [])
        app.typeText("192.0.2.61")
        XCTAssertEqual(address.value as? String, "192.0.2.61")
        app.typeKey(.tab, modifierFlags: .shift)
        app.typeKey("a", modifierFlags: .command)
        app.typeText("Saved Keyboard Storage")
        XCTAssertEqual(name.value as? String, "Saved Keyboard Storage")
        XCTAssertEqual(address.value as? String, "192.0.2.61")
        XCTAssertTrue(add.isEnabled)
        record("Shift-Tab returned to the name; Return will save", app: app)
        app.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        XCTAssertTrue(
            app.outlines.staticTexts["Saved Keyboard Storage"].firstMatch.waitForExistence(
                timeout: 5))
        XCTAssertFalse(app.outlines.staticTexts["Discarded Keyboard Storage"].exists)
        record("Keyboard save added only the intended server", app: app)
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
