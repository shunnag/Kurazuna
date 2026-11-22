import XCTest

/// Runs the production views in the existing memory-only preview host.
/// These tests never mount a disk, connect to a NAS, or use the real Keychain.
final class ServerEditorUITests: XCTestCase {
    @MainActor
    func testEnglishUnavailableWriteCompletionOffersReadOnlyRetry() {
        checkWriteCompletion(language: .english)
    }

    @MainActor
    func testJapaneseUnavailableWriteCompletionOffersReadOnlyRetry() {
        checkWriteCompletion(language: .japanese)
    }

    @MainActor
    func testEnglishReadOnlyRecoveryCancelThenReturn() {
        checkWriteCompletion(language: .english, cancelFirst: true)
    }

    @MainActor
    func testJapaneseReadOnlyRecoveryCancelThenReturn() {
        checkWriteCompletion(language: .japanese, cancelFirst: true)
    }

    @MainActor
    func testEnglishReadOnlyRecoveryEscapeThenReturn() {
        checkWriteCompletion(language: .english, cancelFirst: true, escape: true)
    }

    @MainActor
    func testJapaneseReadOnlyRecoveryEscapeThenReturn() {
        checkWriteCompletion(language: .japanese, cancelFirst: true, escape: true)
    }

    @MainActor
    private func checkWriteCompletion(
        language: EditorLanguage, cancelFirst: Bool = false, escape: Bool = false
    ) {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", "(\(language.rawValue))", "-AppleLocale", language.locale,
            "--write-completion-unavailable",
        ]
        launchPreview(app)
        let target = "iqn.2026-10.example:available"
        let label =
            language == .english
            ? "Connect Disk 0 from \(target)"
            : "\(target)のディスク0に接続"
        let connect = connectControl(app, target: target, unit: 0)
        XCTAssertTrue(connect.waitForExistence(timeout: 10) && connect.isEnabled)
        XCTAssertEqual(connect.label, label)
        clickConnect(connect)
        let title =
            language == .english
            ? "Read-Only Connection Required" : "読み出し専用で接続してください"
        let message =
            language == .english
            ? "This connection can’t confirm when writes are complete. You can connect read-only to view and copy files."
            : "この接続では書き込みの完了を確認できません。読み出し専用で接続すると、ファイルを表示したりコピーしたりできます。"
        let alert = app.windows["preview"].sheets.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(alert.staticTexts[title].exists)
        XCTAssertTrue(alert.staticTexts[message].exists)
        let before = XCTAttachment(screenshot: app.screenshot())
        before.name = "\(language.rawValue) write completion unavailable"
        before.lifetime = .keepAlways
        add(before)
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = "\(language.rawValue) write completion guidance accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
        let action = alert.buttons[language == .english ? "Connect Read-Only" : "読み出し専用で接続"]
        XCTAssertTrue(action.isEnabled && action.isHittable)
        // Read-only is a per-disk choice; there is no window-wide option to leave turned on.
        XCTAssertEqual(app.windows["preview"].checkBoxes.count, 0)
        if cancelFirst {
            if escape {
                app.typeKey(.escape, modifierFlags: [])
            } else {
                alert.buttons[language.text("Cancel")].click()
            }
            XCTAssertTrue(alert.waitForNonExistence(timeout: 5))
            XCTAssertFalse(app.staticTexts["Read-only Archive"].exists)
            XCTAssertEqual(app.windows["preview"].checkBoxes.count, 0)
            XCTAssertTrue(connect.isEnabled && connect.isHittable)
            clickConnect(connect)
            XCTAssertTrue(alert.waitForExistence(timeout: 10))
            XCTAssertTrue(alert.staticTexts[message].exists && action.isEnabled)
            app.typeKey(.return, modifierFlags: [])
        } else {
            action.click()
        }
        XCTAssertTrue(alert.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Read-only Archive"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts[language == .english ? "Read-only" : "読み出し専用"].exists)
        XCTAssertEqual(app.windows["preview"].checkBoxes.count, 0)
        XCTAssertFalse(connect.isEnabled)
        XCTAssertFalse(app.staticTexts[message].exists)
        let after = XCTAttachment(screenshot: app.screenshot())
        after.name = "\(language.rawValue) explicit read-only retry connected"
        after.lifetime = .keepAlways
        add(after)
    }

    @MainActor
    func testEnglishWriteProtectedDiskUsesReadOnlyConnection() throws {
        checkWriteProtection(language: .english)
    }

    @MainActor
    func testJapaneseWriteProtectedDiskUsesReadOnlyConnection() throws {
        checkWriteProtection(language: .japanese)
    }

    @MainActor
    private func checkWriteProtection(language: EditorLanguage) {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", "(\(language.rawValue))", "-AppleLocale", language.locale,
            "--write-protected",
        ]
        launchPreview(app)
        let target = "iqn.2026-10.example:available"
        let label =
            language == .english
            ? "Connect Disk 0 from \(target) read-only"
            : "\(target)のディスク0に読み出し専用で接続"
        let connect = connectControl(app, target: target, unit: 0)
        XCTAssertTrue(connect.waitForExistence(timeout: 10))
        XCTAssertEqual(connect.label, label)
        XCTAssertTrue(connect.isEnabled && connect.isHittable)
        XCTAssertTrue(app.staticTexts[language.text("Read-only disk")].exists)
        // The second disk is writable. Connecting the protected disk must not change its choice.
        let writable = connectControl(app, target: target, unit: 1)
        func requireWritableChoice(_ phase: String) {
            XCTAssertTrue(writable.exists)
            let observation = XCTAttachment(
                string: "label=\(writable.label), type=\(writable.elementType.rawValue)")
            observation.name = "\(language.rawValue) writable disk control \(phase)"
            observation.lifetime = .keepAlways
            add(observation)
            XCTAssertEqual(
                writable.label,
                language == .english
                    ? "Connect Disk 1 from \(target)" : "\(target)のディスク1に接続")
            XCTAssertEqual(app.windows["preview"].checkBoxes.count, 0)
        }
        requireWritableChoice("before connecting")
        let before = XCTAttachment(screenshot: app.screenshot())
        before.name = "\(language.rawValue) write-protected disk action"
        before.lifetime = .keepAlways
        add(before)
        connect.click()
        // The memory backend accepts only a read-only descriptor; it never mounts or uses a NAS.
        XCTAssertTrue(app.staticTexts["Read-only Archive"].waitForExistence(timeout: 10))
        requireWritableChoice("after connecting")
        XCTAssertTrue(writable.isEnabled)
        XCTAssertFalse(connect.isEnabled)
        XCTAssertEqual(app.alerts.count, 0)
        let after = XCTAttachment(screenshot: app.screenshot())
        after.name = "\(language.rawValue) read-only disk connected"
        after.lifetime = .keepAlways
        add(after)
    }

    @MainActor
    func testEnglishServerRemovalNeedsExplicitConfirmation() throws {
        checkServerRemoval(language: .english)
    }

    @MainActor
    func testJapaneseServerRemovalNeedsExplicitConfirmation() throws {
        checkServerRemoval(language: .japanese)
    }

    @MainActor
    private func checkServerRemoval(language: EditorLanguage) {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language, savesCredentials: true)
        let editor = app.sheets.firstMatch
        fillBasics(editor, language: language)
        editor.buttons[language.text("Add")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        let row = app.outlines.staticTexts["UI Storage"].firstMatch
        let confirmation = app.sheets.firstMatch
        // The title keeps the server's name on one line with a no-break space.
        let title = confirmation.staticTexts[language.text("Remove “UI\u{00A0}Storage”?")]
        func requestRemoval() {
            XCTAssertTrue(row.exists)
            row.rightClick()
            app.menuItems[language.text("Remove Server…")].click()
            XCTAssertTrue(title.waitForExistence(timeout: 5))
            XCTAssertTrue(row.exists)
        }
        requestRemoval()
        let screenshot = XCTAttachment(screenshot: confirmation.screenshot())
        screenshot.name = "\(language.rawValue) server removal confirmation"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        confirmation.buttons[language.text("Cancel")].click()
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
        XCTAssertTrue(row.exists)
        requestRemoval()
        app.typeKey(.return, modifierFlags: [])
        // Cancel is the default button: Return must never approve removal.
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
        XCTAssertTrue(row.exists)
        requestRemoval()
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
        XCTAssertTrue(row.exists)
        requestRemoval()
        confirmation.buttons[language.text("Remove")].click()
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
        XCTAssertTrue(row.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.outlines.staticTexts["Test Storage"].firstMatch.exists)
    }

    @MainActor
    func testEnglishCompactEditorKeepsActionsVisible() throws {
        checkCompactEditor(language: .english)
    }

    @MainActor
    func testJapaneseCompactEditorKeepsActionsVisible() throws {
        checkCompactEditor(language: .japanese)
    }

    @MainActor
    private func checkCompactEditor(language: EditorLanguage) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language, compact: true)
        let editor = app.sheets.firstMatch
        fillBasics(editor, language: language)
        chooseMutualAuthentication(app, editor: editor, language: language)
        let scroll = editor.scrollViews["server-editor-fields"]
        XCTAssertTrue(scroll.exists)
        XCTAssertLessThanOrEqual(editor.frame.height, 441)
        for key in ["Cancel", "Add"] {
            let button = editor.buttons[language.text(key)]
            XCTAssertTrue(button.isHittable)
            XCTAssertTrue(editor.frame.contains(button.frame))
            XCTAssertLessThan(scroll.frame.maxY, button.frame.minY)
        }
        scroll.scroll(byDeltaX: 0, deltaY: -300)
        XCTAssertTrue(
            editor.secureTextFields[language.text("Server Password for Finding Disks")].isHittable)
        record("\(language.rawValue) compact mutual editor with visible actions", app: app)
        editor.buttons[language.text("Cancel")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
    }

    @MainActor
    func testEnglishServerEditorCancelsUnsavedChanges() throws {
        checkCancellation(language: .english)
    }

    @MainActor
    func testJapaneseServerEditorCancelsUnsavedChanges() throws {
        checkCancellation(language: .japanese)
    }

    @MainActor
    func testEnglishAuthenticationFieldsHaveDistinctNames() throws {
        checkAuthenticationNames(language: .english)
    }

    @MainActor
    func testJapaneseAuthenticationFieldsHaveDistinctNames() throws {
        checkAuthenticationNames(language: .japanese)
    }

    @MainActor
    func testEnglishServerEditorSavesAndEditsAuthentication() throws {
        checkSaving(language: .english)
    }

    @MainActor
    func testJapaneseServerEditorSavesAndEditsAuthentication() throws {
        checkSaving(language: .japanese)
    }

    @MainActor
    func testEnglishServerEditorKeepsChangesAfterPasswordSaveFailure() throws {
        checkSaveFailure(language: .english)
    }

    @MainActor
    func testJapaneseServerEditorKeepsChangesAfterPasswordSaveFailure() throws {
        checkSaveFailure(language: .japanese)
    }

    @MainActor
    private func checkSaving(language: EditorLanguage) {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language, savesCredentials: true)
        let editor = app.sheets.firstMatch
        fillBasics(editor, language: language)
        chooseMutualAuthentication(app, editor: editor, language: language)
        fillAuthentication(editor, language: language)
        XCTAssertTrue(editor.buttons[language.text("Add")].isEnabled)
        record("\(language.rawValue) server ready to add", app: app)
        editor.buttons[language.text("Add")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        editSavedServer(app, name: "UI Storage", language: language)
        XCTAssertEqual(editor.textFields[language.text("Name")].value as? String, "UI Storage")
        XCTAssertEqual(
            editor.textFields[language.text("Server Address")].value as? String, "192.0.2.50:3260")
        for (key, expected) in [
            ("Connection User Name", "ui-connection"),
            ("Connection Server User Name", "ui-server"),
            ("User Name for Finding Disks", "ui-search"),
            ("Server User Name for Finding Disks", "ui-search-server"),
        ] {
            XCTAssertEqual(editor.textFields[language.text(key)].value as? String, expected)
        }
        for key in [
            "Connection Password", "Connection Server Password",
            "Password for Finding Disks", "Server Password for Finding Disks",
        ] {
            let value = editor.secureTextFields[language.text(key)].value as? String
            XCTAssertTrue(["", language.text("Saved password")].contains(value ?? "<missing>"))
        }
        XCTAssertTrue(editor.buttons[language.text("Save")].isEnabled)
        // With saved mutual CHAP passwords for both, every field and the closing notes fit
        // in the sheet at the default window size, without scrolling.
        let scroll = editor.scrollViews["server-editor-fields"]
        // A query by identifier is limited to 128 characters, so match the label instead.
        let noteText = language.text(
            "Your passwords are stored in your keychain. To keep a saved password, leave its field blank. To change a mutual CHAP password, enter both."
        )
        let note = editor.staticTexts.matching(
            NSPredicate(format: "label == %@ OR value == %@", noteText, noteText)
        ).firstMatch
        XCTAssertTrue(note.exists)
        let frames = XCTAttachment(
            string: "window=\(app.windows.firstMatch.frame) sheet=\(editor.frame) "
                + "fields=\(scroll.frame) note=\(note.frame)")
        frames.name = "\(language.rawValue) saved mutual CHAP editor frames"
        frames.lifetime = .keepAlways
        add(frames)
        XCTAssertTrue(scroll.frame.contains(note.frame))
        record("\(language.rawValue) saved authentication without exposed passwords", app: app)

        replace(editor.textFields[language.text("Name")], with: "Renamed Storage")
        // Keeping the same endpoint permits blank password fields when renaming.
        editor.buttons[language.text("Save")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        editSavedServer(app, name: "Renamed Storage", language: language)
        replace(editor.textFields[language.text("Server Address")], with: "192.0.2.51")
        // A different endpoint must not reuse either connection or search credentials.
        XCTAssertFalse(editor.buttons[language.text("Save")].isEnabled)
        fillAuthentication(editor, language: language, includeUserNames: false)
        XCTAssertTrue(editor.buttons[language.text("Save")].isEnabled)
        editor.buttons[language.text("Save")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        editSavedServer(app, name: "Renamed Storage", language: language)
        XCTAssertEqual(
            editor.textFields[language.text("Server Address")].value as? String, "192.0.2.51:3260")
        record("\(language.rawValue) saved new endpoint", app: app)
        editor.buttons[language.text("Cancel")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
    }

    @MainActor
    private func checkSaveFailure(language: EditorLanguage) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language)
        let editor = app.sheets.firstMatch
        fillBasics(editor, language: language)
        chooseMutualAuthentication(app, editor: editor, language: language)
        fillAuthentication(editor, language: language)
        editor.buttons[language.text("Add")].click()
        XCTAssertTrue(
            editor.staticTexts[
                language.text("Unlock your Mac, then try saving the password again.")
            ]
            .waitForExistence(timeout: 5))
        XCTAssertEqual(editor.textFields[language.text("Name")].value as? String, "UI Storage")
        XCTAssertTrue(editor.buttons[language.text("Add")].isEnabled)
        XCTAssertTrue(editor.buttons[language.text("Cancel")].isEnabled)
        record("\(language.rawValue) password save failure preserves editor", app: app)
        editor.buttons[language.text("Cancel")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        XCTAssertFalse(app.outlines.staticTexts["UI Storage"].exists)
    }

    @MainActor
    private func fillBasics(_ editor: XCUIElement, language: EditorLanguage) {
        editor.textFields[language.text("Name")].click()
        editor.textFields[language.text("Name")].typeText("UI Storage")
        editor.textFields[language.text("Server Address")].click()
        editor.textFields[language.text("Server Address")].typeText("192.0.2.50")
    }

    @MainActor
    private func chooseMutualAuthentication(
        _ app: XCUIApplication, editor: XCUIElement, language: EditorLanguage
    ) {
        editor.popUpButtons[language.text("Connection Authentication")].click()
        app.menuItems[language.text("Mutual CHAP")].firstMatch.click()
        // Finding Disks is a form section below the connection fields.
        let discovery = editor.popUpButtons[language.text("Authentication for Finding Disks")]
        let scroll = editor.scrollViews["server-editor-fields"]
        if scroll.exists {
            for _ in 0..<5 where !discovery.isHittable {
                scroll.scroll(byDeltaX: 0, deltaY: -180)
            }
        }
        discovery.click()
        app.menuItems[language.text("Mutual CHAP")].firstMatch.click()
    }

    @MainActor
    private func fillAuthentication(
        _ editor: XCUIElement, language: EditorLanguage, includeUserNames: Bool = true
    ) {
        if includeUserNames {
            for (key, value) in [
                ("Connection User Name", "ui-connection"),
                ("Connection Server User Name", "ui-server"),
                ("User Name for Finding Disks", "ui-search"),
                ("Server User Name for Finding Disks", "ui-search-server"),
            ] {
                let field = editor.textFields[language.text(key)]
                reveal(field, in: editor)
                field.click()
                field.typeText(value)
            }
        }
        for (key, value) in [
            ("Connection Password", "UI-connection-123"),
            ("Connection Server Password", "UI-server-456"),
            ("Password for Finding Disks", "UI-search-789"),
            ("Server Password for Finding Disks", "UI-search-server-012"),
        ] {
            let field = editor.secureTextFields[language.text(key)]
            reveal(field, in: editor)
            field.click()
            field.typeText(value)
        }
    }

    /// With both kinds of mutual CHAP, the fields are taller than the default window, so the
    /// editor scrolls. Scroll a field into view before clicking it, as a person would.
    /// A field clipped by the scroll view can still report itself as hittable, so compare
    /// frames instead.
    @MainActor
    private func reveal(_ field: XCUIElement, in editor: XCUIElement) {
        let scroll = editor.scrollViews["server-editor-fields"]
        if scroll.exists {
            for _ in 0..<8 where !scroll.frame.contains(field.frame) {
                let below = field.frame.midY > scroll.frame.midY
                scroll.scroll(byDeltaX: 0, deltaY: below ? -120 : 120)
            }
            XCTAssertTrue(scroll.frame.contains(field.frame))
        }
        XCTAssertTrue(field.isHittable)
    }

    @MainActor
    private func editSavedServer(_ app: XCUIApplication, name: String, language: EditorLanguage) {
        let row = app.outlines.staticTexts[name].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.rightClick()
        app.menuItems[language.text("Edit Server…")].click()
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 5))
    }

    @MainActor
    private func replace(_ field: XCUIElement, with text: String) {
        field.click()
        field.typeKey("a", modifierFlags: .command)
        field.typeText(text)
    }

    @MainActor
    private func checkCancellation(language: EditorLanguage) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language)

        let editor = app.sheets.firstMatch
        let title = editor.staticTexts[language.text("Add Server")]
        let name = editor.textFields[language.text("Name")]
        let address = editor.textFields[language.text("Server Address")]
        XCTAssertTrue(name.exists)
        XCTAssertTrue(address.exists)
        XCTAssertFalse(editor.buttons[language.text("Add")].isEnabled)
        name.click()
        name.typeText("Unsaved remote UI test")
        XCTAssertEqual(name.value as? String, "Unsaved remote UI test")
        XCTAssertFalse(editor.buttons[language.text("Add")].isEnabled)
        app.typeKey(.tab, modifierFlags: [])
        app.typeText("192.0.2.50")
        XCTAssertEqual(address.value as? String, "192.0.2.50")
        XCTAssertEqual(name.value as? String, "Unsaved remote UI test")
        XCTAssertTrue(editor.buttons[language.text("Add")].isEnabled)
        record("\(language.rawValue) editor with unsaved changes", app: app)

        editor.buttons[language.text("Cancel")].click()
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
        app.buttons[language.text("Add Server")].click()
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, "")
        // An empty text field can expose its placeholder as its value on macOS.
        XCTAssertTrue(["", "nas.local:3260"].contains(address.value as? String ?? "<missing>"))
        XCTAssertFalse(editor.buttons[language.text("Add")].isEnabled)
        record("\(language.rawValue) editor after cancel", app: app)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(title.waitForNonExistence(timeout: 5))
    }

    @MainActor
    private func checkAuthenticationNames(language: EditorLanguage) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        openEditor(app, language: language)
        let editor = app.sheets.firstMatch
        let connection = editor.popUpButtons[language.text("Connection Authentication")]
        XCTAssertTrue(connection.exists)
        connection.click()
        app.menuItems[language.text("Mutual CHAP")].firstMatch.click()

        // Finding Disks is a form section with its own header; no disclosure hides it.
        XCTAssertEqual(editor.disclosureTriangles.count, 0)
        XCTAssertTrue(editor.staticTexts[language.text("Finding Disks")].exists)
        let discovery = editor.popUpButtons[language.text("Authentication for Finding Disks")]
        XCTAssertTrue(discovery.waitForExistence(timeout: 5))
        discovery.click()
        app.menuItems[language.text("Mutual CHAP")].firstMatch.click()

        for key in [
            "Name", "Server Address", "Connection User Name", "Connection Server User Name",
            "User Name for Finding Disks", "Server User Name for Finding Disks",
        ] {
            XCTAssertEqual(
                editor.textFields.matching(.textField, identifier: language.text(key)).count, 1, key
            )
        }
        for key in [
            "Connection Password", "Connection Server Password",
            "Password for Finding Disks", "Server Password for Finding Disks",
        ] {
            XCTAssertEqual(
                editor.secureTextFields.matching(.secureTextField, identifier: language.text(key))
                    .count, 1, key)
        }
        XCTAssertEqual(editor.popUpButtons.count, 2)
        XCTAssertFalse(editor.buttons[language.text("Add")].isEnabled)
        record("\(language.rawValue) mutual authentication names", app: app)
        editor.buttons[language.text("Cancel")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
    }

    @MainActor
    private func openEditor(
        _ app: XCUIApplication, language: EditorLanguage, savesCredentials: Bool = false,
        compact: Bool = false
    ) {
        app.launchArguments = [
            "-AppleLanguages", "(\(language.rawValue))", "-AppleLocale", language.locale,
        ]
        if savesCredentials { app.launchArguments.append("--save-credentials") }
        if compact { app.launchArguments.append("--compact-editor") }
        launchPreview(app)
        let addServer = app.buttons[language.text("Add Server")]
        XCTAssertTrue(addServer.waitForExistence(timeout: 10))
        XCTAssertTrue(addServer.isEnabled)
        addServer.click()
        XCTAssertTrue(
            app.sheets.firstMatch.staticTexts[language.text("Add Server")].waitForExistence(
                timeout: 5))
    }

    /// Connect is a menu with a primary action, and a write-protected disk has a button.
    /// Their element types differ, so find either one by its stable identifier.
    @MainActor
    private func connectControl(_ app: XCUIApplication, target: String, unit: Int) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: "connect-\(target)-\(unit)")
            .firstMatch
    }

    /// A writable disk's Connect is a pull-down button whose primary segment connects.
    /// On macOS 27, XCUITest's click on the pull-down element does not run the primary action,
    /// although a real click of 20 ms or longer at the same point does (a 5 ms click does not).
    /// Clicking the Connect segment element itself runs it, so click that segment.
    @MainActor
    private func clickConnect(_ control: XCUIElement) {
        if control.elementType == .popUpButton {
            let primary = control.buttons.firstMatch
            XCTAssertTrue(primary.exists && primary.isHittable)
            primary.click()
        } else {
            control.click()
        }
    }

    @MainActor
    private func record(_ name: String, app: XCUIApplication) {
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
        let sheet = XCTAttachment(screenshot: app.sheets.firstMatch.screenshot())
        sheet.name = name + " sheet"
        sheet.lifetime = .keepAlways
        add(sheet)
        let tree = XCTAttachment(string: app.debugDescription)
        tree.name = name + " accessibility hierarchy"
        tree.lifetime = .keepAlways
        add(tree)
    }
}

private enum EditorLanguage: String {
    case english = "en"
    case japanese = "ja"

    var locale: String { self == .english ? "en_US" : "ja_JP" }

    func text(_ key: String) -> String {
        guard self == .japanese else { return key }
        return [
            "Read-only disk": "読み出し専用のディスク",
            "Add Server": "サーバを追加",
            "Name": "名前", "Server Address": "サーバアドレス", "Cancel": "キャンセル", "Add": "追加",
            "Connection Authentication": "接続時の認証",
            "Authentication for Finding Disks": "ディスクの検索時の認証",
            "Finding Disks": "ディスクの検索", "Mutual CHAP": "相互CHAP",
            "Connection User Name": "接続時のユーザ名", "Connection Password": "接続時のパスワード",
            "Connection Server User Name": "接続時のサーバのユーザ名",
            "Connection Server Password": "接続時のサーバのパスワード",
            "User Name for Finding Disks": "ディスクの検索時のユーザ名",
            "Password for Finding Disks": "ディスクの検索時のパスワード",
            "Server User Name for Finding Disks": "ディスクの検索時のサーバのユーザ名",
            "Server Password for Finding Disks": "ディスクの検索時のサーバのパスワード",
            "Save": "保存", "Edit Server…": "サーバを編集…", "Saved password": "保存済みのパスワード",
            "Remove Server…": "サーバを削除…", "Remove": "削除",
            "Remove “UI\u{00A0}Storage”?": "“UI\u{00A0}Storage”を削除しますか?",
            "Unlock your Mac, then try saving the password again.":
                "Macのロックを解除してから、もう一度パスワードを保存してください。",
            "Your passwords are stored in your keychain. To keep a saved password, leave its field blank. To change a mutual CHAP password, enter both.":
                "パスワードはキーチェーンに保存されています。保存済みのパスワードを引き続き使用する場合は、そのフィールドを空欄のままにしてください。相互CHAPのパスワードを変更する場合は、両方を入力してください。",
        ][key]!
    }
}
