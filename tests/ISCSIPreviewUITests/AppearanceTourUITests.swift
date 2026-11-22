import XCTest

/// Visits each screen of the production views with the memory-only fixtures and keeps a
/// window-only screenshot of it, in English and Japanese and in Dark Mode, for design review.
/// Each visit also checks the screen's essential content. No disk, NAS or Keychain is used.
final class AppearanceTourUITests: XCTestCase {
    @MainActor func testEnglishDiskScreens() { diskScreens(.english) }
    @MainActor func testJapaneseDiskScreens() { diskScreens(.japanese) }
    @MainActor func testEnglishStateScreens() { stateScreens(.english) }
    @MainActor func testJapaneseStateScreens() { stateScreens(.japanese) }
    @MainActor func testEnglishEditorScreens() { editorScreens(.english) }
    @MainActor func testJapaneseEditorScreens() { editorScreens(.japanese) }
    @MainActor func testEnglishAlertScreens() { alertScreens(.english) }
    @MainActor func testJapaneseAlertScreens() { alertScreens(.japanese) }
    @MainActor func testEnglishReconnectingScreens() { reconnectingScreens(.english) }
    @MainActor func testJapaneseReconnectingScreens() { reconnectingScreens(.japanese) }
    @MainActor func testEnglishDarkReconnectingScreens() {
        reconnectingScreens(.english, dark: true)
    }
    @MainActor func testJapaneseDarkReconnectingScreens() {
        reconnectingScreens(.japanese, dark: true)
    }
    @MainActor func testDarkScreens() {
        let app = launch(.english, ["--reconnecting", "--dark-appearance"])
        XCTAssertTrue(app.buttons["Eject Work"].waitForExistence(timeout: 10))
        capture("dark-main-overview", app)
        openEditor(app, .english)
        chooseMutual(app, .english)
        capture("dark-editor-add-mutual-chap", app)
        app.terminate()
        let issues = launch(.japanese, ["--dark-appearance"])
        XCTAssertTrue(issues.buttons["システム設定を開く"].waitForExistence(timeout: 10))
        capture("dark-ja-main-issues", issues)
        issues.terminate()
    }

    private enum Language: String {
        case english = "en"
        case japanese = "ja"
        var locale: String { self == .english ? "en_US" : "ja_JP" }
        func text(_ english: String, _ japanese: String) -> String {
            self == .english ? english : japanese
        }
    }

    @MainActor private func launch(_ language: Language, _ arguments: [String]) -> XCUIApplication {
        continueAfterFailure = false
        executionTimeAllowance = 120
        let app = XCUIApplication()
        // Open the window at its default size, as on first launch, rather than restoring it.
        app.launchArguments =
            [
                "-AppleLanguages", "(\(language.rawValue))", "-AppleLocale", language.locale,
                "-ApplePersistenceIgnoreState", "YES",
            ] + arguments
        launchPreview(app)
        let window = app.windows["preview"]
        XCTAssertTrue(window.waitForExistence(timeout: 10))
        let small = arguments.contains("--small-window")
        XCTAssertEqual(window.frame.width, small ? 780 : 960, accuracy: 1)
        XCTAssertEqual(window.frame.height, small ? 600 : 800, accuracy: 1)
        return app
    }

    /// Connected disks, found disks and their details.
    @MainActor private func diskScreens(_ language: Language) {
        let name = language.rawValue
        let overview = launch(language, ["--reconnecting"])
        let work = overview.buttons[language.text("Eject Work", "Workを取り出す")]
        XCTAssertTrue(work.waitForExistence(timeout: 10))
        XCTAssertTrue(
            overview.buttons[language.text("Find Disks", "ディスクを検索")].isHittable)
        XCTAssertTrue(
            overview.buttons[language.text("Check Connections", "接続を確認")].isHittable)
        capture("\(name)-main-overview", overview)
        let target = "iqn.2026-10.example:available"
        overview.buttons[
            language.text(
                "Show Info for Disk 0 from \(target)", "\(target)のディスク0の情報を表示")
        ].click()
        XCTAssertTrue(overview.popovers.firstMatch.waitForExistence(timeout: 5))
        capture("\(name)-disk-info-popover", overview)
        overview.typeKey(.escape, modifierFlags: [])
        overview.terminate()

        // At the narrowest window, every row keeps its actions and text visible.
        let small = launch(language, ["--reconnecting", "--small-window"])
        let smallEject = small.buttons[language.text("Eject Work", "Workを取り出す")]
        XCTAssertTrue(smallEject.waitForExistence(timeout: 10) && smallEject.isHittable)
        capture("\(name)-main-small-window", small)
        small.terminate()

        let issues = launch(language, [])
        XCTAssertTrue(
            issues.buttons[language.text("Open System Settings", "システム設定を開く")]
                .waitForExistence(timeout: 10))
        capture("\(name)-main-issues", issues)
        // Scroll to the disks found on the server, below the connected ones.
        let connectedHeader = issues.staticTexts[language.text("Connected Disks", "接続中のディスク")]
        XCTAssertTrue(connectedHeader.exists)
        connectedHeader.scroll(byDeltaX: 0, deltaY: -600)
        capture("\(name)-main-found-disk-errors", issues)
        issues.terminate()

        let protected = launch(language, ["--write-protected"])
        XCTAssertTrue(
            protected.staticTexts[language.text("Read-only disk", "読み出し専用のディスク")]
                .waitForExistence(timeout: 10))
        capture("\(name)-main-write-protected", protected)
        protected.terminate()

        let unverified = launch(language, ["--unverified-connection"])
        XCTAssertTrue(
            unverified.descendants(matching: .any).matching(
                identifier: "connection-recovery-notice"
            ).firstMatch.waitForExistence(timeout: 10))
        capture("\(name)-unverified-disk", unverified)
        unverified.terminate()

        // Each connected disk is also a found disk: its found row shows the same state.
        let shared = launch(language, ["--reconnecting", "--shared-target"])
        XCTAssertTrue(
            shared.buttons[language.text("Eject Work", "Workを取り出す")]
                .waitForExistence(timeout: 10))
        let reconnecting = language.text("Reconnecting…", "再接続中…")
        XCTAssertEqual(
            shared.staticTexts.matching(
                NSPredicate(format: "value == %@ OR label == %@", reconnecting, reconnecting)
            ).count, 2)
        capture("\(name)-found-disks-mirror-connections", shared)
        shared.terminate()

        // A new disk without a volume is named by its LUN and says how to prepare it.
        let blank = launch(language, ["--unformatted-disk"])
        XCTAssertTrue(
            blank.buttons[language.text("Eject Disk 0", "ディスク0を取り出す")]
                .waitForExistence(timeout: 10))
        XCTAssertTrue(
            blank.buttons[
                language.text("Check Disk 0 in Disk Utility", "ディスクユーティリティでディスク0を確認")
            ].isHittable)
        capture("\(name)-unformatted-disk", blank)
        blank.terminate()

        // Two disks without volumes are both LUN 0, of different targets: each name adds its
        // target, as Finder tells apart items of the same name.
        let same = launch(language, ["--same-lun-disks"])
        let disk = language.text("Disk 0", "ディスク0")
        XCTAssertTrue(
            same.buttons[language.text("Eject \(disk) — preview-0", "\(disk) — preview-0を取り出す")]
                .waitForExistence(timeout: 10))
        XCTAssertTrue(
            same.buttons[language.text("Eject \(disk) — preview-1", "\(disk) — preview-1を取り出す")]
                .exists)
        capture("\(name)-disks-of-the-same-name", same)
        same.terminate()
    }

    /// The empty, unselected and unavailable states.
    @MainActor private func stateScreens(_ language: Language) {
        let name = language.rawValue
        let empty = launch(language, ["--server-selection", "--empty-servers"])
        XCTAssertTrue(
            empty.buttons[language.text("Add Server…", "サーバを追加…")]
                .waitForExistence(timeout: 10))
        capture("\(name)-empty-state", empty)
        empty.terminate()

        let unselected = launch(language, ["--server-selection", "--no-server-selection"])
        XCTAssertTrue(
            unselected.staticTexts[language.text("Select a Server", "サーバを選択")]
                .waitForExistence(timeout: 10))
        capture("\(name)-no-server-selected", unselected)
        unselected.terminate()

        let saved = launch(language, ["--server-selection"])
        XCTAssertTrue(
            saved.findDisksToolbarButton(japanese: language == .japanese)
                .waitForExistence(timeout: 10))
        // Before a search, the text names a labeled Find Disks button beside it.
        XCTAssertTrue(saved.findDisksPlaceholderButton.isHittable)
        capture("\(name)-server-before-search", saved)
        saved.typeKey(",", modifierFlags: .command)
        let settings = saved.windows.matching(NSPredicate(format: "identifier != %@", "preview"))
            .firstMatch
        XCTAssertTrue(settings.waitForExistence(timeout: 5))
        XCTAssertTrue(
            settings.staticTexts[language.text("Initiator Name", "イニシエータ名")].exists)
        let image = XCTAttachment(screenshot: settings.screenshot())
        image.name = "\(name)-settings"
        image.lifetime = .keepAlways
        add(image)
        saved.terminate()

        // The memory search waits before it fails, which shows the activity bar.
        let busy = launch(language, ["--quit-during-search"])
        let find = busy.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(find.waitForExistence(timeout: 10))
        find.click()
        XCTAssertTrue(
            busy.buttons[language.text("Cancel", "キャンセル")].waitForExistence(timeout: 5))
        capture("\(name)-finding-disks", busy)
        busy.terminate()

        let cleanup = launch(language, ["--metadata-cleanup-failure"])
        let eject = cleanup.buttons[language.text("Eject Archive", "Archiveを取り出す")]
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        eject.click()
        let sheet = cleanup.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        capture("\(name)-cleanup-failure-alert", cleanup)
        sheet.buttons["OK"].click()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        capture("\(name)-cleanup-pending", cleanup)
        cleanup.terminate()
    }

    /// The server editor with each kind of authentication.
    @MainActor private func editorScreens(_ language: Language) {
        let name = language.rawValue
        let app = launch(language, [])
        openEditor(app, language)
        capture("\(name)-editor-add-no-auth", app)
        let editor = app.sheets.firstMatch
        editor.popUpButtons[language.text("Connection Authentication", "接続時の認証")].click()
        app.menuItems["CHAP"].firstMatch.click()
        capture("\(name)-editor-add-chap", app)
        chooseMutual(app, language)
        // With mutual CHAP for both, the whole form, down to its last note, fits in the sheet
        // at the default window size, and the sheet fits in the window.
        let scroll = editor.scrollViews["server-editor-fields"]
        let last = editor.staticTexts[
            language.text(
                "Your passwords are stored in your keychain.", "パスワードはキーチェーンに保存されます。")]
        XCTAssertTrue(last.exists)
        let window = app.windows["preview"]
        let frame = XCTAttachment(
            string: "window=\(window.frame) sheet=\(editor.frame) "
                + "fields=\(scroll.frame) last=\(last.frame)")
        frame.name = "\(name) editor frames"
        frame.lifetime = .keepAlways
        add(frame)
        XCTAssertTrue(scroll.frame.contains(last.frame))
        XCTAssertTrue(window.frame.contains(editor.frame))
        capture("\(name)-editor-add-mutual-chap", app)
        editor.buttons[language.text("Cancel", "キャンセル")].click()
        XCTAssertTrue(editor.waitForNonExistence(timeout: 5))
        app.terminate()
    }

    /// Errors and confirmations.
    @MainActor private func alertScreens(_ language: Language) {
        let name = language.rawValue
        let force = launch(language, ["--force-ejection"])
        let eject = force.buttons[language.text("Eject Archive", "Archiveを取り出す")]
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        eject.click()
        let window = force.windows["preview"]
        let sheet = window.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        capture("\(name)-eject-failed-alert", force)
        sheet.buttons[language.text("Force Eject…", "強制的に取り出す…")].click()
        let confirm = window.buttons[language.text("Force Eject", "強制的に取り出す")]
        XCTAssertTrue(confirm.waitForExistence(timeout: 10))
        capture("\(name)-force-eject-confirmation", force)
        force.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(confirm.waitForNonExistence(timeout: 5))
        force.terminate()

        let readOnly = launch(language, ["--write-completion-unavailable"])
        let target = "iqn.2026-10.example:available"
        let connect = readOnly.descendants(matching: .any)
            .matching(identifier: "connect-\(target)-0").firstMatch
        XCTAssertTrue(connect.waitForExistence(timeout: 10))
        connect.buttons.firstMatch.click()
        XCTAssertTrue(readOnly.windows["preview"].sheets.firstMatch.waitForExistence(timeout: 10))
        capture("\(name)-read-only-required-alert", readOnly)
        readOnly.typeKey(.escape, modifierFlags: [])
        readOnly.terminate()

        // Finding disks without a password on a server that requires one.
        let search = launch(language, ["--search-authentication-failure"])
        let find = search.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(find.waitForExistence(timeout: 10))
        find.click()
        XCTAssertTrue(search.windows["preview"].sheets.firstMatch.waitForExistence(timeout: 10))
        capture("\(name)-search-authentication-alert", search)
        search.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(
            search.windows["preview"].sheets.firstMatch.waitForNonExistence(timeout: 5))
        // After a failed search, the placeholder offers Find Disks again.
        XCTAssertTrue(search.findDisksPlaceholderButton.isHittable)
        capture("\(name)-search-failed-placeholder", search)
        search.terminate()

        // The same refusal on a server with a connected disk, which can't be edited: the
        // alert says to eject its disks first and offers only OK.
        let withDisk = launch(language, ["--search-failure-with-connected-disk"])
        let findWithDisk = withDisk.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(findWithDisk.waitForExistence(timeout: 10))
        findWithDisk.click()
        let refused = withDisk.windows["preview"].sheets.firstMatch
        XCTAssertTrue(refused.waitForExistence(timeout: 10))
        XCTAssertTrue(refused.buttons["OK"].exists)
        XCTAssertFalse(refused.buttons[language.text("Edit Server…", "サーバを編集…")].exists)
        capture("\(name)-search-authentication-with-connected-disk-alert", withDisk)
        withDisk.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(refused.waitForNonExistence(timeout: 5))
        withDisk.terminate()

        // Finding Disks is Same as Connection, and the server refuses the connection password:
        // the alert points to Connection and opens the editor.
        let wrong = launch(language, ["--search-uses-connection-password"])
        let findAgain = wrong.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(findAgain.waitForExistence(timeout: 10))
        findAgain.click()
        let alert = wrong.windows["preview"].sheets.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(
            text(
                language.text(
                    "Couldn’t Find Disks on “Test\u{00A0}Storage”",
                    "“Test\u{00A0}Storage”でディスクを検索できませんでした"),
                in: alert
            ).exists)
        let edit = alert.buttons[language.text("Edit Server…", "サーバを編集…")]
        XCTAssertTrue(edit.exists)
        capture("\(name)-search-wrong-connection-password-alert", wrong)
        edit.click()
        // Find the editor's heading by its label within the sheet, as the editor tests do.
        let editor = wrong.sheets.firstMatch
        let heading = editor.staticTexts[language.text("Edit Server", "サーバを編集")]
        XCTAssertTrue(heading.waitForExistence(timeout: 10))
        capture("\(name)-search-wrong-connection-password-editor", wrong)
        editor.buttons[language.text("Cancel", "キャンセル")].click()
        XCTAssertTrue(heading.waitForNonExistence(timeout: 5))
        wrong.terminate()

        closedLoginScreens(language)

        // The question ends with the half-width question mark macOS uses in Japanese too.
        let removal = launch(language, ["--server-selection"])
        let row = removal.outlines.staticTexts["Test Storage"].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.rightClick()
        removal.menuItems[language.text("Remove Server…", "サーバを削除…")].click()
        let question = text(
            language.text("Remove “Test\u{00A0}Storage”?", "“Test\u{00A0}Storage”を削除しますか?"),
            in: removal)
        XCTAssertTrue(question.waitForExistence(timeout: 10))
        capture("\(name)-remove-server-confirmation", removal)
        removal.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(question.waitForNonExistence(timeout: 5))
        removal.terminate()

        let settings = launch(language, ["--server-selection", "--settings-load-failure"])
        XCTAssertTrue(settings.windows["preview"].sheets.firstMatch.waitForExistence(timeout: 10))
        capture("\(name)-settings-failure-alert", settings)
        settings.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(
            settings.windows["preview"].sheets.firstMatch.waitForNonExistence(timeout: 5))
        capture("\(name)-settings-unavailable", settings)
        settings.terminate()
    }

    /// The server accepts the connection and closes it during the login, as Linux LIO does when
    /// it requires CHAP and the Mac offers none. Each alert says the server closed the
    /// connection and what to check for the authentication that was used, and offers Edit
    /// Server… unless the server's disks are connected.
    @MainActor private func closedLoginScreens(_ language: Language) {
        let name = language.rawValue
        let server = "Test\u{00A0}Storage"
        let searchTitle = language.text(
            "Couldn’t Find Disks on “\(server)”", "“\(server)”でディスクを検索できませんでした")
        let edit = language.text("Edit Server…", "サーバを編集…")

        // Finding disks without a password.
        let closed = launch(language, ["--server-closes-login"])
        let find = closed.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(find.waitForExistence(timeout: 10))
        find.click()
        let alert = closed.windows["preview"].sheets.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(text(searchTitle, in: alert).exists)
        XCTAssertTrue(
            text(
                language.text(
                    "The server closed the connection. If it requires a user name and password to find disks, edit this server and choose an authentication method under Finding Disks, then try again.",
                    "サーバが接続を閉じました。このサーバでディスクを検索するのにユーザ名とパスワードが必要な場合は、このサーバを編集して、“ディスクの検索”で認証方法を選択してから、やり直してください。"
                ), in: alert
            ).exists)
        XCTAssertTrue(alert.buttons[edit].exists)
        XCTAssertFalse(alert.buttons["OK"].exists)
        capture("\(name)-search-closed-login-alert", closed)
        alert.buttons[edit].click()
        let editor = closed.sheets.firstMatch
        let heading = editor.staticTexts[language.text("Edit Server", "サーバを編集")]
        XCTAssertTrue(heading.waitForExistence(timeout: 10))
        capture("\(name)-search-closed-login-editor", closed)
        editor.buttons[language.text("Cancel", "キャンセル")].click()
        XCTAssertTrue(heading.waitForNonExistence(timeout: 5))
        closed.terminate()

        // Reading a target's disks, which uses the authentication under Connection.
        let viewing = launch(language, ["--server-closes-login"])
        let target = "iqn.2026-10.example:available"
        let refresh = viewing.buttons[
            language.text("Refresh disks for \(target)", "\(target)のディスクを更新")]
        XCTAssertTrue(refresh.waitForExistence(timeout: 10))
        refresh.click()
        let viewAlert = viewing.windows["preview"].sheets.firstMatch
        XCTAssertTrue(viewAlert.waitForExistence(timeout: 10))
        XCTAssertTrue(
            text(
                language.text(
                    "Couldn’t View Disks on “\(server)”", "“\(server)”のディスクを表示できませんでした"),
                in: viewAlert
            ).exists)
        XCTAssertTrue(
            text(
                language.text(
                    "The server closed the connection. If it requires a user name and password to connect to its disks, edit this server and choose an authentication method under Connection, then try again.",
                    "サーバが接続を閉じました。このサーバのディスクに接続するのにユーザ名とパスワードが必要な場合は、このサーバを編集して、“接続”で認証方法を選択してから、やり直してください。"
                ), in: viewAlert
            ).exists)
        XCTAssertTrue(viewAlert.buttons[edit].exists)
        capture("\(name)-view-disks-closed-login-alert", viewing)
        viewing.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(viewAlert.waitForNonExistence(timeout: 5))
        viewing.terminate()

        // Finding disks with the Connection password.
        let password = launch(language, ["--server-closes-login-with-password"])
        let findWithPassword = password.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(findWithPassword.waitForExistence(timeout: 10))
        findWithPassword.click()
        let passwordAlert = password.windows["preview"].sheets.firstMatch
        XCTAssertTrue(passwordAlert.waitForExistence(timeout: 10))
        XCTAssertTrue(text(searchTitle, in: passwordAlert).exists)
        XCTAssertTrue(
            text(
                language.text(
                    "The server closed the connection. Edit this server and check the server address and the user name and password under Connection, then try again.",
                    "サーバが接続を閉じました。このサーバを編集して、サーバアドレスと“接続”のユーザ名とパスワードを確認してから、やり直してください。"
                ), in: passwordAlert
            ).exists)
        XCTAssertTrue(passwordAlert.buttons[edit].exists)
        capture("\(name)-search-closed-login-with-password-alert", password)
        password.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(passwordAlert.waitForNonExistence(timeout: 5))
        password.terminate()

        // A server with a connected disk can't be edited: eject its disks first, OK only.
        let withDisk = launch(language, ["--server-closes-login-with-connected-disk"])
        let findWithDisk = withDisk.findDisksToolbarButton(japanese: language == .japanese)
        XCTAssertTrue(findWithDisk.waitForExistence(timeout: 10))
        findWithDisk.click()
        let diskAlert = withDisk.windows["preview"].sheets.firstMatch
        XCTAssertTrue(diskAlert.waitForExistence(timeout: 10))
        XCTAssertTrue(text(searchTitle, in: diskAlert).exists)
        XCTAssertTrue(
            text(
                language.text(
                    "The server closed the connection. If it requires a user name and password to find disks, eject this server’s disks, then edit the server and choose an authentication method under Finding Disks.",
                    "サーバが接続を閉じました。このサーバでディスクを検索するのにユーザ名とパスワードが必要な場合は、このサーバのディスクを取り出してから、サーバを編集して“ディスクの検索”で認証方法を選択してください。"
                ), in: diskAlert
            ).exists)
        XCTAssertTrue(diskAlert.buttons["OK"].exists)
        XCTAssertFalse(diskAlert.buttons[edit].exists)
        capture("\(name)-search-closed-login-with-connected-disk-alert", withDisk)
        withDisk.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(diskAlert.waitForNonExistence(timeout: 5))
        withDisk.terminate()
    }

    /// A disk that keeps reconnecting, beside a read-only disk; Force Eject once it's offered;
    /// a Force Eject that no longer applies because the disk reconnected; and a disk in use.
    @MainActor private func reconnectingScreens(_ language: Language, dark: Bool = false) {
        let name = (dark ? "dark-" : "") + language.rawValue
        let appearance = dark ? ["--dark-appearance"] : []
        // The disk has been reconnecting for longer than the delay before Force Eject.
        let longer = ["--reconnecting", "--reconnecting-for=11"]
        let offered = launch(language, longer + ["--read-only-disk"] + appearance)
        let force = offered.buttons[language.text("Force Eject Work", "Workを強制的に取り出す")]
        XCTAssertTrue(force.waitForExistence(timeout: 10))
        XCTAssertTrue(text(language.text("Reconnecting…", "再接続中…"), in: offered).exists)
        XCTAssertTrue(text(language.text("Read-only", "読み出し専用"), in: offered).exists)
        XCTAssertTrue(offered.buttons[language.text("Eject Work", "Workを取り出す")].isHittable)
        capture("\(name)-reconnecting-force-eject-offered", offered)
        force.click()
        let window = offered.windows["preview"]
        let confirm = window.buttons[language.text("Force Eject", "強制的に取り出す")]
        XCTAssertTrue(confirm.waitForExistence(timeout: 10))
        capture("\(name)-reconnecting-force-eject-confirmation", offered)
        offered.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(confirm.waitForNonExistence(timeout: 5))
        offered.terminate()

        // The server came back just as Force Eject was chosen, so the disk stays connected.
        let reconnected = launch(language, longer + ["--reconnects-on-force-eject"] + appearance)
        let again = reconnected.buttons[language.text("Force Eject Work", "Workを強制的に取り出す")]
        XCTAssertTrue(again.waitForExistence(timeout: 10))
        again.click()
        let sheet = reconnected.windows["preview"].sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 10))
        XCTAssertTrue(
            text(language.text("“Work” Is Connected Again", "“Work”は再接続されました"), in: sheet)
                .exists)
        // Nothing needs checking: the disk is connected, so the alert only acknowledges.
        XCTAssertTrue(sheet.buttons["OK"].exists)
        XCTAssertFalse(
            sheet.buttons[language.text("Open Disk Utility", "ディスクユーティリティを開く")].exists)
        capture("\(name)-reconnected-before-force-eject-alert", reconnected)
        reconnected.typeKey(.return, modifierFlags: [])
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        XCTAssertFalse(again.exists)
        XCTAssertTrue(
            reconnected.buttons[language.text("Show Work in Finder", "WorkをFinderに表示")].exists)
        capture("\(name)-reconnected-before-force-eject", reconnected)
        reconnected.terminate()

        // A disk in use: Cancel is the trailing default, and Force Eject… comes before it.
        let inUse = launch(language, ["--force-ejection-in-use"] + appearance)
        let eject = inUse.buttons[language.text("Eject Archive", "Archiveを取り出す")]
        XCTAssertTrue(eject.waitForExistence(timeout: 10))
        eject.click()
        let alert = inUse.windows["preview"].sheets.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        let cancel = alert.buttons[language.text("Cancel", "キャンセル")]
        let forceEject = alert.buttons[language.text("Force Eject…", "強制的に取り出す…")]
        XCTAssertTrue(cancel.exists && forceEject.exists)
        // Side by side, Cancel is on the right; stacked, it is on top.
        XCTAssertTrue(
            cancel.frame.minX > forceEject.frame.maxX || cancel.frame.maxY < forceEject.frame.minY)
        capture("\(name)-disk-in-use-alert", inUse)
        inUse.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(alert.waitForNonExistence(timeout: 5))
        inUse.terminate()
    }

    @MainActor private func text(_ value: String, in element: XCUIElement) -> XCUIElement {
        element.staticTexts.matching(
            NSPredicate(format: "value == %@ OR label == %@", value, value)
        ).firstMatch
    }

    @MainActor private func openEditor(_ app: XCUIApplication, _ language: Language) {
        let add = app.buttons[language.text("Add Server", "サーバを追加")]
        XCTAssertTrue(add.waitForExistence(timeout: 10) && add.isEnabled)
        add.click()
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 5))
    }

    @MainActor private func chooseMutual(_ app: XCUIApplication, _ language: Language) {
        let editor = app.sheets.firstMatch
        let mutual = language.text("Mutual CHAP", "相互CHAP")
        editor.popUpButtons[language.text("Connection Authentication", "接続時の認証")].click()
        app.menuItems[mutual].firstMatch.click()
        editor.popUpButtons[language.text("Authentication for Finding Disks", "ディスクの検索時の認証")]
            .click()
        app.menuItems[mutual].firstMatch.click()
    }

    /// The window, with any sheet or popover over it, cropped from the screen.
    @MainActor private func capture(_ name: String, _ app: XCUIApplication) {
        let window = app.windows["preview"]
        var frame = window.frame
        for element in app.popovers.allElementsBoundByIndex + app.sheets.allElementsBoundByIndex
        where element.exists {
            frame = frame.union(element.frame)
        }
        let size = XCTAttachment(string: "\(name): window=\(window.frame) capture=\(frame)")
        size.name = "\(name) frame"
        size.lifetime = .keepAlways
        add(size)
        let screen = XCUIScreen.main.screenshot()
        let attachment: XCTAttachment
        if let image = crop(screen.image, to: frame.insetBy(dx: -24, dy: -24)) {
            attachment = XCTAttachment(image: image)
        } else {
            attachment = XCTAttachment(screenshot: window.screenshot())
        }
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    @MainActor private func crop(_ image: NSImage, to frame: CGRect) -> NSImage? {
        guard let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil),
            let screen = NSScreen.main
        else { return nil }
        let scale = CGFloat(cgImage.width) / screen.frame.width
        let bounds = CGRect(x: 0, y: 0, width: cgImage.width, height: cgImage.height)
        let pixels = CGRect(
            x: frame.minX * scale, y: frame.minY * scale,
            width: frame.width * scale, height: frame.height * scale
        ).intersection(bounds)
        guard let cropped = cgImage.cropping(to: pixels) else { return nil }
        return NSImage(cgImage: cropped, size: NSSize(width: pixels.width, height: pixels.height))
    }
}
