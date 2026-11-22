import XCTest

/// Inserts realistic disk information after the production view is already visible.
/// All data stays in the preview model; no network or disk connection is made.
final class DiskInformationUITests: XCTestCase {
    @MainActor
    func testEnglishInsertedDiskInformationRemainsAccessible() {
        checkDiskInformation(language: "en", locale: "en_US")
    }

    @MainActor
    func testJapaneseInsertedDiskInformationRemainsAccessible() {
        checkDiskInformation(language: "ja", locale: "ja_JP")
    }

    @MainActor
    private func checkDiskInformation(language: String, locale: String) {
        continueAfterFailure = false
        let app = XCUIApplication()
        defer { app.terminate() }
        app.launchArguments = [
            "-AppleLanguages", "(\(language))", "-AppleLocale", locale,
            "--dynamic-disk-information",
        ]
        launchPreview(app)
        let load = app.buttons["preview-load-disk-information"]
        XCTAssertTrue(load.waitForExistence(timeout: 10))
        let before = XCTAttachment(string: app.debugDescription)
        before.name = "\(language) before disk information"
        before.lifetime = .keepAlways
        add(before)
        load.click()
        let target = "iqn.2026-10.example:discovered-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        // Connect is a menu with a primary action; find it by identifier, not element type.
        let connect = app.descendants(matching: .any).matching(identifier: "connect-\(target)-0")
            .firstMatch
        XCTAssertTrue(connect.waitForExistence(timeout: 10))
        XCTAssertEqual(
            connect.label,
            language == "en" ? "Connect Disk 0 from \(target)" : "\(target)のディスク0に接続")
        XCTAssertTrue(connect.isEnabled)
        XCTAssertTrue(app.staticTexts["discovered-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"].exists)
        XCTAssertTrue(app.staticTexts[target].exists)
        XCTAssertTrue(app.staticTexts["4.29 GB · SobaDev Archive Disk · LUN 0"].exists)
        // The connection address is a technical detail, shown with the disk's other details.
        let info = app.buttons[
            language == "en"
                ? "Show Info for Disk 0 from \(target)" : "\(target)のディスク0の情報を表示"]
        XCTAssertTrue(info.exists && info.isHittable)
        info.click()
        let popover = app.popovers.firstMatch
        XCTAssertTrue(popover.waitForExistence(timeout: 5))
        XCTAssertTrue(popover.staticTexts["127.0.0.1:3260"].exists)
        XCTAssertTrue(popover.staticTexts[target].exists)
        let details = XCTAttachment(screenshot: app.windows["preview"].screenshot())
        details.name = "\(language) disk information details"
        details.lifetime = .keepAlways
        add(details)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(popover.waitForNonExistence(timeout: 5))
        for index in 0..<3 {
            let tree = XCTAttachment(string: app.debugDescription)
            tree.name = "\(language) inserted disk information \(index)"
            tree.lifetime = .keepAlways
            add(tree)
            XCTAssertTrue(app.state == .runningForeground || app.state == .runningBackground)
        }
        let snapshot = XCTAttachment(screenshot: app.screenshot())
        snapshot.name = "\(language) accessible disk information"
        snapshot.lifetime = .keepAlways
        add(snapshot)
    }
}
