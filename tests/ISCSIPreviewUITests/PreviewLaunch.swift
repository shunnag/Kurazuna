import XCTest

extension XCUIApplication {
    /// The toolbar's Find Disks button. Before a search, the Available Disks section has a
    /// button of the same name, identified as `find-disks-placeholder`.
    func findDisksToolbarButton(japanese: Bool) -> XCUIElement {
        buttons.matching(
            NSPredicate(
                format: "label == %@ AND identifier != %@",
                japanese ? "ディスクを検索" : "Find Disks", "find-disks-placeholder")
        ).firstMatch
    }

    /// The Find Disks button beside the text that explains it, before a search.
    var findDisksPlaceholderButton: XCUIElement {
        buttons.matching(identifier: "find-disks-placeholder").firstMatch
    }
}

extension XCTestCase {
    /// A previous crash can leave this preview's standard window-restoration dialog.
    /// Decline only that dialog; do not change application or system preferences.
    @MainActor
    func launchPreview(_ app: XCUIApplication) {
        app.launch()
        let restoration = app.dialogs.firstMatch
        guard restoration.exists else { return }
        let text = restoration.staticTexts.allElementsBoundByIndex.map {
            String(describing: $0.value ?? $0.label)
        }.joined(separator: "\n")
        guard text.contains("Kurazuna Preview"), text.contains("reopen") || text.contains("再開")
        else {
            XCTFail("Unexpected preview startup dialog")
            return
        }
        let recovery = XCTAttachment(string: text)
        recovery.name = "Preview window restoration dialog"
        recovery.lifetime = .keepAlways
        add(recovery)
        restoration.buttons["action-button--999"].click()
        XCTAssertTrue(restoration.waitForNonExistence(timeout: 5))
    }
}
