import AppKit

/// The native alert sheets are begun and ended from views that SwiftUI updates while it
/// renders the window. A sheet lays out the window when it is attached or removed, and
/// laying out the window while it renders is not supported, so both wait for the next turn
/// of the main queue.
enum AlertSheet {
    /// Ends the alert's sheet, if it is still attached, without calling its completion
    /// handler with a response the user chose.
    @MainActor static func end(_ alert: NSAlert) {
        DispatchQueue.main.async {
            alert.window.sheetParent?.endSheet(alert.window, returnCode: .abort)
            alert.window.orderOut(nil)
        }
    }
}
