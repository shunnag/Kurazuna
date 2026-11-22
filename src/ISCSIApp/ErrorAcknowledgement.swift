import AppKit
import SwiftUI

/// An error with a single safe response, with Return and Escape scoped to its own alert.
/// An error that offers Force Eject keeps Cancel as that response: like the force ejection
/// confirmation, Cancel is the first, trailing button and the Return default, and the
/// destructive choice sits before it, so neither key can start a forced ejection.
struct ErrorAcknowledgement: NSViewRepresentable {
    let issue: AppIssue?
    let dismiss: @MainActor (UUID) -> Void
    /// The issue, then the disk that it offers to force eject.
    var forceEject: @MainActor (UUID, UUID) -> Void = { _, _ in }

    func makeNSView(context: Context) -> AlertView { AlertView() }

    func updateNSView(_ view: AlertView, context: Context) {
        view.update(issue: issue, dismiss: dismiss, forceEject: forceEject)
    }

    static func dismantleNSView(_ view: AlertView, coordinator: ()) {
        view.dismissAlert()
    }

    final class AlertView: NSView {
        private var issue: AppIssue?
        private var alert: NSAlert?
        private var presentationPending = false
        private var monitor: Any?
        private var dismiss: (@MainActor (UUID) -> Void)?
        private var forceEject: (@MainActor (UUID, UUID) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil { dismissAlert() } else { presentIfNeeded() }
        }

        func update(
            issue: AppIssue?, dismiss: @escaping @MainActor (UUID) -> Void,
            forceEject: @escaping @MainActor (UUID, UUID) -> Void
        ) {
            if self.issue?.id != issue?.id { dismissAlert() }
            self.issue = issue
            self.dismiss = dismiss
            self.forceEject = forceEject
            presentIfNeeded()
        }

        func dismissAlert() {
            removeMonitor()
            let presented = alert
            alert = nil
            if let presented { AlertSheet.end(presented) }
        }

        private func removeMonitor() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }

        /// SwiftUI updates this view while it renders the window, and attaching a sheet lays
        /// out the window. Present on the next turn of the main queue instead, for whichever
        /// issue is current then.
        private func presentIfNeeded() {
            guard issue != nil, window != nil, alert == nil, !presentationPending else { return }
            presentationPending = true
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                presentationPending = false
                present()
            }
        }

        private func present() {
            guard let issue, let window, alert == nil else { return }
            // A settings error may occur while the server editor is already a sheet.
            var parent = window
            while let sheet = parent.attachedSheet { parent = sheet }
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = issue.title
            alert.informativeText = issue.message
            let diskID = issue.forceEjectionDiskID
            // NSAlert places its first button at the trailing edge, or at the top when the
            // buttons are stacked, and gives it Return.
            alert.addButton(
                withTitle: diskID == nil ? String(localized: "OK") : String(localized: "Cancel"))
            alert.buttons[0].keyEquivalent = "\r"
            if diskID != nil {
                let force = alert.addButton(withTitle: String(localized: "Force Eject…"))
                force.keyEquivalent = ""
                force.hasDestructiveAction = true
            }
            let issueID = issue.id
            self.alert = alert
            // A button has one key equivalent. Keep Escape and Command–Period on the safe
            // response too, scoped to this alert and removed when it ends.
            monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak alert] event in
                let handled = MainActor.assumeIsolated {
                    let modifiers = event.modifierFlags.intersection([
                        .command, .option, .control, .shift,
                    ])
                    let cancelKey =
                        (event.keyCode == 53 && modifiers.isEmpty)
                        || (event.charactersIgnoringModifiers == "." && modifiers == .command)
                    guard let alert, event.window === alert.window, alert.window.isKeyWindow,
                        cancelKey
                    else { return false }
                    alert.buttons[0].performClick(nil)
                    return true
                }
                return handled ? nil : event
            }
            alert.beginSheetModal(for: parent) { [weak self, weak alert] response in
                MainActor.assumeIsolated {
                    guard let self, let alert, self.alert === alert else { return }
                    self.alert = nil
                    self.removeMonitor()
                    guard self.issue?.id == issueID else { return }
                    if response == .alertSecondButtonReturn, let diskID {
                        self.forceEject?(issueID, diskID)
                    } else {
                        self.dismiss?(issueID)
                    }
                }
            }
        }
    }
}
