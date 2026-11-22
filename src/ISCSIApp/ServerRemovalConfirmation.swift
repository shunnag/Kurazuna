import AppKit
import SwiftUI

/// Removing saved passwords cannot be undone. Use a native sheet whose Return default is Cancel.
struct ServerRemovalConfirmation: NSViewRepresentable {
    let request: ServerRemovalRequest?
    let confirm: @MainActor (ServerRemovalRequest) -> Void
    let cancel: @MainActor (ServerRemovalRequest) -> Void

    func makeNSView(context: Context) -> ConfirmationView { ConfirmationView() }

    func updateNSView(_ view: ConfirmationView, context: Context) {
        view.update(request: request, confirm: confirm, cancel: cancel)
    }

    static func dismantleNSView(_ view: ConfirmationView, coordinator: ()) {
        view.dismiss(cancelRequest: true)
    }

    final class ConfirmationView: NSView {
        private var request: ServerRemovalRequest?
        private var alert: NSAlert?
        private var presentationPending = false
        private var monitor: Any?
        private var confirm: (@MainActor (ServerRemovalRequest) -> Void)?
        private var cancel: (@MainActor (ServerRemovalRequest) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil, alert != nil {
                dismiss(cancelRequest: true)
            } else {
                presentIfNeeded()
            }
        }

        func update(
            request: ServerRemovalRequest?,
            confirm: @escaping @MainActor (ServerRemovalRequest) -> Void,
            cancel: @escaping @MainActor (ServerRemovalRequest) -> Void
        ) {
            if self.request != request { dismiss(cancelRequest: false) }
            self.request = request
            self.confirm = confirm
            self.cancel = cancel
            presentIfNeeded()
        }

        func dismiss(cancelRequest: Bool) {
            let previous = request
            request = nil
            removeMonitor()
            let presented = alert
            alert = nil
            if let presented { AlertSheet.end(presented) }
            if cancelRequest, let previous, let cancel {
                // A SwiftUI view can be dismantled during an update. Cancel after that update.
                Task { @MainActor in cancel(previous) }
            }
        }

        private func removeMonitor() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }

        /// Present outside SwiftUI's update of the window; see `AlertSheet`. The deferred
        /// presentation checks the request and the window's sheets again.
        private func presentIfNeeded() {
            guard request != nil, window != nil, alert == nil, !presentationPending else {
                return
            }
            presentationPending = true
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                presentationPending = false
                present()
            }
        }

        private func present() {
            guard let request, let window, alert == nil, window.attachedSheet == nil else {
                return
            }
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(
                localized: "Remove “\(NameInTitle.keptTogether(request.server.displayName))”?")
            alert.informativeText = String(
                localized:
                    "The server’s settings and saved passwords will be removed from this Mac.")
            // NSAlert gives its first button Return. Cancel is first, so Return never removes.
            alert.addButton(withTitle: String(localized: "Cancel"))
            alert.addButton(withTitle: String(localized: "Remove"))
            let cancel = alert.buttons[0]
            let remove = alert.buttons[1]
            cancel.keyEquivalent = "\r"
            remove.keyEquivalent = ""
            remove.hasDestructiveAction = true
            self.alert = alert
            // A button has one key equivalent. Keep Escape and Command–Period on Cancel,
            // scoped to this sheet and removed when it ends.
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
            alert.beginSheetModal(for: window) { [weak self, weak alert] response in
                MainActor.assumeIsolated {
                    guard let self, let alert, self.alert === alert else { return }
                    self.alert = nil
                    self.removeMonitor()
                    guard self.request == request else { return }
                    self.request = nil
                    if response == .alertSecondButtonReturn {
                        self.confirm?(request)
                    } else {
                        self.cancel?(request)
                    }
                }
            }
        }
    }
}
