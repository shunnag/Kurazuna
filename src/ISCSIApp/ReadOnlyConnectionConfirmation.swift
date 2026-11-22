import AppKit
import SwiftUI

/// Keep the request alive until an explicit sheet response, independent of SwiftUI dismissal.
struct ReadOnlyConnectionConfirmation: NSViewRepresentable {
    let request: ReadOnlyConnectionRequest?
    let title: String
    let message: String
    let confirm: @MainActor (ReadOnlyConnectionRequest) -> Void
    let cancel: @MainActor (ReadOnlyConnectionRequest) -> Void

    func makeNSView(context: Context) -> ConfirmationView { ConfirmationView() }

    func updateNSView(_ view: ConfirmationView, context: Context) {
        view.update(
            request: request, title: title, message: message, confirm: confirm, cancel: cancel)
    }

    static func dismantleNSView(_ view: ConfirmationView, coordinator: ()) {
        view.dismiss(cancelRequest: true)
    }

    final class ConfirmationView: NSView {
        private var request: ReadOnlyConnectionRequest?
        private var title = ""
        private var message = ""
        private var alert: NSAlert?
        private var presentationPending = false
        private var confirm: (@MainActor (ReadOnlyConnectionRequest) -> Void)?
        private var cancel: (@MainActor (ReadOnlyConnectionRequest) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil, alert != nil {
                dismiss(cancelRequest: true)
            } else {
                presentIfNeeded()
            }
        }

        func update(
            request: ReadOnlyConnectionRequest?, title: String, message: String,
            confirm: @escaping @MainActor (ReadOnlyConnectionRequest) -> Void,
            cancel: @escaping @MainActor (ReadOnlyConnectionRequest) -> Void
        ) {
            if self.request != request { dismiss(cancelRequest: false) }
            self.request = request
            self.title = title
            self.message = message
            self.confirm = confirm
            self.cancel = cancel
            presentIfNeeded()
        }

        func dismiss(cancelRequest: Bool) {
            let previous = request
            request = nil
            let presented = alert
            alert = nil
            if let presented { AlertSheet.end(presented) }
            if cancelRequest, let previous, let cancel {
                Task { @MainActor in cancel(previous) }
            }
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
            guard let request, let window, alert == nil, window.attachedSheet == nil else { return }
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = title
            alert.informativeText = message
            alert.addButton(withTitle: String(localized: "Connect Read-Only"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            alert.buttons[0].keyEquivalent = "\r"
            alert.buttons[1].keyEquivalent = "\u{1b}"
            self.alert = alert
            alert.beginSheetModal(for: window) { [weak self, weak alert] response in
                MainActor.assumeIsolated {
                    guard let self, let alert, self.alert === alert else { return }
                    self.alert = nil
                    guard self.request == request else { return }
                    self.request = nil
                    if response == .alertFirstButtonReturn {
                        self.confirm?(request)
                    } else {
                        self.cancel?(request)
                    }
                }
            }
        }
    }
}
