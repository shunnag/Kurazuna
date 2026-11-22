import AppKit
import ISCSIPlatform
import SwiftUI

/// Force ejecting can lose unsaved changes. Use the same native sheet as server removal:
/// the title is a question, Cancel is the Return default, and Escape and Command–Period
/// cancel. The sheet waits until any other sheet on the window, such as the eject error
/// that offered this choice, has ended.
struct ForceEjectionConfirmation: NSViewRepresentable {
    let request: ForceEjectionRequest?
    /// The disk's name, as its row shows it.
    let name: String
    let message: String
    let confirm: @MainActor (ForceEjectionRequest) -> Void
    let cancel: @MainActor (ForceEjectionRequest) -> Void

    func makeNSView(context: Context) -> ConfirmationView { ConfirmationView() }

    func updateNSView(_ view: ConfirmationView, context: Context) {
        view.update(
            request: request, name: name, message: message, confirm: confirm, cancel: cancel)
    }

    static func dismantleNSView(_ view: ConfirmationView, coordinator: ()) {
        view.dismiss(cancelRequest: true)
        view.stopObservingSheets()
    }

    final class ConfirmationView: NSView {
        private var request: ForceEjectionRequest?
        private var name = ""
        private var message = ""
        private var alert: NSAlert?
        private var presentationPending = false
        private var monitor: Any?
        private var sheetObserver: (any NSObjectProtocol)?
        private var confirm: (@MainActor (ForceEjectionRequest) -> Void)?
        private var cancel: (@MainActor (ForceEjectionRequest) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            stopObservingSheets()
            if window == nil {
                if alert != nil { dismiss(cancelRequest: true) }
                return
            }
            // Another sheet, such as the error that offered Force Eject, may still be ending.
            sheetObserver = NotificationCenter.default.addObserver(
                forName: NSWindow.didEndSheetNotification, object: window, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.presentIfNeeded() }
            }
            presentIfNeeded()
        }

        func stopObservingSheets() {
            if let sheetObserver { NotificationCenter.default.removeObserver(sheetObserver) }
            sheetObserver = nil
        }

        func update(
            request: ForceEjectionRequest?, name: String, message: String,
            confirm: @escaping @MainActor (ForceEjectionRequest) -> Void,
            cancel: @escaping @MainActor (ForceEjectionRequest) -> Void
        ) {
            if self.request != request { dismiss(cancelRequest: false) }
            self.request = request
            self.name = name
            self.message = message
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
                localized: "Force Eject “\(NameInTitle.keptTogether(name))”?")
            alert.informativeText = message
            // NSAlert gives its first button Return. Cancel is first, so Return never ejects.
            alert.addButton(withTitle: String(localized: "Cancel"))
            alert.addButton(withTitle: String(localized: "Force Eject"))
            let cancel = alert.buttons[0]
            let eject = alert.buttons[1]
            cancel.keyEquivalent = "\r"
            eject.keyEquivalent = ""
            eject.hasDestructiveAction = true
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
