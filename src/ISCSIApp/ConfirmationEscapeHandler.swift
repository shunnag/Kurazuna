import AppKit
import SwiftUI

/// SwiftUI's explicit default shortcut replaces the cancel button's Escape shortcut.
/// Keep the native default button and handle Escape and Command–Period only in this
/// window's active sheet.
struct ConfirmationEscapeHandler: NSViewRepresentable {
    let isPresented: Bool
    let cancel: @MainActor () -> Void

    func makeNSView(context: Context) -> EscapeView { EscapeView() }

    func updateNSView(_ view: EscapeView, context: Context) {
        view.cancel = isPresented ? cancel : nil
        view.updateMonitor()
    }

    static func dismantleNSView(_ view: EscapeView, coordinator: ()) {
        view.cancel = nil
        view.updateMonitor()
    }

    final class EscapeView: NSView {
        var cancel: (@MainActor () -> Void)?
        private var monitor: Any?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            updateMonitor()
        }

        func updateMonitor() {
            if monitor == nil, cancel != nil, window != nil {
                monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) {
                    [weak self] event in
                    let handled = MainActor.assumeIsolated {
                        let modifiers = event.modifierFlags.intersection([
                            .command, .option, .control, .shift,
                        ])
                        let cancelKey =
                            (event.keyCode == 53 && modifiers.isEmpty)
                            || (event.charactersIgnoringModifiers == "." && modifiers == .command)
                        guard let self, let cancel = self.cancel, cancelKey,
                            let sheet = self.window?.attachedSheet,
                            event.window === sheet, sheet.isKeyWindow
                        else { return false }
                        self.cancel = nil
                        self.updateMonitor()
                        cancel()
                        return true
                    }
                    return handled ? nil : event
                }
            } else if cancel == nil || window == nil {
                if let monitor { NSEvent.removeMonitor(monitor) }
                monitor = nil
            }
        }
    }
}
