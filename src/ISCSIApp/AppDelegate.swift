import AppKit

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    #if KURAZUNA_UPDATES
        weak var updates: SoftwareUpdates?
    #endif
    weak var model: AppModel?
    var showMainWindow: (@MainActor () -> Void)?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        guard let model else { return false }
        return !model.busy && !model.connectionStatusNeedsAttention && model.attached.isEmpty
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }
        if model.busy {
            let alert = NSAlert()
            alert.messageText = String(localized: "An Operation Is in Progress")
            alert.informativeText = String(
                localized:
                    "Wait for the current operation to finish before quitting \(AppName.inSentence)."
            )
            alert.addButton(withTitle: String(localized: "OK"))
            _ = runSafeQuitAlert(alert)
            return .terminateCancel
        }
        #if KURAZUNA_UPDATES
            // A prepared Sparkle update may install on ordinary quit. Keep the app alive
            // if the inventory is uncertain, including a bridge the app cannot eject.
            if updates?.updatePrepared == true,
                model.connectionStatusNeedsAttention || !model.untrackedBridgeURLs.isEmpty
            {
                let alert = NSAlert()
                alert.messageText = String(localized: "Check Connected Disks Before Updating")
                alert.informativeText = String(
                    localized:
                        "Check the disks in Disk Utility, then choose Check Connections in Kurazuna."
                )
                alert.addButton(withTitle: String(localized: "OK"))
                _ = runSafeQuitAlert(alert)
                return .terminateCancel
            }
        #endif
        if model.connectionStatusNeedsAttention {
            let warning = model.quitWarning
            let alert = NSAlert()
            alert.messageText = warning.title
            alert.informativeText = warning.message
            alert.addButton(withTitle: String(localized: "Cancel"))
            alert.addButton(withTitle: String(localized: "Quit"))
            return runSafeQuitAlert(alert) == .alertSecondButtonReturn
                ? .terminateNow : .terminateCancel
        }
        guard !model.attached.isEmpty else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = String(localized: "Eject all disks and quit \(AppName.inSentence)?")
        alert.informativeText = String(
            localized: "Connected disks must be ejected before quitting.")
        // Ejecting is the requested action and the Return default; Cancel keeps Escape.
        alert.addButton(withTitle: String(localized: "Eject and Quit"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard runQuitAlert(alert, cancel: alert.buttons[1]) == .alertFirstButtonReturn else {
            return .terminateCancel
        }
        Task {
            let ejected = await model.ejectAll()
            sender.reply(toApplicationShouldTerminate: ejected)
            if !ejected {
                showMainWindow?()
                sender.activate()
            }
        }
        return .terminateLater
    }

    /// The first button is the safe Return default.
    private func runSafeQuitAlert(_ alert: NSAlert) -> NSApplication.ModalResponse {
        let cancel = alert.buttons[0]
        cancel.keyEquivalent = "\r"
        return runQuitAlert(alert, cancel: cancel)
    }

    private func runQuitAlert(_ alert: NSAlert, cancel: NSButton) -> NSApplication.ModalResponse {
        if cancel !== alert.buttons[0] { cancel.keyEquivalent = "\u{1b}" }
        // A button has one key equivalent. Keep Escape and Command–Period on Cancel,
        // scoped to this app-modal alert and removed when its modal loop ends.
        let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let handled = MainActor.assumeIsolated {
                let modifiers = event.modifierFlags.intersection([
                    .command, .option, .control, .shift,
                ])
                let cancelKey =
                    (event.keyCode == 53 && modifiers.isEmpty)
                    || (event.charactersIgnoringModifiers == "." && modifiers == .command)
                guard cancelKey, event.window === alert.window, NSApp.modalWindow === alert.window
                else { return false }
                cancel.performClick(nil)
                return true
            }
            return handled ? nil : event
        }
        defer { if let monitor { NSEvent.removeMonitor(monitor) } }
        return alert.runModal()
    }
}
