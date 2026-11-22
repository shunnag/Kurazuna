import AppKit
import SwiftUI

@main
struct ISCSIApp: App {
    @State private var model = AppModel()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    #if KURAZUNA_UPDATES
        @StateObject private var updates = SoftwareUpdates()
    #endif

    var body: some Scene {
        Window(AppName.display, id: "main") {
            AppRootView(model: model, delegate: delegate)
                #if KURAZUNA_UPDATES
                    .onAppear {
                        delegate.updates = updates
                        updates.start(for: model)
                    }
                #endif
        }
        // Tall enough for the server editor with every authentication field, and wide enough
        // for the toolbar's actions, without scrolling.
        .defaultSize(width: 960, height: 800)
        .commands {
            #if KURAZUNA_UPDATES
                CommandGroup(after: .appInfo) {
                    Button("Check for Updates…") { updates.check() }.disabled(!updates.canCheck)
                }
            #endif
            CommandGroup(replacing: .newItem) {
                Button("Add Server…") {
                    model.addServer()
                }.keyboardShortcut("n").disabled(!model.canAddServer)
            }
            CommandMenu("Server") {
                Button("Find Disks") {
                    if let server = model.selectedServer { model.search(server) }
                }.keyboardShortcut("r").disabled(!model.canFindDisksOnSelectedServer)
                Button("Check Connections") {
                    model.checkConnections()
                }.disabled(!model.canRunMenuCommand)
                Divider()
                Button("Edit Server…") {
                    if let server = model.selectedServer { model.editServer(server) }
                }.disabled(model.selectedServer.map { !model.canEditServer($0) } ?? true)
                Button("Remove Server…", role: .destructive) {
                    if let server = model.selectedServer { model.removeServer(server) }
                }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(model.selectedServer.map { !model.canEditServer($0) } ?? true)
            }
        }
        Settings {
            InitiatorSettings(model: model)
                #if KURAZUNA_UPDATES
                    .environmentObject(updates)
                #endif
        }
    }
}

private struct AppRootView: View {
    let model: AppModel
    let delegate: AppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        MainView(model: model)
            .task {
                delegate.model = model
                delegate.showMainWindow = { [openWindow] in openWindow(id: "main") }
                await model.load()
                await model.monitorConnections()
            }
    }
}
