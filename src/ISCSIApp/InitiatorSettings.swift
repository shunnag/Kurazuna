import AppKit
import SwiftUI

/// The Settings window: this Mac's iSCSI name, to grant it access on a server.
struct InitiatorSettings: View {
    let model: AppModel
    #if KURAZUNA_UPDATES
        @EnvironmentObject private var updates: SoftwareUpdates
    #endif

    var body: some View {
        Form {
            Section {
                LabeledContent("Initiator Name") {
                    HStack(spacing: 8) {
                        Text(model.identityName)
                            .textSelection(.enabled)
                            .monospaced()
                            .lineLimit(1).truncationMode(.middle)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(model.identityName, forType: .string)
                        }
                        .disabled(model.identityName.isEmpty)
                    }
                }
            } footer: {
                Text("Use this name when granting this Mac access to a disk on your server.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            #if KURAZUNA_UPDATES
                Section("Software Update") {
                    Toggle(
                        "Automatically check for updates",
                        isOn: Binding(
                            get: { updates.automaticChecks }, set: updates.setAutomaticChecks))
                    Toggle(
                        "Automatically download and install updates",
                        isOn: Binding(
                            get: { updates.automaticDownloads }, set: updates.setAutomaticDownloads)
                    )
                    .disabled(!updates.automaticChecks)
                }
            #endif
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        // Wide enough for the whole initiator name beside its label.
        .frame(width: 700)
        .fixedSize(horizontal: false, vertical: true)
    }
}
