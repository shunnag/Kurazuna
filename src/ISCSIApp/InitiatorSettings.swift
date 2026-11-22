import AppKit
import SwiftUI

/// The Settings window: this Mac's iSCSI name, to grant it access on a server.
struct InitiatorSettings: View {
    let model: AppModel

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
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        // Wide enough for the whole initiator name beside its label.
        .frame(width: 700)
        .fixedSize(horizontal: false, vertical: true)
    }
}
