import AppKit
import ISCSINetwork
import ISCSIPlatform
import SwiftUI

/// The colour of a disk's status dot. The dot always accompanies the status text.
enum DiskStatusTone {
    case normal, progress, attention, failure, inactive

    var color: Color {
        switch self {
        case .normal: .green
        case .progress: .orange
        case .attention: .yellow
        case .failure: .red
        case .inactive: .gray
        }
    }
}

extension AttachedDisk {
    /// Follows the same order as `AppModel.diskStatus(_:)`, so the dot matches its text.
    var statusTone: DiskStatusTone {
        if resourceCleanupError != nil { return .inactive }
        if verificationFailed || needsCleanup { return .attention }
        switch connectionState {
        case .connected: return .normal
        case .reconnecting: return .progress
        case .interrupted, .closed: return .failure
        case .unknown: return .inactive
        }
    }
}

/// A disk symbol in a fixed-width column, so the titles of every row line up.
struct DiskSymbol: View {
    static let width: CGFloat = 32
    /// The space between the symbol and the row's text.
    static let spacing: CGFloat = 12
    /// Where a row's text begins, so lines below the title can align with it.
    static let indent = width + spacing

    let systemName: String
    var prominent = false
    var locked = false

    var body: some View {
        Image(systemName: systemName)
            .font(.title2)
            .foregroundStyle(prominent ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
            .frame(width: Self.width, height: 28)
            .overlay(alignment: .bottomTrailing) {
                if locked {
                    Image(systemName: "lock.circle.fill")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .gray)
                        .font(.system(size: 12, weight: .semibold))
                        .offset(x: 2, y: 2)
                }
            }
            .accessibilityHidden(true)
    }
}

/// A status dot followed by its text. Colour is never the only indication.
struct DiskStatusLabel: View {
    let text: String
    let tone: DiskStatusTone

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tone.color).frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(text)
        }
    }
}

/// A short secondary message with a leading symbol, such as a disk's read-only state.
struct RowNote: View {
    let text: String
    let systemImage: String
    var symbolColor: Color? = nil
    var primary = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 5) {
            Image(systemName: systemImage)
                .foregroundStyle(symbolColor.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.secondary))
                .accessibilityHidden(true)
            Text(text)
                .foregroundStyle(primary ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(primary ? .callout : .subheadline)
    }
}

/// Technical details that most people don't need, shown in a popover like Get Info.
struct DiskInfoButton: View {
    struct Item: Identifiable {
        var id: String { label }
        let label: String
        let value: String
    }

    /// The full name VoiceOver reads, which starts with the button's help text.
    let label: Text
    let items: [Item]
    @State private var showing = false

    var body: some View {
        Button {
            showing.toggle()
        } label: {
            Image(systemName: "info.circle")
                .imageScale(.large)
        }
        .buttonStyle(.borderless)
        .help(Text("Show Info"))
        .accessibilityLabel(label)
        .accessibilityInputLabels([Text("Show Info"), label])
        .popover(isPresented: $showing, arrowEdge: .bottom) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 6) {
                ForEach(items) { item in
                    GridRow {
                        Text(item.label)
                            .foregroundStyle(.secondary)
                            .gridColumnAlignment(.trailing)
                        Text(item.value)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                            .frame(maxWidth: 320, alignment: .leading)
                    }
                }
            }
            .padding(16)
            .fixedSize()
        }
    }
}

/// A disk this Mac is connected to.
struct ConnectedDiskRow: View {
    let model: AppModel
    let disk: AttachedDisk

    private var unit: String { disk.descriptor.lun.displayIdentifier }

    private var symbolName: String {
        if disk.resourceCleanupError != nil { return "externaldrive" }
        switch disk.statusTone {
        case .normal, .progress: return "externaldrive.fill"
        case .attention, .failure: return "externaldrive.fill.trianglebadge.exclamationmark"
        case .inactive: return "externaldrive"
        }
    }

    private var facts: String { Self.facts(for: disk) }
    private var message: String? { Self.message(for: disk) }

    /// The line below the status: the LUN, then the target that the row's title omits.
    static func facts(for disk: AttachedDisk) -> String {
        let target = disk.descriptor.targetName
        var parts = [String(localized: "LUN \(disk.descriptor.lun.displayIdentifier)")]
        if disk.displayName != target { parts.append(target) }
        return parts.joined(separator: " · ")
    }

    /// What to do next, below the row's title.
    static func message(for disk: AttachedDisk) -> String? {
        if disk.hasNoMountedVolumes {
            // The disk may be new, or its volumes may be unreadable or unmounted, so only a
            // new disk is told to be initialized, as Disk Utility calls it.
            return String(
                localized:
                    "No volumes are mounted on this disk. To use a new disk with this Mac, initialize it in Disk Utility."
            )
        }
        if !disk.needsCleanup,
            disk.connectionState == .interrupted || disk.connectionState == .closed
        {
            return String(
                localized: "Close files on this disk, then eject it before connecting again.")
        }
        return nil
    }

    private var infoItems: [DiskInfoButton.Item] {
        var items = [
            DiskInfoButton.Item(
                label: String(localized: "Target"), value: disk.descriptor.targetName),
            DiskInfoButton.Item(label: String(localized: "LUN"), value: unit),
        ]
        if !disk.verificationFailed, disk.connectionState == .connected {
            items.append(
                DiskInfoButton.Item(
                    label: String(localized: "Connection Address"),
                    value: disk.connectedPortal.description))
        }
        if let device = disk.attachment?.device {
            items.append(DiskInfoButton.Item(label: String(localized: "Device"), value: device))
        }
        return items
    }

    var body: some View {
        // Unique among the server's disks, as are its VoiceOver labels and alerts.
        let name = model.name(of: disk)
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: DiskSymbol.spacing) {
                DiskSymbol(
                    systemName: symbolName, prominent: disk.statusTone == .normal,
                    locked: disk.descriptor.readOnly && disk.resourceCleanupError == nil)
                VStack(alignment: .leading, spacing: 3) {
                    Text(name)
                        .lineLimit(1).truncationMode(.middle)
                        .help(disk.descriptor.targetName)
                    // Separated like the line below, with a space on each side of the dot.
                    HStack(spacing: 0) {
                        DiskStatusLabel(text: model.diskStatus(disk), tone: disk.statusTone)
                        if disk.descriptor.readOnly, disk.resourceCleanupError == nil {
                            Text(verbatim: " · ").accessibilityHidden(true)
                            Text("Read-only")
                        }
                    }
                    .font(.subheadline).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                controls(name: name)
            }
            // The LUN and the target's full name span the row below the buttons, which can be
            // wide in Japanese, so the name is shortened only in a very narrow window.
            Text(facts)
                .font(.subheadline).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
                .padding(.leading, DiskSymbol.indent)
            // What to do next spans the row below its title, so it rarely needs to wrap.
            if let message {
                Text(message)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, DiskSymbol.indent)
            }
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private func controls(name: String) -> some View {
        // Like Bluetooth devices in System Settings, the details button ends each row, so
        // it lines up in every row whichever actions come before it.
        HStack(spacing: 8) {
            if !disk.needsCleanup, disk.connectionState == .connected,
                let url = disk.attachment?.volumeURLs.first
            {
                Button("Show in Finder") { NSWorkspace.shared.open(url) }
                    .accessibilityLabel(Text("Show \(name) in Finder"))
                    .accessibilityInputLabels([
                        Text("Show in Finder"), Text("Show \(name) in Finder"),
                    ])
            }
            if disk.hasNoMountedVolumes {
                Button("Open Disk Utility") { model.openDiskUtility() }
                    .accessibilityLabel(Text("Check \(name) in Disk Utility"))
                    .accessibilityInputLabels([
                        Text("Open Disk Utility"), Text("Check \(name) in Disk Utility"),
                    ])
            }
            if disk.resourceCleanupError != nil {
                Button("Try Again") { model.eject(disk) }.disabled(model.busy)
                    .accessibilityLabel(Text("Remove connection information for \(name)"))
                    .accessibilityInputLabels([
                        Text("Try Again"), Text("Remove connection information for \(name)"),
                    ])
            } else {
                if model.offersForceEjection(disk) {
                    Button("Force Eject…") { model.prepareForceEjection(disk.id) }
                        .disabled(model.busy)
                        .accessibilityLabel(Text("Force Eject \(name)"))
                        .accessibilityInputLabels([
                            Text("Force Eject"), Text("Force Eject \(name)"),
                        ])
                }
                Button("Eject", systemImage: "eject") { model.eject(disk) }
                    .disabled(model.busy)
                    .accessibilityLabel(Text("Eject \(name)"))
                    .accessibilityInputLabels([Text("Eject"), Text("Eject \(name)")])
            }
            DiskInfoButton(label: Text("Show Info for \(name)"), items: infoItems)
        }
        .fixedSize()
    }
}

/// The first row of a target's group: its name, its full name, and the action that
/// reads its disks.
struct TargetRow: View {
    let model: AppModel
    let target: DiscoveredTarget
    let server: ServerProfile
    let viewed: Bool

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(target.friendlyName).font(.headline)
                Text(target.name)
                    .font(.subheadline).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if viewed {
                Button("Refresh") { model.inspect(target, server: server) }
                    .disabled(model.busy)
                    .accessibilityLabel(Text("Refresh disks for \(target.name)"))
                    .accessibilityInputLabels([
                        Text("Refresh"), Text("Refresh disks for \(target.name)"),
                    ])
            } else {
                Button("View Disks") { model.inspect(target, server: server) }
                    .disabled(model.busy)
                    .accessibilityLabel(Text("View disks for \(target.name)"))
                    .accessibilityInputLabels([
                        Text("View Disks"), Text("View disks for \(target.name)"),
                    ])
            }
        }
        .padding(.vertical, 2)
    }
}

/// A disk found on a server, with the control that connects it.
struct FoundDiskRow: View {
    let model: AppModel
    let disk: FoundDisk
    let target: DiscoveredTarget
    let server: ServerProfile

    private var unit: String { disk.lun.displayIdentifier }

    private var facts: String {
        var parts: [String] = []
        if let information = disk.information {
            parts.append(
                ByteCountFormatter.string(
                    fromByteCount: Int64(clamping: information.capacity.byteCount),
                    countStyle: .file))
            if !information.device.displayName.isEmpty {
                parts.append(information.device.displayName)
            }
        }
        parts.append(String(localized: "LUN \(unit)"))
        return parts.joined(separator: " · ")
    }

    private var infoItems: [DiskInfoButton.Item] {
        var items = [
            DiskInfoButton.Item(label: String(localized: "Target"), value: target.name),
            DiskInfoButton.Item(label: String(localized: "LUN"), value: unit),
        ]
        if let address = disk.connectionAddress {
            items.append(
                DiskInfoButton.Item(
                    label: String(localized: "Connection Address"),
                    value: address.portal.description))
        }
        return items
    }

    var body: some View {
        let existing = model.existingConnection(for: disk)
        let failure: DiskProbeIssue? = {
            if disk.information == nil, case .failure(let issue) = disk.inspection.result {
                return issue
            }
            return nil
        }()
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: DiskSymbol.spacing) {
                DiskSymbol(
                    systemName: existing != nil
                        ? "externaldrive.fill.badge.checkmark" : "externaldrive",
                    locked: disk.isWriteProtected)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Disk \(unit)")
                    // A disk already connected shows the state of that connection, as its
                    // row under Connected Disks does, so the two rows never disagree.
                    if let existing {
                        DiskStatusLabel(
                            text: model.diskStatus(existing), tone: existing.statusTone
                        )
                        .font(.subheadline).foregroundStyle(.secondary)
                    }
                    Text(facts)
                        .font(.subheadline).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail)
                        .textSelection(.enabled)
                    if disk.isWriteProtected {
                        RowNote(
                            text: String(localized: "Read-only disk"), systemImage: "lock.fill")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                HStack(spacing: 8) {
                    connectControl(existing: existing)
                    DiskInfoButton(
                        label: Text("Show Info for Disk \(unit) from \(target.name)"),
                        items: infoItems)
                }
                .fixedSize()
            }
            // Explanations span the row below the title, so they rarely need to wrap.
            if let failure {
                RowNote(
                    text: failure.userMessage, systemImage: "exclamationmark.triangle.fill",
                    symbolColor: .orange, primary: true
                )
                .padding(.leading, DiskSymbol.indent)
            }
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private func connectControl(existing: AttachedDisk?) -> some View {
        let enabled = model.canConnect && disk.information != nil && existing == nil
        if disk.isWriteProtected {
            // A write-protected disk can only be connected read-only.
            Button("Connect Read-Only") { model.connect(disk, server: server) }
                .disabled(!enabled)
                .accessibilityLabel(
                    Text("Connect Disk \(unit) from \(target.name) read-only")
                )
                .accessibilityInputLabels([
                    Text("Connect Read-Only"),
                    Text("Connect Disk \(unit) from \(target.name) read-only"),
                ])
                .accessibilityIdentifier("connect-\(target.name)-\(unit)")
        } else {
            Menu {
                Button("Connect Read-Only") {
                    model.connect(disk, server: server, readOnly: true)
                }
            } label: {
                Text("Connect")
            } primaryAction: {
                model.connect(disk, server: server)
            }
            .fixedSize()
            .disabled(!enabled)
            .accessibilityLabel(Text("Connect Disk \(unit) from \(target.name)"))
            .accessibilityInputLabels([
                Text("Connect"), Text("Connect Disk \(unit) from \(target.name)"),
            ])
            .accessibilityIdentifier("connect-\(target.name)-\(unit)")
        }
    }
}
