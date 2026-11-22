import SwiftUI

/// An inline notice above the window's content, like the ones in System Settings: a
/// symbol, a title, a message, and the actions that resolve it. The actions sit at the
/// trailing edge when the message fits on one line beside them; otherwise they follow the
/// message, so a long or translated message isn't squeezed into a narrow column.
struct NoticeBanner<Actions: View, Details: View>: View {
    enum Tone {
        case information, warning

        var color: Color {
            switch self {
            case .information: .blue
            case .warning: .orange
            }
        }
    }

    let title: String
    let message: String
    let systemImage: String
    var tone = Tone.warning
    @ViewBuilder var actions: Actions
    @ViewBuilder var details: Details

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 12) {
                symbol
                text.fixedSize()
                Spacer(minLength: 12)
                buttons
            }
            HStack(alignment: .top, spacing: 12) {
                symbol
                VStack(alignment: .leading, spacing: 8) {
                    text
                    HStack {
                        Spacer()
                        buttons
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(tone.color.opacity(0.1))
        }
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(tone.color.opacity(0.3), lineWidth: 1)
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 4)
    }

    private var symbol: some View {
        Image(systemName: systemImage)
            .font(.title2)
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(tone.color)
            .frame(width: 32)
            .accessibilityHidden(true)
    }

    private var text: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
            Text(message)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            details
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var buttons: some View {
        HStack(spacing: 8) { actions }
            .fixedSize()
    }
}

extension NoticeBanner where Details == EmptyView {
    init(
        title: String, message: String, systemImage: String, tone: Tone = .warning,
        @ViewBuilder actions: () -> Actions
    ) {
        self.title = title
        self.message = message
        self.systemImage = systemImage
        self.tone = tone
        self.actions = actions()
        self.details = EmptyView()
    }
}
