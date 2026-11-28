import SwiftUI
import UIKit

/// Faro's look on iOS, the same as the web app's (web/src/app.css): quiet
/// surfaces, hairline borders, small radii, a neutral graphite dark theme,
/// and two type families. Fira Code sets the interface itself (titles,
/// labels, buttons, chips, codes and figures); the system font sets prose,
/// so explanations stay easy to read. Both scale with Dynamic Type.
///
/// Fira Code is bundled in Faro/Fonts (SIL Open Font License 1.1, shown on
/// the Licences screen) and registered through UIAppFonts. If it is missing,
/// SwiftUI falls back to the system font.
enum Theme {
    // MARK: Colours (light, dark), as in app.css

    static let bg = Color(light: 0xF7F7F5, dark: 0x181818)
    static let surface = Color(light: 0xFFFFFF, dark: 0x202020)
    static let surface2 = Color(light: 0xF2F1EE, dark: 0x292929)
    static let text = Color(light: 0x1B1A18, dark: 0xECECEC)
    static let muted = Color(light: 0x5F5C56, dark: 0xA3A3A3)
    static let border = Color(light: 0xE5E3DE, dark: 0x2F2F2F)
    static let borderStrong = Color(light: 0xCFCCC4, dark: 0x444444)
    /// Text and controls. The brand amber is too light on white, so the light
    /// theme uses a darker shade of the same hue.
    static let accent = Color(light: 0xA14A0C, dark: 0xF19E4B)
    static let accentText = Color(light: 0xFFFFFF, dark: 0x1A1006)
    /// Faro amber, for marks that aren't text.
    static let brand = Color(light: 0xF19E4B, dark: 0xF19E4B)
    static let ok = Color(light: 0x2C7146, dark: 0x7CD19B)
    static let warn = Color(light: 0x8A5300, dark: 0xF0C060)
    static let danger = Color(light: 0xB02A23, dark: 0xFF8A80)

    static let radius: CGFloat = 6
    static let radiusSmall: CGFloat = 4

    // MARK: UIKit

    /// Navigation bar titles and buttons in the code face, set once at
    /// launch. The bar itself keeps the system's material.
    static func applyAppearance() {
        let title: [NSAttributedString.Key: Any] = [
            .font: UIFont.mono(16, .semibold, relativeTo: .headline),
            .foregroundColor: UIColor(text),
        ]
        let large: [NSAttributedString.Key: Any] = [
            .font: UIFont.mono(30, .semibold, relativeTo: .largeTitle),
            .foregroundColor: UIColor(text),
        ]
        let bar = UINavigationBar.appearance()
        bar.titleTextAttributes = title
        bar.largeTitleTextAttributes = large
    }
}

// MARK: - Type

enum MonoWeight {
    case regular, medium, semibold

    var postScriptName: String {
        switch self {
        case .regular: return "FiraCode-Regular"
        case .medium: return "FiraCode-Medium"
        case .semibold: return "FiraCode-SemiBold"
        }
    }

    var uiWeight: UIFont.Weight {
        switch self {
        case .regular: return .regular
        case .medium: return .medium
        case .semibold: return .semibold
        }
    }
}

extension Font {
    /// Fira Code at `size` points, scaled with `style`'s Dynamic Type size.
    /// It runs wider than the system font, so sizes here are a little
    /// smaller than the system font's for the same role.
    static func mono(_ size: CGFloat, _ weight: MonoWeight = .regular, relativeTo style: Font.TextStyle = .body) -> Font {
        .custom(weight.postScriptName, size: size, relativeTo: style)
    }
}

extension UIFont {
    static func mono(_ size: CGFloat, _ weight: MonoWeight = .regular, relativeTo style: UIFont.TextStyle = .body) -> UIFont {
        let base = UIFont(name: weight.postScriptName, size: size)
            ?? .monospacedSystemFont(ofSize: size, weight: weight.uiWeight)
        return UIFontMetrics(forTextStyle: style).scaledFont(for: base)
    }
}

// MARK: - Colour helpers

extension Color {
    /// A colour that follows the light or dark appearance.
    init(light: UInt32, dark: UInt32) {
        self.init(uiColor: UIColor { traits in
            UIColor(hex: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

extension UIColor {
    convenience init(hex: UInt32) {
        self.init(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
}

// MARK: - Lists

extension View {
    /// A List on Faro's background. Sections put their rows on the surface
    /// colour with `faroRows()`; sections of facts add `.labeledContentStyle(.fact)`
    /// themselves (a Toggle or Picker is a LabeledContent too, so not list-wide).
    func faroList() -> some View {
        self
            .scrollContentBackground(.hidden)
            .background(Theme.bg)
            .listRowSeparatorTint(Theme.border)
    }

    /// One List section's rows on the surface colour.
    func faroRows() -> some View {
        self
            .listRowBackground(Theme.surface)
            .listRowSeparatorTint(Theme.border)
    }
}

/// A small, letter-spaced label over a group of things (`.eyebrow` on the web).
struct Eyebrow: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text.uppercased())
            .font(.mono(11, .medium, relativeTo: .caption))
            .tracking(1)
            .foregroundStyle(Theme.muted)
            .accessibilityAddTraits(.isHeader)
    }
}

/// A key and its value: the key small and muted, both in the code face.
struct FactLabeledContentStyle: LabeledContentStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            configuration.label
                .font(.mono(12, relativeTo: .footnote))
                .foregroundStyle(Theme.muted)
                .fixedSize()
            Spacer(minLength: 8)
            configuration.content
                .font(.mono(14, relativeTo: .body))
                .foregroundStyle(Theme.text)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }
}

extension LabeledContentStyle where Self == FactLabeledContentStyle {
    static var fact: FactLabeledContentStyle { FactLabeledContentStyle() }
}

// MARK: - Buttons

/// Faro's buttons: the code face, a small radius, and a filled or outlined
/// body. `wide` fills the width, as for the main action on a page.
struct FaroButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, danger }
    var kind: Kind = .primary
    var wide = true
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.mono(15, .medium, relativeTo: .body))
            .padding(.vertical, 13)
            .padding(.horizontal, 18)
            .frame(maxWidth: wide ? .infinity : nil)
            .foregroundStyle(foreground)
            .background(
                RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                    .fill(fill.opacity(configuration.isPressed ? 0.82 : 1)))
            .overlay(
                RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                    .strokeBorder(stroke, lineWidth: 1))
            .contentShape(Rectangle())
    }

    private var fill: Color {
        guard isEnabled else { return Theme.surface2 }
        switch kind {
        case .primary: return Theme.accent
        case .secondary: return Theme.surface
        case .danger: return Theme.danger
        }
    }

    private var foreground: Color {
        guard isEnabled else { return Theme.muted }
        switch kind {
        case .primary: return Theme.accentText
        case .secondary: return Theme.text
        case .danger: return Theme.surface
        }
    }

    private var stroke: Color {
        switch kind {
        case .secondary: return Theme.borderStrong
        default: return isEnabled ? .clear : Theme.border
        }
    }
}

extension ButtonStyle where Self == FaroButtonStyle {
    static var faroPrimary: FaroButtonStyle { FaroButtonStyle(kind: .primary) }
    static var faroSecondary: FaroButtonStyle { FaroButtonStyle(kind: .secondary) }
    static var faroDanger: FaroButtonStyle { FaroButtonStyle(kind: .danger) }
}

/// A quiet text button in the code face, for "Back", "Stay", "Check now".
struct FaroLinkButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.mono(14, .medium, relativeTo: .body))
            .foregroundStyle(Theme.accent)
            .opacity(configuration.isPressed ? 0.6 : 1)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
    }
}

extension ButtonStyle where Self == FaroLinkButtonStyle {
    static var faroLink: FaroLinkButtonStyle { FaroLinkButtonStyle() }
}

// MARK: - Fields

/// A text field in the code face on a hairline box.
struct FaroFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .font(.mono(15, relativeTo: .body))
            .padding(.vertical, 12)
            .padding(.horizontal, 12)
            .background(
                RoundedRectangle(cornerRadius: Theme.radiusSmall, style: .continuous)
                    .fill(Theme.surface))
            .overlay(
                RoundedRectangle(cornerRadius: Theme.radiusSmall, style: .continuous)
                    .strokeBorder(Theme.borderStrong, lineWidth: 1))
    }
}

extension TextFieldStyle where Self == FaroFieldStyle {
    static var faro: FaroFieldStyle { FaroFieldStyle() }
}

// MARK: - Pieces

/// A raised box with a hairline border (`.card` on the web).
struct Card<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                    .fill(Theme.surface))
            .overlay(
                RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                    .strokeBorder(Theme.border, lineWidth: 1))
    }
}

/// A tinted panel with a rule on the left and an icon (`.notice` on the web).
struct Notice: View {
    enum Kind { case info, ok, warn, error }
    let kind: Kind
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(tone)
                .accessibilityHidden(true)
            Text(text)
                .font(.subheadline)
                .foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 11)
        .padding(.horizontal, 12)
        .background(tone.opacity(0.08))
        .overlay(alignment: .leading) { Rectangle().fill(tone).frame(width: 2) }
        .clipShape(RoundedRectangle(cornerRadius: Theme.radiusSmall, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var tone: Color {
        switch kind {
        case .info: return Theme.accent
        case .ok: return Theme.ok
        case .warn: return Theme.warn
        case .error: return Theme.danger
        }
    }

    private var symbol: String {
        switch kind {
        case .info: return "info.circle"
        case .ok: return "checkmark.circle"
        case .warn: return "exclamationmark.triangle"
        case .error: return "exclamationmark.circle"
        }
    }
}

/// A code people read aloud or compare: fingerprints and safety codes.
struct CodeBox: View {
    let code: String

    var body: some View {
        Text(code)
            .font(.mono(16, .medium, relativeTo: .body))
            .tracking(1)
            .foregroundStyle(Theme.text)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 12)
            .padding(.horizontal, 14)
            .background(
                RoundedRectangle(cornerRadius: Theme.radiusSmall, style: .continuous)
                    .fill(Theme.surface2))
            .overlay(
                RoundedRectangle(cornerRadius: Theme.radiusSmall, style: .continuous)
                    .strokeBorder(Theme.borderStrong, style: StrokeStyle(lineWidth: 1, dash: [4, 3])))
    }
}

/// A small square-cornered tag in the code face (`.chip` on the web).
struct Chip: View {
    enum Tone { case neutral, good, warn, bad }
    let text: String
    var tone: Tone = .neutral

    var body: some View {
        Text(text)
            .font(.mono(11, .medium, relativeTo: .caption))
            .foregroundStyle(color)
            .padding(.vertical, 2)
            .padding(.horizontal, 6)
            .background(
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .fill(tone == .neutral ? Theme.surface2 : color.opacity(0.1)))
            .overlay(
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .strokeBorder(tone == .neutral ? Theme.border : color.opacity(0.35), lineWidth: 1))
    }

    private var color: Color {
        switch tone {
        case .neutral: return Theme.muted
        case .good: return Theme.ok
        case .warn: return Theme.warn
        case .bad: return Theme.danger
        }
    }
}
