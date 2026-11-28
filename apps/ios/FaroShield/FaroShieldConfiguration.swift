import FaroKit
import ManagedSettings
import ManagedSettingsUI
import UIKit

/// The block screen's look and words (docs/IOS.md §6.4). It counts how
/// often it is shown, never which app or site. Foundation, UIKit and the
/// Screen Time frameworks only: no Rust core (6 MB limit).
final class FaroShieldConfiguration: ShieldConfigurationDataSource {
    override func configuration(shielding application: Application) -> ShieldConfiguration {
        shield()
    }

    override func configuration(shielding application: Application, in category: ActivityCategory) -> ShieldConfiguration {
        shield()
    }

    override func configuration(shielding webDomain: WebDomain) -> ShieldConfiguration {
        shield()
    }

    override func configuration(shielding webDomain: WebDomain, in category: ActivityCategory) -> ShieldConfiguration {
        shield()
    }

    private func shield() -> ShieldConfiguration {
        if let group = AppGroup.container(), let counter = try? Counter(group: group, name: CounterName.shieldShown) {
            _ = try? counter.increment()
        }
        return ShieldConfiguration(
            backgroundBlurStyle: nil,
            backgroundColor: Palette.background,
            title: ShieldConfiguration.Label(text: ShieldText.title, color: Palette.text),
            subtitle: ShieldConfiguration.Label(text: ShieldText.subtitle, color: Palette.muted),
            primaryButtonLabel: ShieldConfiguration.Label(text: ShieldText.closeButton, color: Palette.accentText),
            primaryButtonBackgroundColor: Palette.accent)
    }
}

/// The app's colours (Faro/Theme.swift, web/src/app.css), repeated here
/// because the extension links nothing else. A shield can't use custom
/// fonts, so only the colours match.
private enum Palette {
    static let background = dynamic(light: 0xF7F7F5, dark: 0x181818)
    static let text = dynamic(light: 0x1B1A18, dark: 0xECECEC)
    static let muted = dynamic(light: 0x5F5C56, dark: 0xA3A3A3)
    static let accent = dynamic(light: 0xA14A0C, dark: 0xF19E4B)
    static let accentText = dynamic(light: 0xFFFFFF, dark: 0x1A1006)

    private static func dynamic(light: UInt32, dark: UInt32) -> UIColor {
        UIColor { $0.userInterfaceStyle == .dark ? rgb(dark) : rgb(light) }
    }

    private static func rgb(_ hex: UInt32) -> UIColor {
        UIColor(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
}
