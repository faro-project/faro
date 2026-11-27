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
            title: ShieldConfiguration.Label(text: ShieldText.title, color: .label),
            subtitle: ShieldConfiguration.Label(text: ShieldText.subtitle, color: .secondaryLabel),
            primaryButtonLabel: ShieldConfiguration.Label(text: ShieldText.closeButton, color: .white))
    }
}
