import FaroKit
import ManagedSettings

/// The block screen's Close button (docs/IOS.md §6.4). It counts the press,
/// never which app or site, and closes the shield. No Rust core (6 MB limit).
final class FaroShieldActionExtension: ShieldActionDelegate {
    override func handle(action: ShieldAction, for application: ApplicationToken, completionHandler: @escaping (ShieldActionResponse) -> Void) {
        completionHandler(respond(to: action))
    }

    override func handle(action: ShieldAction, for webDomain: WebDomainToken, completionHandler: @escaping (ShieldActionResponse) -> Void) {
        completionHandler(respond(to: action))
    }

    override func handle(action: ShieldAction, for category: ActivityCategoryToken, completionHandler: @escaping (ShieldActionResponse) -> Void) {
        completionHandler(respond(to: action))
    }

    private func respond(to action: ShieldAction) -> ShieldActionResponse {
        guard action == .primaryButtonPressed else { return .close }
        if let group = AppGroup.container(), let counter = try? Counter(group: group, name: "shield_closed") {
            _ = try? counter.increment()
        }
        return .close
    }
}
