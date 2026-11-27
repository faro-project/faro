import FaroKit
import Foundation

extension SettingChange {
    /// What the change does, in the member's own words, for the choices
    /// screen. Other people's screens use the web app's wording (`ios-settings.ts`).
    public var summary: String {
        func categoryName(_ n: String) -> String {
            switch n {
            case "gambling": return "gambling"
            case "violence": return "violent"
            case "proxy_vpn": return "proxy and VPN"
            default: return n
            }
        }
        let blocking = new == "blocked" || new == "on"
        switch key {
        case _ where key.hasPrefix(IosSettingKey.categoryPrefix):
            let name = categoryName(String(key.dropFirst(IosSettingKey.categoryPrefix.count)))
            return blocking ? "Block \(name) sites" : "Stop blocking \(name) sites"
        case IosSettingKey.site:
            return new.map { "Block \($0)" } ?? "Stop blocking \(old ?? "a site")"
        case IosSettingKey.apps: return "Blocked apps: \(old ?? "0") to \(new ?? "0")"
        case IosSettingKey.appCategories: return "Blocked app categories: \(old ?? "0") to \(new ?? "0")"
        case IosSettingKey.webDomains: return "Blocked websites from the list: \(old ?? "0") to \(new ?? "0")"
        case IosSettingKey.webDomainCategories:
            return "Blocked website categories: \(old ?? "0") to \(new ?? "0")"
        case IosSettingKey.explicitMedia: return blocking ? "Block explicit media" : "Allow explicit media"
        case IosSettingKey.appRemovalProtection:
            return blocking ? "Protect Faro from deletion" : "Allow deleting Faro"
        case IosSettingKey.automaticTime:
            return blocking ? "Require automatic date and time" : "Stop requiring automatic date and time"
        case IosSettingKey.appRating:
            return new == "off" || new == nil ? "Remove the App Store age limit" : "Limit the App Store to \(new ?? "")+"
        case IosSettingKey.delayHours:
            return "Wait \(new ?? "0") hours before loosening"
        default: return key
        }
    }
}
