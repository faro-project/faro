import Foundation

/// The member's choices as the DNS filter wants them, and where the tunnel
/// finds them (docs/IOS.md §7, §9).
///
/// The tunnel reads `filter.json` in the app group, which it can't before
/// the first unlock after a reboot. The app also copies the choices into the
/// tunnel's `NETunnelProviderProtocol.providerConfiguration`, which the
/// tunnel can read at once, so an opted-in gambling block holds from the
/// first lookup. The copy is only written when the app runs, though, while a
/// loosening can apply later from the monitor or the tunnel. So each copy
/// carries the settings' `generation`, and the tunnel takes the newer one,
/// the provider configuration when they tie.
public enum TunnelConfig {
    /// Keys of the provider configuration dictionary.
    public static let filterKey = "filter"
    public static let generationKey = "generation"

    /// A `faro_dnsfilter::FilterConfig` as JSON: the optional categories, the
    /// member's sites and the sites never blocked. Names that aren't valid
    /// host names are left out, because the filter refuses a config with one.
    public static func filterJSON(for settings: FaroSettings) -> Data {
        let categories = Set(settings.blockedCategories)
            .intersection(IosSettingKey.optionalCategories).sorted()
        let object: [String: Any] = [
            "categories": categories,
            "block": ScreenTimePlan.cleanDomains(settings.extraBlockedDomains, limit: 10_000),
            "allow": ScreenTimePlan.cleanDomains(settings.allowedDomains, limit: 10_000),
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
    }

    /// The dictionary for `providerConfiguration`. Property-list values only.
    public static func providerConfiguration(for settings: FaroSettings) -> [String: Any] {
        [
            filterKey: String(decoding: filterJSON(for: settings), as: UTF8.self),
            generationKey: settings.generation,
        ]
    }

    /// The filter config the tunnel should use: the provider configuration's
    /// copy, unless `filter.json` (with the settings' generation) is newer;
    /// `nil` when neither can be read.
    public static func choose(
        provider: [String: Any]?, fileJSON: String?, fileGeneration: Int?
    ) -> String? {
        let copy = (provider?[filterKey] as? String).map {
            (json: $0, generation: (provider?[generationKey] as? Int) ?? 0)
        }
        switch (copy, fileJSON) {
        case let (copy?, file?):
            if let g = fileGeneration, g > copy.generation { return file }
            return copy.json
        case let (copy?, nil):
            return copy.json
        case let (nil, file?):
            return file
        case (nil, nil):
            return nil
        }
    }
}
