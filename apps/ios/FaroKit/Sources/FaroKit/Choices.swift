import Foundation

/// The keys of an iPhone `settings_change` (docs/IOS.md §9, PROTOCOL.md §3).
/// The web app renders them in words ("Gambling sites will be unblocked on
/// iPhone-X tomorrow at 21:04"), so a key or a value format changes in both
/// places or in neither (`web/src/lib/feed/ios-settings.ts`).
///
/// | Key | old / new |
/// |---|---|
/// | `ios.category.<name>` (`gambling`, `violence`, `proxy_vpn`) | `blocked` or `allowed` |
/// | `ios.site` | the domain: `old` is set when it was unblocked, `new` when it was blocked |
/// | `ios.apps`, `ios.app_categories`, `ios.web_domains`, `ios.web_domain_categories` | how many are shielded (a count: which ones is never sent) |
/// | `ios.explicit_media`, `ios.app_removal_protection`, `ios.automatic_time` | `on` or `off` |
/// | `ios.app_rating` | `4`, `9`, `12`, `17`, or `off` |
/// | `ios.delay_hours` | the loosening delay in hours, `0` to `72` |
public enum IosSettingKey {
    public static let categoryPrefix = "ios.category."
    public static let site = "ios.site"
    public static let apps = "ios.apps"
    public static let appCategories = "ios.app_categories"
    public static let webDomains = "ios.web_domains"
    public static let webDomainCategories = "ios.web_domain_categories"
    public static let explicitMedia = "ios.explicit_media"
    public static let appRemovalProtection = "ios.app_removal_protection"
    public static let automaticTime = "ios.automatic_time"
    public static let appRating = "ios.app_rating"
    public static let delayHours = "ios.delay_hours"

    public static func category(_ name: String) -> String { categoryPrefix + name }

    /// The categories the DNS filter can block on top of adult.
    public static let optionalCategories = ["gambling", "violence", "proxy_vpn"]
}

/// What a change does to `FaroSettings`, kept with a pending loosening so
/// it can be applied later, to whatever the settings are by then.
public struct SettingOp: Codable, Equatable, Sendable {
    public enum Field: String, Codable, Sendable {
        case blockedCategories, extraBlockedDomains
        case shieldApps, shieldAppCategories, shieldWebDomains, shieldWebDomainCategories
        case explicitMedia, appRemoval, automaticTime, appRating, delayHours
    }

    public var field: Field
    /// For the set-valued fields.
    public var add: [String]
    public var remove: [String]
    /// For the single-valued fields: `on`/`off`, a rating or `off`, hours.
    public var value: String?

    public init(field: Field, add: [String] = [], remove: [String] = [], value: String? = nil) {
        self.field = field
        self.add = add
        self.remove = remove
        self.value = value
    }

    var isSet: Bool {
        switch field {
        case .blockedCategories, .extraBlockedDomains, .shieldApps, .shieldAppCategories,
             .shieldWebDomains, .shieldWebDomainCategories:
            return true
        default:
            return false
        }
    }

    /// Whether the two touch the same thing: the same single value, or a
    /// set field with an element in common.
    func overlaps(_ other: SettingOp) -> Bool {
        guard field == other.field else { return false }
        if !isSet { return true }
        return !Set(add + remove).isDisjoint(with: other.add + other.remove)
    }
}

/// One entry of a `settings_change`: the key, the value before and after
/// (see `IosSettingKey`), and the op that does it.
public struct SettingChange: Codable, Equatable, Sendable {
    public var key: String
    public var old: String?
    public var new: String?
    public var op: SettingOp

    public init(key: String, old: String?, new: String?, op: SettingOp) {
        self.key = key
        self.old = old
        self.new = new
        self.op = op
    }
}

extension FaroSettings {
    /// Applies `op`. Adding what is there, or removing what isn't, changes
    /// nothing, so applying a pending op twice is harmless.
    public mutating func apply(_ op: SettingOp) {
        func edit(_ list: inout [String]) {
            var set = Set(list)
            set.subtract(op.remove)
            set.formUnion(op.add)
            list = set.sorted()
        }
        switch op.field {
        case .blockedCategories: edit(&blockedCategories)
        case .extraBlockedDomains: edit(&extraBlockedDomains)
        case .shieldApps: edit(&shieldApps)
        case .shieldAppCategories: edit(&shieldAppCategories)
        case .shieldWebDomains: edit(&shieldWebDomains)
        case .shieldWebDomainCategories: edit(&shieldWebDomainCategories)
        case .explicitMedia: denyExplicitContent = op.value == "on"
        case .appRemoval: denyAppRemoval = op.value == "on"
        case .automaticTime: requireAutomaticDateAndTime = op.value == "on"
        case .appRating: maximumAppRating = op.value.flatMap { Int($0) }
        case .delayHours:
            if let hours = op.value.flatMap({ Int($0) }) {
                loosenDelayHours = min(max(hours, 0), FaroSettings.maxLoosenDelayHours)
            }
        }
    }

    /// The App Store rating as the member sees it: a valid rating, or `nil`
    /// for no limit (also what 1000, "all", means).
    var effectiveRating: Int? {
        guard let r = maximumAppRating else { return nil }
        guard let valid = ScreenTimePlan.validRatings.first(where: { $0 >= r }), valid < 1000 else { return nil }
        return valid
    }
}

/// What changing the settings from one state to another means: which part
/// blocks more and applies at once, which part blocks less and waits
/// (docs/IOS.md §9).
public struct ChoiceDiff: Equatable, Sendable {
    public var tightening: [SettingChange] = []
    public var loosening: [SettingChange] = []

    public var isEmpty: Bool { tightening.isEmpty && loosening.isEmpty }

    /// The most entries a `settings_change` carries (`MAX_SETTING_CHANGES`).
    public static let maxChangesPerEvent = 32

    /// The changes from `old` to `new`. Only the member's choices are
    /// compared (never `allowedDomains` or `generation`). Where one field
    /// both gains and loses entries, the gains come first, so a loosening's
    /// `old` is the state after the tightening.
    public static func between(_ old: FaroSettings, _ new: FaroSettings) -> ChoiceDiff {
        var diff = ChoiceDiff()

        // Sets of names: one change per name.
        func names(
            _ field: SettingOp.Field, _ before: [String], _ after: [String],
            key: (String) -> String, blocked: String, allowed: String
        ) {
            let b = Set(before), a = Set(after)
            for n in a.subtracting(b).sorted() {
                diff.tightening.append(SettingChange(
                    key: key(n), old: allowed, new: blocked, op: SettingOp(field: field, add: [n])))
            }
            for n in b.subtracting(a).sorted() {
                diff.loosening.append(SettingChange(
                    key: key(n), old: blocked, new: allowed, op: SettingOp(field: field, remove: [n])))
            }
        }
        names(.blockedCategories, old.blockedCategories, new.blockedCategories,
              key: IosSettingKey.category, blocked: "blocked", allowed: "allowed")

        // Sites carry the domain itself: `new` set means blocked.
        let beforeSites = Set(old.extraBlockedDomains), afterSites = Set(new.extraBlockedDomains)
        for d in afterSites.subtracting(beforeSites).sorted() {
            diff.tightening.append(SettingChange(
                key: IosSettingKey.site, old: nil, new: d,
                op: SettingOp(field: .extraBlockedDomains, add: [d])))
        }
        for d in beforeSites.subtracting(afterSites).sorted() {
            diff.loosening.append(SettingChange(
                key: IosSettingKey.site, old: d, new: nil,
                op: SettingOp(field: .extraBlockedDomains, remove: [d])))
        }

        // Picker tokens: a count, never which.
        func tokens(_ field: SettingOp.Field, _ key: String, _ before: [String], _ after: [String]) {
            let b = Set(before), a = Set(after)
            let added = a.subtracting(b).sorted(), removed = b.subtracting(a).sorted()
            if !added.isEmpty {
                diff.tightening.append(SettingChange(
                    key: key, old: String(b.count), new: String(b.count + added.count),
                    op: SettingOp(field: field, add: added)))
            }
            if !removed.isEmpty {
                diff.loosening.append(SettingChange(
                    key: key, old: String(b.count + added.count), new: String(a.count),
                    op: SettingOp(field: field, remove: removed)))
            }
        }
        tokens(.shieldApps, IosSettingKey.apps, old.shieldApps, new.shieldApps)
        tokens(.shieldAppCategories, IosSettingKey.appCategories, old.shieldAppCategories, new.shieldAppCategories)
        tokens(.shieldWebDomains, IosSettingKey.webDomains, old.shieldWebDomains, new.shieldWebDomains)
        tokens(.shieldWebDomainCategories, IosSettingKey.webDomainCategories,
               old.shieldWebDomainCategories, new.shieldWebDomainCategories)

        // On/off protections: off blocks less.
        func toggle(_ field: SettingOp.Field, _ key: String, _ before: Bool, _ after: Bool) {
            guard before != after else { return }
            let change = SettingChange(
                key: key, old: before ? "on" : "off", new: after ? "on" : "off",
                op: SettingOp(field: field, value: after ? "on" : "off"))
            if after { diff.tightening.append(change) } else { diff.loosening.append(change) }
        }
        toggle(.explicitMedia, IosSettingKey.explicitMedia, old.denyExplicitContent, new.denyExplicitContent)
        toggle(.appRemoval, IosSettingKey.appRemovalProtection, old.denyAppRemoval, new.denyAppRemoval)
        toggle(.automaticTime, IosSettingKey.automaticTime,
               old.requireAutomaticDateAndTime, new.requireAutomaticDateAndTime)

        // The App Store rating: a lower limit blocks more, no limit least.
        let r0 = old.effectiveRating, r1 = new.effectiveRating
        if r0 != r1 {
            let change = SettingChange(
                key: IosSettingKey.appRating, old: r0.map(String.init) ?? "off", new: r1.map(String.init) ?? "off",
                op: SettingOp(field: .appRating, value: r1.map(String.init) ?? "off"))
            if (r1 ?? Int.max) < (r0 ?? Int.max) { diff.tightening.append(change) } else { diff.loosening.append(change) }
        }

        // The delay: a shorter wait is a loosening.
        let d0 = clampHours(old.loosenDelayHours), d1 = clampHours(new.loosenDelayHours)
        if d0 != d1 {
            let change = SettingChange(
                key: IosSettingKey.delayHours, old: String(d0), new: String(d1),
                op: SettingOp(field: .delayHours, value: String(d1)))
            if d1 > d0 { diff.tightening.append(change) } else { diff.loosening.append(change) }
        }
        return diff
    }

    static func clampHours(_ h: Int) -> Int { min(max(h, 0), FaroSettings.maxLoosenDelayHours) }

    /// Splits into groups a `settings_change` can carry.
    public static func chunks(_ changes: [SettingChange]) -> [[SettingChange]] {
        stride(from: 0, to: changes.count, by: maxChangesPerEvent).map {
            Array(changes[$0..<min($0 + maxChangesPerEvent, changes.count)])
        }
    }
}
