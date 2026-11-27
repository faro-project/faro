import Foundation

/// Names of the small files the extensions and the app share in the app
/// group. One place, so no target spells one on its own.
public enum CounterName {
    /// How many times the block screen was shown (docs/IOS.md §6.4).
    public static let shieldShown = "shield_shown"
    /// How many times its Close button was pressed.
    public static let shieldClosed = "shield_closed"
}

public enum MarkerName {
    /// Set by the monitor extension each time it runs (docs/IOS.md §6.3), so
    /// the app and the tunnel can tell it is still being called.
    public static let monitorAlive = "monitor_alive"
    /// Set by the packet tunnel every minute while it runs (docs/IOS.md
    /// §10.2). Older than `TunnelWatch.staleAfterMs` (20 minutes) while the
    /// phone is in use means the DNS filter is off.
    public static let tunnelAlive = "tunnel_alive"
    /// Set by the packet tunnel when the phone goes to sleep, and when it
    /// stops for a reason that isn't the member's (no network, an app
    /// update), so a quiet `tunnel_alive` then isn't read as the filter
    /// being switched off (`TunnelWatch`).
    public static let tunnelResting = "tunnel_resting"
}

/// The words on the block screen (docs/IOS.md §6.4).
public enum ShieldText {
    public static let title = "Blocked by Faro"
    public static let subtitle = "You chose to block this."
    public static let closeButton = "Close"
}

/// What the "faro" ManagedSettingsStore should hold, worked out from the
/// settings file. The Screen Time frameworks can't run on the host or in
/// the Simulator, so everything that is a decision lives here, where
/// `swift test` reaches it, and `ScreenTimeEnforcer` only copies the values
/// into the store (docs/IOS.md §6.2).
public struct ScreenTimePlan: Equatable, Sendable {
    /// `webContent.blockedByFilter = .auto(extra, except: allowed)`.
    public var extraBlockedDomains: [String]
    public var allowedDomains: [String]
    public var denyAppRemoval: Bool
    public var denyExplicitContent: Bool
    public var requireAutomaticDateAndTime: Bool
    /// `appStore.maximumRating`, `nil` for off.
    public var maximumAppRating: Int?

    /// The ratings the App Store accepts: 4+, 9+, 12+, 17+, and 1000 for "all".
    public static let validRatings: [Int] = [0, 4, 9, 12, 17, 1000]

    /// Longest hand-listed domain set sent to Apple. The filter takes few
    /// (docs/IOS.md §6.2, spike S2); the full list is layer 2's job.
    public static let maxDomains = 50

    public init(_ settings: FaroSettings) {
        extraBlockedDomains = ScreenTimePlan.cleanDomains(settings.extraBlockedDomains)
        // A domain the member both blocks and allows stays blocked.
        let blocked = Set(extraBlockedDomains)
        allowedDomains = ScreenTimePlan.cleanDomains(settings.allowedDomains).filter { !blocked.contains($0) }
        denyAppRemoval = settings.denyAppRemoval
        denyExplicitContent = settings.denyExplicitContent
        requireAutomaticDateAndTime = settings.requireAutomaticDateAndTime
        maximumAppRating = settings.maximumAppRating.flatMap { rating in
            ScreenTimePlan.validRatings.first { $0 >= rating }
        }
    }

    /// Lowercased, trimmed, without a scheme, path or leading dot, no
    /// duplicates, in a stable order. Entries that aren't a hostname are dropped.
    static func cleanDomains(_ raw: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for entry in raw {
            var d = entry.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if let r = d.range(of: "://") { d = String(d[r.upperBound...]) }
            if let slash = d.firstIndex(of: "/") { d = String(d[..<slash]) }
            while d.hasPrefix(".") { d.removeFirst() }
            while d.hasSuffix(".") { d.removeLast() }
            let labelsOK = d.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
                !$0.isEmpty && $0.count <= 63
                    && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
            }
            guard labelsOK, d.contains("."), d.count <= 253, seen.insert(d).inserted else { continue }
            out.append(d)
        }
        return Array(out.sorted().prefix(maxDomains))
    }
}

/// The monitor extension's schedule (docs/IOS.md §6.3). DeviceActivity won't
/// take an interval under 15 minutes, and a schedule repeats daily at the
/// same times, so "every 15 minutes" is a chain: each window runs from now
/// to 15 minutes on, and the extension starts the next one when it ends.
///
/// One dropped callback would stop a chain, and with it the re-applying
/// and the checks of §10.2, until the app next opens. So under the chain
/// there is a backbone: `backboneWindows` daily-repeating windows end to end
/// around the clock, whose every start and end also runs the checks and
/// restarts the chain. A dropped callback then costs at most one backbone
/// window. Apple allows about 20 monitored activities per app; this uses
/// 19 (the chain and 18 windows), leaving one spare.
public enum MonitorSchedule {
    /// The `DeviceActivityName` of the chain.
    public static let activityName = "faro.reapply"
    public static let windowMinutes = 15

    /// How many backbone windows, and how long each is (80 minutes).
    public static let backboneWindows = 18
    public static let backboneMinutes = 24 * 60 / backboneWindows

    /// The backbone's `DeviceActivityName`s, `faro.backbone.00` and on.
    public static var backboneNames: [String] {
        (0..<backboneWindows).map { String(format: "faro.backbone.%02d", $0) }
    }

    /// Every monitored activity: the chain, then the backbone.
    public static var allActivityNames: [String] { [activityName] + backboneNames }

    /// Whether `name` is a backbone window rather than the chain.
    public static func isBackbone(_ name: String) -> Bool { name.hasPrefix("faro.backbone.") }

    /// The longest the monitor goes without a callback while Screen Time
    /// stands, if one is dropped: one backbone window, plus a chain window
    /// of slack. An older `monitor_alive` means the monitor isn't being
    /// called (docs/IOS.md §10.3, spike S8).
    public static var monitorStaleAfterMs: Int64 { Int64(backboneMinutes + windowMinutes) * 60 * 1000 }

    /// Backbone window `index`: from `index * backboneMinutes` past
    /// midnight to the next one; the last ends at midnight.
    public static func backboneWindow(_ index: Int) -> (start: DateComponents, end: DateComponents) {
        func at(_ minutes: Int) -> DateComponents {
            let m = minutes % (24 * 60)
            return DateComponents(hour: m / 60, minute: m % 60, second: 0)
        }
        return (at(index * backboneMinutes), at((index + 1) * backboneMinutes))
    }

    /// The start and end of the chain window that begins at `date`.
    public static func window(
        from date: Date, calendar: Calendar = .current
    ) -> (start: DateComponents, end: DateComponents) {
        let end = date.addingTimeInterval(TimeInterval(windowMinutes * 60))
        let parts: Set<Calendar.Component> = [.hour, .minute, .second]
        return (calendar.dateComponents(parts, from: date), calendar.dateComponents(parts, from: end))
    }
}
