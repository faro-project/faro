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
/// to 15 minutes on, and the extension starts the next one when it ends. The
/// window also repeats daily, so if the chain is ever broken the monitor
/// still runs once a day until the app restarts it.
public enum MonitorSchedule {
    /// The `DeviceActivityName` of the one activity.
    public static let activityName = "faro.reapply"
    public static let windowMinutes = 15

    /// The start and end of the window that begins at `date`.
    public static func window(
        from date: Date, calendar: Calendar = .current
    ) -> (start: DateComponents, end: DateComponents) {
        let end = date.addingTimeInterval(TimeInterval(windowMinutes * 60))
        let parts: Set<Calendar.Component> = [.hour, .minute, .second]
        return (calendar.dateComponents(parts, from: date), calendar.dateComponents(parts, from: end))
    }
}
