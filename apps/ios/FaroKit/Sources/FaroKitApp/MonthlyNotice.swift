import FaroKit
import Foundation

/// The monthly notice (docs/IOS.md §12, ARCHITECTURE.md §12): a local
/// notification, once a month, that opens a screen listing the instance
/// and who it reports to. This is its schedule.
public enum MonthlyNotice {
    /// The notification's request identifier.
    public static let identifier = "org.faro.ios.monthly-notice"
    /// `userInfo[routeKey] == routeValue` on the notification, so the app
    /// knows to open the notice screen.
    public static let routeKey = "faro"
    public static let routeValue = "notice"

    /// The day of the month and time of day it fires, from when this phone
    /// was enrolled. Days 29 to 31 become the 28th, so every month has one,
    /// and the hour is held to 09:00 to 20:59, never the small hours.
    public static func fireComponents(enrolledAt: Date, calendar: Calendar = .current) -> DateComponents {
        let c = calendar.dateComponents([.day, .hour, .minute], from: enrolledAt)
        var out = DateComponents()
        out.day = min(c.day ?? 1, 28)
        out.hour = min(max(c.hour ?? 10, 9), 20)
        out.minute = c.minute ?? 0
        return out
    }

    /// How the notice screen titles the ally at `position` (from 1): the
    /// name the member signed into the recipient list, or "Ally 2" when
    /// the list names no one (one signed before names were added) or this
    /// ally has no name. `name` comes from the Rust core, which has checked
    /// the member's signature and sanitized it; it is shown verbatim, never
    /// as Markdown.
    public static func allyTitle(name: String?, position: Int) -> String {
        if let name, !name.isEmpty { return name }
        return "Ally \(position)"
    }

    /// Whether the list names every ally, so the screen can say the names
    /// are the member's own and not the instance's.
    public static func namesEveryAlly(_ names: [String?]) -> Bool {
        !names.isEmpty && names.allSatisfy { !($0 ?? "").isEmpty }
    }

    /// The first time it fires after `now`.
    public static func nextFire(enrolledAt: Date, after now: Date, calendar: Calendar = .current) -> Date? {
        calendar.nextDate(
            after: now, matching: fireComponents(enrolledAt: enrolledAt, calendar: calendar),
            matchingPolicy: .nextTime)
    }
}
