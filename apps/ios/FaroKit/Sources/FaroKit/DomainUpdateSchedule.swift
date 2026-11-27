import Foundation

/// When the app looks for a newer domain list on the instance's update
/// channel (docs/IOS.md §7.2). The desktop service checks about every 6
/// hours; the app does the same, in the foreground and from a background
/// refresh, and skips a check made recently. The tunnel never downloads.
public enum DomainUpdateSchedule {
    /// The `BGAppRefreshTask` identifier (also in Info.plist).
    public static let taskIdentifier = "org.faro.ios.refresh-domains"
    /// Marker (in the app group) with the time of the last check, whether
    /// it found anything or not.
    public static let checkedMarker = "domains_checked"
    /// The least time between two checks.
    public static let interval: TimeInterval = 6 * 3600

    /// Whether a check is due at `nowMs`, given the last one (`nil`: never).
    /// A last check in the future (the clock moved back) counts as due.
    public static func isDue(lastCheckMs: Int64?, nowMs: Int64) -> Bool {
        guard let last = lastCheckMs else { return true }
        let age = nowMs - last
        return age < 0 || Double(age) >= interval * 1000
    }

    /// The earliest time to ask iOS to run the background refresh again.
    public static func nextBegin(lastCheckMs: Int64?, nowMs: Int64) -> Date {
        let base = lastCheckMs.map { min($0, nowMs) } ?? nowMs
        return Date(timeIntervalSince1970: Double(base) / 1000 + interval)
    }
}
