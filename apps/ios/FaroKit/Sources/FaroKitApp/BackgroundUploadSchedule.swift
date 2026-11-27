import Foundation

/// The background refresh that keeps a phone with its tunnel off checking
/// in, and sends what the outbox holds (docs/IOS.md §10.1). iOS decides
/// when, if at all; the request only names the earliest time.
public enum BackgroundUploadSchedule {
    /// The `BGAppRefreshTask` identifier (also in Info.plist).
    public static let taskIdentifier = "org.faro.ios.heartbeat-upload"
    /// The earliest the next run may begin.
    public static let interval: TimeInterval = 15 * 60

    public static func nextBegin(nowMs: Int64) -> Date {
        Date(timeIntervalSince1970: Double(nowMs) / 1000 + interval)
    }
}
