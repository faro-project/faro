import DeviceActivity
import FaroKit
import Foundation
import ManagedSettings

/// Writes the "faro" ManagedSettingsStore (docs/IOS.md §6.2) and keeps the
/// monitor schedule running (§6.3). The app calls `apply` at setup and on
/// every foreground; the monitor extension calls it from its callbacks.
/// Compiled into both. It is small and has no Rust, no networking and no
/// crypto, because the monitor has a 6 MB limit. What to write is decided
/// by `ScreenTimePlan` in FaroKit, which the tests cover; this file only
/// copies it into the store, and it only runs on a device.
///
/// It never touches the app, category or site shields: Phase B's picker
/// owns those, and they stay empty until then.
enum ScreenTimeEnforcer {
    static let storeName = ManagedSettingsStore.Name("faro")

    /// Writes `settings` into the store.
    static func apply(_ settings: FaroSettings) {
        let plan = ScreenTimePlan(settings)
        let store = ManagedSettingsStore(named: storeName)

        let extra = Set(plan.extraBlockedDomains.map { WebDomain(domain: $0) })
        let allowed = Set(plan.allowedDomains.map { WebDomain(domain: $0) })
        store.webContent.blockedByFilter = .auto(extra, except: allowed)
        store.application.denyAppRemoval = plan.denyAppRemoval
        store.media.denyExplicitContent = plan.denyExplicitContent
        store.dateAndTime.requireAutomaticDateAndTime = plan.requireAutomaticDateAndTime
        store.appStore.maximumRating = plan.maximumAppRating
    }

    /// Re-applies the settings file in the app group. With no file (setup
    /// hasn't run), a file from a newer Faro or a damaged one, it leaves the
    /// store alone and returns false rather than guess.
    @discardableResult
    static func applySavedSettings(group: AppGroup? = AppGroup.container()) -> Bool {
        guard let group, let settings = try? SettingsStore(group: group).load() else { return false }
        apply(settings)
        return true
    }

    /// What the app does each time it comes to the foreground: re-apply the
    /// saved settings and, if that found any, make sure the monitor's chain
    /// of windows is running.
    static func refreshOnForeground() {
        if applySavedSettings() { startMonitoring() }
    }

    /// Starts (or restarts) the monitor's 15-minute window from `date`.
    /// Returns false if DeviceActivity refused, which happens without
    /// Screen Time authorization.
    @discardableResult
    static func startMonitoring(from date: Date = Date()) -> Bool {
        let window = MonitorSchedule.window(from: date)
        let schedule = DeviceActivitySchedule(
            intervalStart: window.start, intervalEnd: window.end, repeats: true)
        do {
            try DeviceActivityCenter().startMonitoring(
                DeviceActivityName(MonitorSchedule.activityName), during: schedule)
            return true
        } catch {
            return false
        }
    }
}
