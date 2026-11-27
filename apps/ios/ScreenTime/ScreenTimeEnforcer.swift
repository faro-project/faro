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
/// The shields hold the member's `FamilyActivityPicker` choices as opaque
/// tokens: the settings file keeps each token's JSON, base64 encoded, and
/// Faro never learns which app one is (docs/IOS.md §4 principle 4).
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

        let apps = Set(tokens(plan.shieldApps, as: ApplicationToken.self))
        store.shield.applications = apps.isEmpty ? nil : apps
        let appCategories = Set(tokens(plan.shieldAppCategories, as: ActivityCategoryToken.self))
        store.shield.applicationCategories = appCategories.isEmpty ? nil : .specific(appCategories)
        let sites = Set(tokens(plan.shieldWebDomains, as: WebDomainToken.self))
        store.shield.webDomains = sites.isEmpty ? nil : sites
        let siteCategories = Set(tokens(plan.shieldWebDomainCategories, as: ActivityCategoryToken.self))
        store.shield.webDomainCategories = siteCategories.isEmpty ? nil : .specific(siteCategories)
    }

    /// The tokens a list of encoded ones stands for. One that no longer
    /// decodes is skipped: it can't name an app any more.
    private static func tokens<T: Decodable>(_ encoded: [String], as: T.Type) -> [T] {
        encoded.compactMap { Data(base64Encoded: $0).flatMap { try? JSONDecoder().decode(T.self, from: $0) } }
    }

    /// A token as the settings file keeps it.
    static func encode<T: Encodable>(_ token: T) -> String? {
        try? JSONEncoder().encode(token).base64EncodedString()
    }

    /// Re-applies the settings file in the app group, after applying any
    /// loosening whose time has come (docs/IOS.md §9; the app, the monitor
    /// and the tunnel each do this, whichever runs first). With no file
    /// (setup hasn't run), a file from a newer Faro or a damaged one, it
    /// leaves the store alone and returns false rather than guess.
    @discardableResult
    static func applySavedSettings(group: AppGroup? = AppGroup.container()) -> Bool {
        guard let group else { return false }
        _ = try? ChoicesStore(group: group).applyDue(nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        guard let settings = try? SettingsStore(group: group).load() else { return false }
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
