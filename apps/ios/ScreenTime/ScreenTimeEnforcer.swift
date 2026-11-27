import DeviceActivity
import FamilyControls
import FaroKit
import Foundation
import ManagedSettings

/// Writes the "faro" ManagedSettingsStore (docs/IOS.md §6.2), reads it back
/// for the check of §10.2, and keeps the monitor schedule running (§6.3).
/// The app calls it at setup and on every foreground; the monitor extension
/// calls it from its callbacks. Compiled into both. It is small and has no
/// Rust, no networking and no crypto, because the monitor has a 6 MB limit.
/// What to write, and whether what it reads back is still Faro's, are
/// decided by `ScreenTimePlan` and `StoreCheck` in FaroKit, which the tests
/// cover; this file only copies values in and out, and it only runs on a
/// device.
///
/// The shields hold the member's `FamilyActivityPicker` choices as opaque
/// tokens: the settings file keeps each token's JSON, base64 encoded, and
/// Faro never learns which app one is (docs/IOS.md §4 principle 4).
enum ScreenTimeEnforcer {
    static let storeName = ManagedSettingsStore.Name("faro")

    /// Whether Faro's Screen Time authorization stands right now.
    static var isAuthorized: Bool {
        AuthorizationCenter.shared.authorizationStatus == .approved
    }

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

    /// What the store holds now (the settings `StoreCheck` judges; the
    /// shields are the member's own picks and aren't judged).
    static func snapshot() -> StoreSnapshot {
        let store = ManagedSettingsStore(named: storeName)
        return StoreSnapshot(
            webFilterOn: store.webContent.blockedByFilter != nil,
            denyAppRemoval: store.application.denyAppRemoval,
            denyExplicitContent: store.media.denyExplicitContent,
            requireAutomaticDateAndTime: store.dateAndTime.requireAutomaticDateAndTime,
            maximumAppRating: store.appStore.maximumRating)
    }

    /// What re-applying found: whether the store still held Faro's settings
    /// before, and whether it does after.
    struct Finding {
        var wasIntact: Bool
        var nowIntact: Bool
    }

    /// Re-applies the settings file in the app group, after applying any
    /// loosening whose time has come (docs/IOS.md §9; the app, the monitor
    /// and the tunnel each do this, whichever runs first), and checks the
    /// store first. It is judged against the settings in force before a
    /// loosening applied, so a loosening isn't mistaken for the store being
    /// cleared. With no file (setup hasn't run), a file from a newer Faro or
    /// a damaged one, it leaves the store alone and returns nil rather than
    /// guess.
    @discardableResult
    static func reapplySavedSettings(group: AppGroup? = AppGroup.container()) -> Finding? {
        guard let group else { return nil }
        let inForce = try? SettingsStore(group: group).load()
        _ = try? ChoicesStore(group: group).applyDue(nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        guard let settings = try? SettingsStore(group: group).load() else { return nil }
        let before = StoreCheck.intact(snapshot(), plan: ScreenTimePlan(inForce ?? settings))
        let plan = ScreenTimePlan(settings)
        apply(settings)
        return Finding(wasIntact: before, nowIntact: StoreCheck.intact(snapshot(), plan: plan))
    }

    /// `reapplySavedSettings`, for callers that only want the settings in
    /// place. Returns whether there were any.
    @discardableResult
    static func applySavedSettings(group: AppGroup? = AppGroup.container()) -> Bool {
        reapplySavedSettings(group: group) != nil
    }

    /// The store check of docs/IOS.md §10.2, for the monitor and the app:
    /// while authorization stands, a store found cleared or changed is
    /// `SettingsCleared`, put right at once, and news again only after it
    /// was seen intact. Returns whether there were settings to apply.
    @discardableResult
    static func reapplyAndCheck(group: AppGroup, ledger: TamperLedger, nowMs: Int64) -> Bool {
        guard isAuthorized, let found = reapplySavedSettings(group: group) else { return false }
        try? ledger.update { book in
            if !found.wasIntact { book.sawOff(.settingsCleared, nowMs: nowMs) }
            if found.nowIntact { book.sawOn(.settings) }
        }
        return true
    }

    /// Starts (or restarts) the monitor's chain window from `date`, and the
    /// backbone of daily windows under it (`MonitorSchedule`). Returns false
    /// if DeviceActivity refused, which happens without Screen Time
    /// authorization.
    @discardableResult
    static func startMonitoring(from date: Date = Date()) -> Bool {
        let center = DeviceActivityCenter()
        var ok = startChain(from: date, center: center)
        for (i, name) in MonitorSchedule.backboneNames.enumerated() {
            let w = MonitorSchedule.backboneWindow(i)
            let schedule = DeviceActivitySchedule(intervalStart: w.start, intervalEnd: w.end, repeats: true)
            do {
                try center.startMonitoring(DeviceActivityName(name), during: schedule)
            } catch {
                ok = false
            }
        }
        return ok
    }

    /// Starts (or restarts) only the 15-minute chain window from `date`.
    @discardableResult
    static func startChain(from date: Date = Date(), center: DeviceActivityCenter = DeviceActivityCenter()) -> Bool {
        let window = MonitorSchedule.window(from: date)
        let schedule = DeviceActivitySchedule(
            intervalStart: window.start, intervalEnd: window.end, repeats: true)
        do {
            try center.startMonitoring(DeviceActivityName(MonitorSchedule.activityName), during: schedule)
            return true
        } catch {
            return false
        }
    }

    /// Leave Faro (docs/IOS.md §12), after the goodbye is delivered: stop
    /// the monitor and empty the store, which lifts `denyAppRemoval`.
    static func liftEverything() {
        DeviceActivityCenter().stopMonitoring()
        ManagedSettingsStore(named: storeName).clearAllSettings()
    }
}
