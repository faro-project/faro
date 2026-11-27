import BackgroundTasks
import FaroKit
import Foundation
import os

/// Domain list updates over the instance's update channel (docs/IOS.md
/// §7.2, §14). The app fetches and installs a newer list into the app group
/// with the Rust core, which verifies it against the project's root of
/// trust shipped in this app, never one the instance supplies (invariant
/// 5): the instance can delay a list but can't forge one. The tunnel picks
/// the installed list up between queries. The copy packaged in the tunnel
/// stays the fallback, and the tunnel never goes below it.
///
/// Without `update-root.json` in the bundle (a development build made
/// before the key ceremony, as on desktop without `FARO_UPDATE_ROOT`) the
/// app logs that and checks nothing.
enum DomainUpdates {
    private static let log = Logger(subsystem: "org.faro.ios", category: "domain-updates")

    /// The project's root of trust from the app bundle.
    static func rootOfTrust() -> Data? {
        Bundle.main.url(forResource: "update-root", withExtension: "json")
            .flatMap { try? Data(contentsOf: $0) }
    }

    /// Checks the instance's mirror and installs a newer list. Skipped
    /// unless a check is due, or `force`. Blocks on the network, so call it
    /// off the main thread. Returns false if it should be tried again soon.
    @discardableResult
    static func check(group: AppGroup, force: Bool = false) -> Bool {
        let markers = Markers(group: group)
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        guard force || DomainUpdateSchedule.isDue(
            lastCheckMs: markers.read(DomainUpdateSchedule.checkedMarker), nowMs: nowMs)
        else { return true }
        guard let root = rootOfTrust() else {
            log.notice("no update root in this build: not checking for domain list updates")
            return true
        }
        do {
            let core = try CoreLink.open(group: group)
            switch try core.updateDomains(trustedRoot: root) {
            case .installed(let info):
                log.notice("installed the domain list \(info.version, privacy: .public)")
            case .rejected(let version, let reason):
                log.error("refused the domain list \(version, privacy: .public): \(reason, privacy: .public)")
            case .unavailable, .upToDate:
                break
            }
            try? markers.touch(DomainUpdateSchedule.checkedMarker, nowMs: nowMs)
            return true
        } catch FaroError.NotEnrolled {
            return true
        } catch {
            // Offline, keys locked or the mirror is down: try again later.
            log.info("domain list check failed: \(String(describing: error), privacy: .public)")
            return false
        }
    }

    // MARK: Background refresh

    /// Registers the handler. Call before the app finishes launching.
    static func register(group: AppGroup?) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: DomainUpdateSchedule.taskIdentifier, using: nil) { task in
            schedule(group: group)
            let work = Task.detached {
                let ok = group.map { check(group: $0) } ?? true
                task.setTaskCompleted(success: ok)
            }
            task.expirationHandler = { work.cancel() }
        }
    }

    /// Asks iOS for a background refresh about 6 hours after the last check.
    /// iOS decides when, if at all.
    static func schedule(group: AppGroup?) {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let last = group.flatMap { Markers(group: $0).read(DomainUpdateSchedule.checkedMarker) }
        let request = BGAppRefreshTaskRequest(identifier: DomainUpdateSchedule.taskIdentifier)
        request.earliestBeginDate = DomainUpdateSchedule.nextBegin(lastCheckMs: last, nowMs: nowMs)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            log.info("background refresh not scheduled: \(String(describing: error), privacy: .public)")
        }
    }
}
