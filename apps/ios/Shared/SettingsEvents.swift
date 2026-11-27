import FaroKit
import Foundation

// Compiled into Faro and FaroTunnel only, the two targets that link the
// Rust core (docs/IOS.md §13).

/// Turns the settings events that are waiting in the app group into
/// `settings_change` events (docs/IOS.md §9). A change the member makes in
/// the app leaves one; so does a loosening that the monitor, which can't
/// link the core, applies when its time comes. Whichever of the app and the
/// tunnel runs first with the keys readable sends it.
enum SettingsEventSender {
    /// Sends what is waiting, oldest first. Returns how many went out. An
    /// event that can't be sent yet (keys still locked, instance
    /// unreachable) stays for the next try; one that the core refuses for
    /// good is dropped, because it would block the ones behind it.
    @discardableResult
    static func send(group: AppGroup, core: FaroCore, nowMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Int {
        let store = ChoicesStore(group: group)
        guard let events = try? store.claimEvents(nowMs: nowMs), !events.isEmpty else { return 0 }
        var sent = Set<String>()
        var retry = Set<String>()
        for event in events {
            if !retry.isEmpty { retry.insert(event.id); continue }
            do {
                _ = try core.recordSettingsChange(
                    changes: event.changes.map {
                        SettingChangeRecord(key: $0.key, oldValue: $0.old, newValue: $0.new)
                    },
                    pending: pending(event))
                sent.insert(event.id)
            } catch FaroError.InvalidArgument {
                sent.insert(event.id)
            } catch {
                retry.insert(event.id)
            }
        }
        try? store.completeEvents(sent)
        try? store.releaseEvents(retry)
        return sent.count
    }

    private static func pending(_ e: SettingsEventRequest) -> PendingLoosening? {
        guard e.kind != .tightened else { return nil }
        return PendingLoosening(
            requestedAtMs: e.requestedAtMs, takesEffectAtMs: e.takesEffectAtMs,
            cancelledAtMs: e.cancelledAtMs, delaySecs: e.delaySecs.map { UInt64(max($0, 0)) })
    }
}
