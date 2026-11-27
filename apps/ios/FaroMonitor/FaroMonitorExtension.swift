import DeviceActivity
import FaroKit
import Foundation

/// Re-applies the settings and shows it is still being called (docs/IOS.md
/// §6.3). The 15-minute window starts and ends here: each callback
/// re-writes the "faro" store from the settings file in the app group,
/// touches the "monitor alive" marker, and when a window ends starts the
/// next one. This extension has a 6 MB memory limit, so it links no Rust and
/// does no networking: file reads and ManagedSettings writes only. The
/// cross-checks of §10.2 come in a later change.
final class FaroMonitorExtension: DeviceActivityMonitor {
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
        tick()
    }

    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
        tick()
        ScreenTimeEnforcer.startMonitoring()
    }

    private func tick() {
        ScreenTimeEnforcer.applySavedSettings()
        guard let group = AppGroup.container() else { return }
        try? Markers(group: group).touch(
            MarkerName.monitorAlive, nowMs: Int64(Date().timeIntervalSince1970 * 1000))
    }
}
