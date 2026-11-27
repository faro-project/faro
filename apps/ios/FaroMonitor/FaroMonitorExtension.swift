import DeviceActivity

/// Re-applies the settings and watches the tunnel (docs/IOS.md §6.3, §10.2).
/// A stub: it does nothing yet. This extension has a 6 MB memory limit, so
/// it never links the Rust core; it will read files in the app group
/// (FaroKit) and write ManagedSettings.
final class FaroMonitorExtension: DeviceActivityMonitor {
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
    }

    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
    }
}
