import DeviceActivity
import FaroKit
import Foundation

/// Re-applies the settings and watches the other layers (docs/IOS.md §6.3,
/// §10.2). It is called at the start and end of the 15-minute chain window
/// and of each window of the daily backbone (`MonitorSchedule`). Each
/// callback:
///
/// * touches the "monitor alive" marker;
/// * reads Screen Time authorization (it is a FamilyControls extension, so
///   it can);
/// * while authorization stands, checks the "faro" store and re-writes it
///   from the settings file (`SettingsCleared` if it had been cleared or
///   changed);
/// * judges the tunnel from its markers (`FilterOff` if it has gone quiet
///   while the phone is in use);
/// * restarts the chain, so a dropped callback costs at most one backbone
///   window.
///
/// This extension has a 6 MB memory limit, so it links no Rust and does no
/// networking: file reads, ManagedSettings and FamilyControls only. What it
/// finds goes into the tamper ledger in the app group; the app or the
/// tunnel turns it into the event.
final class FaroMonitorExtension: DeviceActivityMonitor {
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
        tick()
        if MonitorSchedule.isBackbone(activity.rawValue) { ScreenTimeEnforcer.startChain() }
    }

    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
        tick()
        ScreenTimeEnforcer.startChain()
    }

    private func tick() {
        guard let group = AppGroup.container() else { return }
        let ledger = TamperLedger(group: group)
        // Leave Faro stood the watchers down: lift nothing back.
        guard !ledger.read().leaving else { return }
        let markers = Markers(group: group)
        try? markers.touch(MarkerName.monitorAlive, nowMs: Self.nowMs())

        guard screenTimeStands(ledger) else { return }
        ScreenTimeEnforcer.reapplyAndCheck(group: group, ledger: ledger, nowMs: Self.nowMs())

        let now = Self.nowMs()
        switch TunnelWatch.judge(
            aliveMs: markers.read(MarkerName.tunnelAlive),
            restingMs: markers.read(MarkerName.tunnelResting), nowMs: now)
        {
        case .stale:
            // The monitor can't see the VPN configuration: the app, when it
            // next runs, says no more (one cause, one signal).
            try? ledger.update { $0.sawOff(.filterOff(.unknown), nowMs: now) }
        case .alive:
            try? ledger.update { $0.sawOn(.filter) }
        case .resting, .neverSeen:
            break
        }
    }

    /// Reads Screen Time authorization into the ledger, reading a second
    /// time a few seconds later before believing a revocation.
    private func screenTimeStands(_ ledger: TamperLedger) -> Bool {
        var approved = ScreenTimeEnforcer.isAuthorized
        let verdict = try? ledger.update {
            $0.sawScreenTime(approved: approved, source: .monitor, nowMs: Self.nowMs())
        }
        if verdict == .recheck {
            Thread.sleep(forTimeInterval: 3)
            approved = ScreenTimeEnforcer.isAuthorized
            try? ledger.update {
                $0.sawScreenTime(approved: approved, source: .monitor, nowMs: Self.nowMs())
            }
        }
        return approved
    }

    static func nowMs() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }
}
