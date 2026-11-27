import Foundation

// What the watchers decide (docs/IOS.md §10.2). The frameworks they read
// (NetworkExtension, ManagedSettings, FamilyControls) don't run on the host
// or in the Simulator, so the glue in each target only copies what it reads
// into the types here, and these decide.

// MARK: The tunnel, seen from outside

/// Whether the packet tunnel is running, from its markers in the app group.
/// The tunnel touches `tunnel_alive` every minute while it runs, and
/// `tunnel_resting` when it stops for a reason that isn't the member's (the
/// phone going to sleep, no network, an app update) and on-demand will
/// bring it back.
public enum TunnelWatch {
    /// How old `tunnel_alive` may be before the tunnel counts as off. It is
    /// written every minute while the tunnel runs, so this tolerates its
    /// timer being held up for a long while; how late the check itself runs
    /// depends on the monitor's schedule (`MonitorSchedule`), not on this.
    public static let staleAfterMs: Int64 = 20 * 60 * 1000

    public enum State: Equatable, Sendable {
        /// No marker yet: the tunnel never ran here (setup isn't done).
        case neverSeen
        case alive
        /// Stopped or asleep for a reason that isn't the member's.
        case resting
        /// Not running, and nothing says why: the DNS filter is off.
        case stale
    }

    public static func judge(
        aliveMs: Int64?, restingMs: Int64?, nowMs: Int64, staleAfterMs: Int64 = staleAfterMs
    ) -> State {
        guard let alive = aliveMs else { return .neverSeen }
        if let resting = restingMs, resting >= alive { return .resting }
        // A marker from the future (the clock was set back): judge from
        // now on rather than call it fresh forever.
        if alive > nowMs { return .alive }
        return nowMs - alive > staleAfterMs ? .stale : .alive
    }
}

// MARK: The "faro" store

/// The values read back from the "faro" ManagedSettings store.
public struct StoreSnapshot: Equatable, Sendable {
    /// `webContent.blockedByFilter` is set.
    public var webFilterOn: Bool
    public var denyAppRemoval: Bool?
    public var denyExplicitContent: Bool?
    public var requireAutomaticDateAndTime: Bool?
    public var maximumAppRating: Int?

    public init(
        webFilterOn: Bool, denyAppRemoval: Bool?, denyExplicitContent: Bool?,
        requireAutomaticDateAndTime: Bool?, maximumAppRating: Int?
    ) {
        self.webFilterOn = webFilterOn
        self.denyAppRemoval = denyAppRemoval
        self.denyExplicitContent = denyExplicitContent
        self.requireAutomaticDateAndTime = requireAutomaticDateAndTime
        self.maximumAppRating = maximumAppRating
    }

    /// An empty store: what revoking Screen Time, or clearing it, leaves.
    public static let empty = StoreSnapshot(
        webFilterOn: false, denyAppRemoval: nil, denyExplicitContent: nil,
        requireAutomaticDateAndTime: nil, maximumAppRating: nil)
}

public enum StoreCheck {
    /// Whether the store still holds what `plan` wrote. Anything that
    /// blocks less than the plan counts as changed; a setting the plan
    /// leaves off may read as unset.
    public static func intact(_ s: StoreSnapshot, plan: ScreenTimePlan) -> Bool {
        func holds(_ want: Bool, _ got: Bool?) -> Bool { !want || got == true }
        return s.webFilterOn
            && holds(plan.denyAppRemoval, s.denyAppRemoval)
            && holds(plan.denyExplicitContent, s.denyExplicitContent)
            && holds(plan.requireAutomaticDateAndTime, s.requireAutomaticDateAndTime)
            && (plan.maximumAppRating == nil || s.maximumAppRating == plan.maximumAppRating)
    }
}
