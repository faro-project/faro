import Foundation

/// What the packet tunnel does at each of its timers and callbacks, in
/// order (docs/IOS.md §10.1). The provider only keeps the timers and hands
/// each round to `TunnelRounds.run`; the order, and that every round ends
/// with an upload of what the outbox holds, are decided here, where a test
/// can drive them.
public enum TunnelTick: Equatable {
    /// The tunnel has started.
    case start
    /// The phone woke.
    case wake
    /// The phone is going to sleep.
    case sleep
    /// The tunnel is stopping. `switchedOff`: the reason was the member's,
    /// so a `FilterOff` was left in the ledger to record.
    case stop(switchedOff: Bool)
    /// Every minute.
    case minute
    /// Every 5 minutes while awake.
    case heartbeat
    /// Every 10 minutes. `dohDropped`: encrypted-DNS packets dropped since
    /// the last one.
    case flush(dohDropped: UInt64)
}

/// The heartbeat states the tunnel sends.
public enum TunnelHeartbeatState: Equatable {
    case active
    case sleeping
}

/// What the provider does for a round. All of it runs on the tunnel's core
/// queue, one call at a time, so two uploads never overlap.
public protocol TunnelWork: AnyObject {
    func refreshFromCore()
    func heartbeat(_ state: TunnelHeartbeatState)
    /// Record what the watchers queued in the ledger as `tamper` events.
    func recordQueuedTamper()
    func flushBursts()
    func flushReports(filterOn: Bool)
    func noteDohDropped(_ count: UInt64)
    /// Whether the outbox holds an event or a report.
    func hasPending() -> Bool
    func uploadPending()
}

public enum TunnelRounds {
    /// The periods of the provider's timers (seconds).
    public static let minute: TimeInterval = 60
    public static let heartbeat: TimeInterval = 5 * 60
    public static let flush: TimeInterval = 10 * 60

    /// Runs one round. Whatever it recorded, or an earlier upload that
    /// failed left, goes out at the end: a flag, a summary, a report, a
    /// tamper event or a settings change is not left for the next tamper
    /// or the member opening the app.
    public static func run(_ tick: TunnelTick, on work: TunnelWork) {
        switch tick {
        case .start:
            work.refreshFromCore()
            work.heartbeat(.active)
            work.recordQueuedTamper()
        case .wake:
            work.heartbeat(.active)
            work.recordQueuedTamper()
        case .sleep:
            work.heartbeat(.sleeping)
            work.flushReports(filterOn: true)
        case .stop(let switchedOff):
            if switchedOff { work.recordQueuedTamper() }
            work.flushReports(filterOn: false)
        case .minute:
            work.recordQueuedTamper()
            work.flushBursts()
        case .heartbeat:
            work.heartbeat(.active)
        case .flush(let dohDropped):
            work.refreshFromCore()
            work.flushReports(filterOn: true)
            work.noteDohDropped(dohDropped)
        }
        if work.hasPending() { work.uploadPending() }
    }
}
