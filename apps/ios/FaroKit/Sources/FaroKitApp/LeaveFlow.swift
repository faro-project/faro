import Foundation

/// Leave Faro (docs/IOS.md §12): allowed, never silent. The member confirms;
/// the app sends `goodbye` and waits for the instance to have it; only then
/// is the protection lifted (`denyAppRemoval` and the rest of the "faro"
/// store, the monitor schedule, the VPN configuration); then the member is
/// told they can delete the app. If the goodbye can't be delivered, nothing
/// is lifted and the member is told so, with a way to try again.
public enum LeaveStep: Equatable, Sendable {
    /// What leaving does, and the button that does it.
    case confirm
    /// Telling the allies.
    case sayingGoodbye
    /// The allies couldn't be told yet. Nothing was lifted. `written`: the
    /// goodbye is already recorded on the phone (and will go with the next
    /// try), so the phone has stopped reporting anything else.
    case notDelivered(message: String, written: Bool)
    /// Lifting the protection.
    case lifting
    /// Done. `leftovers` are what couldn't be undone here, for the member
    /// to do in Settings.
    case done(leftovers: [String])
}

public enum LeaveEvent: Equatable, Sendable {
    case confirmed
    /// The instance has the goodbye, or never needed one (retired, never
    /// approved, never enrolled).
    case delivered
    /// Not delivered: couldn't reach the instance before writing it.
    case unreachable(String)
    /// Written, not acknowledged in time.
    case queued(String)
    case retry
    case lifted(leftovers: [String])
}

public struct LeaveFlow: Equatable, Sendable {
    public private(set) var step: LeaveStep

    public init(step: LeaveStep = .confirm) {
        self.step = step
    }

    /// Where to pick up after a relaunch, from the core's status.
    public static func resume(leaving: Bool, goodbyeDelivered: Bool) -> LeaveFlow? {
        guard leaving else { return nil }
        if goodbyeDelivered { return LeaveFlow(step: .lifting) }
        return LeaveFlow(step: .notDelivered(
            message: "Faro hasn't confirmed that your allies were told yet.", written: true))
    }

    /// Whether the protection may be lifted now: only once the goodbye is
    /// delivered.
    public var mayLift: Bool { step == .lifting }

    /// Whether the member can still change their mind: only until a goodbye
    /// is recorded.
    public var canCancel: Bool {
        switch step {
        case .confirm: return true
        case .notDelivered(_, let written): return !written
        default: return false
        }
    }

    /// Applies `event`. Returns `false`, changing nothing, when the event
    /// doesn't belong to the current step.
    @discardableResult
    public mutating func apply(_ event: LeaveEvent) -> Bool {
        switch (step, event) {
        case (.confirm, .confirmed):
            step = .sayingGoodbye
        case (.sayingGoodbye, .delivered):
            step = .lifting
        case (.sayingGoodbye, .unreachable(let m)):
            step = .notDelivered(message: m, written: false)
        case (.sayingGoodbye, .queued(let m)):
            step = .notDelivered(message: m, written: true)
        case (.notDelivered, .retry):
            step = .sayingGoodbye
        case (.lifting, .lifted(let leftovers)):
            step = .done(leftovers: leftovers)
        default:
            return false
        }
        return true
    }
}
