import FaroKit
import Foundation

// Compiled into Faro and FaroTunnel, the two targets that link the Rust
// core. The watchers (these two and the monitor extension) queue what they
// find in FaroKit's `TamperLedger`; this turns the queue into urgent
// `tamper` events (docs/IOS.md §10.2).

enum TamperLink {
    static func tamper(_ r: TamperRequest) -> Tamper {
        switch r {
        case .screenTimeRevoked: return .screenTimeRevoked
        case .settingsCleared: return .settingsCleared
        case .filterOff(let c): return .filterOff(cause: cause(c))
        }
    }

    static func cause(_ c: FilterCauseCode) -> FilterCause {
        switch c {
        case .vpnDisconnected: return .vpnDisconnected
        case .onDemandOff: return .onDemandOff
        case .otherVpn: return .otherVpn
        case .profileRemoved: return .profileRemoved
        case .unknown: return .unknown
        }
    }

    /// Records every queued request in `core`, oldest first. What can't be
    /// recorded yet (the keys are locked before the first unlock, the phone
    /// isn't approved yet) stays queued. Returns how many were recorded.
    /// Blocks: call it off the main thread.
    @discardableResult
    static func drain(_ ledger: TamperLedger, into core: FaroCore) -> Int {
        (try? ledger.drain { _ = try core.recordTamper(signal: tamper($0)) }) ?? 0
    }

    /// Records the context signal `signal` (named `name` in the ledger) for
    /// the daily report, at most once per `ContextName.everyMs`.
    static func context(
        _ signal: Context, named name: String, ledger: TamperLedger, core: FaroCore, nowMs: Int64
    ) {
        let due = (try? ledger.update {
            $0.shouldRecordContext(name, nowMs: nowMs, everyMs: ContextName.everyMs)
        }) ?? false
        if due { try? core.recordContext(signal: signal) }
    }

    static func nowMs() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }
}
