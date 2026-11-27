import FaroKit
import Foundation

// What only the app and the tunnel decide (docs/IOS.md §10.2): why the
// tunnel stopped, what the VPN configuration says, the context checks. It
// is its own module so the three 6 MB extensions, which link FaroKit whole,
// don't carry it (`check-extension-sizes.sh`).

/// Why the tunnel was stopped, as `NEProviderStopReason` says it. The
/// tunnel's glue maps each case here one to one.
public enum TunnelStopReason: String, CaseIterable, Sendable {
    case none, userInitiated, providerFailed, noNetworkAvailable, unrecoverableNetworkChange
    case providerDisabled, authenticationCanceled, configurationFailed, idleTimeout
    case configurationDisabled, configurationRemoved, superceded, userLogout, userSwitch
    case connectionFailed, sleep, appUpdate, internalError
}

/// What a stop means for the filter.
public enum TunnelStopMeaning: Equatable, Sendable {
    /// Switched off: report it now, with this cause.
    case off(FilterCauseCode)
    /// Not the member's doing, and on-demand brings it back.
    case resting
    /// Nothing to say now: if it doesn't come back, the staleness check
    /// reports it.
    case unexplained

    public static func of(_ reason: TunnelStopReason) -> TunnelStopMeaning {
        switch reason {
        // Settings → VPN switched off (or Faro's own Leave Faro, which
        // stands the watchers down first).
        case .userInitiated: return .off(.vpnDisconnected)
        // iOS runs one VPN at a time: another one was turned on.
        case .superceded, .configurationDisabled: return .off(.otherVpn)
        case .configurationRemoved: return .off(.profileRemoved)
        // The provider can't run any more (the app offloaded, spike S3).
        case .providerDisabled: return .off(.unknown)
        case .sleep, .noNetworkAvailable, .unrecoverableNetworkChange, .connectionFailed,
             .idleTimeout, .appUpdate, .userLogout, .userSwitch:
            return .resting
        case .none, .providerFailed, .authenticationCanceled, .configurationFailed, .internalError:
            return .unexplained
        }
    }
}

// MARK: The VPN configuration, seen from the app

/// `NEVPNStatus`, one to one.
public enum VPNState: String, Sendable {
    case invalid, disconnected, connecting, connected, reasserting, disconnecting
}

/// What the app reads of Faro's VPN configuration (`NETunnelProviderManager`).
public struct VPNSnapshot: Equatable, Sendable {
    /// Faro's configuration exists.
    public var configured: Bool
    public var enabled: Bool
    public var onDemand: Bool
    public var state: VPNState
    /// Another VPN looks connected (`OtherVPN`).
    public var otherVPN: Bool

    public init(configured: Bool, enabled: Bool, onDemand: Bool, state: VPNState, otherVPN: Bool) {
        self.configured = configured
        self.enabled = enabled
        self.onDemand = onDemand
        self.state = state
        self.otherVPN = otherVPN
    }
}

public enum FilterVerdict: Equatable, Sendable {
    case on
    /// Not running yet, but nothing is switched off: it is starting, or
    /// waiting for a network, and on-demand will connect it.
    case waiting
    /// Off, with the best cause the app can tell.
    case off(FilterCauseCode)

    public static func of(_ s: VPNSnapshot) -> FilterVerdict {
        guard s.configured, s.state != .invalid else { return .off(.profileRemoved) }
        switch s.state {
        case .connected:
            return .on
        case .connecting, .reasserting:
            return .waiting
        case .disconnected, .disconnecting, .invalid:
            if s.otherVPN { return .off(.otherVpn) }
            if !s.enabled { return .off(.vpnDisconnected) }
            if !s.onDemand { return .off(.onDemandOff) }
            // Enabled with Connect On Demand: iOS connects it when there is
            // a network. Switching it off in Settings turns on-demand off.
            return .waiting
        }
    }
}

/// Another VPN, from the interfaces the system's proxy settings list per
/// network (`CFNetworkCopySystemProxySettings()["__SCOPED__"]`), the usual
/// cheap check. Faro's own tunnel is a `utun` too, so it can only be judged
/// while Faro's is down.
public enum OtherVPN {
    public static let prefixes = ["utun", "ipsec", "ppp", "tap", "tun"]

    public static func active(scopedInterfaces: [String], faroTunnelUp: Bool) -> Bool {
        guard !faroTunnelUp else { return false }
        return scopedInterfaces.contains { name in prefixes.contains { name.hasPrefix($0) } }
    }
}

// MARK: Context

/// Well-known signs of a jailbroken phone (docs/IOS.md §10.2, context
/// only): files a jailbreak leaves, and whether the app can write outside
/// its sandbox. Cheap, and easy to hide from; it is a hint in the report,
/// never an alert.
public enum JailbreakCheck {
    public static let paths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/var/jb",
    ]

    public static func suspected(fileExists: (String) -> Bool, canWriteOutsideSandbox: () -> Bool) -> Bool {
        paths.contains(where: fileExists) || canWriteOutsideSandbox()
    }
}

/// The context signals and how often each is recorded at most.
public enum ContextName {
    public static let otherVPN = "other_vpn"
    public static let dohDropped = "doh_dropped"
    public static let jailbreakSuspected = "jailbreak_suspected"
    /// Once an hour: the report lists when, the alerts never do.
    public static let everyMs: Int64 = 60 * 60 * 1000
}
