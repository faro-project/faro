import FamilyControls
import FaroKit
import FaroKitApp
import Foundation
import NetworkExtension
import UserNotifications

// The three iOS permissions setup asks for, each behind a small type so the
// views and the model never touch the frameworks directly. None of this
// runs in the Simulator: Screen Time authorization and VPN configurations
// need a real phone and the entitlements Apple grants per App ID
// (docs/DEVELOPMENT.md "The iOS app").

// MARK: Screen Time

enum ScreenTime {
    /// Whether Faro's Screen Time authorization stands right now.
    static var isAuthorized: Bool {
        AuthorizationCenter.shared.authorizationStatus == .approved
    }

    /// The Face ID or passcode prompt (docs/IOS.md §6.1), then the default
    /// settings: saved to the app group file the monitor re-applies, written
    /// to the "faro" store, and the monitor schedule started. Throws the
    /// system's error if the member cancels.
    @MainActor
    static func authorize(choices: ChoicesStore) async throws {
        try await AuthorizationCenter.shared.requestAuthorization(for: .individual)
        guard isAuthorized else {
            throw SetupError("Screen Time access wasn't granted.")
        }
        // The defaults on a first setup; the member's own choices when this
        // is Screen Time being turned back on, which never resets them.
        let settings = try choices.ensureSettings()
        ScreenTimeEnforcer.apply(settings)
        ScreenTimeEnforcer.startMonitoring()
    }
}

// MARK: The VPN configuration

enum TunnelInstaller {
    static let providerBundleID = "org.faro.ios.tunnel"

    /// Installs (or updates) Faro's VPN configuration with Connect On
    /// Demand for every interface (docs/IOS.md §7.1), which triggers iOS's
    /// "Allow Faro to add VPN configurations" prompt the first time, and
    /// starts the tunnel.
    static func install(instanceName: String, settings: FaroSettings? = nil) async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == providerBundleID }) ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleID
        // Shown in Settings → VPN. The tunnel carries DNS only; there is no server.
        proto.serverAddress = "Faro"
        proto.disconnectOnSleep = false
        // The member's choices, which the tunnel can read before the first unlock.
        proto.providerConfiguration = TunnelConfig.providerConfiguration(for: settings ?? .default)
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Faro"
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        manager.isOnDemandEnabled = true
        manager.isEnabled = true

        try await manager.saveToPreferences()
        // A second load is needed before the first start after a save.
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
    }

    /// Copies the member's choices into the VPN configuration's
    /// `providerConfiguration` (docs/IOS.md §7, §9), which the tunnel can
    /// read before the first unlock. Does nothing if the configuration
    /// isn't installed yet; `install` writes it then. A running tunnel keeps
    /// going: it reads `filter.json` for changes.
    static func updateProviderConfiguration(_ settings: FaroSettings) async {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let m = managers.first(where: {
                  ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
              }),
              let proto = m.protocolConfiguration as? NETunnelProviderProtocol
        else { return }
        let wanted = TunnelConfig.providerConfiguration(for: settings)
        let have = proto.providerConfiguration
        if (have?[TunnelConfig.filterKey] as? String) == (wanted[TunnelConfig.filterKey] as? String),
           (have?[TunnelConfig.generationKey] as? Int) == (wanted[TunnelConfig.generationKey] as? Int) {
            return
        }
        proto.providerConfiguration = wanted
        m.protocolConfiguration = proto
        try? await m.saveToPreferences()
    }

    /// The current state of Faro's VPN, for the status screen.
    static func status() async -> NEVPNStatus? {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let m = managers.first(where: {
                  ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
              })
        else { return nil }
        return m.connection.status
    }

    /// Whether the configuration exists with Connect On Demand switched on.
    static func onDemandIsOn() async -> Bool {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let m = managers.first(where: {
                  ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
              })
        else { return false }
        return m.isEnabled && m.isOnDemandEnabled
    }

    /// What the app can see of Faro's VPN, for `FilterVerdict` (docs/IOS.md
    /// §10.2). `nil` when the configurations can't be read at all, which
    /// says nothing about the filter.
    static func snapshot() async -> VPNSnapshot? {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences() else { return nil }
        let m = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
        })
        let state = m.map { vpnState($0.connection.status) } ?? .invalid
        let up = state == .connected || state == .connecting || state == .reasserting
        return VPNSnapshot(
            configured: m != nil, enabled: m?.isEnabled ?? false, onDemand: m?.isOnDemandEnabled ?? false,
            state: state, otherVPN: OtherVPN.active(scopedInterfaces: scopedInterfaces(), faroTunnelUp: up))
    }

    /// Leave Faro: removes Faro's VPN configuration, which stops the tunnel.
    static func remove() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for m in managers where (m.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == providerBundleID
        {
            try await m.removeFromPreferences()
        }
    }

    static func vpnState(_ s: NEVPNStatus) -> VPNState {
        switch s {
        case .invalid: return .invalid
        case .disconnected: return .disconnected
        case .connecting: return .connecting
        case .connected: return .connected
        case .reasserting: return .reasserting
        case .disconnecting: return .disconnecting
        @unknown default: return .invalid
        }
    }

    /// The interfaces the system's proxy settings list per network: a VPN's
    /// `utun` or `ipsec` shows here while it is connected.
    static func scopedInterfaces() -> [String] {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = settings["__SCOPED__"] as? [String: Any]
        else { return [] }
        return Array(scoped.keys)
    }
}

// MARK: Context

enum DeviceContext {
    /// The cheap, well-known jailbreak checks (`JailbreakCheck`).
    static func jailbreakSuspected() -> Bool {
        JailbreakCheck.suspected(
            fileExists: { FileManager.default.fileExists(atPath: $0) },
            canWriteOutsideSandbox: {
                let probe = "/private/faro-sandbox-check"
                guard (try? Data().write(to: URL(fileURLWithPath: probe))) != nil else { return false }
                try? FileManager.default.removeItem(atPath: probe)
                return true
            })
    }
}

// MARK: The monthly notice

enum NoticeScheduler {
    /// Asks for permission to show notifications, and schedules the monthly
    /// notice either way: if the member declines, the screen is still one
    /// tap away on the status screen, and the status screen says so.
    static func schedule(enrolledAt: Date, recipients: RecipientsInfo? = nil) async -> Bool {
        let center = UNUserNotificationCenter.current()
        let allowed = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false

        let content = UNMutableNotificationContent()
        content.title = "Faro is on this phone"
        content.body = body(recipients)
        content.userInfo = [MonthlyNotice.routeKey: MonthlyNotice.routeValue]
        let trigger = UNCalendarNotificationTrigger(
            dateMatching: MonthlyNotice.fireComponents(enrolledAt: enrolledAt), repeats: true)
        center.removePendingNotificationRequests(withIdentifiers: [MonthlyNotice.identifier])
        try? await center.add(UNNotificationRequest(
            identifier: MonthlyNotice.identifier, content: content, trigger: trigger))
        return allowed
    }

    /// The notification's text: who Faro reports to, as far as the signed
    /// recipient list says. Allies by count only: the notification can show
    /// on the lock screen, so the names are on the screen it opens.
    static func body(_ r: RecipientsInfo?) -> String {
        guard let r else {
            return "Tap to see who it reports to and which Faro instance holds the reports."
        }
        let who: String
        switch r.allies.count {
        case 0: who = "It reports to you only, for now"
        case 1: who = "It reports to 1 ally"
        default: who = "It reports to \(r.allies.count) allies"
        }
        return "\(who), through \(r.instanceName). Tap to see who."
    }

    /// Leave Faro: no more monthly notices.
    static func cancel() {
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [MonthlyNotice.identifier])
    }

    static func notificationsAllowed() async -> Bool {
        let s = await UNUserNotificationCenter.current().notificationSettings()
        return s.authorizationStatus == .authorized || s.authorizationStatus == .provisional
    }
}

/// Opens the notice screen when the member taps the notification.
final class NoticeTapHandler: NSObject, UNUserNotificationCenterDelegate {
    var onNotice: (() -> Void)?

    func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        if response.notification.request.content.userInfo[MonthlyNotice.routeKey] as? String
            == MonthlyNotice.routeValue
        {
            await MainActor.run { onNotice?() }
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}

struct SetupError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}
