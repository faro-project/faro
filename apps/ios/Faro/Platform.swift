import FamilyControls
import FaroKit
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
    static func authorize(settingsStore: SettingsStore) async throws {
        try await AuthorizationCenter.shared.requestAuthorization(for: .individual)
        guard isAuthorized else {
            throw SetupError("Screen Time access wasn't granted.")
        }
        try settingsStore.save(.default)
        ScreenTimeEnforcer.apply(.default)
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
    static func install(instanceName: String) async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == providerBundleID }) ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleID
        // Shown in Settings → VPN. The tunnel carries DNS only; there is no server.
        proto.serverAddress = "Faro"
        proto.disconnectOnSleep = false
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
}

// MARK: The monthly notice

enum NoticeScheduler {
    /// Asks for permission to show notifications, and schedules the monthly
    /// notice either way: if the member declines, the screen is still one
    /// tap away on the status screen, and the status screen says so.
    static func schedule(enrolledAt: Date) async -> Bool {
        let center = UNUserNotificationCenter.current()
        let allowed = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false

        let content = UNMutableNotificationContent()
        content.title = "Faro is on this phone"
        content.body = "Tap to see who it reports to and which Faro instance holds the reports."
        content.userInfo = [MonthlyNotice.routeKey: MonthlyNotice.routeValue]
        let trigger = UNCalendarNotificationTrigger(
            dateMatching: MonthlyNotice.fireComponents(enrolledAt: enrolledAt), repeats: true)
        center.removePendingNotificationRequests(withIdentifiers: [MonthlyNotice.identifier])
        try? await center.add(UNNotificationRequest(
            identifier: MonthlyNotice.identifier, content: content, trigger: trigger))
        return allowed
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
