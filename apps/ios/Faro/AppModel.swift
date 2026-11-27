import FaroKit
import Foundation
import NetworkExtension
import SwiftUI

/// Everything the screens show and do. Calls into the Rust core block, so
/// each runs on a background queue and the results come back here.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var flow = SetupFlow()
    @Published private(set) var preview: InstancePreview?
    @Published private(set) var enrolledDevice: EnrolledDevice?
    @Published private(set) var status: CoreStatus?
    @Published private(set) var busy = false
    /// Set when the member taps the monthly notification.
    @Published var showingNotice = false
    @Published private(set) var screenTimeOn = false
    @Published private(set) var vpnStatus: NEVPNStatus?
    @Published private(set) var onDemandOn = false
    @Published private(set) var notificationsOn = true
    @Published private(set) var loaded = false
    /// Who this phone reports to, from the recipient list the member signed.
    @Published private(set) var recipients: RecipientsInfo?
    /// Leave Faro, once the member has started it.
    @Published private(set) var leave: LeaveFlow?

    let notices = NoticeTapHandler()
    private var group: AppGroup?
    private var core: FaroCore?
    private var progressStore: SetupProgressStore?
    private let settingsStore: SettingsStore

    init() {
        let group = AppGroup.container() ?? AppModel.fallbackGroup()
        self.group = group
        if let group {
            progressStore = SetupProgressStore(group: group)
            settingsStore = SettingsStore(group: group)
        } else {
            settingsStore = SettingsStore(url: URL(fileURLWithPath: "/dev/null"))
        }
        notices.onNotice = { [weak self] in self?.showingNotice = true }
    }

    /// Unsigned builds (and the Simulator without the entitlement) have no
    /// app group container; use a folder in Application Support so the app
    /// still runs. A signed build never takes this path.
    private static func fallbackGroup() -> AppGroup? {
        guard let base = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        else { return nil }
        return AppGroup(root: base.appendingPathComponent("faro-dev-group", isDirectory: true))
    }

    // MARK: Loading

    /// Reads where this phone stands and picks the first screen.
    func load() async {
        guard let group else {
            loaded = true
            flow.apply(.failed("Faro can't find a place to keep its files on this phone."))
            return
        }
        let result: Result<CoreStatus, Error> = await Task.detached {
            Result { try CoreLink.open(group: group).status() }
        }.value
        switch result {
        case .success(let s):
            status = s
            flow = SetupFlow.resume(
                enrolled: s.enrolled, approved: s.approved,
                progress: progressStore?.load() ?? SetupProgress())
            leave = LeaveFlow.resume(leaving: s.leaving, goodbyeDelivered: s.goodbyeDelivered)
        case .failure(let e):
            flow = SetupFlow()
            flow.apply(.failed(describe(e)))
        }
        loaded = true
        if leave?.mayLift == true {
            await lift()
            return
        }
        await refreshPlatformState()
        await watch()
    }

    func refreshPlatformState() async {
        screenTimeOn = ScreenTime.isAuthorized
        vpnStatus = await TunnelInstaller.status()
        onDemandOn = await TunnelInstaller.onDemandIsOn()
        notificationsOn = await NoticeScheduler.notificationsAllowed()
    }

    func refreshStatus() async {
        guard let core = try? openCore() else { return }
        if let s = try? await Task.detached(operation: { try core.status() }).value { status = s }
        await refreshPlatformState()
    }

    // MARK: Watching (docs/IOS.md §10.2)

    /// Each time the app comes forward (after the first load).
    func foreground() async {
        guard loaded else { return }
        if leave != nil { return }
        if flow.step == .done {
            await refreshStatus()
            await watch()
        } else if progressStore?.load().screenTimeDone == true, ScreenTime.isAuthorized {
            // Mid-setup: keep the settings applied (docs/IOS.md §6.3).
            ScreenTimeEnforcer.reapplySavedSettings(group: group)
        }
    }

    /// What the app checks each time it comes forward, once setup is done:
    /// Screen Time authorization, the "faro" store (re-applied), Faro's VPN
    /// configuration (`NEVPNManager` status, with the best cause if the
    /// filter is off), and the context signals. What it finds goes into the
    /// tamper ledger with what the monitor and the tunnel found, and is
    /// recorded and uploaded from here, with a heartbeat (§10.1: the app
    /// checks in whenever it runs, so a phone whose tunnel is off still
    /// does).
    func watch() async {
        guard leave == nil, flow.step == .done, let group, let s = status, s.approved, !s.leaving,
              let core = try? openCore()
        else { return }
        let ledger = TamperLedger(group: group)
        let progress = progressStore?.load() ?? SetupProgress()

        if progress.screenTimeDone {
            var verdict = try? ledger.update {
                $0.sawScreenTime(approved: ScreenTime.isAuthorized, source: .app, nowMs: Self.nowMs())
            }
            if verdict == .recheck {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                verdict = try? ledger.update {
                    $0.sawScreenTime(approved: ScreenTime.isAuthorized, source: .app, nowMs: Self.nowMs())
                }
            }
            if ScreenTimeEnforcer.reapplyAndCheck(group: group, ledger: ledger, nowMs: Self.nowMs()) {
                ScreenTimeEnforcer.startMonitoring()
            }
        }

        var otherVPN = false
        if progress.tunnelDone, let vpn = await TunnelInstaller.snapshot() {
            otherVPN = vpn.otherVPN
            let now = Self.nowMs()
            switch FilterVerdict.of(vpn) {
            case .on: try? ledger.update { $0.sawOn(.filter) }
            case .off(let cause): try? ledger.update { $0.sawOff(.filterOff(cause), nowMs: now) }
            case .waiting: break
            }
        }

        let jailbroken = DeviceContext.jailbreakSuspected()
        let info: RecipientsInfo? = await Task.detached {
            TamperLink.drain(ledger, into: core)
            let now = TamperLink.nowMs()
            if otherVPN {
                TamperLink.context(.otherVpn, named: ContextName.otherVPN, ledger: ledger, core: core, nowMs: now)
            }
            if jailbroken {
                TamperLink.context(
                    .jailbreakSuspected, named: ContextName.jailbreakSuspected, ledger: ledger, core: core,
                    nowMs: now)
            }
            _ = try? core.heartbeat(state: .active)
            _ = try? core.uploadPending()
            return try? core.allies()
        }.value
        if let info { await useRecipients(info) }
        await refreshStatus()
    }

    /// Who Faro reports to, fresh from the instance if it can be reached
    /// (a newer list the member signed is adopted), else as stored.
    func refreshRecipients() async {
        guard let core = try? openCore(), status?.approved == true, status?.leaving != true else { return }
        let info = await Task.detached { () -> RecipientsInfo? in
            _ = try? core.uploadPending()
            return try? core.allies()
        }.value
        if let info { await useRecipients(info) }
    }

    private func useRecipients(_ info: RecipientsInfo) async {
        let changed = recipients != info
        recipients = info
        // The monthly notice names them too, so it is rescheduled with the
        // current list.
        if changed, leave == nil, flow.step == .done { await scheduleNotice() }
    }

    // MARK: Leave Faro (docs/IOS.md §12)

    func beginLeave() {
        guard leave == nil, status?.enrolled == true else { return }
        leave = LeaveFlow()
    }

    /// Back out, while nothing has been sent.
    func cancelLeave() {
        if leave?.canCancel == true { leave = nil }
    }

    func confirmLeave() async {
        guard leave?.step == .confirm else { return }
        leave?.apply(.confirmed)
        await sayGoodbye()
    }

    func retryLeave() async {
        guard case .notDelivered = leave?.step else { return }
        leave?.apply(.retry)
        await sayGoodbye()
    }

    /// Sends the goodbye and waits for the instance to have it. Nothing is
    /// lifted unless it does: offline, the member is told and can try again.
    private func sayGoodbye() async {
        guard let group, let core = try? openCore() else {
            leave?.apply(.unreachable("Faro can't open its files on this phone."))
            return
        }
        let ledger = TamperLedger(group: group)
        let result = await Task.detached { () -> Result<GoodbyeOutcome, Error> in
            // What the watchers found goes before the goodbye.
            TamperLink.drain(ledger, into: core)
            return Result { try core.goodbye(deliverWithinSecs: 30) }
        }.value
        switch result {
        case .success(.delivered), .success(.alreadyRetired), .success(.notActivated), .success(.notEnrolled):
            leave?.apply(.delivered)
            await lift()
        case .success(.queued(_, let error)):
            leave?.apply(.queued(
                "Faro couldn't confirm that your allies were told. Check your connection and try again. (\(error))"))
        case .failure(let e):
            leave?.apply(.unreachable(describe(e)))
        }
        await refreshStatus()
    }

    /// Lifts the protection, only once the goodbye is delivered: the
    /// watchers stand down, the monitor stops, the store is emptied (which
    /// lifts `denyAppRemoval`), the VPN configuration is removed. Safe to
    /// run again after a relaunch.
    private func lift() async {
        guard leave?.mayLift == true, let group else { return }
        try? TamperLedger(group: group).update { $0.standDown() }
        ScreenTimeEnforcer.liftEverything()
        try? FileManager.default.removeItem(at: group.settingsFile)
        NoticeScheduler.cancel()
        var leftovers: [String] = []
        do {
            try await TunnelInstaller.remove()
        } catch {
            leftovers.append("Faro's VPN is still listed. Remove it in Settings, General, VPN & Device Management.")
        }
        leave?.apply(.lifted(leftovers: leftovers))
        await refreshPlatformState()
    }

    private func openCore() throws -> FaroCore {
        if let core { return core }
        guard let group else { throw SetupError("Faro can't find a place to keep its files.") }
        let c = try CoreLink.open(group: group)
        core = c
        return c
    }

    // MARK: Setup steps

    func acceptCosts() { flow.apply(.acceptedCosts) }
    func back() { flow.apply(.back) }

    /// A link from the camera, the URL scheme or the pasteboard. Asks the
    /// instance who it is, then shows it for the member to confirm.
    func receive(link text: String) async {
        guard flow.step == .costs || flow.step == .link || flow.step == .confirmInstance else { return }
        guard let link = EnrollLinkFinder.find(in: text) else {
            if flow.step == .costs { flow.apply(.acceptedCosts) }
            flow.apply(.failed("That isn't a Faro enrollment link. It starts with faro://enroll."))
            return
        }
        if flow.step == .costs { flow.apply(.acceptedCosts) }
        if flow.step == .confirmInstance { flow.apply(.back) }
        guard flow.apply(.linkGiven(link)) else { return }
        await run {
            let core = try self.openCore()
            let p = try await Task.detached { try core.previewEnrollment(link: link.text) }.value
            self.preview = p
        } onError: { message in
            self.flow.apply(.back)
            self.flow.apply(.failed(message))
        }
    }

    func confirmInstance() { flow.apply(.instanceConfirmed) }

    func enroll(deviceName: String) async {
        guard flow.apply(.deviceNamed(deviceName)), flow.step == .enrolling,
              let link = flow.link, let name = flow.deviceName, let fingerprint = preview?.identityFingerprint
        else { return }
        await run {
            let core = try self.openCore()
            let device = try await Task.detached {
                try core.enroll(link: link.text, deviceName: name, identityFingerprint: fingerprint)
            }.value
            self.enrolledDevice = device
            try? self.progressStore?.update { $0.enrolledAtMs = Int64(Date().timeIntervalSince1970 * 1000) }
            // A new enrollment starts a new book of what was reported.
            if let group = self.group { try? TamperLedger(group: group).reset() }
            self.flow.apply(.enrolled)
        } onError: { message in
            self.flow.apply(.failed(message))
        }
        await refreshStatus()
    }

    /// Checks once whether the member approved this phone.
    func pollApproval() async {
        guard flow.step == .waitingForApproval, let core = try? openCore() else { return }
        let result = await Task.detached { Result { try core.pollApproval() } }.value
        switch result {
        case .success(.approved):
            flow.apply(.approved)
            await refreshStatus()
        case .success(.pending):
            break
        case .failure(let e):
            // Transient network trouble shouldn't alarm anyone: keep waiting.
            if case FaroError.Network = e { break }
            flow.apply(.failed(describe(e)))
        }
    }

    func authorizeScreenTime() async {
        guard flow.step == .screenTime else { return }
        await run {
            try await ScreenTime.authorize(settingsStore: self.settingsStore)
            try self.progressStore?.update { $0.screenTimeDone = true }
            // The app has now read it approved, so it can tell a revocation.
            if let group = self.group {
                try? TamperLedger(group: group).update {
                    $0.sawScreenTime(approved: true, source: .app, nowMs: Self.nowMs())
                }
            }
            self.flow.apply(.screenTimeAuthorized)
        } onError: { message in
            self.flow.apply(.failed(message))
        }
        await refreshPlatformState()
    }

    func installTunnel() async {
        guard flow.step == .tunnel else { return }
        await run {
            try await TunnelInstaller.install(instanceName: self.status?.instanceName ?? "")
            try self.progressStore?.update { $0.tunnelDone = true }
            self.flow.apply(.tunnelInstalled)
            await self.scheduleNotice()
        } onError: { message in
            self.flow.apply(.failed(message))
        }
        await refreshPlatformState()
    }

    /// Schedules the monthly notice from the enrollment date.
    func scheduleNotice() async {
        let ms = progressStore?.load().enrolledAtMs
        let enrolled = ms.map { Date(timeIntervalSince1970: Double($0) / 1000) } ?? Date()
        notificationsOn = await NoticeScheduler.schedule(enrolledAt: enrolled, recipients: recipients)
    }

    /// When the next monthly notice is due, for the status screen.
    var nextNotice: Date? {
        guard let ms = progressStore?.load().enrolledAtMs else { return nil }
        return MonthlyNotice.nextFire(
            enrolledAt: Date(timeIntervalSince1970: Double(ms) / 1000), after: Date())
    }

    /// Setup for a part that came undone later (Screen Time revoked, the
    /// VPN removed): walk back to that step from the status screen.
    func redo(_ step: SetupStep) {
        guard step == .screenTime || step == .tunnel else { return }
        flow = SetupFlow(step: step)
    }

    func finishRedo() { flow = SetupFlow(step: .done) }

    // MARK: Helpers

    nonisolated static func nowMs() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }

    private func run(_ work: () async throws -> Void, onError: (String) -> Void) async {
        busy = true
        defer { busy = false }
        do { try await work() } catch { onError(describe(error)) }
    }

    private func describe(_ error: Error) -> String {
        switch error {
        case FaroError.NotEnrolled: return "This phone isn't enrolled yet."
        case FaroError.NotApproved: return "This phone hasn't been approved yet."
        case FaroError.AlreadyEnrolled(let instance):
            return "This phone is already enrolled with \(instance)."
        case FaroError.Network(let m): return "Couldn't reach the instance. Check your connection and try again. (\(m))"
        case FaroError.KeysLocked: return "Unlock the phone once and try again."
        case FaroError.Left: return "Faro is leaving this phone."
        case FaroError.InvalidLink(let m), FaroError.Instance(let m), FaroError.Integrity(let m),
             FaroError.Retired(let m), FaroError.KeyStore(let m), FaroError.Storage(let m),
             FaroError.Update(let m), FaroError.InvalidArgument(let m):
            return m
        default:
            return error.localizedDescription
        }
    }
}
