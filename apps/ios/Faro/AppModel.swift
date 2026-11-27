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
    /// The settings in force, and the loosenings waiting to take effect.
    @Published private(set) var settings: FaroSettings?
    @Published private(set) var pending: [PendingChange] = []
    @Published var choicesError: String?

    let notices = NoticeTapHandler()
    private var group: AppGroup?
    private var core: FaroCore?
    private var progressStore: SetupProgressStore?
    private var choicesStore: ChoicesStore?

    init() {
        let group = AppGroup.container() ?? AppModel.fallbackGroup()
        self.group = group
        if let group {
            progressStore = SetupProgressStore(group: group)
            choicesStore = ChoicesStore(group: group)
        }
        notices.onNotice = { [weak self] in self?.showingNotice = true }
    }

    /// Unsigned builds (and the Simulator without the entitlement) have no
    /// app group container; use a folder in Application Support so the app
    /// still runs. A signed build never takes this path.
    static func fallbackGroup() -> AppGroup? {
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
        case .failure(let e):
            flow = SetupFlow()
            flow.apply(.failed(describe(e)))
        }
        loaded = true
        await refreshPlatformState()
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
        await refreshChoices()
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
            guard let choices = self.choicesStore else { throw SetupError("Faro can't find a place to keep its files.") }
            try await ScreenTime.authorize(choices: choices)
            try self.progressStore?.update { $0.screenTimeDone = true }
            self.flow.apply(.screenTimeAuthorized)
        } onError: { message in
            self.flow.apply(.failed(message))
        }
        await refreshPlatformState()
    }

    func installTunnel() async {
        guard flow.step == .tunnel else { return }
        await run {
            try await TunnelInstaller.install(
                instanceName: self.status?.instanceName ?? "",
                settings: try? self.choicesStore?.read().settings)
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
        notificationsOn = await NoticeScheduler.schedule(enrolledAt: enrolled)
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

    // MARK: What is blocked (docs/IOS.md §9)

    private static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// Brings the choices up to date: applies a loosening whose time has
    /// come, writes the settings to Screen Time and the tunnel's
    /// configuration, and sends the events that are waiting.
    func refreshChoices() async {
        guard let store = choicesStore else { return }
        if let changed = try? store.applyDue(nowMs: Self.nowMs()), screenTimeOn {
            ScreenTimeEnforcer.apply(changed)
        }
        guard let snapshot = try? store.read() else { return }
        settings = snapshot.settings
        pending = snapshot.pending.items.sorted { $0.takesEffectAtMs < $1.takesEffectAtMs }
        await TunnelInstaller.updateProviderConfiguration(snapshot.settings)
        await sendSettingsEvents()
    }

    /// Turns the settings events in the app group into `settings_change`
    /// events, if the core can sign them now.
    func sendSettingsEvents() async {
        guard let group, let core = try? openCore() else { return }
        await Task.detached { SettingsEventSender.send(group: group, core: core) }.value
    }

    /// The member saved their choices. Tightening applies at once; loosening
    /// waits for the delay (`PendingState.submit`).
    @discardableResult
    func saveChoices(_ draft: FaroSettings) async -> SubmitResult? {
        guard let store = choicesStore else { return nil }
        do {
            let result = try store.submit(draft, nowMs: Self.nowMs())
            if screenTimeOn, let s = try? store.read().settings { ScreenTimeEnforcer.apply(s) }
            choicesError = nil
            await refreshChoices()
            return result
        } catch {
            choicesError = "Couldn't save your choices: \(error.localizedDescription)"
            return nil
        }
    }

    func cancelPending(_ id: String) async {
        guard let store = choicesStore else { return }
        switch try? store.cancel(id, nowMs: Self.nowMs()) {
        case .alreadyApplied?:
            choicesError = "That change had already taken effect."
        case nil:
            choicesError = "Couldn't cancel that change."
        default:
            choicesError = nil
        }
        if screenTimeOn, let s = try? store.read().settings { ScreenTimeEnforcer.apply(s) }
        await refreshChoices()
    }

    // MARK: Helpers

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
        case FaroError.InvalidLink(let m), FaroError.Instance(let m), FaroError.Integrity(let m),
             FaroError.Retired(let m), FaroError.KeyStore(let m), FaroError.Storage(let m),
             FaroError.Update(let m), FaroError.InvalidArgument(let m):
            return m
        default:
            return error.localizedDescription
        }
    }
}
