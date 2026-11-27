import XCTest
@testable import FaroKit
@testable import FaroKitApp

/// The watchers' decisions (docs/IOS.md §10.2): staleness, dedupe, causes,
/// the monitor's schedule and Leave Faro's order.
final class TamperTests: XCTestCase {
    private var root: URL!
    private let minute: Int64 = 60_000

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("faro-tamper-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    // MARK: One cause, one signal

    func testALayerIsReportedOnceUntilSeenOnAgain() {
        var book = TamperBook()
        XCTAssertTrue(book.sawOff(.filterOff(.vpnDisconnected), nowMs: 1))
        // Still off, by whatever cause: no second signal.
        XCTAssertFalse(book.sawOff(.filterOff(.vpnDisconnected), nowMs: 2))
        XCTAssertFalse(book.sawOff(.filterOff(.otherVpn), nowMs: 3))
        XCTAssertEqual(book.pending.map(\.request), [.filterOff(.vpnDisconnected)])
        // Other layers are their own.
        XCTAssertTrue(book.sawOff(.settingsCleared, nowMs: 4))
        // Seen on, then off again: news again.
        XCTAssertTrue(book.sawOn(.filter))
        XCTAssertFalse(book.sawOn(.filter), "nothing to clear twice")
        XCTAssertTrue(book.sawOff(.filterOff(.profileRemoved), nowMs: 5))
        XCTAssertEqual(
            book.pending.map(\.request),
            [.filterOff(.vpnDisconnected), .settingsCleared, .filterOff(.profileRemoved)])
        XCTAssertEqual(Set(book.pending.map(\.id)).count, 3, "ids are unique")
    }

    func testEveryRequestIsTamperClass() {
        // The three requests the watchers make, one per layer, and each maps
        // to a core `Tamper` (the glue switches over all of them).
        let all: [TamperRequest] = [.screenTimeRevoked, .settingsCleared]
            + FilterCauseCode.allCases.map { .filterOff($0) }
        XCTAssertEqual(Set(all.map(\.layer)), Set(ProtectionLayer.allCases))
        XCTAssertEqual(
            FilterCauseCode.allCases.map(\.rawValue),
            ["vpn_disconnected", "on_demand_off", "other_vpn", "profile_removed", "unknown"])
    }

    // MARK: Screen Time readings

    func testScreenTimeNeedsAConfirmingSecondReading() {
        var book = TamperBook()
        XCTAssertEqual(book.sawScreenTime(approved: true, source: .tunnel, nowMs: 0), .approved)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .tunnel, nowMs: 1_000), .recheck)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .tunnel, nowMs: 1_500), .recheck, "too soon")
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .tunnel, nowMs: 4_000), .reported)
        XCTAssertEqual(book.pending.map(\.request), [.screenTimeRevoked])
        // A source that never read it approved can't tell.
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .monitor, nowMs: 5_000), .unknown)
        XCTAssertEqual(book.pending.count, 1)
    }

    func testATransientMisreadIsForgotten() {
        var book = TamperBook()
        book.sawScreenTime(approved: true, source: .app, nowMs: 0)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 1_000), .recheck)
        XCTAssertEqual(book.sawScreenTime(approved: true, source: .app, nowMs: 4_000), .approved)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 6_000), .recheck, "starts over")
        // A doubt from long ago doesn't confirm a new reading on its own.
        XCTAssertEqual(
            book.sawScreenTime(approved: false, source: .app, nowMs: 6_000 + TamperBook.doubtExpiresMs + 1),
            .recheck)
        XCTAssertTrue(book.pending.isEmpty)
    }

    func testASourceThatNeverReadApprovedCantReportARevocation() {
        // Spike S6: if the tunnel can't read the status, it reads "not
        // determined" from the start, and must never call that a revocation.
        var book = TamperBook()
        for t in stride(from: Int64(0), to: 100_000, by: 10_000) {
            XCTAssertEqual(book.sawScreenTime(approved: false, source: .tunnel, nowMs: t), .unknown)
        }
        XCTAssertTrue(book.pending.isEmpty)
    }

    func testRevokedThenRestoredThenRevokedIsTwoSignals() {
        var book = TamperBook()
        book.sawScreenTime(approved: true, source: .app, nowMs: 0)
        book.sawScreenTime(approved: false, source: .app, nowMs: 10_000)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 13_000), .reported)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 20_000), .recheck)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 23_000), .alreadyReported)
        book.sawScreenTime(approved: true, source: .app, nowMs: 30_000)
        book.sawScreenTime(approved: false, source: .app, nowMs: 40_000)
        XCTAssertEqual(book.sawScreenTime(approved: false, source: .app, nowMs: 43_000), .reported)
        XCTAssertEqual(book.pending.count, 2)
    }

    func testScreenTimeStateForTheProtectionTimeline() {
        var book = TamperBook()
        XCTAssertNil(book.screenTimeState(reading: false, source: .tunnel), "nobody knows yet")
        book.sawScreenTime(approved: true, source: .monitor, nowMs: 0)
        // A tunnel that can't read it leans on the monitor.
        XCTAssertEqual(book.screenTimeState(reading: false, source: .tunnel), true)
        book.sawOff(.screenTimeRevoked, nowMs: 1)
        XCTAssertEqual(book.screenTimeState(reading: false, source: .tunnel), false)
        // A tunnel that has read it approved is believed.
        book.sawScreenTime(approved: true, source: .tunnel, nowMs: 2)
        XCTAssertEqual(book.screenTimeState(reading: true, source: .tunnel), true)
        XCTAssertEqual(book.screenTimeState(reading: false, source: .tunnel), false)
    }

    // MARK: The ledger file

    func testTheLedgerKeepsTheBookAcrossProcesses() throws {
        let a = TamperLedger(directory: root)
        let b = TamperLedger(directory: root)
        XCTAssertTrue(try a.update { $0.sawOff(.settingsCleared, nowMs: 1) })
        XCTAssertFalse(try b.update { $0.sawOff(.settingsCleared, nowMs: 2) }, "the other process sees it")
        XCTAssertEqual(b.read().pending.count, 1)
    }

    func testDrainKeepsWhatCouldNotBeRecorded() throws {
        let ledger = TamperLedger(directory: root)
        try ledger.update {
            $0.sawOff(.screenTimeRevoked, nowMs: 1)
            $0.sawOff(.filterOff(.otherVpn), nowMs: 2)
        }
        struct Locked: Error {}
        var seen: [TamperRequest] = []
        let n = try ledger.drain { r in
            seen.append(r)
            if r == .screenTimeRevoked { throw Locked() }
        }
        XCTAssertEqual(n, 1)
        XCTAssertEqual(seen, [.screenTimeRevoked, .filterOff(.otherVpn)], "oldest first")
        XCTAssertEqual(ledger.read().pending.map(\.request), [.screenTimeRevoked])
        XCTAssertEqual(try ledger.drain { _ in }, 1)
        XCTAssertTrue(ledger.read().pending.isEmpty)
        // Recorded is not "seen on": the layer stays reported off.
        XCTAssertFalse(try ledger.update { $0.sawOff(.screenTimeRevoked, nowMs: 3) })
    }

    func testAClaimedRequestIsLeftToItsClaimerUntilTheLeaseLapses() {
        var book = TamperBook()
        book.sawOff(.settingsCleared, nowMs: 0)
        XCTAssertEqual(book.claim(nowMs: 1_000).map(\.request), [.settingsCleared])
        XCTAssertTrue(book.claim(nowMs: 2_000).isEmpty, "another process is recording it")
        XCTAssertEqual(book.claim(nowMs: 1_000 + PendingState.claimLeaseMs).count, 1, "the lease lapsed")
        let id = book.pending[0].id
        book.release([id])
        XCTAssertEqual(book.claim(nowMs: 1_000 + PendingState.claimLeaseMs + 1).count, 1, "released")
        book.complete([id])
        XCTAssertTrue(book.pending.isEmpty)
    }

    func testConcurrentWatchersQueueOneRequest() throws {
        let ledger = TamperLedger(directory: root)
        let lock = NSLock()
        var news = 0
        DispatchQueue.concurrentPerform(iterations: 16) { i in
            let fresh = (try? ledger.update { $0.sawOff(.filterOff(.unknown), nowMs: Int64(i)) }) ?? false
            if fresh { lock.lock(); news += 1; lock.unlock() }
        }
        XCTAssertEqual(news, 1)
        XCTAssertEqual(ledger.read().pending.count, 1)
    }

    func testADamagedLedgerStartsOver() throws {
        let ledger = TamperLedger(directory: root)
        try Data("{nope".utf8).write(to: ledger.url)
        XCTAssertEqual(ledger.read(), TamperBook())
        XCTAssertTrue(try ledger.update { $0.sawOff(.settingsCleared, nowMs: 1) })
    }

    func testStandingDownOnlyAfterTheGoodbye() {
        var book = TamperBook()
        book.sawOff(.settingsCleared, nowMs: 1)
        book.standDown()
        XCTAssertTrue(book.pending.isEmpty)
        XCTAssertFalse(book.sawOff(.filterOff(.vpnDisconnected), nowMs: 2))
        XCTAssertFalse(book.shouldRecordContext(ContextName.otherVPN, nowMs: 3, everyMs: 1))
    }

    func testContextIsRecordedAtMostOncePerInterval() {
        var book = TamperBook()
        let hour = ContextName.everyMs
        XCTAssertTrue(book.shouldRecordContext(ContextName.dohDropped, nowMs: 0, everyMs: hour))
        XCTAssertFalse(book.shouldRecordContext(ContextName.dohDropped, nowMs: hour - 1, everyMs: hour))
        XCTAssertTrue(book.shouldRecordContext(ContextName.otherVPN, nowMs: 1, everyMs: hour), "its own")
        XCTAssertTrue(book.shouldRecordContext(ContextName.dohDropped, nowMs: hour, everyMs: hour))
        // A clock set back doesn't silence it.
        XCTAssertTrue(book.shouldRecordContext(ContextName.dohDropped, nowMs: 5, everyMs: hour))
    }

    // MARK: Is the tunnel running?

    func testTunnelStaleness() {
        let stale = TunnelWatch.staleAfterMs
        XCTAssertEqual(stale, 20 * minute)
        XCTAssertEqual(TunnelWatch.judge(aliveMs: nil, restingMs: nil, nowMs: 0), .neverSeen)
        XCTAssertEqual(TunnelWatch.judge(aliveMs: 0, restingMs: nil, nowMs: stale), .alive)
        XCTAssertEqual(TunnelWatch.judge(aliveMs: 0, restingMs: nil, nowMs: stale + 1), .stale)
        // Asleep (or stopped for no network) since its last minute: resting,
        // however long.
        XCTAssertEqual(TunnelWatch.judge(aliveMs: 0, restingMs: 30_000, nowMs: 10 * stale), .resting)
        // Awake again since: judged on its marker.
        XCTAssertEqual(TunnelWatch.judge(aliveMs: 60_000, restingMs: 30_000, nowMs: 60_000 + stale + 1), .stale)
        XCTAssertEqual(TunnelWatch.judge(aliveMs: 10 * minute, restingMs: nil, nowMs: 0), .alive, "clock set back")
    }

    func testStopReasons() {
        XCTAssertEqual(TunnelStopMeaning.of(.userInitiated), .off(.vpnDisconnected))
        XCTAssertEqual(TunnelStopMeaning.of(.superceded), .off(.otherVpn))
        XCTAssertEqual(TunnelStopMeaning.of(.configurationDisabled), .off(.otherVpn))
        XCTAssertEqual(TunnelStopMeaning.of(.configurationRemoved), .off(.profileRemoved))
        XCTAssertEqual(TunnelStopMeaning.of(.providerDisabled), .off(.unknown))
        for r in [TunnelStopReason.sleep, .noNetworkAvailable, .appUpdate, .connectionFailed] {
            XCTAssertEqual(TunnelStopMeaning.of(r), .resting, "\(r)")
        }
        XCTAssertEqual(TunnelStopMeaning.of(.providerFailed), .unexplained)
        // Every reason means something.
        XCTAssertEqual(TunnelStopReason.allCases.count, 18)
    }

    // MARK: The VPN configuration on app launch

    private func vpn(
        configured: Bool = true, enabled: Bool = true, onDemand: Bool = true,
        _ state: VPNState, otherVPN: Bool = false
    ) -> FilterVerdict {
        FilterVerdict.of(VPNSnapshot(
            configured: configured, enabled: enabled, onDemand: onDemand, state: state, otherVPN: otherVPN))
    }

    func testTheBestCauseForAFilterThatIsOff() {
        XCTAssertEqual(vpn(.connected), .on)
        XCTAssertEqual(vpn(.connecting), .waiting)
        XCTAssertEqual(vpn(.reasserting), .waiting)
        XCTAssertEqual(vpn(configured: false, .disconnected), .off(.profileRemoved))
        XCTAssertEqual(vpn(.invalid), .off(.profileRemoved))
        XCTAssertEqual(vpn(.disconnected, otherVPN: true), .off(.otherVpn))
        XCTAssertEqual(vpn(enabled: false, .disconnected), .off(.vpnDisconnected))
        XCTAssertEqual(vpn(onDemand: false, .disconnected), .off(.onDemandOff))
        // Enabled with Connect On Demand but not up: no network yet, say.
        XCTAssertEqual(vpn(.disconnected), .waiting)
        XCTAssertEqual(vpn(onDemand: false, .connected), .on, "running is on")
    }

    func testOtherVPNNeedsFarosOwnTunnelDown() {
        XCTAssertTrue(OtherVPN.active(scopedInterfaces: ["en0", "ipsec0"], faroTunnelUp: false))
        XCTAssertTrue(OtherVPN.active(scopedInterfaces: ["utun4"], faroTunnelUp: false))
        XCTAssertFalse(OtherVPN.active(scopedInterfaces: ["en0", "pdp_ip0"], faroTunnelUp: false))
        XCTAssertFalse(OtherVPN.active(scopedInterfaces: ["utun4"], faroTunnelUp: true))
    }

    // MARK: The "faro" store

    func testAClearedOrLoosenedStoreIsNotIntact() {
        let plan = ScreenTimePlan(.default)
        let applied = StoreSnapshot(
            webFilterOn: true, denyAppRemoval: true, denyExplicitContent: true,
            requireAutomaticDateAndTime: true, maximumAppRating: nil)
        XCTAssertTrue(StoreCheck.intact(applied, plan: plan))
        XCTAssertFalse(StoreCheck.intact(.empty, plan: plan))
        var loosened = applied
        loosened.denyAppRemoval = false
        XCTAssertFalse(StoreCheck.intact(loosened, plan: plan))
        var noFilter = applied
        noFilter.webFilterOn = false
        XCTAssertFalse(StoreCheck.intact(noFilter, plan: plan))
        // What the plan leaves off may read as unset.
        let relaxed = ScreenTimePlan(FaroSettings(denyExplicitContent: false, maximumAppRating: 12))
        var r = applied
        r.denyExplicitContent = nil
        XCTAssertFalse(StoreCheck.intact(r, plan: relaxed), "rating missing")
        r.maximumAppRating = 12
        XCTAssertTrue(StoreCheck.intact(r, plan: relaxed))
        r.maximumAppRating = 17
        XCTAssertFalse(StoreCheck.intact(r, plan: relaxed))
    }

    // MARK: Context

    func testJailbreakCheck() {
        XCTAssertFalse(JailbreakCheck.suspected(fileExists: { _ in false }, canWriteOutsideSandbox: { false }))
        XCTAssertTrue(JailbreakCheck.suspected(fileExists: { $0 == "/var/jb" }, canWriteOutsideSandbox: { false }))
        XCTAssertTrue(JailbreakCheck.suspected(fileExists: { _ in false }, canWriteOutsideSandbox: { true }))
    }

    // MARK: The monitor's schedule

    func testTheBackboneCoversTheDayWithinApplesLimit() {
        XCTAssertLessThanOrEqual(MonitorSchedule.allActivityNames.count, 20)
        XCTAssertEqual(Set(MonitorSchedule.allActivityNames).count, MonitorSchedule.allActivityNames.count)
        XCTAssertEqual(MonitorSchedule.backboneMinutes * MonitorSchedule.backboneWindows, 24 * 60)
        XCTAssertGreaterThanOrEqual(MonitorSchedule.backboneMinutes, MonitorSchedule.windowMinutes)
        var covered = 0
        for i in 0..<MonitorSchedule.backboneWindows {
            let w = MonitorSchedule.backboneWindow(i)
            let start = w.start.hour! * 60 + w.start.minute!
            let end = w.end.hour! * 60 + w.end.minute!
            XCTAssertEqual(start, covered, "end to end")
            covered = end == 0 ? 24 * 60 : end
        }
        XCTAssertEqual(covered, 24 * 60)
        XCTAssertTrue(MonitorSchedule.backboneNames.allSatisfy(MonitorSchedule.isBackbone))
        XCTAssertFalse(MonitorSchedule.isBackbone(MonitorSchedule.activityName))
        // A dropped callback costs at most one backbone window, with slack.
        XCTAssertEqual(MonitorSchedule.monitorStaleAfterMs, Int64(80 + 15) * minute)
    }

    // MARK: Leave Faro

    func testLeavingLiftsNothingBeforeTheGoodbyeIsDelivered() {
        var flow = LeaveFlow()
        XCTAssertTrue(flow.canCancel)
        XCTAssertFalse(flow.apply(.delivered), "not asked yet")
        XCTAssertTrue(flow.apply(.confirmed))
        XCTAssertFalse(flow.mayLift)
        XCTAssertTrue(flow.apply(.unreachable("offline")))
        XCTAssertEqual(flow.step, .notDelivered(message: "offline", written: false))
        XCTAssertFalse(flow.mayLift)
        XCTAssertTrue(flow.canCancel, "nothing written: the member can still stay")
        XCTAssertFalse(flow.apply(.lifted(leftovers: [])))
        XCTAssertTrue(flow.apply(.retry))
        XCTAssertTrue(flow.apply(.queued("timed out")))
        XCTAssertFalse(flow.canCancel, "the goodbye is written")
        XCTAssertTrue(flow.apply(.retry))
        XCTAssertTrue(flow.apply(.delivered))
        XCTAssertTrue(flow.mayLift)
        XCTAssertTrue(flow.apply(.lifted(leftovers: ["Remove the VPN in Settings."])))
        XCTAssertEqual(flow.step, .done(leftovers: ["Remove the VPN in Settings."]))
    }

    func testLeavingResumesAfterARelaunch() {
        XCTAssertNil(LeaveFlow.resume(leaving: false, goodbyeDelivered: false))
        XCTAssertEqual(LeaveFlow.resume(leaving: true, goodbyeDelivered: true)?.step, .lifting)
        let pending = LeaveFlow.resume(leaving: true, goodbyeDelivered: false)
        XCTAssertFalse(pending?.mayLift ?? true)
        XCTAssertFalse(pending?.canCancel ?? true)
    }
}
