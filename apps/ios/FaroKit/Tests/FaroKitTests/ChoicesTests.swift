import XCTest
@testable import FaroKit

/// The choice diff, the pending-change state machine and its clock edges
/// (docs/IOS.md §9).
final class ChoicesTests: XCTestCase {
    private let hour: Int64 = 3600 * 1000
    private let t0: Int64 = 1_800_000_000_000
    private var counter = 0

    private func id() -> String {
        counter += 1
        return "id\(counter)"
    }

    private func base(delay: Int = 24) -> FaroSettings {
        FaroSettings(blockedCategories: ["gambling"], loosenDelayHours: delay)
    }

    // MARK: Which way a change goes

    func testBlockingMoreIsTightening() {
        var new = FaroSettings.default
        new.blockedCategories = ["gambling"]
        new.extraBlockedDomains = ["a.example"]
        new.shieldApps = ["t1", "t2"]
        new.maximumAppRating = 12
        new.loosenDelayHours = 48
        let d = ChoiceDiff.between(.default, new)
        XCTAssertTrue(d.loosening.isEmpty)
        XCTAssertEqual(Set(d.tightening.map(\.key)), [
            "ios.category.gambling", "ios.site", "ios.apps", "ios.app_rating", "ios.delay_hours",
        ])
        let apps = d.tightening.first { $0.key == "ios.apps" }
        XCTAssertEqual(apps?.old, "0")
        XCTAssertEqual(apps?.new, "2")
    }

    func testBlockingLessIsLoosening() {
        var old = FaroSettings.default
        old.blockedCategories = ["gambling"]
        old.extraBlockedDomains = ["a.example"]
        old.shieldApps = ["t1", "t2"]
        old.maximumAppRating = 12
        var new = FaroSettings.default
        new.shieldApps = ["t1"]
        new.denyExplicitContent = false
        new.loosenDelayHours = 0
        let d = ChoiceDiff.between(old, new)
        XCTAssertTrue(d.tightening.isEmpty)
        XCTAssertEqual(Set(d.loosening.map(\.key)), [
            "ios.category.gambling", "ios.site", "ios.apps", "ios.app_rating", "ios.explicit_media", "ios.delay_hours",
        ])
        let site = d.loosening.first { $0.key == "ios.site" }
        XCTAssertEqual(site?.old, "a.example")
        XCTAssertNil(site?.new)
        let rating = d.loosening.first { $0.key == "ios.app_rating" }
        XCTAssertEqual(rating?.old, "12")
        XCTAssertEqual(rating?.new, "off")
    }

    func testRatingDirections() {
        func dir(_ a: Int?, _ b: Int?) -> String {
            let d = ChoiceDiff.between(FaroSettings(maximumAppRating: a), FaroSettings(maximumAppRating: b))
            return d.tightening.isEmpty ? (d.loosening.isEmpty ? "same" : "loosen") : "tighten"
        }
        XCTAssertEqual(dir(nil, 17), "tighten")
        XCTAssertEqual(dir(17, 12), "tighten")
        XCTAssertEqual(dir(12, 17), "loosen")
        XCTAssertEqual(dir(4, nil), "loosen")
        // "All" (1000) and off are the same thing.
        XCTAssertEqual(dir(nil, 1000), "same")
        // A number between ratings rounds up, as the plan does.
        XCTAssertEqual(dir(10, 12), "same")
    }

    func testShorteningTheDelayIsALoosening() {
        let d = ChoiceDiff.between(base(delay: 24), base(delay: 12))
        XCTAssertEqual(d.loosening.map(\.key), ["ios.delay_hours"])
        XCTAssertEqual(d.loosening.first?.old, "24")
        XCTAssertEqual(d.loosening.first?.new, "12")
        XCTAssertTrue(ChoiceDiff.between(base(delay: 24), base(delay: 72)).loosening.isEmpty)
        // Out of range values are held to 0...72.
        XCTAssertTrue(ChoiceDiff.between(base(delay: 72), base(delay: 500)).isEmpty)
        XCTAssertEqual(base(delay: -3).loosenDelaySecs, 0)
        XCTAssertEqual(base(delay: 500).loosenDelaySecs, 72 * 3600)
    }

    func testSwappingAnAppIsBothAndTheCountsChain() {
        var old = FaroSettings.default
        old.shieldApps = ["a", "b"]
        var new = FaroSettings.default
        new.shieldApps = ["a", "c"]
        let d = ChoiceDiff.between(old, new)
        XCTAssertEqual(d.tightening.map { [$0.old, $0.new] }, [["2", "3"]])
        XCTAssertEqual(d.loosening.map { [$0.old, $0.new] }, [["3", "2"]])
    }

    func testNothingChangedIsEmpty() {
        XCTAssertTrue(ChoiceDiff.between(base(), base()).isEmpty)
        // The generation and the allow list aren't choices.
        var b = base()
        b.generation = 9
        b.allowedDomains = ["x.example"]
        XCTAssertTrue(ChoiceDiff.between(base(), b).isEmpty)
    }

    func testChunksStayWithinWhatAnEventCarries() {
        var new = FaroSettings.default
        new.extraBlockedDomains = (0..<70).map { "site\($0).example" }
        let d = ChoiceDiff.between(.default, new)
        let chunks = ChoiceDiff.chunks(d.tightening)
        XCTAssertEqual(chunks.map(\.count), [32, 32, 6])
    }

    func testEveryKeyFitsTheCoreLimits() {
        // faro-mobile: keys of 1-64 of [A-Za-z0-9_.-], values at most 512 bytes.
        var new = FaroSettings.default
        new.blockedCategories = IosSettingKey.optionalCategories
        new.extraBlockedDomains = ["a.example"]
        new.shieldApps = ["x"]
        new.shieldAppCategories = ["x"]
        new.shieldWebDomains = ["x"]
        new.shieldWebDomainCategories = ["x"]
        for c in ChoiceDiff.between(.default, new).tightening {
            XCTAssertLessThanOrEqual(c.key.count, 64)
            XCTAssertTrue(c.key.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "_.-".contains($0)) })
            XCTAssertTrue(c.key.hasPrefix("ios."))
        }
    }

    // MARK: Submitting

    func testTighteningAppliesAtOnceAndIsOneEvent() {
        var s = FaroSettings.default
        var p = PendingState()
        var draft = s
        draft.blockedCategories = ["gambling"]
        let r = p.submit(draft, to: &s, nowMs: t0, newID: id)
        XCTAssertEqual(s.blockedCategories, ["gambling"])
        XCTAssertEqual(s.generation, 1)
        XCTAssertTrue(p.items.isEmpty)
        XCTAssertEqual(r.appliedNow.count, 1)
        XCTAssertEqual(p.events.map(\.kind), [.tightened])
        XCTAssertNil(p.events[0].takesEffectAtMs)
    }

    func testLooseningWaitsForTheDelay() {
        var s = base()
        var p = PendingState()
        var draft = s
        draft.blockedCategories = []
        let r = p.submit(draft, to: &s, nowMs: t0, newID: id)
        // Nothing changed yet, and the request is on the way out.
        XCTAssertEqual(s.blockedCategories, ["gambling"])
        XCTAssertEqual(s.generation, 0)
        XCTAssertEqual(r.waiting.count, 1)
        XCTAssertEqual(p.items[0].takesEffectAtMs, t0 + 24 * hour)
        XCTAssertEqual(p.items[0].delaySecs, 86400)
        let e = p.events[0]
        XCTAssertEqual(e.kind, .loosenRequested)
        XCTAssertEqual(e.requestedAtMs, t0)
        XCTAssertEqual(e.takesEffectAtMs, t0 + 24 * hour)
        XCTAssertEqual(e.delaySecs, 86400)
        XCTAssertEqual(e.changes.first?.key, "ios.category.gambling")
        XCTAssertEqual(e.changes.first?.old, "blocked")
        XCTAssertEqual(e.changes.first?.new, "allowed")
    }

    func testMixedSaveTightensNowAndWaitsOnTheRest() {
        var s = base()
        var p = PendingState()
        var draft = s
        draft.blockedCategories = []
        draft.extraBlockedDomains = ["new.example"]
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        XCTAssertEqual(s.extraBlockedDomains, ["new.example"])
        XCTAssertEqual(s.blockedCategories, ["gambling"])
        XCTAssertEqual(p.events.map(\.kind), [.tightened, .loosenRequested])
    }

    func testZeroDelayLoosensAtOnceButStaysLoud() {
        var s = base(delay: 0)
        var p = PendingState()
        var draft = s
        draft.blockedCategories = []
        let r = p.submit(draft, to: &s, nowMs: t0, newID: id)
        XCTAssertEqual(s.blockedCategories, [])
        XCTAssertEqual(r.loosenedNow.count, 1)
        XCTAssertTrue(p.items.isEmpty)
        XCTAssertEqual(p.events.map(\.kind), [.loosenApplied])
        XCTAssertEqual(p.events[0].requestedAtMs, t0)
        XCTAssertEqual(p.events[0].takesEffectAtMs, t0)
        XCTAssertEqual(p.events[0].delaySecs, 0)
    }

    func testShorteningTheDelayWaitsOutTheOldDelay() {
        var s = base(delay: 24)
        var p = PendingState()
        var draft = s
        draft.loosenDelayHours = 0
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        XCTAssertEqual(s.loosenDelayHours, 24)
        XCTAssertEqual(p.items[0].takesEffectAtMs, t0 + 24 * hour)
        // Until it applies, a loosening still waits the full day.
        var draft2 = s
        draft2.blockedCategories = []
        _ = p.submit(draft2, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertEqual(p.items.last?.takesEffectAtMs, t0 + 25 * hour)
        _ = p.applyDue(to: &s, nowMs: t0 + 24 * hour, newID: id)
        XCTAssertEqual(s.loosenDelayHours, 0)
    }

    func testAskingAgainForTheSameLooseningDoesNothing() {
        var s = base()
        var p = PendingState()
        var draft = s
        draft.blockedCategories = []
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        let r = p.submit(draft, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertTrue(r.isEmpty)
        XCTAssertEqual(p.items.count, 1)
        XCTAssertEqual(p.items[0].takesEffectAtMs, t0 + 24 * hour)
        XCTAssertEqual(p.events.count, 1)
    }

    func testChangingTheSameSettingAgainDropsTheWaitingOne() {
        var s = FaroSettings(maximumAppRating: 12, loosenDelayHours: 24)
        var p = PendingState()
        var draft = s
        draft.maximumAppRating = nil
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        // The member thinks again and tightens it further instead.
        var draft2 = s
        draft2.maximumAppRating = 9
        let r = p.submit(draft2, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertEqual(r.superseded.count, 1)
        XCTAssertTrue(p.items.isEmpty)
        XCTAssertEqual(s.maximumAppRating, 9)
        XCTAssertEqual(p.events.map(\.kind), [.loosenRequested, .loosenCancelled, .tightened])
        // Later, nothing is left to apply.
        XCTAssertFalse(p.applyDue(to: &s, nowMs: t0 + 48 * hour, newID: id))
        XCTAssertEqual(s.maximumAppRating, 9)
    }

    func testAnotherSiteDoesNotDropTheWaitingOne() {
        var s = FaroSettings(extraBlockedDomains: ["a.example", "b.example"], loosenDelayHours: 24)
        var p = PendingState()
        var draft = s
        draft.extraBlockedDomains = ["b.example"]
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        var draft2 = s
        draft2.extraBlockedDomains = ["a.example", "b.example", "c.example"]
        _ = p.submit(draft2, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertEqual(p.items.count, 1, "removing a.example still waits")
        XCTAssertEqual(s.extraBlockedDomains, ["a.example", "b.example", "c.example"])
    }

    // MARK: The clock

    private func waitingGambling() -> (FaroSettings, PendingState) {
        var s = base()
        var p = PendingState()
        var draft = s
        draft.blockedCategories = []
        _ = p.submit(draft, to: &s, nowMs: t0, newID: id)
        return (s, p)
    }

    func testAppliesAtExactlyTheTimeNotBefore() {
        var (s, p) = waitingGambling()
        XCTAssertFalse(p.applyDue(to: &s, nowMs: t0 + 24 * hour - 1, newID: id))
        XCTAssertEqual(s.blockedCategories, ["gambling"])
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 24 * hour, newID: id))
        XCTAssertEqual(s.blockedCategories, [])
        XCTAssertEqual(s.generation, 1)
        XCTAssertTrue(p.items.isEmpty)
        let applied = p.events.last
        XCTAssertEqual(applied?.kind, .loosenApplied)
        XCTAssertEqual(applied?.requestedAtMs, t0)
        XCTAssertEqual(applied?.takesEffectAtMs, t0 + 24 * hour)
    }

    func testAClockSetBackKeepsItWaiting() {
        var (s, p) = waitingGambling()
        XCTAssertFalse(p.applyDue(to: &s, nowMs: t0 - 5 * hour, newID: id))
        XCTAssertFalse(p.applyDue(to: &s, nowMs: 0, newID: id))
        XCTAssertFalse(p.applyDue(to: &s, nowMs: -1, newID: id))
        XCTAssertEqual(p.items.count, 1)
        // Back to the real time, it still applies at its time.
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 24 * hour, newID: id))
    }

    func testAppliesWhenTheClockIsLongPast() {
        // A phone that was off for a week.
        var (s, p) = waitingGambling()
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 7 * 24 * hour, newID: id))
        XCTAssertEqual(s.blockedCategories, [])
    }

    func testApplyingTwiceIsHarmlessAndSendsOneEvent() {
        var (s, p) = waitingGambling()
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 25 * hour, newID: id))
        XCTAssertFalse(p.applyDue(to: &s, nowMs: t0 + 26 * hour, newID: id))
        XCTAssertEqual(p.events.filter { $0.kind == .loosenApplied }.count, 1)
        XCTAssertEqual(s.generation, 1)
    }

    func testSeveralDueTogetherApplyInOrder() {
        var s = FaroSettings(extraBlockedDomains: ["a.example", "b.example"], maximumAppRating: 9, loosenDelayHours: 24)
        var p = PendingState()
        var d1 = s
        d1.extraBlockedDomains = ["b.example"]
        _ = p.submit(d1, to: &s, nowMs: t0, newID: id)
        var d2 = s
        d2.maximumAppRating = nil
        _ = p.submit(d2, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 30 * hour, newID: id))
        XCTAssertEqual(s.extraBlockedDomains, ["b.example"])
        XCTAssertNil(s.maximumAppRating)
        XCTAssertEqual(p.events.filter { $0.kind == .loosenApplied }.map { $0.changes.first?.key },
                       ["ios.site", "ios.app_rating"])
        XCTAssertEqual(s.generation, 1, "one save, however many were due")
    }

    func testAPendingLooseningAppliesToWhatTheSettingsAreByThen() {
        var s = FaroSettings(extraBlockedDomains: ["a.example"], loosenDelayHours: 24)
        var p = PendingState()
        var d1 = s
        d1.extraBlockedDomains = []
        _ = p.submit(d1, to: &s, nowMs: t0, newID: id)
        // Meanwhile the member blocks gambling.
        var d2 = s
        d2.blockedCategories = ["gambling"]
        _ = p.submit(d2, to: &s, nowMs: t0 + hour, newID: id)
        XCTAssertTrue(p.applyDue(to: &s, nowMs: t0 + 24 * hour, newID: id))
        XCTAssertEqual(s.extraBlockedDomains, [])
        XCTAssertEqual(s.blockedCategories, ["gambling"], "later choices survive")
    }

    // MARK: Cancelling

    func testCancelBeforeItsTimeKeepsTheSetting() {
        var (s, p) = waitingGambling()
        let pid = p.items[0].id
        XCTAssertEqual(p.cancel(pid, settings: &s, nowMs: t0 + hour, newID: id), .cancelled)
        XCTAssertTrue(p.items.isEmpty)
        let e = p.events.last
        XCTAssertEqual(e?.kind, .loosenCancelled)
        XCTAssertEqual(e?.cancelledAtMs, t0 + hour)
        XCTAssertEqual(e?.requestedAtMs, t0)
        XCTAssertEqual(e?.takesEffectAtMs, t0 + 24 * hour)
        XCTAssertFalse(p.applyDue(to: &s, nowMs: t0 + 48 * hour, newID: id))
        XCTAssertEqual(s.blockedCategories, ["gambling"])
    }

    func testCancelAtExactlyItsTimeIsTooLate() {
        var (s, p) = waitingGambling()
        let pid = p.items[0].id
        XCTAssertEqual(p.cancel(pid, settings: &s, nowMs: t0 + 24 * hour, newID: id), .alreadyApplied)
        XCTAssertEqual(s.blockedCategories, [])
        XCTAssertEqual(p.cancel(pid, settings: &s, nowMs: t0 + 25 * hour, newID: id), .notFound)
    }

    func testCancelOneMillisecondBeforeStillWorks() {
        var (s, p) = waitingGambling()
        XCTAssertEqual(p.cancel(p.items[0].id, settings: &s, nowMs: t0 + 24 * hour - 1, newID: id), .cancelled)
    }

    func testCancelWithAClockSetBack() {
        var (s, p) = waitingGambling()
        XCTAssertEqual(p.cancel(p.items[0].id, settings: &s, nowMs: 0, newID: id), .cancelled)
    }

    // MARK: Sending events

    func testClaimsAreExclusiveUntilTheLeaseRunsOut() {
        var (_, p) = waitingGambling()
        let first = p.claimEvents(nowMs: t0)
        XCTAssertEqual(first.count, 1)
        // Another process looks while the first is sending.
        XCTAssertTrue(p.claimEvents(nowMs: t0 + 1000).isEmpty)
        // It died: after the lease the event is up for grabs again.
        XCTAssertEqual(p.claimEvents(nowMs: t0 + PendingState.claimLeaseMs).count, 1)
        // A clock set back doesn't hide it forever either.
        XCTAssertEqual(p.claimEvents(nowMs: t0 - 1).count, 1)
    }

    func testCompleteAndRelease() {
        var (_, p) = waitingGambling()
        let e = p.claimEvents(nowMs: t0)
        p.release(Set(e.map(\.id)))
        XCTAssertEqual(p.claimEvents(nowMs: t0 + 1).count, 1)
        p.complete(Set(e.map(\.id)))
        XCTAssertTrue(p.events.isEmpty)
        XCTAssertTrue(p.claimEvents(nowMs: t0 + 2).isEmpty)
    }

    func testStateRoundTripsThroughJSON() throws {
        var (_, p) = waitingGambling()
        _ = p.claimEvents(nowMs: t0)
        let data = try JSONEncoder().encode(p)
        XCTAssertEqual(try JSONDecoder().decode(PendingState.self, from: data), p)
    }
}

/// The store: the lock, the files, and the hand-off between processes.
final class ChoicesStoreTests: XCTestCase {
    private var root: URL!
    private let t0: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3600 * 1000

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("faro-choices-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    private func store(settings: FaroSettings? = FaroSettings(loosenDelayHours: 24)) throws -> ChoicesStore {
        let group = AppGroup(root: root)
        if let settings { try SettingsStore(group: group).save(settings) }
        return ChoicesStore(group: group)
    }

    func testNothingToDoBeforeSetup() throws {
        let s = try store(settings: nil)
        XCTAssertThrowsError(try s.read()) { XCTAssertEqual($0 as? ChoicesStore.StoreError, .notSetUp) }
        XCTAssertThrowsError(try s.applyDue(nowMs: t0))
    }

    func testSubmitWritesTheSettingsAndTheFilterFile() throws {
        let s = try store()
        var draft = FaroSettings(loosenDelayHours: 24)
        draft.blockedCategories = ["gambling"]
        draft.extraBlockedDomains = ["bad.example"]
        _ = try s.submit(draft, nowMs: t0)
        let loaded = try SettingsStore(group: s.group).load()
        XCTAssertEqual(loaded?.blockedCategories, ["gambling"])
        XCTAssertEqual(loaded?.generation, 1)
        let filter = try JSONSerialization.jsonObject(with: Data(contentsOf: s.group.filterConfigFile)) as? [String: Any]
        XCTAssertEqual(filter?["categories"] as? [String], ["gambling"])
        XCTAssertEqual(filter?["block"] as? [String], ["bad.example"])
    }

    func testTheMonitorAppliesAndTheAppSendsTheEvent() throws {
        let s = try store(settings: FaroSettings(blockedCategories: ["gambling"], loosenDelayHours: 24))
        var draft = FaroSettings(blockedCategories: [], loosenDelayHours: 24)
        draft.generation = 0
        _ = try s.submit(draft, nowMs: t0)
        // The request goes out when the app has the core.
        let sent = try s.claimEvents(nowMs: t0)
        XCTAssertEqual(sent.map(\.kind), [.loosenRequested])
        try s.completeEvents(Set(sent.map(\.id)))

        // A day later the monitor (a separate value, as in another process).
        let monitor = ChoicesStore(group: AppGroup(root: root))
        XCTAssertNil(try monitor.applyDue(nowMs: t0 + 23 * hour))
        let applied = try monitor.applyDue(nowMs: t0 + 24 * hour)
        XCTAssertEqual(applied?.blockedCategories, [])
        // The DNS filter's file followed.
        let filter = try JSONSerialization.jsonObject(with: Data(contentsOf: s.group.filterConfigFile)) as? [String: Any]
        XCTAssertEqual(filter?["categories"] as? [String], [])

        // The tunnel (or the app) turns the request file into the event.
        let events = try s.claimEvents(nowMs: t0 + 25 * hour)
        XCTAssertEqual(events.map(\.kind), [.loosenApplied])
        XCTAssertTrue(try s.claimEvents(nowMs: t0 + 25 * hour).isEmpty, "claimed, so the other one waits")
        try s.completeEvents(Set(events.map(\.id)))
        XCTAssertTrue(try s.read().pending.events.isEmpty)
    }

    func testCancelThroughTheStore() throws {
        let s = try store(settings: FaroSettings(blockedCategories: ["gambling"], loosenDelayHours: 24))
        _ = try s.submit(FaroSettings(blockedCategories: [], loosenDelayHours: 24), nowMs: t0)
        let pid = try XCTUnwrap(try s.read().pending.items.first?.id)
        XCTAssertEqual(try s.cancel(pid, nowMs: t0 + hour), .cancelled)
        XCTAssertNil(try s.applyDue(nowMs: t0 + 48 * hour))
        XCTAssertEqual(try s.read().settings.blockedCategories, ["gambling"])
    }

    func testTwoProcessesNeverApplyTheSameLooseningTwice() throws {
        let s = try store(settings: FaroSettings(blockedCategories: ["gambling"], loosenDelayHours: 1))
        _ = try s.submit(FaroSettings(blockedCategories: [], loosenDelayHours: 1), nowMs: t0)
        let group = AppGroup(root: root)
        let results = Results()
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            let applied = (try? ChoicesStore(group: group).applyDue(nowMs: t0 + 2 * hour)) ?? nil
            results.add(applied != nil)
        }
        XCTAssertEqual(results.trueCount, 1)
        let st = try s.read()
        XCTAssertEqual(st.pending.events.filter { $0.kind == .loosenApplied }.count, 1)
        XCTAssertEqual(st.settings.generation, 1)
    }

    func testAnOldSettingsFileStillReads() throws {
        let old = #"{"version":1,"extraBlockedDomains":[],"allowedDomains":[],"denyAppRemoval":true,"denyExplicitContent":true,"requireAutomaticDateAndTime":true}"#
        try Data(old.utf8).write(to: AppGroup(root: root).settingsFile)
        let loaded = try SettingsStore(group: AppGroup(root: root)).load()
        XCTAssertEqual(loaded?.loosenDelayHours, 24)
        XCTAssertEqual(loaded?.blockedCategories, [])
        XCTAssertEqual(loaded?.generation, 0)
    }

    func testANewerPendingFileIsNotOverwritten() throws {
        let s = try store()
        try Data(#"{"version":99,"items":[],"events":[]}"#.utf8).write(to: s.pendingFile)
        XCTAssertThrowsError(try s.submit(FaroSettings(blockedCategories: ["gambling"]), nowMs: t0))
    }
}

private final class Results: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Bool] = []
    func add(_ v: Bool) { lock.lock(); values.append(v); lock.unlock() }
    var trueCount: Int { values.filter { $0 }.count }
}

final class TunnelConfigTests: XCTestCase {
    func testFilterJSONHasTheChoicesAndOnlyValidNames() throws {
        var s = FaroSettings.default
        s.blockedCategories = ["gambling", "bogus"]
        s.extraBlockedDomains = ["Bad.Example", "not a host", "https://other.example/path"]
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: TunnelConfig.filterJSON(for: s)) as? [String: Any])
        XCTAssertEqual(obj["categories"] as? [String], ["gambling"])
        XCTAssertEqual(obj["block"] as? [String], ["bad.example", "other.example"])
        XCTAssertEqual(obj["allow"] as? [String], [])
        XCTAssertNil(obj["instance_host"])
    }

    func testProviderConfigurationIsAPropertyList() throws {
        var s = FaroSettings.default
        s.blockedCategories = ["gambling"]
        s.generation = 4
        let cfg = TunnelConfig.providerConfiguration(for: s)
        XCTAssertTrue(PropertyListSerialization.propertyList(cfg, isValidFor: .binary))
        XCTAssertEqual(cfg[TunnelConfig.generationKey] as? Int, 4)
    }

    func testTheTunnelPrefersTheProviderConfiguration() {
        let provider: [String: Any] = ["filter": "{\"categories\":[\"gambling\"]}", "generation": 3]
        // Before the first unlock: only the copy can be read.
        XCTAssertEqual(TunnelConfig.choose(provider: provider, fileJSON: nil, fileGeneration: nil),
                       "{\"categories\":[\"gambling\"]}")
        // After it, with the same generation: still the copy.
        XCTAssertEqual(TunnelConfig.choose(provider: provider, fileJSON: "{}", fileGeneration: 3),
                       "{\"categories\":[\"gambling\"]}")
        // A loosening applied by the monitor or the tunnel since: the file is newer.
        XCTAssertEqual(TunnelConfig.choose(provider: provider, fileJSON: "{}", fileGeneration: 4), "{}")
    }

    func testFallbacks() {
        XCTAssertEqual(TunnelConfig.choose(provider: nil, fileJSON: "{}", fileGeneration: 1), "{}")
        XCTAssertNil(TunnelConfig.choose(provider: nil, fileJSON: nil, fileGeneration: nil))
        XCTAssertNil(TunnelConfig.choose(provider: ["filter": 5], fileJSON: nil, fileGeneration: nil))
        XCTAssertEqual(TunnelConfig.choose(provider: ["filter": "{}"], fileJSON: nil, fileGeneration: nil), "{}")
    }

    func testPlanCarriesTheShieldTokensSorted() {
        var s = FaroSettings.default
        s.shieldApps = ["b", "a", "a"]
        s.shieldWebDomainCategories = ["z"]
        let plan = ScreenTimePlan(s)
        XCTAssertEqual(plan.shieldApps, ["a", "b"])
        XCTAssertEqual(plan.shieldWebDomainCategories, ["z"])
        XCTAssertEqual(plan.shieldAppCategories, [])
    }
}
