import XCTest
@testable import FaroKit

final class FaroKitTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("faro-kit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    func testAppGroupPaths() throws {
        let group = AppGroup(root: root)
        XCTAssertEqual(AppGroup.identifier, "group.org.faro.ios")
        XCTAssertEqual(group.settingsFile.lastPathComponent, "settings.json")
        try group.prepare()
        try group.prepare()
        for dir in [group.coreDirectory, group.countersDirectory, group.markersDirectory] {
            var isDir: ObjCBool = false
            XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir))
            XCTAssertTrue(isDir.boolValue)
            XCTAssertTrue(dir.path.hasPrefix(root.path))
        }
        // The DNS filter's files: its counters next to the others.
        XCTAssertEqual(group.filterConfigFile.deletingLastPathComponent().path, root.path)
        XCTAssertEqual(group.dnsCountersFile.deletingLastPathComponent().path, group.countersDirectory.path)
        XCTAssertNoThrow(try Markers.check(MarkerName.tunnelAlive))
    }

    func testSettingsDefaultsFollowTheSpec() {
        let s = FaroSettings.default
        XCTAssertTrue(s.denyAppRemoval)
        XCTAssertTrue(s.denyExplicitContent)
        XCTAssertTrue(s.requireAutomaticDateAndTime)
        XCTAssertNil(s.maximumAppRating)
        XCTAssertEqual(s.version, FaroSettings.currentVersion)
    }

    func testSettingsRoundTrip() throws {
        let store = SettingsStore(group: AppGroup(root: root))
        XCTAssertNil(try store.load())
        let saved = FaroSettings(
            extraBlockedDomains: ["example.com"], allowedDomains: ["school.example"],
            denyExplicitContent: false, maximumAppRating: 12)
        try store.save(saved)
        XCTAssertEqual(try store.load(), saved)
        try store.save(.default)
        XCTAssertEqual(try store.load(), .default)
    }

    func testDamagedSettingsThrowInsteadOfReadingAsEmpty() throws {
        let store = SettingsStore(group: AppGroup(root: root))
        try Data("{not json".utf8).write(to: store.url)
        XCTAssertThrowsError(try store.load())
    }

    func testNewerSettingsVersionIsRefused() throws {
        let store = SettingsStore(group: AppGroup(root: root))
        try store.save(FaroSettings(version: FaroSettings.currentVersion + 1))
        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? SettingsFileError, .newerVersion(FaroSettings.currentVersion + 1))
        }
    }

    func testMarkers() throws {
        let markers = Markers(directory: root.appendingPathComponent("markers"))
        XCTAssertNil(markers.read("tunnel_alive"))
        XCTAssertFalse(markers.isFresh("tunnel_alive", nowMs: 1_000, maxAgeMs: 100))
        try markers.touch("tunnel_alive", nowMs: 1_000)
        XCTAssertEqual(markers.read("tunnel_alive"), 1_000)
        XCTAssertTrue(markers.isFresh("tunnel_alive", nowMs: 1_100, maxAgeMs: 100))
        XCTAssertFalse(markers.isFresh("tunnel_alive", nowMs: 1_101, maxAgeMs: 100))
        markers.remove("tunnel_alive")
        XCTAssertNil(markers.read("tunnel_alive"))
    }

    func testMarkerNamesCannotEscapeTheDirectory() {
        let markers = Markers(directory: root)
        XCTAssertThrowsError(try markers.touch("../x", nowMs: 1))
        XCTAssertThrowsError(try markers.touch("", nowMs: 1))
        XCTAssertNil(markers.read("a/b"))
    }

    func testPlanDefaultsFollowTheSpec() {
        let p = ScreenTimePlan(.default)
        XCTAssertTrue(p.denyAppRemoval)
        XCTAssertTrue(p.denyExplicitContent)
        XCTAssertTrue(p.requireAutomaticDateAndTime)
        XCTAssertNil(p.maximumAppRating)
        XCTAssertTrue(p.extraBlockedDomains.isEmpty)
        XCTAssertTrue(p.allowedDomains.isEmpty)
    }

    func testPlanCleansDomains() {
        let s = FaroSettings(
            extraBlockedDomains: [" Example.COM ", "https://bad.example/path?q=1", ".dup.test", "dup.test",
                                  "nodots", "", "has space.com", "a..b.com", "trailing.dot."],
            allowedDomains: ["Ok.example", "example.com"])
        let p = ScreenTimePlan(s)
        XCTAssertEqual(p.extraBlockedDomains, ["bad.example", "dup.test", "example.com", "trailing.dot"])
        // example.com is blocked, so it can't also be allowed.
        XCTAssertEqual(p.allowedDomains, ["ok.example"])
    }

    func testPlanCapsDomains() {
        let many = (0..<200).map { "site\($0).example" }
        XCTAssertEqual(ScreenTimePlan(FaroSettings(extraBlockedDomains: many)).extraBlockedDomains.count,
                       ScreenTimePlan.maxDomains)
    }

    func testPlanRoundsRatingsUpToAValidOne() {
        func rating(_ r: Int?) -> Int? { ScreenTimePlan(FaroSettings(maximumAppRating: r)).maximumAppRating }
        XCTAssertEqual(rating(4), 4)
        XCTAssertEqual(rating(10), 12)
        XCTAssertEqual(rating(17), 17)
        XCTAssertEqual(rating(500), 1000)
        XCTAssertEqual(rating(5000), nil)
        XCTAssertNil(rating(nil))
    }

    func testPlanSurvivesTheSettingsFile() throws {
        let store = SettingsStore(group: AppGroup(root: root))
        try store.save(FaroSettings(extraBlockedDomains: ["b.example", "a.example"], denyExplicitContent: false))
        let p = ScreenTimePlan(try XCTUnwrap(try store.load()))
        XCTAssertEqual(p.extraBlockedDomains, ["a.example", "b.example"])
        XCTAssertFalse(p.denyExplicitContent)
    }

    func testMonitorWindowIsFifteenMinutes() throws {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let start = try XCTUnwrap(cal.date(from: DateComponents(year: 2026, month: 11, day: 26, hour: 10, minute: 50, second: 7)))
        let w = MonitorSchedule.window(from: start, calendar: cal)
        XCTAssertEqual([w.start.hour, w.start.minute, w.start.second], [10, 50, 7])
        XCTAssertEqual([w.end.hour, w.end.minute, w.end.second], [11, 5, 7])
        // Across midnight the end wraps to the next day's clock time.
        let late = try XCTUnwrap(cal.date(from: DateComponents(year: 2026, month: 11, day: 26, hour: 23, minute: 55)))
        let wrapped = MonitorSchedule.window(from: late, calendar: cal)
        XCTAssertEqual([wrapped.end.hour, wrapped.end.minute], [0, 10])
    }

    func testMarkerAndCounterNamesAreValid() throws {
        XCTAssertNoThrow(try Markers.check(MarkerName.monitorAlive))
        XCTAssertNoThrow(try Counter(group: AppGroup(root: root), name: CounterName.shieldShown))
        XCTAssertNoThrow(try Counter(group: AppGroup(root: root), name: CounterName.shieldClosed))
        XCTAssertNotEqual(CounterName.shieldShown, CounterName.shieldClosed)
    }

    func testShieldWording() {
        XCTAssertEqual("\(ShieldText.title). \(ShieldText.subtitle)", "Blocked by Faro. You chose to block this.")
        XCTAssertEqual(ShieldText.closeButton, "Close")
        for text in [ShieldText.title, ShieldText.subtitle, ShieldText.closeButton] {
            XCTAssertFalse(text.contains("\u{2014}"))
        }
    }

    func testCounterAddsUp() throws {
        let counter = try Counter(group: AppGroup(root: root), name: "shield_shown")
        XCTAssertEqual(counter.value(), 0)
        XCTAssertEqual(try counter.increment(), 1)
        XCTAssertEqual(try counter.increment(by: 4), 5)
        XCTAssertEqual(counter.value(), 5)
    }

    func testCounterDoesNotLoseConcurrentIncrements() throws {
        let counter = try Counter(group: AppGroup(root: root), name: "shield_closed")
        let rounds = 50
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            for _ in 0..<rounds { _ = try? counter.increment() }
        }
        XCTAssertEqual(counter.value(), UInt64(8 * rounds))
    }
}
