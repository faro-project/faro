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
