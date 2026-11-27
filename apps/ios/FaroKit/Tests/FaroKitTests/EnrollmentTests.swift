import XCTest
@testable import FaroKit
@testable import FaroKitApp

final class EnrollLinkTests: XCTestCase {
    private let good = "faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=7q2k-m9xd&m=0123456789abcdef"

    func testParsesAFullLink() throws {
        let link = try XCTUnwrap(EnrollLink(good))
        XCTAssertEqual(link.instance.absoluteString, "https://faro.example.org")
        XCTAssertEqual(link.instanceHost, "faro.example.org")
        XCTAssertEqual(link.code, "7Q2K-M9XD")
        XCTAssertEqual(link.memberKey, "0123456789abcdef")
        XCTAssertEqual(link.text, good)
    }

    func testMemberKeyIsOptional() throws {
        let link = try XCTUnwrap(EnrollLink("  faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2KM9XD\n"))
        XCTAssertNil(link.memberKey)
        XCTAssertEqual(link.code, "7Q2K-M9XD")
    }

    func testRefusesWhatIsNotAnEnrollLink() {
        let bad = [
            "", "hello", "https://faro.example.org",
            "faro://other?i=https%3A%2F%2Ff.example&c=7Q2KM9XD",
            "faro://enroll?c=7Q2KM9XD",
            "faro://enroll?i=https%3A%2F%2Ff.example",
            "faro://enroll?i=ftp%3A%2F%2Ff.example&c=7Q2KM9XD",
            "faro://enroll?i=notaurl&c=7Q2KM9XD",
            "faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2K",
            "faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2K-M9X!",
            "faro://enroll?i=https%3A%2F%2Ff.example&i=https%3A%2F%2Fg.example&c=7Q2KM9XD",
            "faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2KM9XD&c=7Q2KM9XE",
        ]
        for text in bad { XCTAssertNil(EnrollLink(text), text) }
        XCTAssertNil(EnrollLink(
            "faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2KM9XD&m=" + String(repeating: "a", count: 5000)))
    }

    func testFindsALinkInPastedText() {
        XCTAssertEqual(EnrollLinkFinder.find(in: "Here: \(good) thanks")?.code, "7Q2K-M9XD")
        XCTAssertNil(EnrollLinkFinder.find(in: "no link here"))
    }
}

final class SetupFlowTests: XCTestCase {
    private let link = EnrollLink("faro://enroll?i=https%3A%2F%2Ff.example&c=7Q2KM9XD")!

    private func walkToDeviceName() -> SetupFlow {
        var flow = SetupFlow()
        XCTAssertTrue(flow.apply(.acceptedCosts))
        XCTAssertTrue(flow.apply(.linkGiven(link)))
        XCTAssertTrue(flow.apply(.instanceConfirmed))
        return flow
    }

    func testTheHappyPathVisitsEveryStepInOrder() {
        var flow = walkToDeviceName()
        XCTAssertEqual(flow.step, .deviceName)
        flow.apply(.deviceNamed("  Sam's iPhone "))
        XCTAssertEqual(flow.step, .enrolling)
        XCTAssertEqual(flow.deviceName, "Sam's iPhone")
        flow.apply(.enrolled)
        XCTAssertEqual(flow.step, .waitingForApproval)
        flow.apply(.approved)
        XCTAssertEqual(flow.step, .screenTime)
        flow.apply(.screenTimeAuthorized)
        XCTAssertEqual(flow.step, .tunnel)
        flow.apply(.tunnelInstalled)
        XCTAssertEqual(flow.step, .done)
    }

    func testStepsCannotBeSkipped() {
        var flow = SetupFlow()
        for event: SetupEvent in [.instanceConfirmed, .enrolled, .approved, .screenTimeAuthorized, .tunnelInstalled] {
            XCTAssertFalse(flow.apply(event))
            XCTAssertEqual(flow, SetupFlow())
        }
        flow = walkToDeviceName()
        XCTAssertFalse(flow.apply(.approved))
        XCTAssertFalse(flow.apply(.tunnelInstalled))
        XCTAssertEqual(flow.step, .deviceName)
    }

    func testABadDeviceNameStaysPut() {
        var flow = walkToDeviceName()
        XCTAssertTrue(flow.apply(.deviceNamed("   ")))
        XCTAssertEqual(flow.step, .deviceName)
        XCTAssertNotNil(flow.error)
        XCTAssertTrue(flow.apply(.deviceNamed(String(repeating: "x", count: 65))))
        XCTAssertEqual(flow.step, .deviceName)
        XCTAssertTrue(flow.apply(.deviceNamed("ok")))
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.step, .enrolling)
    }

    func testEnrollmentFailureReturnsToTheName() {
        var flow = walkToDeviceName()
        flow.apply(.deviceNamed("Phone"))
        flow.apply(.failed("could not reach the instance"))
        XCTAssertEqual(flow.step, .deviceName)
        XCTAssertEqual(flow.error, "could not reach the instance")
        flow.apply(.deviceNamed("Phone"))
        XCTAssertNil(flow.error)
    }

    func testFailuresKeepLaterStepsWhereTheyAre() {
        var flow = SetupFlow(step: .screenTime)
        flow.apply(.failed("denied"))
        XCTAssertEqual(flow.step, .screenTime)
        XCTAssertEqual(flow.error, "denied")
        flow.apply(.screenTimeAuthorized)
        XCTAssertNil(flow.error)
        var done = SetupFlow(step: .done)
        XCTAssertFalse(done.apply(.failed("x")))
    }

    func testBackGoesOneStep() {
        var flow = walkToDeviceName()
        flow.apply(.back)
        XCTAssertEqual(flow.step, .confirmInstance)
        flow.apply(.back)
        XCTAssertEqual(flow.step, .link)
        XCTAssertNil(flow.link)
        XCTAssertFalse(flow.apply(.back))
    }

    func testResumeNeverRepeatsEnrollment() {
        func start(_ enrolled: Bool, _ approved: Bool, _ p: SetupProgress = .init()) -> SetupStep {
            SetupFlow.resume(enrolled: enrolled, approved: approved, progress: p).step
        }
        XCTAssertEqual(start(false, false), .costs)
        XCTAssertEqual(start(true, false), .waitingForApproval)
        XCTAssertEqual(start(true, true), .screenTime)
        XCTAssertEqual(start(true, true, .init(screenTimeDone: true)), .tunnel)
        XCTAssertEqual(start(true, true, .init(screenTimeDone: true, tunnelDone: true)), .done)
        XCTAssertEqual(start(true, false, .init(screenTimeDone: true, tunnelDone: true)), .waitingForApproval)
    }

    func testProgressSurvivesARelaunch() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("faro-setup-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = SetupProgressStore(group: AppGroup(root: dir))
        XCTAssertEqual(store.load(), SetupProgress())
        try store.update { $0.screenTimeDone = true; $0.enrolledAtMs = 5 }
        XCTAssertEqual(store.load(), SetupProgress(screenTimeDone: true, tunnelDone: false, enrolledAtMs: 5))
        try Data("garbage".utf8).write(to: store.url)
        XCTAssertEqual(store.load(), SetupProgress())
    }
}

final class MonthlyNoticeTests: XCTestCase {
    private var calendar: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }

    private func date(_ y: Int, _ m: Int, _ d: Int, _ h: Int = 12, _ min: Int = 0) -> Date {
        calendar.date(from: DateComponents(year: y, month: m, day: d, hour: h, minute: min))!
    }

    func testFiresOnTheEnrollmentDay() {
        let c = MonthlyNotice.fireComponents(enrolledAt: date(2026, 11, 14, 15, 30), calendar: calendar)
        XCTAssertEqual(c.day, 14)
        XCTAssertEqual(c.hour, 15)
        XCTAssertEqual(c.minute, 30)
    }

    func testLateDaysAndSmallHoursAreMoved() {
        let late = MonthlyNotice.fireComponents(enrolledAt: date(2026, 1, 31, 2), calendar: calendar)
        XCTAssertEqual(late.day, 28)
        XCTAssertEqual(late.hour, 9)
        let night = MonthlyNotice.fireComponents(enrolledAt: date(2026, 1, 5, 23), calendar: calendar)
        XCTAssertEqual(night.hour, 20)
    }

    func testNextFire() {
        let enrolled = date(2026, 11, 14, 15, 30)
        XCTAssertEqual(MonthlyNotice.nextFire(enrolledAt: enrolled, after: date(2026, 11, 20), calendar: calendar),
                       date(2026, 12, 14, 15, 30))
        XCTAssertEqual(MonthlyNotice.nextFire(enrolledAt: enrolled, after: date(2026, 12, 1), calendar: calendar),
                       date(2026, 12, 14, 15, 30))
    }
}
