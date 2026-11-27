import XCTest
@testable import FaroKit
@testable import FaroKitApp

final class ChoiceTextTests: XCTestCase {
    func testSummariesReadInPlainWords() {
        var old = FaroSettings(maximumAppRating: 12, blockedCategories: ["gambling"])
        old.extraBlockedDomains = ["a.example"]
        var new = FaroSettings.default
        new.extraBlockedDomains = ["b.example"]
        new.maximumAppRating = nil
        let d = ChoiceDiff.between(old, new)
        XCTAssertEqual(Set(d.tightening.map { $0.summary }), ["Block b.example"])
        XCTAssertEqual(Set(d.loosening.map { $0.summary }), [
            "Stop blocking gambling sites", "Stop blocking a.example", "Remove the App Store age limit",
        ])
        let delay = ChoiceDiff.between(FaroSettings(loosenDelayHours: 24), FaroSettings(loosenDelayHours: 6))
        XCTAssertEqual(delay.loosening.first?.summary, "Wait 6 hours before loosening")
    }
}
