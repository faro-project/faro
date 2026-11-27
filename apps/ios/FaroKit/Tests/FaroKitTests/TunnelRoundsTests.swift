import XCTest

@testable import FaroKitApp

private final class FakeWork: TunnelWork {
    var calls: [String] = []
    var pending = false
    /// Whether an upload succeeds.
    var online = true
    var recordsBurst = false
    var queuedTamper = false

    func refreshFromCore() { calls.append("refresh") }
    func heartbeat(_ state: TunnelHeartbeatState) { calls.append("heartbeat \(state)") }
    func recordQueuedTamper() {
        calls.append("tamper")
        if queuedTamper { pending = true; queuedTamper = false }
    }
    func flushBursts() {
        calls.append("bursts")
        if recordsBurst { pending = true; recordsBurst = false }
    }
    func flushReports(filterOn: Bool) { calls.append("reports \(filterOn)") }
    func noteDohDropped(_ count: UInt64) { calls.append("doh \(count)") }
    func hasPending() -> Bool { pending }
    func uploadPending() {
        calls.append("upload")
        if online { pending = false }
    }
}

final class TunnelRoundsTests: XCTestCase {
    func testMinuteUploadsABurstItRecorded() {
        let w = FakeWork()
        w.recordsBurst = true
        TunnelRounds.run(.minute, on: w)
        XCTAssertEqual(w.calls, ["tamper", "bursts", "upload"])
        XCTAssertFalse(w.pending)
    }

    func testNothingPendingMeansNoUpload() {
        let w = FakeWork()
        let ticks: [TunnelTick] = [.start, .wake, .sleep, .stop(switchedOff: true), .minute, .heartbeat, .flush(dohDropped: 0)]
        for tick in ticks { TunnelRounds.run(tick, on: w) }
        XCTAssertFalse(w.calls.contains("upload"))
    }

    /// The tamper path used to retry only when it had just drained a request.
    func testFailedUploadIsRetriedWhenTheLedgerIsEmpty() {
        let w = FakeWork()
        w.queuedTamper = true
        w.online = false
        TunnelRounds.run(.minute, on: w)
        XCTAssertTrue(w.pending)
        // The next minute: nothing new is queued, the outbox still holds it.
        w.online = true
        w.calls = []
        TunnelRounds.run(.minute, on: w)
        XCTAssertEqual(w.calls, ["tamper", "bursts", "upload"])
        XCTAssertFalse(w.pending)
    }

    func testHeartbeatTickUploadsAWaitingOutbox() {
        let w = FakeWork()
        w.pending = true
        TunnelRounds.run(.heartbeat, on: w)
        XCTAssertEqual(w.calls, ["heartbeat active", "upload"])
    }

    func testFlushRoundSendsReportsAfterRecordingThem() {
        let w = FakeWork()
        w.pending = true
        TunnelRounds.run(.flush(dohDropped: 3), on: w)
        XCTAssertEqual(w.calls, ["refresh", "reports true", "doh 3", "upload"])
    }

    func testSleepAndStopSendBeforeTheyFinish() {
        let w = FakeWork()
        w.pending = true
        TunnelRounds.run(.sleep, on: w)
        XCTAssertEqual(w.calls, ["heartbeat sleeping", "reports true", "upload"])
        w.calls = []
        w.pending = true
        TunnelRounds.run(.stop(switchedOff: true), on: w)
        XCTAssertEqual(w.calls, ["tamper", "reports false", "upload"])
    }

    func testPeriodsMatchTheDocumentedCadence() {
        XCTAssertEqual(TunnelRounds.minute, 60)
        XCTAssertEqual(TunnelRounds.heartbeat, 300)
        XCTAssertEqual(TunnelRounds.flush, 600)
    }
}
