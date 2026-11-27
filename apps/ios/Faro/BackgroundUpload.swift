import BackgroundTasks
import FaroKit
import FaroKitApp
import Foundation
import os

/// The app's `BGAppRefreshTask` heartbeat and upload (docs/IOS.md §10.1):
/// a phone whose tunnel is off still checks in, and events that wait in the
/// outbox go out without the member opening Faro.
enum BackgroundUpload {
    private static let log = Logger(subsystem: "org.faro.ios", category: "background-upload")

    /// Registers the handler. Call before the app finishes launching.
    static func register(group: AppGroup?) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: BackgroundUploadSchedule.taskIdentifier, using: nil) { task in
            schedule()
            let work = Task.detached {
                task.setTaskCompleted(success: group.map { run(group: $0) } ?? true)
            }
            task.expirationHandler = { work.cancel() }
        }
    }

    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: BackgroundUploadSchedule.taskIdentifier)
        request.earliestBeginDate = BackgroundUploadSchedule.nextBegin(
            nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            log.info("background upload not scheduled: \(String(describing: error), privacy: .public)")
        }
    }

    /// One heartbeat and one upload. Blocks on the network. False if it
    /// should be tried again soon.
    static func run(group: AppGroup) -> Bool {
        do {
            let core = try CoreLink.open(group: group)
            _ = try core.heartbeat(state: .active)
            _ = try core.uploadPending()
            return true
        } catch FaroError.NotEnrolled, FaroError.NotApproved, FaroError.Left {
            return true
        } catch {
            // Offline or keys locked: the next run tries again.
            log.info("background upload failed: \(String(describing: error), privacy: .public)")
            return false
        }
    }
}
