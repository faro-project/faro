import FaroKit
import SwiftUI
import UserNotifications

@main
struct FaroApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    /// Where domain list updates are installed (the same group the model uses).
    private let updateGroup = AppGroup.container() ?? AppModel.fallbackGroup()

    init() {
        // Must happen before the app finishes launching.
        DomainUpdates.register(group: updateGroup)
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .task {
                    UNUserNotificationCenter.current().delegate = model.notices
                    await model.load()
                }
                // faro://enroll?... (docs/IOS.md §14)
                .onOpenURL { url in
                    Task { await model.receive(link: url.absoluteString) }
                }
        }
        .onChange(of: scenePhase) { phase in
            // docs/IOS.md §6.3: re-apply the Screen Time settings each time
            // the app comes forward. Does nothing before setup.
            if phase == .active {
                ScreenTimeEnforcer.refreshOnForeground()
                // docs/IOS.md §7.2: look for a newer domain list (skipped if
                // one was checked in the last 6 hours).
                let group = updateGroup
                if let group { Task.detached { DomainUpdates.check(group: group) } }
            }
            if phase == .background { DomainUpdates.schedule(group: updateGroup) }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationStack {
            Group {
                if !model.loaded {
                    ProgressView()
                } else if model.flow.step == .done {
                    StatusView()
                } else {
                    SetupView()
                }
            }
            .navigationDestination(isPresented: $model.showingNotice) { NoticeView() }
        }
    }
}
