import FaroKit
import SwiftUI
import UserNotifications

@main
struct FaroApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

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
            if phase == .active { ScreenTimeEnforcer.refreshOnForeground() }
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
