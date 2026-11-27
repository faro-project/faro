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
            // docs/IOS.md §6.3, §10.2: re-apply the Screen Time settings and
            // check every layer each time the app comes forward.
            if phase == .active { Task { await model.foreground() } }
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
                } else if let leave = model.leave {
                    LeaveView(flow: leave)
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
