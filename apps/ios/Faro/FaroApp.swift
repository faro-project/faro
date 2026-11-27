import SwiftUI

@main
struct FaroApp: App {
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                HomeView()
            }
        }
        .onChange(of: scenePhase) { phase in
            // docs/IOS.md §6.3: re-apply the Screen Time settings each time
            // the app comes forward. Does nothing before setup.
            if phase == .active { ScreenTimeEnforcer.refreshOnForeground() }
        }
    }
}

/// The scaffold's only screen. Enrollment, setup, status and Leave Faro
/// come with their own issues.
struct HomeView: View {
    var body: some View {
        List {
            Section {
                Text("Faro is not set up on this phone yet.")
            }
            Section {
                NavigationLink("Licences") { LicencesView() }
            }
        }
        .navigationTitle("Faro")
    }
}
