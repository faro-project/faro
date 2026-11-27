import SwiftUI

@main
struct FaroApp: App {
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                HomeView()
            }
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
