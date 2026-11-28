import FaroKit
import FaroKitApp
import SwiftUI

/// Leave Faro (docs/IOS.md §12), one screen per `LeaveStep`. Leaving is
/// always allowed and never silent: the allies are told first, and nothing
/// is turned off until the instance has the goodbye.
struct LeaveView: View {
    @EnvironmentObject var model: AppModel
    let flow: LeaveFlow

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                switch flow.step {
                case .confirm: confirm
                case .sayingGoodbye: working("Telling your allies", "Faro is sending the goodbye to your instance. This takes a few seconds.")
                case .notDelivered(let message, let written): notDelivered(message, written: written)
                case .lifting: working("Turning Faro off", "Your allies have been told. Faro is turning its protection off.")
                case .done(let leftovers): done(leftovers)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
        .background(Theme.bg)
        .navigationTitle("Leave Faro")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
    }

    private var confirm: some View {
        Group {
            Title("Leave Faro?")
            Text("You can leave at any time. Your allies are told first: they get a message that Faro was removed from this phone.")
            Text("Then Faro turns everything off. Apps can be deleted again, its Screen Time settings are cleared, and its VPN is removed. After that you can delete the Faro app.")
            Text("If this phone is offline, nothing changes until it can reach your instance.")
                .foregroundStyle(Theme.muted)
            Button(role: .destructive) {
                Task { await model.confirmLeave() }
            } label: {
                Text("Tell my allies and leave")
            }
            .buttonStyle(.faroDanger)
            .padding(.top, 8)
            Button("Stay") { model.cancelLeave() }
                .buttonStyle(.faroLink)
                .frame(maxWidth: .infinity)
        }
    }

    private func working(_ title: String, _ text: String) -> some View {
        Group {
            Title(title)
            Text(text)
            ProgressView().frame(maxWidth: .infinity).padding(.top, 8)
        }
    }

    private func notDelivered(_ message: String, written: Bool) -> some View {
        Group {
            Title("Your allies haven't been told yet")
            Notice(kind: .error, text: message)
            if written {
                Text("Faro is still on, and has stopped reporting anything else. It leaves as soon as your instance has the goodbye.")
            } else {
                Text("Nothing has changed: Faro is still on and still reporting.")
            }
            Button {
                Task { await model.retryLeave() }
            } label: {
                Text("Try again")
            }
            .buttonStyle(.faroPrimary)
            .padding(.top, 8)
            if flow.canCancel {
                Button("Stay") { model.cancelLeave() }
                    .buttonStyle(.faroLink)
                    .frame(maxWidth: .infinity)
            }
        }
    }

    private func done(_ leftovers: [String]) -> some View {
        Group {
            Title("You've left Faro")
            Text("Your allies were told, and Faro's protection is off on this phone.")
            ForEach(leftovers, id: \.self) { Notice(kind: .warn, text: $0) }
            Text("You can delete the Faro app now: touch and hold its icon, then choose Remove App.")
        }
    }
}

/// A page title in the code face.
private struct Title: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.mono(28, .semibold, relativeTo: .largeTitle))
            .tracking(-0.8)
            .foregroundStyle(Theme.text)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isHeader)
    }
}
