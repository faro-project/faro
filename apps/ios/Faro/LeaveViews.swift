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
        .navigationTitle("Leave Faro")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
    }

    private var confirm: some View {
        Group {
            Text("Leave Faro?").font(.largeTitle.bold())
            Text("You can leave at any time. Your allies are told first: they get a message that Faro was removed from this phone.")
            Text("Then Faro turns everything off. Apps can be deleted again, its Screen Time settings are cleared, and its VPN is removed. After that you can delete the Faro app.")
            Text("If this phone is offline, nothing changes until it can reach your instance.")
                .foregroundStyle(.secondary)
            Button(role: .destructive) {
                Task { await model.confirmLeave() }
            } label: {
                Text("Tell my allies and leave").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            Button("Stay") { model.cancelLeave() }
                .frame(maxWidth: .infinity)
        }
    }

    private func working(_ title: String, _ text: String) -> some View {
        Group {
            Text(title).font(.largeTitle.bold())
            Text(text)
            ProgressView().frame(maxWidth: .infinity)
        }
    }

    private func notDelivered(_ message: String, written: Bool) -> some View {
        Group {
            Text("Your allies haven't been told yet").font(.largeTitle.bold())
            Text(message).foregroundStyle(.red)
            if written {
                Text("Faro is still on, and has stopped reporting anything else. It leaves as soon as your instance has the goodbye.")
            } else {
                Text("Nothing has changed: Faro is still on and still reporting.")
            }
            Button {
                Task { await model.retryLeave() }
            } label: {
                Text("Try again").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            if flow.canCancel {
                Button("Stay") { model.cancelLeave() }
                    .frame(maxWidth: .infinity)
            }
        }
    }

    private func done(_ leftovers: [String]) -> some View {
        Group {
            Text("You've left Faro").font(.largeTitle.bold())
            Text("Your allies were told, and Faro's protection is off on this phone.")
            ForEach(leftovers, id: \.self) { Text($0).foregroundStyle(.orange) }
            Text("You can delete the Faro app now: touch and hold its icon, then choose Remove App.")
        }
    }
}
