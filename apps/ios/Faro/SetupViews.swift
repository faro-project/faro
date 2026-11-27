import FaroKit
import SwiftUI

/// The setup flow, one screen per `SetupStep` (docs/IOS.md §12, §14).
struct SetupView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            switch model.flow.step {
            case .costs: CostsView()
            case .link: LinkView()
            case .confirmInstance: ConfirmInstanceView()
            case .deviceName, .enrolling: DeviceNameView()
            case .waitingForApproval: WaitingView()
            case .screenTime: ScreenTimeStepView()
            case .tunnel: TunnelStepView()
            case .done: EmptyView()
            }
        }
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// A page of text with a button at the bottom.
private struct StepPage<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(title).font(.largeTitle.bold())
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
    }
}

private struct ErrorText: View {
    let message: String?

    var body: some View {
        if let message {
            Text(message)
                .foregroundStyle(.red)
                .accessibilityLabel("Problem: \(message)")
        }
    }
}

private struct Point: View {
    let heading: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(heading).font(.headline)
            Text(text).foregroundStyle(.secondary)
        }
    }
}

// MARK: 1. What it does and what it costs

struct CostsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Faro on your iPhone") {
            Text("Faro blocks adult content on this phone. If protection is ever turned off, loosened or removed, the allies you chose are told.")
            Text("What it costs you").font(.title2.bold())
            Point(heading: "Apps can't be deleted",
                  text: "While Faro is protecting itself, no app on this phone can be deleted, Faro included. To remove Faro, turn off its Screen Time access in Settings, or use Leave Faro in Faro's settings. Your allies are told either way.")
            Point(heading: "No other VPN at the same time",
                  text: "Faro uses a VPN setting to check website names against its block list. iPhones run only one VPN at a time, so a work or privacy VPN won't work while Faro is on.")
            Point(heading: "iCloud Private Relay is turned off",
                  text: "Private Relay hides website names from Faro's filter, so it can't run alongside it.")
            Point(heading: "Date and time stay automatic",
                  text: "Faro locks this setting so the clock can't be used to get around it. Explicit music, podcasts, books and TV are blocked in Apple's apps too, and you can change that later.")
            Text("What your allies see").font(.title2.bold())
            Point(heading: "Blocking, not watching",
                  text: "Faro on an iPhone can't see your screen and never takes screenshots. Allies see when each protection was on, how often something was blocked, the names of blocked adult and gambling sites, and how many times a blocked app was opened. They don't see which app.")
            Point(heading: "Faro never sees your pages",
                  text: "The VPN carries only website name lookups. It doesn't carry your pages, messages or anything else you do.")
            Point(heading: "Limits",
                  text: "It can't block sites reached through some private DNS services or apps. Your allies are told that too.")
            Point(heading: "Leaving is always allowed",
                  text: "You can leave Faro whenever you like. It is never silent: your allies are told.")
            Button("I understand, continue") { model.acceptCosts() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            NavigationLink("Licences") { LicencesView() }
        }
    }
}

// MARK: 2. The link

struct LinkView: View {
    @EnvironmentObject var model: AppModel
    @State private var scanning = false
    @State private var pasted = ""

    var body: some View {
        StepPage(title: "Add this phone") {
            Text("Open the Faro web app, go to Computers and choose Add an iPhone. It shows a QR code and a link. Scan the code here, or paste the link.")
            ErrorText(message: model.flow.error)
            Button {
                scanning = true
            } label: {
                Label("Scan the QR code", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            TextField("faro://enroll?...", text: $pasted, axis: .vertical)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
            Button("Use this link") { submit(pasted) }
                .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if model.busy { ProgressView("Asking the instance who it is...") }
        }
        .sheet(isPresented: $scanning) {
            NavigationStack {
                QRScanner { code in
                    scanning = false
                    submit(code)
                }
                .ignoresSafeArea()
                .navigationTitle("Scan the QR code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanning = false } } }
            }
        }
    }

    private func submit(_ text: String) {
        Task { await model.receive(link: text) }
    }
}

// MARK: 3. Confirm the instance

struct ConfirmInstanceView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Is this your instance?") {
            if let p = model.preview {
                Point(heading: "Name", text: p.name)
                Point(heading: "Address", text: p.url)
                Point(heading: "Instance key",
                      text: p.identityFingerprint)
                Text("Faro remembers this key. If the instance ever shows a different one, Faro stops talking to it.")
                if !p.linkNamesMemberKey {
                    Text("This link doesn't name your member key, so after the next step compare the safety code with the one in the web app.")
                        .foregroundStyle(.secondary)
                }
                ErrorText(message: model.flow.error)
                Button("Yes, this is it") { model.confirmInstance() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            } else {
                ProgressView("Asking the instance who it is...")
            }
            Button("Use a different link") { model.back() }
        }
    }
}

// MARK: 4. Name the phone

struct DeviceNameView: View {
    @EnvironmentObject var model: AppModel
    @State private var name = UIDevice.current.name

    var body: some View {
        StepPage(title: "Name this phone") {
            Text("This is how the phone appears in the web app and in your allies' reports.")
            TextField("Name", text: $name)
                .textFieldStyle(.roundedBorder)
                .disabled(model.busy)
            ErrorText(message: model.flow.error)
            if model.busy {
                ProgressView("Adding this phone...")
            } else {
                Button("Add this phone") { Task { await model.enroll(deviceName: name) } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                Button("Back") { model.back() }
            }
        }
    }
}

// MARK: 5. Waiting for approval

struct WaitingView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Waiting for you to approve") {
            Text("This phone is added but doesn't count yet. Open the Faro web app on a computer and approve it there.")
            if let d = model.enrolledDevice {
                Point(heading: "This phone's code", text: d.deviceFingerprint)
                Point(heading: "Safety code",
                      text: d.memberFingerprint)
                Text("Check that the web app shows the same codes before you approve.")
                    .foregroundStyle(.secondary)
            }
            ErrorText(message: model.flow.error)
            HStack(spacing: 8) {
                ProgressView()
                Text("Checking every few seconds")
            }
            Button("Check now") { Task { await model.pollApproval() } }
        }
        .task {
            while !Task.isCancelled && model.flow.step == .waitingForApproval {
                await model.pollApproval()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

// MARK: 6. Screen Time

struct ScreenTimeStepView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Turn on Screen Time") {
            Text("Faro uses Apple's Screen Time to filter adult websites in Safari and other web views, and to stop itself from being deleted. You confirm with Face ID or your passcode.")
            Point(heading: "What Faro sets",
                  text: "Apple's adult website filter, no deleting apps, no explicit media in Apple's stores and apps, and automatic date and time. You can choose apps and sites to block later.")
            Point(heading: "What it costs",
                  text: "While this is on, no app can be deleted. To undo it, turn off Faro's access under Settings, Screen Time. Your allies are told if you do.")
            ErrorText(message: model.flow.error)
            if model.busy {
                ProgressView()
            } else {
                Button("Turn on Screen Time") { Task { await model.authorizeScreenTime() } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            }
        }
    }
}

// MARK: 7. The VPN

struct TunnelStepView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Turn on the filter") {
            Text("Faro adds a VPN setting so it can check website names for every app and browser. iPhone asks you to allow it.")
            Point(heading: "Only names, nothing else",
                  text: "Only website name lookups go through it. Faro never sees your pages, messages or connections.")
            Point(heading: "It stays on",
                  text: "The VPN starts by itself after a restart or a network change. Turning it off, or turning off Connect On Demand in Settings, is reported to your allies.")
            Point(heading: "One VPN at a time",
                  text: "Another VPN app can't run while Faro is on. Turning Faro off to use one is reported too.")
            Point(heading: "A monthly reminder",
                  text: "Once a month Faro sends a notification that shows who it reports to, so it is never out of sight.")
            ErrorText(message: model.flow.error)
            if model.busy {
                ProgressView()
            } else {
                Button("Allow the VPN") { Task { await model.installTunnel() } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            }
        }
    }
}
