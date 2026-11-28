import FaroKit
import FaroKitApp
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

/// A page of text with a button at the bottom, under a bar that shows how
/// far through setup this is.
private struct StepPage<Content: View>: View {
    @EnvironmentObject var model: AppModel
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                SetupProgress(step: model.flow.step)
                Text(title)
                    .font(.mono(28, .semibold, relativeTo: .largeTitle))
                    .tracking(-0.8)
                    .foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 20)
            .padding(.top, 8)
            .padding(.bottom, 28)
        }
        .background(Theme.bg)
        .tint(Theme.accent)
    }
}

/// One segment per setup step: done and current in amber, the rest grey.
private struct SetupProgress: View {
    let step: SetupStep

    /// The steps a person sees, in order; enrolling shows as naming.
    private static let order: [SetupStep] = [
        .costs, .link, .confirmInstance, .deviceName, .waitingForApproval, .screenTime, .tunnel,
    ]

    private var index: Int {
        let s: SetupStep = step == .enrolling ? .deviceName : step
        return Self.order.firstIndex(of: s) ?? 0
    }

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Self.order.indices, id: \.self) { i in
                Capsule()
                    .fill(i < index ? Theme.brand.opacity(0.45) : i == index ? Theme.brand : Theme.border)
                    .frame(height: 3)
            }
        }
        .padding(.bottom, 4)
        .accessibilityElement()
        .accessibilityLabel("Step \(index + 1) of \(Self.order.count)")
    }
}

/// A heading within a page, smaller than its title.
private struct Subheading: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.mono(18, .semibold, relativeTo: .title2))
            .tracking(-0.4)
            .foregroundStyle(Theme.text)
            .padding(.top, 8)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Prose in the body of a page.
private struct Prose: View {
    let text: String
    var muted = false
    init(_ text: String, muted: Bool = false) {
        self.text = text
        self.muted = muted
    }

    var body: some View {
        Text(text)
            .font(.body)
            .foregroundStyle(muted ? Theme.muted : Theme.text)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct ErrorText: View {
    let message: String?

    var body: some View {
        if let message {
            Notice(kind: .error, text: message)
                .accessibilityLabel("Problem: \(message)")
        }
    }
}

private struct Point: View {
    let heading: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(heading)
                .font(.mono(14, .semibold, relativeTo: .headline))
                .foregroundStyle(Theme.text)
            Text(text)
                .font(.subheadline)
                .foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Points in one card, with hairlines between them.
private struct Points: View {
    let items: [(String, String)]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(items.indices, id: \.self) { i in
                if i > 0 { Rectangle().fill(Theme.border).frame(height: 1) }
                Point(heading: items[i].0, text: items[i].1)
                    .padding(.vertical, 13)
                    .padding(.horizontal, 16)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.surface))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                .strokeBorder(Theme.border, lineWidth: 1))
    }
}

/// A labelled code (a fingerprint or safety code) to compare.
private struct LabelledCode: View {
    let label: String
    let code: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Eyebrow(label)
            CodeBox(code: code)
        }
        .accessibilityElement(children: .combine)
    }
}

/// "Asking the instance who it is...": a spinner and a line in the code face.
private struct Working: View {
    var text: String?

    var body: some View {
        HStack(spacing: 10) {
            ProgressView()
            if let text {
                Text(text).font(.mono(13, relativeTo: .footnote)).foregroundStyle(Theme.muted)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: 1. What it does and what it costs

struct CostsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Faro on your iPhone") {
            Prose("Faro blocks adult content on this phone. If protection is ever turned off, loosened or removed, the allies you chose are told.")
            Subheading("What it costs you")
            Points(items: [
                ("Apps can't be deleted",
                 "While Faro is protecting itself, no app on this phone can be deleted, Faro included. To remove Faro, turn off its Screen Time access in Settings, or use Leave Faro in Faro's settings. Your allies are told either way."),
                ("No other VPN at the same time",
                 "Faro uses a VPN setting to check website names against its block list. iPhones run only one VPN at a time, so a work or privacy VPN won't work while Faro is on."),
                ("iCloud Private Relay is turned off",
                 "Private Relay hides website names from Faro's filter, so it can't run alongside it."),
                ("Date and time stay automatic",
                 "Faro locks this setting so the clock can't be used to get around it. Explicit music, podcasts, books and TV are blocked in Apple's apps too, and you can change that later."),
            ])
            Subheading("What your allies see")
            Points(items: [
                ("Blocking, not watching",
                 "Faro on an iPhone can't see your screen and never takes screenshots. Allies see when each protection was on, how often something was blocked, the names of blocked adult and gambling sites, and how many times a blocked app was opened. They don't see which app."),
                ("Faro never sees your pages",
                 "The VPN carries only website name lookups. It doesn't carry your pages, messages or anything else you do."),
                ("Limits",
                 "It can't block sites reached through some private DNS services or apps. Your allies are told that too."),
                ("Leaving is always allowed",
                 "You can leave Faro whenever you like. It is never silent: your allies are told."),
            ])
            Button("I understand, continue") { model.acceptCosts() }
                .buttonStyle(.faroPrimary)
                .padding(.top, 8)
            NavigationLink("Licences") { LicencesView() }
                .buttonStyle(.faroLink)
                .frame(maxWidth: .infinity)
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
            Prose("Open the Faro web app, go to Computers and choose Add an iPhone. It shows a QR code and a link. Scan the code here, or paste the link.")
            ErrorText(message: model.flow.error)
            Button {
                scanning = true
            } label: {
                Label("Scan the QR code", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.faroPrimary)

            TextField("faro://enroll?...", text: $pasted, axis: .vertical)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.faro)
                .lineLimit(1...4)
                .padding(.top, 8)
            Button("Use this link") { submit(pasted) }
                .buttonStyle(.faroSecondary)
                .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if model.busy { Working(text: "Asking the instance who it is...") }
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
                Card {
                    LabeledContent("Name", value: p.name)
                    Rectangle().fill(Theme.border).frame(height: 1)
                    LabeledContent("Address", value: p.url)
                }
                .labeledContentStyle(.fact)
                LabelledCode(label: "Instance key", code: p.identityFingerprint)
                Prose("Faro remembers this key. If the instance ever shows a different one, Faro stops talking to it.")
                if !p.linkNamesMemberKey {
                    Notice(kind: .info, text: "This link doesn't name your member key, so after the next step compare the safety code with the one in the web app.")
                }
                ErrorText(message: model.flow.error)
                Button("Yes, this is it") { model.confirmInstance() }
                    .buttonStyle(.faroPrimary)
            } else {
                Working(text: "Asking the instance who it is...")
            }
            Button("Use a different link") { model.back() }
                .buttonStyle(.faroLink)
                .frame(maxWidth: .infinity)
        }
    }
}

// MARK: 4. Name the phone

struct DeviceNameView: View {
    @EnvironmentObject var model: AppModel
    @State private var name = UIDevice.current.name

    var body: some View {
        StepPage(title: "Name this phone") {
            Prose("This is how the phone appears in the web app and in your allies' reports.")
            TextField("Name", text: $name)
                .textFieldStyle(.faro)
                .disabled(model.busy)
            ErrorText(message: model.flow.error)
            if model.busy {
                Working(text: "Adding this phone...")
            } else {
                Button("Add this phone") { Task { await model.enroll(deviceName: name) } }
                    .buttonStyle(.faroPrimary)
                Button("Back") { model.back() }
                    .buttonStyle(.faroLink)
                    .frame(maxWidth: .infinity)
            }
        }
    }
}

// MARK: 5. Waiting for approval

struct WaitingView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Waiting for you to approve") {
            Prose("This phone is added but doesn't count yet. Open the Faro web app on a computer and approve it there.")
            if let d = model.enrolledDevice {
                LabelledCode(label: "This phone's code", code: d.deviceFingerprint)
                LabelledCode(label: "Safety code", code: d.memberFingerprint)
                Prose("Check that the web app shows the same codes before you approve.", muted: true)
            }
            ErrorText(message: model.flow.error)
            Working(text: "Checking every few seconds")
            Button("Check now") { Task { await model.pollApproval() } }
                .buttonStyle(.faroSecondary)
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
            Prose("Faro uses Apple's Screen Time to filter adult websites in Safari and other web views, and to stop itself from being deleted. You confirm with Face ID or your passcode.")
            Points(items: [
                ("What Faro sets",
                 "Apple's adult website filter, no deleting apps, no explicit media in Apple's stores and apps, and automatic date and time. You can choose apps and sites to block later."),
                ("What it costs",
                 "While this is on, no app can be deleted. To undo it, turn off Faro's access under Settings, Screen Time. Your allies are told if you do."),
            ])
            ErrorText(message: model.flow.error)
            if model.busy {
                Working()
            } else {
                Button("Turn on Screen Time") { Task { await model.authorizeScreenTime() } }
                    .buttonStyle(.faroPrimary)
            }
        }
    }
}

// MARK: 7. The VPN

struct TunnelStepView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        StepPage(title: "Turn on the filter") {
            Prose("Faro adds a VPN setting so it can check website names for every app and browser. iPhone asks you to allow it.")
            Points(items: [
                ("Only names, nothing else",
                 "Only website name lookups go through it. Faro never sees your pages, messages or connections."),
                ("It stays on",
                 "The VPN starts by itself after a restart or a network change. Turning it off, or turning off Connect On Demand in Settings, is reported to your allies."),
                ("One VPN at a time",
                 "Another VPN app can't run while Faro is on. Turning Faro off to use one is reported too."),
                ("A monthly reminder",
                 "Once a month Faro sends a notification that shows who it reports to, so it is never out of sight."),
            ])
            ErrorText(message: model.flow.error)
            if model.busy {
                Working()
            } else {
                Button("Allow the VPN") { Task { await model.installTunnel() } }
                    .buttonStyle(.faroPrimary)
            }
        }
    }
}
