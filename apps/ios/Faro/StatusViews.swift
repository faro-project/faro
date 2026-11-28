import FaroKit
import FaroKitApp
import NetworkExtension
import SwiftUI

/// The screen after setup: what is on, what isn't, and a way to fix it.
struct StatusView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List {
            Section {
                row("Screen Time", on: model.screenTimeOn,
                    onText: "On", offText: "Off. Faro can be deleted and settings aren't applied.")
                row("Website filter", on: vpnIsOn, onText: vpnText, offText: vpnText)
                row("Starts by itself", on: model.onDemandOn,
                    onText: "Connect On Demand is on", offText: "Connect On Demand is off")
                if !model.screenTimeOn {
                    Button("Turn Screen Time back on") { model.redo(.screenTime) }
                        .buttonStyle(.faroPrimary)
                }
                if !vpnIsOn || !model.onDemandOn {
                    Button("Turn the filter back on") { model.redo(.tunnel) }
                        .buttonStyle(.faroPrimary)
                }
            } header: {
                Eyebrow("Protection")
            } footer: {
                Text("Your allies are told when any of this is turned off.")
            }
            .faroRows()

            Section {
                NavigationLink {
                    ChoicesView()
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Choose what is blocked").font(.mono(15, .medium))
                        if !model.pending.isEmpty {
                            Text("\(model.pending.count) change\(model.pending.count == 1 ? "" : "s") waiting to take effect")
                                .font(.mono(12, relativeTo: .footnote)).foregroundStyle(Theme.warn)
                        }
                    }
                }
            } header: {
                Eyebrow("What Faro blocks")
            }
            .faroRows()

            Section {
                if let s = model.status {
                    LabeledContent("Instance", value: s.instanceName ?? "Unknown")
                    if let url = s.instanceUrl { LabeledContent("Address", value: url) }
                    LabeledContent("Approved", value: s.approved ? "Yes" : "Not yet")
                    LabeledContent("Waiting to send", value: "\(s.pendingEvents)")
                }
            } header: {
                Eyebrow("This phone")
            }
            .faroRows()
            .labeledContentStyle(.fact)

            Section {
                NavigationLink { NoticeView() } label: { Text("Who Faro reports to").font(.mono(15, .medium)) }
                if let next = model.nextNotice {
                    LabeledContent("Next monthly notice", value: next.formatted(date: .abbreviated, time: .omitted))
                }
            } header: {
                Eyebrow("Never out of sight")
            } footer: {
                if !model.notificationsOn {
                    Text("Notifications are off for Faro, so the monthly notice can't appear. You can still open it here, any time.")
                }
            }
            .faroRows()
            .labeledContentStyle(.fact)

            Section {
                NavigationLink { SettingsView() } label: { Text("Settings").font(.mono(15, .medium)) }
                NavigationLink { LicencesView() } label: { Text("Licences").font(.mono(15, .medium)) }
            }
            .faroRows()
        }
        .faroList()
        .navigationTitle("Faro")
        .refreshable { await model.watch() }
        .task { await model.refreshStatus() }
    }

    private var vpnIsOn: Bool {
        model.vpnStatus == .connected || model.vpnStatus == .connecting || model.vpnStatus == .reasserting
    }

    private var vpnText: String {
        switch model.vpnStatus {
        case .connected: return "On"
        case .connecting, .reasserting: return "Starting"
        case .disconnecting: return "Stopping"
        case .invalid, nil: return "Not set up"
        default: return "Off"
        }
    }

    private func row(_ title: String, on: Bool, onText: String, offText: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Circle()
                .fill(on ? Theme.ok : Theme.danger)
                .frame(width: 7, height: 7)
                .alignmentGuide(.firstTextBaseline) { $0[.bottom] - 1 }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.mono(15, .medium))
                Text(on ? onText : offText).font(.footnote).foregroundStyle(Theme.muted)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

/// The screen the monthly notification opens (docs/IOS.md §12).
struct NoticeView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List {
            Section {
                Text("Faro is on this phone. It blocks adult content and tells the allies you chose if protection is turned off, loosened or removed.")
            }
            .faroRows()
            Section {
                LabeledContent("Name", value: model.status?.instanceName ?? "Unknown")
                if let url = model.status?.instanceUrl {
                    LabeledContent("Address", value: url)
                    if let u = URL(string: url) {
                        Link(destination: u) {
                            Label("Open the web app", systemImage: "arrow.up.right")
                                .labelStyle(TrailingIconLabelStyle())
                        }
                        .font(.mono(14, .medium))
                        .foregroundStyle(Theme.accent)
                    }
                }
                if let code = model.status?.memberFingerprint {
                    LabeledContent("Safety code", value: code)
                }
            } header: {
                Eyebrow("Faro instance")
            }
            .faroRows()
            .labeledContentStyle(.fact)
            Section {
                if let r = model.recipients {
                    if r.allies.isEmpty {
                        Text("No allies yet. Faro reports to you only, until you add one in the web app.")
                    } else {
                        Text(r.allies.count == 1
                             ? "Faro reports to 1 ally."
                             : "Faro reports to \(r.allies.count) allies.")
                        ForEach(Array(r.allies.enumerated()), id: \.element.allyId) { i, ally in
                            VStack(alignment: .leading, spacing: 4) {
                                // Verbatim: a signed, sanitized name, never Markdown.
                                Text(verbatim: MonthlyNotice.allyTitle(name: ally.name, position: i + 1))
                                    .font(.mono(15, .semibold, relativeTo: .headline))
                                Text(ally.safetyCode)
                                    .font(.mono(12, relativeTo: .footnote))
                                    .foregroundStyle(Theme.muted)
                                    .textSelection(.enabled)
                                    .accessibilityLabel("Safety code \(ally.safetyCode)")
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    if r.allies.isEmpty || MonthlyNotice.namesEveryAlly(r.allies.map(\.name)) {
                        Text("This list comes from the one you signed in the web app, names included, so the instance can't add anyone to it or change what they are called. Each safety code is the one your web app shows next to that ally. You can change your allies there at any time.")
                            .font(.footnote).foregroundStyle(Theme.muted)
                    } else {
                        Text("This list comes from the one you signed in the web app, so the instance can't add anyone to it. It was signed before Faro put names in the list, so it holds each ally's key, not their name: your web app shows each ally's name next to the same safety code. The names appear here after the next change to your allies. You can change them there at any time.")
                            .font(.footnote).foregroundStyle(Theme.muted)
                    }
                    LabeledContent(
                        "Signed",
                        value: Date(timeIntervalSince1970: Double(r.signedAtMs) / 1000)
                            .formatted(date: .abbreviated, time: .shortened))
                } else {
                    Text("The people who get your reports are listed in the web app, under your allies. You can change them there at any time.")
                }
            } header: {
                Eyebrow("Your allies")
            }
            .faroRows()
            .labeledContentStyle(.fact)
        }
        .faroList()
        .navigationTitle("Who Faro reports to")
        .task {
            await model.refreshStatus()
            await model.refreshRecipients()
        }
    }
}

/// Faro's settings. For now, one: Leave Faro (docs/IOS.md §12).
struct SettingsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List {
            Section {
                Button("Leave Faro", role: .destructive) { model.beginLeave() }
                    .font(.mono(15, .medium))
                    .foregroundStyle(Theme.danger)
            } footer: {
                Text("Stops Faro on this phone. Your allies are told first, then Faro turns its protection off, and you can delete the app.")
            }
            .faroRows()
        }
        .faroList()
        .navigationTitle("Settings")
    }
}

/// A label with its icon after the title, for links that leave the app.
struct TrailingIconLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 5) {
            configuration.title
            configuration.icon.imageScale(.small)
        }
    }
}
