import FaroKit
import FaroKitApp
import NetworkExtension
import SwiftUI

/// The screen after setup: what is on, what isn't, and a way to fix it.
struct StatusView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List {
            Section("Protection") {
                row("Screen Time", on: model.screenTimeOn,
                    onText: "On", offText: "Off. Faro can be deleted and settings aren't applied.")
                row("Website filter", on: vpnIsOn, onText: vpnText, offText: vpnText)
                row("Starts by itself", on: model.onDemandOn,
                    onText: "Connect On Demand is on", offText: "Connect On Demand is off")
                if !model.screenTimeOn {
                    Button("Turn Screen Time back on") { model.redo(.screenTime) }
                }
                if !vpnIsOn || !model.onDemandOn {
                    Button("Turn the filter back on") { model.redo(.tunnel) }
                }
                Text("Your allies are told when any of this is turned off.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("What Faro blocks") {
                NavigationLink {
                    ChoicesView()
                } label: {
                    VStack(alignment: .leading) {
                        Text("Choose what is blocked")
                        if !model.pending.isEmpty {
                            Text("\(model.pending.count) change\(model.pending.count == 1 ? "" : "s") waiting to take effect")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section("This phone") {
                if let s = model.status {
                    LabeledContent("Instance", value: s.instanceName ?? "Unknown")
                    if let url = s.instanceUrl { LabeledContent("Address", value: url) }
                    LabeledContent("Approved", value: s.approved ? "Yes" : "Not yet")
                    LabeledContent("Waiting to send", value: "\(s.pendingEvents)")
                }
            }

            Section("Never out of sight") {
                NavigationLink("Who Faro reports to") { NoticeView() }
                if let next = model.nextNotice {
                    LabeledContent("Next monthly notice", value: next.formatted(date: .abbreviated, time: .omitted))
                }
                if !model.notificationsOn {
                    Text("Notifications are off for Faro, so the monthly notice can't appear. You can still open it here, any time.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            Section {
                NavigationLink("Settings") { SettingsView() }
                NavigationLink("Licences") { LicencesView() }
            }
        }
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
        HStack {
            Image(systemName: on ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(on ? .green : .orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading) {
                Text(title)
                Text(on ? onText : offText).font(.footnote).foregroundStyle(.secondary)
            }
        }
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
            Section("Faro instance") {
                LabeledContent("Name", value: model.status?.instanceName ?? "Unknown")
                if let url = model.status?.instanceUrl {
                    LabeledContent("Address", value: url)
                    if let u = URL(string: url) { Link("Open the web app", destination: u) }
                }
                if let code = model.status?.memberFingerprint {
                    LabeledContent("Safety code", value: code)
                }
            }
            Section("Your allies") {
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
                                    .font(.headline)
                                Text(ally.safetyCode)
                                    .font(.footnote.monospaced())
                                    .foregroundStyle(.secondary)
                                    .accessibilityLabel("Safety code \(ally.safetyCode)")
                            }
                        }
                    }
                    if r.allies.isEmpty || MonthlyNotice.namesEveryAlly(r.allies.map(\.name)) {
                        Text("This list comes from the one you signed in the web app, names included, so the instance can't add anyone to it or change what they are called. Each safety code is the one your web app shows next to that ally. You can change your allies there at any time.")
                            .font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Text("This list comes from the one you signed in the web app, so the instance can't add anyone to it. It was signed before Faro put names in the list, so it holds each ally's key, not their name: your web app shows each ally's name next to the same safety code. The names appear here after the next change to your allies. You can change them there at any time.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    LabeledContent(
                        "Signed",
                        value: Date(timeIntervalSince1970: Double(r.signedAtMs) / 1000)
                            .formatted(date: .abbreviated, time: .shortened))
                } else {
                    Text("The people who get your reports are listed in the web app, under your allies. You can change them there at any time.")
                }
            }
        }
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
            } footer: {
                Text("Stops Faro on this phone. Your allies are told first, then Faro turns its protection off, and you can delete the app.")
            }
        }
        .navigationTitle("Settings")
    }
}
