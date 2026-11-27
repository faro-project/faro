import FaroKit
import NetworkExtension
import SwiftUI

/// The screen after setup: what is on, what isn't, and a way to fix it.
struct StatusView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

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
                NavigationLink("Licences") { LicencesView() }
            }
        }
        .navigationTitle("Faro")
        .refreshable { await model.refreshStatus() }
        .task { await model.refreshStatus() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.refreshStatus() } }
        }
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
                Text("The people who get your reports are listed in the web app, under your allies. You can change them there at any time.")
            }
        }
        .navigationTitle("Who Faro reports to")
        .task { await model.refreshStatus() }
    }
}
