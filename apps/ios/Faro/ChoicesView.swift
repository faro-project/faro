import FamilyControls
import FaroKit
import ManagedSettings
import SwiftUI

/// What Faro blocks (docs/IOS.md §9). The member edits a draft and saves it.
/// Blocking more takes effect at once. Blocking less waits for the delay the
/// member set, allies are told when it is asked for and again when it takes
/// effect, and it can be cancelled until then.
struct ChoicesView: View {
    @EnvironmentObject var model: AppModel
    @State private var draft = FaroSettings.default
    @State private var selection = FamilyActivitySelection()
    @State private var loadedFrom: FaroSettings?
    @State private var picking = false
    @State private var newSite = ""
    @State private var siteError: String?
    @State private var saved: SubmitResult?

    var body: some View {
        List {
            if let error = model.choicesError {
                Section { Text(error).foregroundStyle(.red) }
            }
            if !model.pending.isEmpty { waitingSection }

            Section {
                Toggle("Gambling sites", isOn: binding(for: "gambling"))
            } header: {
                Text("Websites")
            } footer: {
                Text("Adult sites are always blocked. This adds gambling sites, in Safari and in every app.")
            }

            Section {
                ForEach(draft.extraBlockedDomains, id: \.self) { Text($0) }
                    .onDelete { offsets in
                        let names = offsets.map { draft.extraBlockedDomains[$0] }
                        draft.extraBlockedDomains.removeAll { names.contains($0) }
                    }
                HStack {
                    TextField("example.com", text: $newSite)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .onSubmit(addSite)
                    Button("Add", action: addSite).disabled(newSite.isEmpty)
                }
                if let siteError { Text(siteError).font(.footnote).foregroundStyle(.red) }
            } header: {
                Text("Sites you choose")
            } footer: {
                Text("A site and everything under it.")
            }

            Section {
                Button("Choose apps and categories") { picking = true }
                Text(pickedSummary).font(.footnote).foregroundStyle(.secondary)
            } header: {
                Text("Apps")
            } footer: {
                Text("Blocked apps show Faro's block screen. Faro never learns which apps you picked, only how many.")
            }

            Section("Other limits") {
                Toggle("Block explicit music, podcasts and books", isOn: $draft.denyExplicitContent)
                Picker("App Store age limit", selection: ratingBinding) {
                    Text("None").tag(0)
                    Text("4+").tag(4)
                    Text("9+").tag(9)
                    Text("12+").tag(12)
                    Text("17+").tag(17)
                }
            }

            Section {
                Stepper(value: $draft.loosenDelayHours, in: 0...FaroSettings.maxLoosenDelayHours) {
                    Text(delayText(draft.loosenDelayHours))
                }
            } header: {
                Text("Wait before loosening")
            } footer: {
                Text("Blocking more takes effect at once. Blocking less waits this long, your allies are told when you ask and again when it happens, and you can cancel before then. Making the wait shorter also waits the current time.")
            }

            Section {
                if changes.isEmpty {
                    Text("Nothing to save.").foregroundStyle(.secondary)
                } else {
                    ForEach(Array(diff.tightening.enumerated()), id: \.offset) { Label($0.element.summary, systemImage: "lock.fill") }
                    ForEach(Array(diff.loosening.enumerated()), id: \.offset) { Label($0.element.summary, systemImage: "clock") }
                    if !diff.loosening.isEmpty {
                        Text("The ones with a clock wait \(delayText(effectiveDelay)) before they take effect.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Button("Save") { Task { saved = await model.saveChoices(draft); reload(force: true) } }
                    .disabled(changes.isEmpty)
            } header: {
                Text("Your changes")
            }

            if let saved, !saved.isEmpty {
                Section { Text(savedText(saved)).font(.footnote) }
            }
        }
        .navigationTitle("What Faro blocks")
        .familyActivityPicker(isPresented: $picking, selection: $selection)
        .onChange(of: selection) { _, new in applyPicker(new) }
        .task { await model.refreshChoices(); reload(force: false) }
        .onChange(of: model.settings) { _, _ in reload(force: false) }
    }

    // MARK: Waiting

    private var waitingSection: some View {
        Section {
            ForEach(model.pending) { item in
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(item.changes.enumerated()), id: \.offset) { Text($0.element.summary) }
                    Text("Takes effect \(Date(timeIntervalSince1970: Double(item.takesEffectAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Cancel this change", role: .destructive) {
                        Task { await model.cancelPending(item.id) }
                    }
                    .font(.footnote)
                }
            }
        } header: {
            Text("Waiting to take effect")
        } footer: {
            Text(model.eventsQueued
                 ? "Your allies will be told as soon as Faro can reach the instance. Until then, these are still blocked."
                 : "Your allies were told. Until then, these are still blocked.")
        }
    }

    // MARK: Draft

    private var effective: FaroSettings { model.settings ?? .default }
    private var diff: ChoiceDiff { ChoiceDiff.between(effective, draft) }
    private var changes: [SettingChange] { diff.tightening + diff.loosening }
    private var effectiveDelay: Int { effective.loosenDelayHours }

    private func binding(for category: String) -> Binding<Bool> {
        Binding(
            get: { draft.blockedCategories.contains(category) },
            set: { on in
                draft.blockedCategories.removeAll { $0 == category }
                if on { draft.blockedCategories.append(category) }
            })
    }

    private var ratingBinding: Binding<Int> {
        Binding(
            get: { draft.maximumAppRating.flatMap { r in ScreenTimePlan.validRatings.first { $0 >= r } } ?? 0 },
            set: { draft.maximumAppRating = $0 == 0 ? nil : $0 })
    }

    private func addSite() {
        let cleaned = ScreenTimePlan.cleanDomains([newSite], limit: 1)
        guard let site = cleaned.first else {
            siteError = "That doesn't look like a site name. Try something like example.com."
            return
        }
        siteError = nil
        if !draft.extraBlockedDomains.contains(site) {
            draft.extraBlockedDomains = (draft.extraBlockedDomains + [site]).sorted()
        }
        newSite = ""
    }

    /// Copies the settings in force into the draft, unless the member has
    /// edits that haven't been saved (a refresh never throws them away).
    private func reload(force: Bool) {
        guard let s = model.settings else { return }
        if !force, let loadedFrom, draft != loadedFrom { return }
        draft = s
        loadedFrom = s
        selection = Self.selection(from: s)
    }

    private func applyPicker(_ s: FamilyActivitySelection) {
        draft.shieldApps = s.applicationTokens.compactMap(ScreenTimeEnforcer.encode).sorted()
        draft.shieldAppCategories = s.categoryTokens.compactMap(ScreenTimeEnforcer.encode).sorted()
        draft.shieldWebDomains = s.webDomainTokens.compactMap(ScreenTimeEnforcer.encode).sorted()
    }

    private static func selection(from s: FaroSettings) -> FamilyActivitySelection {
        func decode<T: Decodable & Hashable>(_ list: [String], _: T.Type) -> Set<T> {
            Set(list.compactMap { Data(base64Encoded: $0).flatMap { try? JSONDecoder().decode(T.self, from: $0) } })
        }
        var sel = FamilyActivitySelection()
        sel.applicationTokens = decode(s.shieldApps, ApplicationToken.self)
        sel.categoryTokens = decode(s.shieldAppCategories, ActivityCategoryToken.self)
        sel.webDomainTokens = decode(s.shieldWebDomains, WebDomainToken.self)
        return sel
    }

    // MARK: Words

    private var pickedSummary: String {
        let a = draft.shieldApps.count, c = draft.shieldAppCategories.count, w = draft.shieldWebDomains.count
        if a + c + w == 0 { return "Nothing chosen." }
        return [a > 0 ? "\(a) app\(a == 1 ? "" : "s")" : nil,
                c > 0 ? "\(c) categor\(c == 1 ? "y" : "ies")" : nil,
                w > 0 ? "\(w) website\(w == 1 ? "" : "s")" : nil]
            .compactMap { $0 }.joined(separator: ", ") + " chosen."
    }

    private func delayText(_ hours: Int) -> String {
        switch hours {
        case 0: return "No wait"
        case 1: return "1 hour"
        default: return "\(hours) hours"
        }
    }

    private func savedText(_ r: SubmitResult) -> String {
        var parts: [String] = []
        let told = model.eventsQueued ? "your allies will be told as soon as Faro can reach the instance" : "your allies were told"
        if !r.appliedNow.isEmpty { parts.append("Blocking more is on now.") }
        if !r.loosenedNow.isEmpty { parts.append("Blocking less took effect now, and \(told).") }
        if !r.waiting.isEmpty { parts.append("Blocking less is waiting, and \(told).") }
        if !r.superseded.isEmpty { parts.append("An earlier change that was waiting was cancelled.") }
        return parts.joined(separator: " ")
    }
}
