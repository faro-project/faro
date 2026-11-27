import Darwin
import Foundation

/// A loosening that waits (docs/IOS.md §9): what the member asked for, and
/// when it takes effect. Times are Unix ms on the wall clock.
public struct PendingChange: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var requestedAtMs: Int64
    public var takesEffectAtMs: Int64
    /// The delay in force when it was asked for, in seconds.
    public var delaySecs: Int64
    public var changes: [SettingChange]

    public init(id: String, requestedAtMs: Int64, takesEffectAtMs: Int64, delaySecs: Int64, changes: [SettingChange]) {
        self.id = id
        self.requestedAtMs = requestedAtMs
        self.takesEffectAtMs = takesEffectAtMs
        self.delaySecs = delaySecs
        self.changes = changes
    }
}

/// A `settings_change` event waiting for a process that can sign one. The
/// monitor can't link the Rust core, so when it applies a loosening it
/// leaves one of these, and the app or the tunnel, whichever runs first,
/// turns it into the event (docs/IOS.md §6.3, §9).
public struct SettingsEventRequest: Codable, Equatable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable {
        /// A tightening, applied at once. No pending fields.
        case tightened
        /// A loosening was asked for and waits.
        case loosenRequested
        /// A loosening took effect.
        case loosenApplied
        /// The member cancelled a waiting loosening.
        case loosenCancelled
    }

    public var id: String
    public var kind: Kind
    public var changes: [SettingChange]
    public var requestedAtMs: Int64?
    public var takesEffectAtMs: Int64?
    public var cancelledAtMs: Int64?
    public var delaySecs: Int64?
    /// When a process took this to send it. A claim older than the lease is
    /// ignored, so a process that died holding one doesn't strand the event.
    public var claimedAtMs: Int64?

    public init(
        id: String, kind: Kind, changes: [SettingChange],
        requestedAtMs: Int64? = nil, takesEffectAtMs: Int64? = nil,
        cancelledAtMs: Int64? = nil, delaySecs: Int64? = nil, claimedAtMs: Int64? = nil
    ) {
        self.id = id
        self.kind = kind
        self.changes = changes
        self.requestedAtMs = requestedAtMs
        self.takesEffectAtMs = takesEffectAtMs
        self.cancelledAtMs = cancelledAtMs
        self.delaySecs = delaySecs
        self.claimedAtMs = claimedAtMs
    }
}

public enum CancelResult: Equatable, Sendable {
    case cancelled
    /// Its time had come, so it applied before the cancel could.
    case alreadyApplied
    case notFound
}

/// What `submit` did, for the screen to say.
public struct SubmitResult: Equatable, Sendable {
    /// Tightenings, applied now.
    public var appliedNow: [SettingChange] = []
    /// Loosenings that wait, as one or more pending changes.
    public var waiting: [PendingChange] = []
    /// Loosenings applied now because the delay is 0.
    public var loosenedNow: [SettingChange] = []
    /// Waiting loosenings dropped because the member changed the same thing again.
    public var superseded: [SettingChange] = []

    public var isEmpty: Bool {
        appliedNow.isEmpty && waiting.isEmpty && loosenedNow.isEmpty && superseded.isEmpty
    }
}

/// The pending-change state machine. Pure: every function takes the time
/// and the ids it needs, so the tests cover the clock's edges without a
/// phone. `ChoicesStore` runs it under a lock.
public struct PendingState: Codable, Equatable, Sendable {
    public static let currentVersion = 1

    public var version: Int
    public var items: [PendingChange]
    public var events: [SettingsEventRequest]

    public init(version: Int = PendingState.currentVersion, items: [PendingChange] = [], events: [SettingsEventRequest] = []) {
        self.version = version
        self.items = items
        self.events = events
    }

    // MARK: Asking

    /// The member's wish: the settings should become `draft`. Tightening
    /// applies at once and waits for nothing; loosening waits for the delay
    /// that is in force now (0 means it applies at once, still as a
    /// `settings_change` that allies see). A waiting loosening that the
    /// member now changes in another way is dropped, with an event.
    public mutating func submit(
        _ draft: FaroSettings, to settings: inout FaroSettings, nowMs: Int64, newID: () -> String
    ) -> SubmitResult {
        var result = SubmitResult()
        applyDue(to: &settings, nowMs: nowMs, newID: newID)
        let delay = settings.loosenDelaySecs
        var diff = ChoiceDiff.between(settings, draft)

        // What is already waiting stays; asking for it again does nothing,
        // and asking for something else on the same entry replaces it.
        let waitingOps = items.flatMap { $0.changes.map(\.op) }
        diff.loosening.removeAll { c in waitingOps.contains(c.op) }
        let touched = diff.tightening + diff.loosening
        var dropped: [SettingChange] = []
        var droppedFrom: [(item: PendingChange, changes: [SettingChange])] = []
        for i in items.indices {
            let hit = items[i].changes.filter { w in touched.contains { $0.op.overlaps(w.op) } }
            if !hit.isEmpty {
                droppedFrom.append((items[i], hit))
                dropped += hit
                items[i].changes.removeAll { w in hit.contains(w) }
            }
        }
        items.removeAll { $0.changes.isEmpty }
        for (item, changes) in droppedFrom {
            for chunk in ChoiceDiff.chunks(changes) {
                events.append(SettingsEventRequest(
                    id: newID(), kind: .loosenCancelled, changes: chunk,
                    requestedAtMs: item.requestedAtMs, takesEffectAtMs: item.takesEffectAtMs,
                    cancelledAtMs: nowMs, delaySecs: item.delaySecs))
            }
        }
        result.superseded = dropped

        var changed = false
        for chunk in ChoiceDiff.chunks(diff.tightening) {
            chunk.forEach { settings.apply($0.op) }
            events.append(SettingsEventRequest(id: newID(), kind: .tightened, changes: chunk))
            result.appliedNow += chunk
            changed = true
        }
        for chunk in ChoiceDiff.chunks(diff.loosening) {
            if delay == 0 {
                chunk.forEach { settings.apply($0.op) }
                events.append(SettingsEventRequest(
                    id: newID(), kind: .loosenApplied, changes: chunk,
                    requestedAtMs: nowMs, takesEffectAtMs: nowMs, delaySecs: 0))
                result.loosenedNow += chunk
                changed = true
            } else {
                let item = PendingChange(
                    id: newID(), requestedAtMs: nowMs, takesEffectAtMs: nowMs + delay * 1000,
                    delaySecs: delay, changes: chunk)
                items.append(item)
                events.append(SettingsEventRequest(
                    id: newID(), kind: .loosenRequested, changes: chunk,
                    requestedAtMs: item.requestedAtMs, takesEffectAtMs: item.takesEffectAtMs,
                    delaySecs: delay))
                result.waiting.append(item)
            }
        }
        if changed { settings.generation += 1 }
        return result
    }

    // MARK: Applying

    /// Applies every loosening whose time has come: at `takesEffectAtMs`
    /// exactly, or later. A clock set back leaves them waiting. Returns
    /// whether the settings changed. Calling it again right away does
    /// nothing, so the app, the monitor and the tunnel can all call it.
    @discardableResult
    public mutating func applyDue(to settings: inout FaroSettings, nowMs: Int64, newID: () -> String) -> Bool {
        let due = items.filter { $0.takesEffectAtMs <= nowMs }
            .sorted { ($0.takesEffectAtMs, $0.id) < ($1.takesEffectAtMs, $1.id) }
        guard !due.isEmpty else { return false }
        for item in due {
            item.changes.forEach { settings.apply($0.op) }
            events.append(SettingsEventRequest(
                id: newID(), kind: .loosenApplied, changes: item.changes,
                requestedAtMs: item.requestedAtMs, takesEffectAtMs: item.takesEffectAtMs,
                delaySecs: item.delaySecs))
        }
        items.removeAll { $0.takesEffectAtMs <= nowMs }
        settings.generation += 1
        return true
    }

    // MARK: Cancelling

    /// Cancels a waiting loosening, if its time hasn't come. One that is
    /// due is applied first, so cancelling can't undo a change after the
    /// fact: it reports `alreadyApplied`.
    public mutating func cancel(
        _ id: String, settings: inout FaroSettings, nowMs: Int64, newID: () -> String
    ) -> CancelResult {
        let wasDue = items.first { $0.id == id }.map { $0.takesEffectAtMs <= nowMs } ?? false
        applyDue(to: &settings, nowMs: nowMs, newID: newID)
        guard let i = items.firstIndex(where: { $0.id == id }) else {
            return wasDue ? .alreadyApplied : .notFound
        }
        let item = items.remove(at: i)
        events.append(SettingsEventRequest(
            id: newID(), kind: .loosenCancelled, changes: item.changes,
            requestedAtMs: item.requestedAtMs, takesEffectAtMs: item.takesEffectAtMs,
            cancelledAtMs: nowMs, delaySecs: item.delaySecs))
        return .cancelled
    }

    // MARK: Sending events

    /// How long a claim on an event holds before another process may take it.
    public static let claimLeaseMs: Int64 = 2 * 60 * 1000

    /// Takes the events no one else is sending, marking them claimed.
    public mutating func claimEvents(nowMs: Int64) -> [SettingsEventRequest] {
        var out: [SettingsEventRequest] = []
        for i in events.indices {
            if let at = events[i].claimedAtMs, nowMs - at < PendingState.claimLeaseMs, nowMs >= at { continue }
            events[i].claimedAtMs = nowMs
            out.append(events[i])
        }
        return out
    }

    /// Drops events that were sent.
    public mutating func complete(_ ids: Set<String>) {
        events.removeAll { ids.contains($0.id) }
    }

    /// Lets go of claims after a failed send, so the next process retries.
    public mutating func release(_ ids: Set<String>) {
        for i in events.indices where ids.contains(events[i].id) { events[i].claimedAtMs = nil }
    }
}

/// The settings, the pending changes and the events waiting to be sent,
/// kept in the app group and changed under one `flock`, so the app, the
/// monitor and the tunnel never act on a half-written state. The lock is
/// held only for file reads and writes, never across a call into the core:
/// iOS ends a process that is suspended while holding a lock on a file in a
/// shared container.
public struct ChoicesStore: Sendable {
    public let group: AppGroup

    public init(group: AppGroup) {
        self.group = group
    }

    public var pendingFile: URL { group.root.appendingPathComponent("pending.json") }
    var lockFile: URL { group.root.appendingPathComponent("choices.lock") }

    public enum StoreError: Error, Equatable {
        /// No settings file yet: setup hasn't reached Screen Time.
        case notSetUp
        case lockFailed
        case newerVersion
    }

    /// The settings and pending state, for showing. Never changes them.
    public func read() throws -> (settings: FaroSettings, pending: PendingState) {
        try transaction { _, _ in }.snapshot
    }

    /// Runs `body` on the current settings and state with the lock held,
    /// then saves what it changed: the state, and the settings file with the
    /// DNS filter's file next to it.
    @discardableResult
    public func transaction<T>(
        _ body: (inout FaroSettings, inout PendingState) throws -> T
    ) throws -> (value: T, snapshot: (settings: FaroSettings, pending: PendingState)) {
        try locked { try unlockedTransaction(body) }
    }

    /// Setup: makes sure there are settings, writing the defaults only when
    /// there are none. Redoing a setup step never resets the member's choices.
    public func ensureSettings() throws -> FaroSettings {
        try locked {
            let store = SettingsStore(group: group)
            if let existing = try store.load() { return existing }
            try store.save(.default)
            try TunnelConfig.filterJSON(for: .default).write(to: group.filterConfigFile, options: .atomic)
            return .default
        }
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: group.root, withIntermediateDirectories: true)
        let fd = open(lockFile.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { throw StoreError.lockFailed }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw StoreError.lockFailed }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    private func unlockedTransaction<T>(
        _ body: (inout FaroSettings, inout PendingState) throws -> T
    ) throws -> (value: T, snapshot: (settings: FaroSettings, pending: PendingState)) {
        let settingsStore = SettingsStore(group: group)
        guard var settings = try settingsStore.load() else { throw StoreError.notSetUp }
        var state = try loadState()
        let beforeSettings = settings, beforeState = state
        let value = try body(&settings, &state)
        if state != beforeState { try saveState(state) }
        if settings != beforeSettings {
            try settingsStore.save(settings)
            try TunnelConfig.filterJSON(for: settings).write(to: group.filterConfigFile, options: .atomic)
        }
        return (value, (settings, state))
    }

    private func loadState() throws -> PendingState {
        guard let data = try? Data(contentsOf: pendingFile) else { return PendingState() }
        let state = try JSONDecoder().decode(PendingState.self, from: data)
        guard state.version <= PendingState.currentVersion else { throw StoreError.newerVersion }
        return state
    }

    private func saveState(_ state: PendingState) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(state).write(to: pendingFile, options: .atomic)
    }

    // MARK: What each process does

    static func newID() -> String { UUID().uuidString.lowercased() }

    /// The app: the member saved their choices.
    public func submit(_ draft: FaroSettings, nowMs: Int64) throws -> SubmitResult {
        try transaction { s, p in p.submit(draft, to: &s, nowMs: nowMs, newID: Self.newID) }.value
    }

    /// The app, the monitor and the tunnel: apply what is due. Returns the
    /// settings if they changed, so the caller can re-apply them.
    public func applyDue(nowMs: Int64) throws -> FaroSettings? {
        let r = try transaction { s, p in p.applyDue(to: &s, nowMs: nowMs, newID: Self.newID) }
        return r.value ? r.snapshot.settings : nil
    }

    /// The app: the member cancelled a waiting loosening.
    public func cancel(_ id: String, nowMs: Int64) throws -> CancelResult {
        try transaction { s, p in p.cancel(id, settings: &s, nowMs: nowMs, newID: Self.newID) }.value
    }

    /// The app or the tunnel: take the events to send.
    public func claimEvents(nowMs: Int64) throws -> [SettingsEventRequest] {
        try transaction { _, p in p.claimEvents(nowMs: nowMs) }.value
    }

    public func completeEvents(_ ids: Set<String>) throws {
        try transaction { _, p in p.complete(ids) }
    }

    public func releaseEvents(_ ids: Set<String>) throws {
        try transaction { _, p in p.release(ids) }
    }
}
