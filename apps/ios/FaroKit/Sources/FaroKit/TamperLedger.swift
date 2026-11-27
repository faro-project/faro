import Darwin
import Foundation

// The tamper watchers' shared book (docs/IOS.md §10.2, ARCHITECTURE.md §3.7
// "One cause, one signal"). Each protection layer is watched by another
// process: the tunnel watches Screen Time, the monitor extension and the
// app watch the tunnel, the monitor and the app watch the "faro" store.
// The monitor can't link the Rust core, so nobody records an event
// directly: every watcher writes what it saw here, this decides whether it
// is news, and the app or the tunnel (the two that link the core) turn the
// queued requests into urgent `tamper` events.

/// A protection layer that can be switched off.
public enum ProtectionLayer: String, Codable, CodingKeyRepresentable, CaseIterable, Sendable {
    /// Screen Time authorization (layer 1's switch).
    case screenTime = "screen_time"
    /// The DNS filter's packet tunnel (layer 2).
    case filter
    /// What Faro wrote to the "faro" ManagedSettings store.
    case settings
}

/// Why the DNS filter is off, as the core's `FilterCause` names it.
public enum FilterCauseCode: String, Codable, CaseIterable, Sendable {
    case vpnDisconnected = "vpn_disconnected"
    case onDemandOff = "on_demand_off"
    case otherVpn = "other_vpn"
    case profileRemoved = "profile_removed"
    case unknown
}

/// A tamper event to record: always urgent, always tamper-class
/// (DEVELOPMENT.md invariant 4).
public enum TamperRequest: Codable, Equatable, Sendable {
    case screenTimeRevoked
    case filterOff(FilterCauseCode)
    case settingsCleared

    public var layer: ProtectionLayer {
        switch self {
        case .screenTimeRevoked: return .screenTime
        case .filterOff: return .filter
        case .settingsCleared: return .settings
        }
    }
}

/// Who read a Screen Time authorization status.
public enum WatchSource: String, Codable, CodingKeyRepresentable, CaseIterable, Sendable {
    case app
    case tunnel
    case monitor
}

/// What a Screen Time reading means.
public enum ScreenTimeVerdict: Equatable, Sendable {
    /// Approved.
    case approved
    /// Not approved, but this source has never read it approved, so it
    /// can't tell a revocation from not being able to read the status at
    /// all (spike S6). Nothing is done.
    case unknown
    /// Not approved, once: read it again in a few seconds before believing
    /// it (a process that just started can read a status that hasn't
    /// loaded yet).
    case recheck
    /// Confirmed off, and queued.
    case reported
    /// Confirmed off, and already reported since it was last seen on.
    case alreadyReported
}

/// A queued request.
public struct PendingTamper: Codable, Equatable, Sendable {
    public var id: Int64
    public var request: TamperRequest
    public var atMs: Int64
}

/// The book itself: plain data and the rules, so the tests reach every
/// decision. `TamperLedger` keeps it in a file.
public struct TamperBook: Codable, Equatable, Sendable {
    /// Layers reported off and not seen on since: the cause and when.
    public var off: [ProtectionLayer: PendingTamper] = [:]
    /// Requests waiting for the app or the tunnel to record them.
    public var pending: [PendingTamper] = []
    /// Sources that have read Screen Time approved on this enrollment.
    public var screenTimeSeenBy: Set<WatchSource> = []
    /// A source's first unconfirmed "not approved" reading.
    public var screenTimeDoubt: [WatchSource: Int64] = [:]
    /// When each context signal was last recorded.
    public var contextAt: [String: Int64] = [:]
    /// Leave Faro has delivered its goodbye: the watchers stand down.
    public var leaving = false
    public var nextId: Int64 = 1

    /// How long after a first "not approved" a second one confirms it.
    public static let confirmAfterMs: Int64 = 2_000
    /// A doubt older than this is stale: start over.
    public static let doubtExpiresMs: Int64 = 10 * 60 * 1000

    public init() {}

    /// `request`'s layer was seen off. Returns whether that is news: the
    /// first time since the layer was last seen on, in which case it is
    /// queued. A layer already reported off isn't reported again, whatever
    /// the cause now (one cause, one signal).
    @discardableResult
    public mutating func sawOff(_ request: TamperRequest, nowMs: Int64) -> Bool {
        guard !leaving, off[request.layer] == nil else { return false }
        let p = PendingTamper(id: nextId, request: request, atMs: nowMs)
        nextId += 1
        off[request.layer] = p
        pending.append(p)
        return true
    }

    /// `layer` was seen on: the next time it goes off is news again.
    /// Returns whether anything changed.
    @discardableResult
    public mutating func sawOn(_ layer: ProtectionLayer) -> Bool {
        off.removeValue(forKey: layer) != nil
    }

    /// A reading of Screen Time authorization by `source`.
    @discardableResult
    public mutating func sawScreenTime(approved: Bool, source: WatchSource, nowMs: Int64) -> ScreenTimeVerdict {
        if approved {
            screenTimeSeenBy.insert(source)
            screenTimeDoubt[source] = nil
            sawOn(.screenTime)
            return .approved
        }
        guard screenTimeSeenBy.contains(source) else { return .unknown }
        if let first = screenTimeDoubt[source], nowMs - first < TamperBook.doubtExpiresMs {
            guard nowMs - first >= TamperBook.confirmAfterMs else { return .recheck }
            screenTimeDoubt[source] = nil
            return sawOff(.screenTimeRevoked, nowMs: nowMs) ? .reported : .alreadyReported
        }
        screenTimeDoubt[source] = nowMs
        return .recheck
    }

    /// Whether the context signal `name` should be recorded now: at most
    /// once per `everyMs`, so the daily report lists it without a row per
    /// check. Marks it recorded when it says yes.
    public mutating func shouldRecordContext(_ name: String, nowMs: Int64, everyMs: Int64) -> Bool {
        guard !leaving else { return false }
        if let last = contextAt[name], nowMs - last < everyMs, nowMs >= last { return false }
        contextAt[name] = nowMs
        return true
    }

    /// Leave Faro: from now on nothing is news. Called only once the
    /// goodbye (itself urgent and tamper-class) is delivered, right before
    /// the protection is lifted on purpose.
    public mutating func standDown() {
        leaving = true
        pending = []
    }

    /// Remove the requests recorded, by id.
    public mutating func recorded(_ ids: Set<Int64>) {
        pending.removeAll { ids.contains($0.id) }
    }
}

/// The book in the app group (`tamper.json`), changed under an exclusive
/// `flock` on `tamper.lock` by whichever process holds it: the app, the
/// tunnel and the monitor extension all write it. The lock is held only to
/// read, change and write the small file, never across a call into the
/// core.
public struct TamperLedger: Sendable {
    public let url: URL
    public let lockURL: URL

    public init(directory: URL) {
        url = directory.appendingPathComponent("tamper.json")
        lockURL = directory.appendingPathComponent("tamper.lock")
    }

    public init(group: AppGroup) {
        self.init(directory: group.root)
    }

    /// The book as it is now (empty if there is none or it can't be read).
    public func read() -> TamperBook {
        (try? withLock { load() }) ?? load()
    }

    /// Reads, changes and saves the book in one locked step. Saves only
    /// when `change` changed it. Returns what `change` returned.
    @discardableResult
    public func update<T>(_ change: (inout TamperBook) -> T) throws -> T {
        try withLock {
            var book = load()
            let before = book
            let out = change(&book)
            if book != before { try save(book) }
            return out
        }
    }

    /// Records each pending request with `record` (outside the lock), then
    /// removes the ones that were recorded. A request whose `record` throws
    /// stays for the next try (keys locked before the first unlock, say).
    /// If two processes drain at once a request can be recorded twice, which
    /// is better than losing one. Returns how many were recorded.
    @discardableResult
    public func drain(_ record: (TamperRequest) throws -> Void) throws -> Int {
        let pending = try update { $0.pending }
        var done = Set<Int64>()
        for p in pending {
            do {
                try record(p.request)
                done.insert(p.id)
            } catch {
                continue
            }
        }
        if !done.isEmpty { try update { $0.recorded(done) } }
        return done.count
    }

    /// Start over (a new enrollment).
    public func reset() throws {
        try withLock { try? FileManager.default.removeItem(at: url) }
    }

    private func load() -> TamperBook {
        guard let data = try? Data(contentsOf: url),
              let book = try? JSONDecoder().decode(TamperBook.self, from: data)
        else { return TamperBook() }
        return book
    }

    private func save(_ book: TamperBook) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(book).write(to: url, options: .atomic)
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(
            at: lockURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let fd = open(lockURL.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
}
