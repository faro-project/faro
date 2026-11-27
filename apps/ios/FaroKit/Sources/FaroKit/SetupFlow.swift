import Foundation

/// Where the member is in setting up Faro on this phone (docs/IOS.md §14):
/// enroll, wait for approval, then Screen Time and the VPN permission.
/// A pure state machine so the order and the "can't skip" rules are tested
/// without a phone.
public enum SetupStep: String, Codable, Equatable, Sendable, CaseIterable {
    /// What Faro does and what it costs (docs/IOS.md §12).
    case costs
    /// Scan or paste the enrollment link.
    case link
    /// The instance's name and key fingerprint, to confirm.
    case confirmInstance
    /// Name this phone.
    case deviceName
    /// Registering with the instance.
    case enrolling
    /// Registered; the member approves this phone in the web app.
    case waitingForApproval
    /// Screen Time authorization and the settings Faro applies.
    case screenTime
    /// The VPN configuration and its permission prompt.
    case tunnel
    /// Everything is on.
    case done
}

public enum SetupEvent: Equatable, Sendable {
    case acceptedCosts
    case linkGiven(EnrollLink)
    case instanceConfirmed
    case deviceNamed(String)
    case enrolled
    case approved
    case screenTimeAuthorized
    case tunnelInstalled
    /// The step's work failed; stay (or go back) with a message.
    case failed(String)
    case back
}

/// What survives a relaunch of the app mid-setup, besides what the core
/// already knows (enrolled, approved).
public struct SetupProgress: Codable, Equatable, Sendable {
    public var screenTimeDone: Bool
    public var tunnelDone: Bool
    /// When this phone was enrolled (Unix ms), which fixes the monthly
    /// notice's day of the month.
    public var enrolledAtMs: Int64?

    public init(screenTimeDone: Bool = false, tunnelDone: Bool = false, enrolledAtMs: Int64? = nil) {
        self.screenTimeDone = screenTimeDone
        self.tunnelDone = tunnelDone
        self.enrolledAtMs = enrolledAtMs
    }
}

/// `setup.json` in the app group. Plain progress flags, no secrets.
public struct SetupProgressStore: Sendable {
    public let url: URL

    public init(url: URL) { self.url = url }

    public init(group: AppGroup) { self.init(url: group.root.appendingPathComponent("setup.json")) }

    /// The saved progress; none saved, or a file that can't be read, is "nothing done yet".
    public func load() -> SetupProgress {
        guard let data = try? Data(contentsOf: url),
              let progress = try? JSONDecoder().decode(SetupProgress.self, from: data)
        else { return SetupProgress() }
        return progress
    }

    public func save(_ progress: SetupProgress) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(progress).write(to: url, options: .atomic)
    }

    /// Loads, changes and saves in one go.
    @discardableResult
    public func update(_ change: (inout SetupProgress) -> Void) throws -> SetupProgress {
        var progress = load()
        change(&progress)
        try save(progress)
        return progress
    }
}

public struct SetupFlow: Equatable, Sendable {
    public private(set) var step: SetupStep
    /// The last failure, cleared by the next event that isn't a failure.
    public private(set) var error: String?
    public private(set) var link: EnrollLink?
    public private(set) var deviceName: String?

    public init(step: SetupStep = .costs) {
        self.step = step
    }

    /// Where to start, given what the core and the saved progress say. An
    /// enrolled phone never goes back through the enrollment steps.
    public static func resume(enrolled: Bool, approved: Bool, progress: SetupProgress) -> SetupFlow {
        guard enrolled else { return SetupFlow() }
        guard approved else { return SetupFlow(step: .waitingForApproval) }
        if !progress.screenTimeDone { return SetupFlow(step: .screenTime) }
        if !progress.tunnelDone { return SetupFlow(step: .tunnel) }
        return SetupFlow(step: .done)
    }

    /// Longest device name the core accepts.
    public static let maxDeviceNameLength = 64

    /// A name the core will accept: 1 to 64 printable characters, no
    /// surrounding spaces. `nil` if there is nothing usable.
    public static func cleanDeviceName(_ raw: String) -> String? {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= maxDeviceNameLength,
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return nil }
        return name
    }

    /// Applies `event`. Returns `false`, changing nothing, when the event
    /// doesn't belong to the current step.
    @discardableResult
    public mutating func apply(_ event: SetupEvent) -> Bool {
        if case .failed(let message) = event {
            return fail(message)
        }
        switch (step, event) {
        case (.costs, .acceptedCosts):
            go(.link)
        case (.link, .linkGiven(let l)):
            link = l
            go(.confirmInstance)
        case (.confirmInstance, .instanceConfirmed):
            go(.deviceName)
        case (.deviceName, .deviceNamed(let raw)):
            guard let name = SetupFlow.cleanDeviceName(raw) else {
                error = "Give this phone a name of 1 to \(SetupFlow.maxDeviceNameLength) characters."
                return true
            }
            deviceName = name
            go(.enrolling)
        case (.enrolling, .enrolled):
            go(.waitingForApproval)
        case (.waitingForApproval, .approved):
            go(.screenTime)
        case (.screenTime, .screenTimeAuthorized):
            go(.tunnel)
        case (.tunnel, .tunnelInstalled):
            go(.done)
        case (.confirmInstance, .back):
            link = nil
            go(.link)
        case (.deviceName, .back):
            go(.confirmInstance)
        default:
            return false
        }
        return true
    }

    private mutating func go(_ next: SetupStep) {
        step = next
        error = nil
    }

    private mutating func fail(_ message: String) -> Bool {
        switch step {
        case .enrolling:
            // Back to the name, where "try again" is one tap.
            step = .deviceName
        case .link, .confirmInstance, .deviceName, .waitingForApproval, .screenTime, .tunnel:
            break
        case .costs, .done:
            return false
        }
        error = message
        return true
    }
}
