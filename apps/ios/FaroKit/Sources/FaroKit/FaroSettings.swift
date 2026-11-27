import Foundation

/// What the app asks the "faro" ManagedSettings store and the DNS filter to
/// hold, written to the app group so the monitor extension can re-apply it
/// without the core (docs/IOS.md §6.2, §6.3). Plain data, no secrets: it is
/// the member's own choices. This is the settings in force. A loosening the
/// member asked for waits in `PendingState` until its time comes.
public struct FaroSettings: Codable, Equatable, Sendable {
    /// The file format. A reader that sees a higher number than it knows
    /// leaves the store alone rather than guessing.
    public static let currentVersion = 1

    public var version: Int
    /// Extra domains for `webContent.blockedByFilter`, on top of Apple's list.
    /// The member's chosen sites; the DNS filter blocks all of them.
    public var extraBlockedDomains: [String]
    /// Domains never blocked by that filter.
    public var allowedDomains: [String]
    /// `application.denyAppRemoval`.
    public var denyAppRemoval: Bool
    /// `media.denyExplicitContent`.
    public var denyExplicitContent: Bool
    /// `dateAndTime.requireAutomaticDateAndTime`.
    public var requireAutomaticDateAndTime: Bool
    /// `appStore.maximumRating` (4, 9, 12, 17 or 1000 for all), or `nil` for off.
    /// Other numbers round up to the next rating (`ScreenTimePlan`).
    public var maximumAppRating: Int?

    // What the member chooses to block (docs/IOS.md §9). All additive to
    // version 1: a file without them reads as "nothing extra".

    /// Categories blocked by the DNS filter on top of adult, which is always
    /// blocked (`gambling`, `violence`, `proxy_vpn`).
    public var blockedCategories: [String]
    /// Opaque `FamilyActivityPicker` tokens (base64 of each token's JSON).
    /// Faro never reads which app one is (docs/IOS.md §4 principle 4).
    public var shieldApps: [String]
    public var shieldAppCategories: [String]
    public var shieldWebDomains: [String]
    public var shieldWebDomainCategories: [String]
    /// How long a loosening waits, in hours, 0 to 72 (docs/IOS.md §9).
    public var loosenDelayHours: Int
    /// Counts up each time the settings are saved by any process. The tunnel
    /// compares it with the copy in its provider configuration to choose the
    /// newer one (`TunnelConfig`).
    public var generation: Int

    public static let defaultLoosenDelayHours = 24
    public static let maxLoosenDelayHours = 72

    public init(
        version: Int = FaroSettings.currentVersion,
        extraBlockedDomains: [String] = [],
        allowedDomains: [String] = [],
        denyAppRemoval: Bool = true,
        denyExplicitContent: Bool = true,
        requireAutomaticDateAndTime: Bool = true,
        maximumAppRating: Int? = nil,
        blockedCategories: [String] = [],
        shieldApps: [String] = [],
        shieldAppCategories: [String] = [],
        shieldWebDomains: [String] = [],
        shieldWebDomainCategories: [String] = [],
        loosenDelayHours: Int = FaroSettings.defaultLoosenDelayHours,
        generation: Int = 0
    ) {
        self.version = version
        self.extraBlockedDomains = extraBlockedDomains
        self.allowedDomains = allowedDomains
        self.denyAppRemoval = denyAppRemoval
        self.denyExplicitContent = denyExplicitContent
        self.requireAutomaticDateAndTime = requireAutomaticDateAndTime
        self.maximumAppRating = maximumAppRating
        self.blockedCategories = blockedCategories
        self.shieldApps = shieldApps
        self.shieldAppCategories = shieldAppCategories
        self.shieldWebDomains = shieldWebDomains
        self.shieldWebDomainCategories = shieldWebDomainCategories
        self.loosenDelayHours = loosenDelayHours
        self.generation = generation
    }

    /// Reads a file from before the choices existed as "nothing extra".
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try c.decode(Int.self, forKey: .version),
            extraBlockedDomains: try c.decodeIfPresent([String].self, forKey: .extraBlockedDomains) ?? [],
            allowedDomains: try c.decodeIfPresent([String].self, forKey: .allowedDomains) ?? [],
            denyAppRemoval: try c.decodeIfPresent(Bool.self, forKey: .denyAppRemoval) ?? true,
            denyExplicitContent: try c.decodeIfPresent(Bool.self, forKey: .denyExplicitContent) ?? true,
            requireAutomaticDateAndTime: try c.decodeIfPresent(Bool.self, forKey: .requireAutomaticDateAndTime) ?? true,
            maximumAppRating: try c.decodeIfPresent(Int.self, forKey: .maximumAppRating),
            blockedCategories: try c.decodeIfPresent([String].self, forKey: .blockedCategories) ?? [],
            shieldApps: try c.decodeIfPresent([String].self, forKey: .shieldApps) ?? [],
            shieldAppCategories: try c.decodeIfPresent([String].self, forKey: .shieldAppCategories) ?? [],
            shieldWebDomains: try c.decodeIfPresent([String].self, forKey: .shieldWebDomains) ?? [],
            shieldWebDomainCategories: try c.decodeIfPresent([String].self, forKey: .shieldWebDomainCategories) ?? [],
            loosenDelayHours: try c.decodeIfPresent(Int.self, forKey: .loosenDelayHours)
                ?? FaroSettings.defaultLoosenDelayHours,
            generation: try c.decodeIfPresent(Int.self, forKey: .generation) ?? 0)
    }

    /// The delay in seconds, kept inside 0 to 72 hours.
    public var loosenDelaySecs: Int64 {
        Int64(min(max(loosenDelayHours, 0), FaroSettings.maxLoosenDelayHours)) * 3600
    }

    /// The defaults of docs/IOS.md §6.2.
    public static let `default` = FaroSettings()
}

public enum SettingsFileError: Error, Equatable {
    /// The file was written by a newer Faro.
    case newerVersion(Int)
}

/// Reads and writes the settings file.
public struct SettingsStore: Sendable {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public init(group: AppGroup) {
        self.init(url: group.settingsFile)
    }

    /// The saved settings, or `nil` if there is no file. A file that can't
    /// be decoded throws, so a caller never mistakes damage for "no settings".
    public func load() throws -> FaroSettings? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let settings = try JSONDecoder().decode(FaroSettings.self, from: Data(contentsOf: url))
        guard settings.version <= FaroSettings.currentVersion else {
            throw SettingsFileError.newerVersion(settings.version)
        }
        return settings
    }

    /// Replaces the file atomically, so a reader in another process sees
    /// the old settings or the new ones, never half of either.
    public func save(_ settings: FaroSettings) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(settings).write(to: url, options: .atomic)
    }
}
