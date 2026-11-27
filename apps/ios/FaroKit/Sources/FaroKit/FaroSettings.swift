import Foundation

/// What the app asks the "faro" ManagedSettings store to hold, written to
/// the app group so the monitor extension can re-apply it without the core
/// (docs/IOS.md §6.2, §6.3). Plain data, no secrets: it is the member's
/// own choices.
public struct FaroSettings: Codable, Equatable, Sendable {
    /// The file format. A reader that sees a higher number than it knows
    /// leaves the store alone rather than guessing.
    public static let currentVersion = 1

    public var version: Int
    /// Extra domains for `webContent.blockedByFilter`, on top of Apple's list.
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

    public init(
        version: Int = FaroSettings.currentVersion,
        extraBlockedDomains: [String] = [],
        allowedDomains: [String] = [],
        denyAppRemoval: Bool = true,
        denyExplicitContent: Bool = true,
        requireAutomaticDateAndTime: Bool = true,
        maximumAppRating: Int? = nil
    ) {
        self.version = version
        self.extraBlockedDomains = extraBlockedDomains
        self.allowedDomains = allowedDomains
        self.denyAppRemoval = denyAppRemoval
        self.denyExplicitContent = denyExplicitContent
        self.requireAutomaticDateAndTime = requireAutomaticDateAndTime
        self.maximumAppRating = maximumAppRating
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
