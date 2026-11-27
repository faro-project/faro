import Foundation

/// The app group container, the one place the app, the tunnel and the
/// extensions share files (docs/IOS.md §13). Every path in it is made here,
/// so no target spells a file name on its own.
public struct AppGroup: Sendable {
    /// The app group identifier in every target's entitlements.
    public static let identifier = "group.org.faro.ios"

    /// The container's root.
    public let root: URL

    /// The real container, or `nil` when the app group isn't available
    /// (unsigned builds, the Simulator without the entitlement).
    public static func container(fileManager: FileManager = .default) -> AppGroup? {
        fileManager.containerURL(forSecurityApplicationGroupIdentifier: identifier)
            .map(AppGroup.init(root:))
    }

    /// A container rooted anywhere, for tests.
    public init(root: URL) {
        self.root = root
    }

    /// The Rust core's data directory (`FaroCore(dataDir:)`): the outbox
    /// database, state and installed domain bundles.
    public var coreDirectory: URL { root.appendingPathComponent("core", isDirectory: true) }

    /// The settings file the monitor extension re-applies (docs/IOS.md §6.3).
    public var settingsFile: URL { root.appendingPathComponent("settings.json") }

    /// Small counters (`shield_shown`, `shield_closed`, docs/IOS.md §6.4).
    public var countersDirectory: URL { root.appendingPathComponent("counters", isDirectory: true) }

    /// Marker files such as the tunnel's "alive" timestamp (docs/IOS.md §10.2).
    public var markersDirectory: URL { root.appendingPathComponent("markers", isDirectory: true) }

    /// Creates the directories above. Safe to call more than once.
    public func prepare(fileManager: FileManager = .default) throws {
        for dir in [coreDirectory, countersDirectory, markersDirectory] {
            try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }
}
