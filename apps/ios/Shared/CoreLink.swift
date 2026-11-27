import FaroKit
import Foundation

// Compiled into Faro and FaroTunnel only, the two targets that link the
// Rust core (docs/IOS.md §13). The monitor and shield extensions never see
// this file.

/// A placeholder `KeyStore` until the Keychain one lands (docs/IOS.md §13,
/// "Keys"): it reads as locked and refuses to store, so the core signs
/// nothing and loses nothing.
final class LockedKeyStore: KeyStore {
    func load(name: String) throws -> Data? {
        throw KeyStoreError.Locked(message: "the Keychain key store is not built yet")
    }

    func store(name: String, value: Data) throws {
        throw KeyStoreError.Locked(message: "the Keychain key store is not built yet")
    }

    func delete(name: String) throws {
        throw KeyStoreError.Locked(message: "the Keychain key store is not built yet")
    }
}

enum CoreLink {
    /// Opens the core on the app group container. This also makes sure the
    /// Rust library is linked into the target.
    static func open(group: AppGroup) throws -> FaroCore {
        try group.prepare()
        return try FaroCore(dataDir: group.coreDirectory.path, keys: LockedKeyStore())
    }
}
