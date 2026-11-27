import FaroKit
import Foundation
import Security

// Compiled into Faro and FaroTunnel only, the two targets that link the
// Rust core (docs/IOS.md §13). The monitor and shield extensions never see
// this file.

/// The Keychain `KeyStore` (docs/IOS.md §13, "Keys"). Items are generic
/// passwords under one service, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
/// so the tunnel can read them in the background but a backup restored to
/// another phone carries none.
///
/// No `kSecAttrAccessGroup` is set on purpose: the app and the tunnel both
/// list the one shared group, `$(AppIdentifierPrefix)org.faro.ios.shared`,
/// as their only `keychain-access-groups` entry, and the Keychain files new
/// items under an app's first group. That way no code needs the team
/// prefix, and both processes see the same items.
///
/// Before the first unlock after a reboot the Keychain refuses reads
/// (`errSecInteractionNotAllowed`). That is reported as `Locked`, which the
/// core turns into "try again later" rather than a failure.
final class KeychainKeyStore: KeyStore {
    private let service: String

    init(service: String = "org.faro.ios") {
        self.service = service
    }

    private func query(_ name: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
        ]
    }

    func load(name: String) throws -> Data? {
        var q = query(name)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            return out as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainKeyStore.error(status, "reading \(name)")
        }
    }

    func store(name: String, value: Data) throws {
        let update = [kSecValueData as String: value]
        var status = SecItemUpdate(query(name) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query(name)
            add[kSecValueData as String] = value
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw KeychainKeyStore.error(status, "writing \(name)")
        }
    }

    func delete(name: String) throws {
        let status = SecItemDelete(query(name) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainKeyStore.error(status, "deleting \(name)")
        }
    }

    private static func error(_ status: OSStatus, _ what: String) -> KeyStoreError {
        let text = (SecCopyErrorMessageString(status, nil) as String?) ?? "status \(status)"
        let message = "Keychain \(what): \(text)"
        if status == errSecInteractionNotAllowed {
            return .Locked(message: message)
        }
        return .Failed(message: message)
    }
}

enum CoreLink {
    /// Opens the core on the app group container. This also makes sure the
    /// Rust library is linked into the target.
    static func open(group: AppGroup) throws -> FaroCore {
        try group.prepare()
        return try FaroCore(dataDir: group.coreDirectory.path, keys: KeychainKeyStore())
    }
}
