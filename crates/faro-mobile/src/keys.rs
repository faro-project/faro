//! The device's secrets, kept by the platform (docs/IOS.md §13 "Keys").
//!
//! The iOS app implements [`KeyStore`] in Swift over the Keychain, in a
//! shared access group with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
//! so the app and the tunnel see the same items and a backup restored onto
//! another phone carries none of them. [`MemoryKeyStore`] is for tests.
//!
//! Two items are kept:
//!
//! | Name | Contents |
//! |---|---|
//! | [`DEVICE_KEY`] | the 32-byte Ed25519 seed of the device signing key |
//! | [`DEVICE_TOKEN`] | the bearer token the instance issued at enrollment |
//!
//! **Keys are made in Rust** with `faro-crypto` and never leave the device.
//! Rust holds key bytes only while it uses them: every copy it makes is in
//! a zeroizing buffer, and the signing key itself (`ed25519-dalek` with
//! `zeroize`) is wiped when it is dropped at the end of each call. The copy
//! UniFFI makes to carry the bytes across the FFI boundary, and whatever
//! Swift keeps, are outside Rust's reach; the Swift side should hand the
//! bytes straight to the Keychain and keep no copy.

use faro_crypto::SigningKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// The device signing key's seed.
pub const DEVICE_KEY: &str = "device-signing-key";
/// The device's bearer token.
pub const DEVICE_TOKEN: &str = "device-token";

/// Why the platform's key store failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum KeyStoreError {
    /// The store can't be read right now: on iOS, before the first unlock
    /// after a reboot. Try again later; nothing is wrong.
    #[error("the key store is locked: {message}")]
    Locked { message: String },
    /// Anything else.
    #[error("the key store failed: {message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeyStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeyStoreError::Failed { message: e.reason }
    }
}

/// Secret storage implemented by the platform (a foreign trait: Swift
/// implements it over the Keychain).
#[uniffi::export(with_foreign)]
pub trait KeyStore: Send + Sync {
    /// The item `name`, or `None` if there is none.
    fn load(&self, name: String) -> Result<Option<Vec<u8>>, KeyStoreError>;
    /// Create or replace the item `name`.
    fn store(&self, name: String, value: Vec<u8>) -> Result<(), KeyStoreError>;
    /// Remove the item `name`; removing a missing item is not an error.
    fn delete(&self, name: String) -> Result<(), KeyStoreError>;
}

/// A [`KeyStore`] in memory, for tests. Values are zeroized when replaced,
/// deleted or dropped.
#[derive(Default, uniffi::Object)]
pub struct MemoryKeyStore {
    items: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

#[uniffi::export]
impl MemoryKeyStore {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[uniffi::export]
impl KeyStore for MemoryKeyStore {
    fn load(&self, name: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(items.get(&name).map(|v| v.to_vec()))
    }

    fn store(&self, name: String, value: Vec<u8>) -> Result<(), KeyStoreError> {
        let mut items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        items.insert(name, Zeroizing::new(value));
        Ok(())
    }

    fn delete(&self, name: String) -> Result<(), KeyStoreError> {
        let mut items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        items.remove(&name);
        Ok(())
    }
}

/// Load an item into a zeroizing buffer.
pub(crate) fn load_secret(
    keys: &dyn KeyStore,
    name: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    Ok(keys.load(name.to_owned())?.map(Zeroizing::new))
}

/// A new device key, stored as [`DEVICE_KEY`] (replacing any earlier one:
/// a key is never reused across enrollments).
pub(crate) fn create_device_key(keys: &dyn KeyStore) -> Result<SigningKey, KeyStoreError> {
    let key = SigningKey::generate();
    let seed = key.to_bytes();
    // `seed` is wiped on return. The Vec is moved into the store: a Rust
    // store keeps it zeroizing, a foreign one gets UniFFI's copy (module
    // docs).
    keys.store(DEVICE_KEY.to_owned(), seed.to_vec())?;
    Ok(key)
}

/// The device key, or `None` if the store has none.
pub(crate) fn device_key(keys: &dyn KeyStore) -> Result<Option<SigningKey>, KeyStoreError> {
    let Some(bytes) = load_secret(keys, DEVICE_KEY)? else {
        return Ok(None);
    };
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| KeyStoreError::Failed {
                    message: "the device key is not 32 bytes".into(),
                })?,
        );
    Ok(Some(SigningKey::from_bytes(&seed)))
}

/// The device token, or `None` if the store has none.
pub(crate) fn device_token(
    keys: &dyn KeyStore,
) -> Result<Option<Zeroizing<String>>, KeyStoreError> {
    let Some(bytes) = load_secret(keys, DEVICE_TOKEN)? else {
        return Ok(None);
    };
    let s = std::str::from_utf8(&bytes).map_err(|_| KeyStoreError::Failed {
        message: "the device token is not UTF-8".into(),
    })?;
    Ok(Some(Zeroizing::new(s.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let s = MemoryKeyStore::new();
        assert_eq!(device_key(s.as_ref()).unwrap().map(|k| k.public()), None);
        let k = create_device_key(s.as_ref()).unwrap();
        assert_eq!(
            device_key(s.as_ref()).unwrap().map(|k| k.public()),
            Some(k.public())
        );
        // A second key replaces the first.
        let k2 = create_device_key(s.as_ref()).unwrap();
        assert_ne!(k.public(), k2.public());
        assert_eq!(
            device_key(s.as_ref()).unwrap().map(|k| k.public()),
            Some(k2.public())
        );
        s.delete(DEVICE_KEY.into()).unwrap();
        s.delete(DEVICE_KEY.into()).unwrap();
        assert!(device_key(s.as_ref()).unwrap().is_none());
    }

    #[test]
    fn malformed_items_are_errors() {
        let s = MemoryKeyStore::new();
        s.store(DEVICE_KEY.into(), vec![1; 31]).unwrap();
        assert!(matches!(
            device_key(s.as_ref()),
            Err(KeyStoreError::Failed { .. })
        ));
        s.store(DEVICE_TOKEN.into(), vec![0xff, 0xfe]).unwrap();
        assert!(device_token(s.as_ref()).is_err());
        s.store(DEVICE_TOKEN.into(), b"token".to_vec()).unwrap();
        assert_eq!(device_token(s.as_ref()).unwrap().unwrap().as_str(), "token");
    }
}
