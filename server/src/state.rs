//! Shared application state handed to every handler.

use crate::blob::BlobStore;
use crate::clock::SharedClock;
use crate::config::Config;
use crate::db::Db;
use crate::identity::Identity;
use crate::mailer::Mailer;
use crate::ratelimit::RateLimiter;
use crate::settings::InstanceSettings;
use crate::tokens::TokenHasher;
use faro_proto::InstanceId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Cheap-to-clone handle to everything a request needs.
#[derive(Clone, Debug)]
pub struct AppState(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    config: Config,
    db: Db,
    blobs: Arc<dyn BlobStore>,
    mailer: Arc<dyn Mailer>,
    clock: SharedClock,
    identity: Identity,
    instance_id: InstanceId,
    rate_limiter: RateLimiter,
    device_locks: KeyedLocks,
    settings: RwLock<InstanceSettings>,
}

/// Everything needed to build an [`AppState`]; see [`crate::bootstrap`].
pub struct StateParts {
    pub config: Config,
    pub db: Db,
    pub blobs: Arc<dyn BlobStore>,
    pub mailer: Arc<dyn Mailer>,
    pub clock: SharedClock,
    pub identity: Identity,
    pub instance_id: InstanceId,
    /// Effective admin-editable settings (config file + stored overrides).
    pub settings: InstanceSettings,
}

impl AppState {
    pub fn new(p: StateParts) -> Self {
        AppState(Arc::new(Inner {
            config: p.config,
            db: p.db,
            blobs: p.blobs,
            mailer: p.mailer,
            clock: p.clock,
            identity: p.identity,
            instance_id: p.instance_id,
            rate_limiter: RateLimiter::new(),
            device_locks: KeyedLocks::default(),
            settings: RwLock::new(p.settings),
        }))
    }

    pub fn config(&self) -> &Config {
        &self.0.config
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    pub fn blobs(&self) -> &dyn BlobStore {
        self.0.blobs.as_ref()
    }

    pub fn mailer(&self) -> Arc<dyn Mailer> {
        self.0.mailer.clone()
    }

    pub fn clock(&self) -> &SharedClock {
        &self.0.clock
    }

    pub fn now_ms(&self) -> i64 {
        self.0.clock.now_ms()
    }

    pub fn identity(&self) -> &Identity {
        &self.0.identity
    }

    pub fn hasher(&self) -> &TokenHasher {
        self.0.identity.hasher()
    }

    pub fn instance_id(&self) -> &InstanceId {
        &self.0.instance_id
    }

    /// The current admin-editable settings. Always read through this (not
    /// `config()`) for registration, retention and liveness, so console
    /// changes apply without a restart.
    pub fn settings(&self) -> InstanceSettings {
        // A poisoned lock still holds a fully written value (writers only
        // ever replace it wholesale).
        self.0
            .settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replace the live settings (after they were persisted).
    pub fn set_settings(&self, s: InstanceSettings) {
        *self.0.settings.write().unwrap_or_else(|p| p.into_inner()) = s;
    }

    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.0.rate_limiter
    }

    /// Serialise chain ingest per device within this process (see
    /// [`crate::api::events`]); the database compare-and-set on the chain head
    /// is the cross-process guard.
    pub async fn lock_device(&self, device: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.0.device_locks.lock(device).await
    }
}

/// A map of named async mutexes that forgets idle entries.
#[derive(Debug, Default)]
struct KeyedLocks {
    map: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl KeyedLocks {
    async fn lock(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = {
            // A poisoned std mutex only means another thread panicked while
            // inserting; the map itself is still usable.
            let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
            if map.len() > 1024 {
                // Drop entries nobody holds or waits on.
                map.retain(|_, v| Arc::strong_count(v) > 1);
            }
            map.entry(key.to_owned()).or_default().clone()
        };
        m.lock_owned().await
    }
}
