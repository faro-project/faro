//! The domain bundle from the signed update channel (docs/IOS.md §7.2,
//! §14; PROTOCOL.md §8.2, models and blocklists).
//!
//! The instance's mirror serves it, and the project signs it: the app
//! passes in the project's root of trust (shipped in the app, never taken
//! from the instance), and the metadata walk, selection and download are
//! `faro_client::fetch`'s and `faro-update`'s, as on desktop. So the
//! instance can delay a list but can't forge one (invariant 5).
//!
//! A newer bundle is installed only if its version is above the one in
//! use and not below the highest ever installed. It is unpacked into a
//! staging directory, checked with `faro_detect::load_domains` (approved
//! sources, allowlisted licences, attribution, the bundle's length,
//! BLAKE3 and domain count) and a version equal to the signed target's,
//! and only then moved into place under `domains/<blake3>/`. A bundle that
//! fails the checks is recorded by BLAKE3 and never downloaded again.

use crate::core::FaroCore;
use crate::error::FaroError;
use crate::store::{DOMAINS, UPDATE_TRUST};
use crate::types::{DomainsInfo, DomainsUpdate, UPDATE_PLATFORM};
use faro_client::bundle::{create_private_dir, sync_dir, unpack_bundle, UnpackError};
use faro_client::fetch::{trusted_updater, verify_metadata, MetadataError, UpdateFetcher};
use faro_client::link::parse_instance_url;
use faro_detect::{load_domains, DomainsManifest, LoadedDomains};
use faro_proto::Hash32;
use faro_update::{Channel, Selection, TargetKind, TrustedState, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Largest domain bundle accepted.
pub const MAX_DOMAINS_BUNDLE_BYTES: u64 = 128 << 20;
/// Where installed bundles live, in the data directory.
pub const DOMAINS_DIR: &str = "domains";
/// The manifest's name in an installed bundle's directory.
pub const DOMAINS_MANIFEST_FILE: &str = "domains.manifest.json";
/// The `integrity_failure` component for an installed bundle that no
/// longer matches what was installed (the desktop service's string).
pub const DOMAINS_UPDATE_CHANGED: &str = "domain list update (changed)";

/// One installed bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Installed {
    version: String,
    blake3: Hash32,
    manifest_blake3: Hash32,
}

/// What is installed, in `mobile_state`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    current: Option<Installed>,
    /// The highest version ever installed: never go below it.
    highest: Option<String>,
    /// Signed bundles that failed the checks, by BLAKE3, with the reason.
    rejected: BTreeMap<String, String>,
}

fn update_err(e: impl std::fmt::Display) -> FaroError {
    FaroError::Update {
        message: e.to_string(),
    }
}

#[uniffi::export]
impl FaroCore {
    /// Check the instance's mirror for a newer domain bundle and install
    /// it. `trusted_root` is the project's root of trust (a signed root
    /// envelope) the app ships with.
    pub fn update_domains(&self, trusted_root: Vec<u8>) -> Result<DomainsUpdate, FaroError> {
        let e = self.enrollment_record()?;
        let base = parse_instance_url(&e.instance_url)?;
        let fetch = UpdateFetcher::new(base, &self.opts)?;
        self.rt
            .block_on(self.update_domains_from(&fetch, &trusted_root))
    }

    /// The installed domain bundle, checked again with `load_domains`.
    /// `None` if none is installed. One that no longer matches what was
    /// installed is removed and reported as an urgent `integrity_failure`
    /// (once approved), and the next update installs it again.
    pub fn installed_domains(&self) -> Result<Option<DomainsInfo>, FaroError> {
        Ok(self.load_installed_domains()?.map(|(l, path)| DomainsInfo {
            version: l.manifest.version.clone(),
            domains: l.manifest.domains as u64,
            manifest_path: path.display().to_string(),
        }))
    }
}

impl FaroCore {
    /// [`FaroCore::installed_domains`], with the loaded categorizer.
    pub fn load_installed_domains(&self) -> Result<Option<(LoadedDomains, PathBuf)>, FaroError> {
        let record = self.domains_record()?;
        let Some(cur) = record.current.clone() else {
            return Ok(None);
        };
        let dir = self.domains_dir().join(hex::encode(cur.blake3.as_bytes()));
        let manifest = dir.join(DOMAINS_MANIFEST_FILE);
        let checked = std::fs::read(&manifest)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                if Hash32::of(&bytes) != cur.manifest_blake3 {
                    return Err("the manifest changed".to_owned());
                }
                let l = load_domains(&manifest).map_err(|e| e.to_string())?;
                if l.manifest.version != cur.version {
                    return Err("the version changed".to_owned());
                }
                Ok(l)
            });
        match checked {
            Ok(l) => Ok(Some((l, manifest))),
            Err(reason) => {
                tracing::error!(%reason, version = %cur.version, "the installed domain list no longer matches; removing it");
                let _ = std::fs::remove_dir_all(&dir);
                let mut record = record;
                record.current = None;
                crate::core::lock(&self.store).put(DOMAINS, &record)?;
                let tamper = crate::types::Tamper::IntegrityFailure {
                    component: DOMAINS_UPDATE_CHANGED.into(),
                };
                match self.record_tamper(tamper) {
                    Ok(_) | Err(FaroError::NotApproved) | Err(FaroError::NotEnrolled) => {}
                    Err(e) => tracing::warn!(error = %e, "could not record the integrity failure"),
                }
                Ok(None)
            }
        }
    }

    /// The version of the installed bundle, from the record alone: nothing
    /// is read or checked. For deciding whether loading it is worth it.
    pub fn installed_domains_version(&self) -> Result<Option<String>, FaroError> {
        Ok(self.domains_record()?.current.map(|c| c.version))
    }

    fn domains_dir(&self) -> PathBuf {
        self.dir.join(DOMAINS_DIR)
    }

    fn domains_record(&self) -> Result<Record, FaroError> {
        Ok(crate::core::lock(&self.store)
            .get::<Record>(DOMAINS)?
            .unwrap_or_default())
    }

    /// [`FaroCore::update_domains`] against `fetch`.
    pub async fn update_domains_from(
        &self,
        fetch: &UpdateFetcher,
        trusted_root: &[u8],
    ) -> Result<DomainsUpdate, FaroError> {
        let Some(info) = fetch.info().await?.filter(|i| i.available) else {
            return Ok(DomainsUpdate::Unavailable);
        };
        let channel = info.channel.parse::<Channel>().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "the instance names an invalid channel; using stable");
            Channel::stable()
        });
        let stored: Option<TrustedState> = match crate::core::lock(&self.store).get(UPDATE_TRUST) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "ignoring unreadable update trust state");
                None
            }
        };
        let mut u = trusted_updater(trusted_root, stored).map_err(|e| FaroError::Update {
            message: format!("the update root of trust is not a valid signed root: {e}"),
        })?;
        let save =
            |u: &faro_update::Updater| crate::core::lock(&self.store).put(UPDATE_TRUST, u.state());
        let verified = verify_metadata(fetch, &mut u, || self.clock.wall_ms(), save).await;
        save(&u)?;
        let verified = verified.map_err(|e| match e {
            MetadataError::Fetch(e) => e.into(),
            MetadataError::Save(e) => e,
            e => update_err(e),
        })?;

        let client_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(update_err)?;
        let q = Selection {
            channel: &channel,
            kind: TargetKind::Blocklist,
            platform: UPDATE_PLATFORM,
            arch: std::env::consts::ARCH,
            current_version: None,
            os_version: None,
            allow_downgrade: false,
        };
        let Some(target) = verified.select_for(&q, &client_version) else {
            return Ok(DomainsUpdate::UpToDate);
        };
        let version = target.custom.version.clone();
        let record = self.domains_record()?;
        let parse = |v: Option<&String>| v.and_then(|v| Version::parse(v).ok());
        let current = parse(record.current.as_ref().map(|c| &c.version));
        let highest = parse(record.highest.as_ref());
        if current.is_some_and(|c| version <= c) || highest.is_some_and(|h| version < h) {
            return Ok(DomainsUpdate::UpToDate);
        }
        let key = target.blake3.to_prefixed_hex();
        if let Some(reason) = record.rejected.get(&key) {
            return Ok(DomainsUpdate::Rejected {
                version: version.to_string(),
                reason: reason.clone(),
            });
        }

        let store_dir = self.domains_dir();
        let downloads = store_dir.join("downloads");
        create_private_dir(&downloads).map_err(FaroError::storage)?;
        let hex = hex::encode(target.blake3.as_bytes());
        let partial = downloads.join(format!("{hex}.partial"));
        let _ = std::fs::remove_file(&partial);
        tracing::info!(%version, bytes = target.length, name = %target.name, "downloading the domain list");
        let got = fetch
            .artifact(&target, MAX_DOMAINS_BUNDLE_BYTES, &partial)
            .await;
        match got {
            Ok(true) => {}
            Ok(false) => {
                let _ = std::fs::remove_file(&partial);
                return Err(update_err(
                    "the instance's mirror doesn't have the domain list",
                ));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                return Err(e.into());
            }
        }

        let staging = store_dir.join(format!(".{hex}.staging"));
        let checked = unpack_bundle(&partial, &staging, DOMAINS_MANIFEST_FILE, |m| {
            serde_json::from_slice::<DomainsManifest>(m)
                .map(|m| m.bundle.file)
                .map_err(|e| format!("invalid domain manifest: {e}"))
        })
        .and_then(|(manifest, manifest_blake3)| {
            let l = load_domains(&manifest).map_err(|e| match e {
                faro_detect::DetectError::Io { path, source } => UnpackError::Io { path, source },
                e => UnpackError::Rejected(e.to_string()),
            })?;
            match Version::parse(&l.manifest.version) {
                Ok(v) if v == version => Ok((l, manifest_blake3)),
                _ => Err(UnpackError::Rejected(format!(
                    "the manifest says version {:?}, the signed target {version}",
                    l.manifest.version
                ))),
            }
        });
        let _ = std::fs::remove_file(&partial);
        let (loaded, manifest_blake3) = match checked {
            Ok(r) => r,
            Err(UnpackError::Io { path, source }) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(FaroError::storage(format!("{}: {source}", path.display())));
            }
            Err(UnpackError::Rejected(reason)) => {
                let _ = std::fs::remove_dir_all(&staging);
                tracing::error!(%version, %reason, "refusing the domain list: it is signed, but fails the checks");
                let mut record = self.domains_record()?;
                record.rejected.insert(key, reason.clone());
                crate::core::lock(&self.store).put(DOMAINS, &record)?;
                return Ok(DomainsUpdate::Rejected {
                    version: version.to_string(),
                    reason,
                });
            }
        };

        // Commit: the directory, then the record, then drop the old one.
        let dest = store_dir.join(&hex);
        if dest.exists() {
            std::fs::remove_dir_all(&dest).map_err(FaroError::storage)?;
        }
        std::fs::rename(&staging, &dest).map_err(FaroError::storage)?;
        sync_dir(&store_dir).map_err(FaroError::storage)?;
        let mut record = self.domains_record()?;
        let old = record.current.replace(Installed {
            version: version.to_string(),
            blake3: target.blake3,
            manifest_blake3,
        });
        if parse(record.highest.as_ref()).is_none_or(|h| version > h) {
            record.highest = Some(version.to_string());
        }
        crate::core::lock(&self.store).put(DOMAINS, &record)?;
        if let Some(old) = old.filter(|o| o.blake3 != target.blake3) {
            let _ = std::fs::remove_dir_all(store_dir.join(hex::encode(old.blake3.as_bytes())));
        }
        tracing::info!(%version, "installed the domain list from the update channel");
        Ok(DomainsUpdate::Installed {
            info: DomainsInfo {
                version: version.to_string(),
                domains: loaded.manifest.domains as u64,
                manifest_path: dest.join(DOMAINS_MANIFEST_FILE).display().to_string(),
            },
        })
    }
}
