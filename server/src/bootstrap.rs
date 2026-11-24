//! Startup: data directory, identity key, database, instance row, setup token.
//!
//! Shared by `faro-server init`, `faro-server serve` and the integration tests,
//! so all three go through exactly the same checks.

use crate::blob::LocalDiskBlobStore;
use crate::clock::SharedClock;
use crate::config::Config;
use crate::db::repo::{auth_tokens, instance, users};
use crate::db::{Db, DbError};
use crate::identity::{self, IdentityError};
use crate::mailer::Mailer;
use crate::settings::{InstanceSettings, StoredSettings};
use crate::state::{AppState, StateParts};
use crate::tokens::{new_token, TokenPurpose};
use faro_crypto::{random_bytes, Zeroizing};
use faro_proto::InstanceId;
use std::path::Path;
use std::sync::Arc;

/// How long a printed setup token stays valid. Long enough to finish DNS and
/// TLS setup after `init`; `init` can always be re-run to mint a fresh one.
pub const SETUP_TOKEN_TTL_MS: i64 = 24 * 3600 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("cannot create data directory {path}: {source}")]
    DataDir {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error(
        "the identity key in the data directory does not match the one recorded in the database; \
         refusing to start (restore the original identity.key, or point at the right database)"
    )]
    IdentityMismatch,
}

fn create_data_dir(dir: &Path) -> Result<(), BootstrapError> {
    let err = |source| BootstrapError::DataDir {
        path: dir.to_owned(),
        source,
    };
    std::fs::create_dir_all(dir).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir).map_err(err)?;
        if meta.permissions().mode() & 0o077 != 0 {
            // Best effort: the data dir holds the identity key and ciphertext.
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

/// Open everything and return a ready [`AppState`].
pub async fn open(
    config: Config,
    mailer: Arc<dyn Mailer>,
    clock: SharedClock,
) -> Result<AppState, BootstrapError> {
    create_data_dir(&config.data_dir)?;
    let (identity, created) = identity::load_or_create(&config.data_dir)?;
    if created {
        tracing::info!(pubkey = %identity.public().to_b64(), "created instance identity key");
    }

    let db = Db::connect(&config.database_url()).await?;
    db.migrate().await?;

    let now = clock.now_ms();
    let row = match instance::get(db.pool()).await? {
        Some(row) => row,
        None => {
            let fresh = instance::InstanceRow {
                id: InstanceId::from_random(&random_bytes::<16>()),
                name: config.instance.name.clone(),
                identity_pubkey: identity.public(),
                created_at_ms: now,
            };
            instance::insert_if_absent(db.pool(), &fresh).await?;
            // Re-read: another process may have won the insert race.
            instance::get(db.pool())
                .await?
                .ok_or_else(|| sqlx::Error::RowNotFound)?
        }
    };
    if row.identity_pubkey != identity.public() {
        return Err(BootstrapError::IdentityMismatch);
    }
    // The config file is the source of truth for the display name until the
    // stage-B admin console takes over instance settings.
    if row.name != config.instance.name {
        instance::set_name(db.pool(), &config.instance.name).await?;
    }

    let blobs = LocalDiskBlobStore::open(config.data_dir.join("blobs")).map_err(|source| {
        BootstrapError::DataDir {
            path: config.data_dir.join("blobs"),
            source,
        }
    })?;

    let settings = load_settings(&db, &config).await?;

    Ok(AppState::new(StateParts {
        settings,
        config,
        db,
        blobs: Arc::new(blobs),
        mailer,
        clock,
        identity,
        instance_id: row.id,
    }))
}

/// Effective settings: config file plus the admin's stored overrides. If the
/// stored overrides no longer validate against the current config file (the
/// file was edited in a way that conflicts), fall back to the file alone and
/// say so, rather than refusing to start: the admin can only fix stored
/// settings through a running console.
async fn load_settings(db: &Db, config: &Config) -> Result<InstanceSettings, BootstrapError> {
    let json = instance::settings_json(db.pool()).await?;
    let stored = match StoredSettings::from_json(&json) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "ignoring unreadable stored instance settings");
            StoredSettings::default()
        }
    };
    match InstanceSettings::resolve(config, &stored) {
        Ok(s) => Ok(s),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "stored instance settings conflict with the config file; using the config file"
            );
            Ok(InstanceSettings::from_config(config))
        }
    }
}

/// Mint a new setup token (invalidating any earlier one), unless an admin
/// already exists. The plaintext is returned exactly once, for printing.
pub async fn issue_setup_token(state: &AppState) -> Result<Option<Zeroizing<String>>, sqlx::Error> {
    let db = state.db();
    let mut tx = db.begin_write().await?;
    if users::count_admins(&mut *tx).await? > 0 {
        return Ok(None);
    }
    let token = new_token();
    let now = state.now_ms();
    auth_tokens::replace_setup_token(
        &mut tx,
        &state.hasher().hash(TokenPurpose::Setup, &token),
        now,
        now + SETUP_TOKEN_TTL_MS,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(token))
}

/// On `serve`: if there is no admin and no still-valid setup token, mint one
/// so a fresh container prints a usable token in its logs.
pub async fn ensure_setup_token(
    state: &AppState,
) -> Result<Option<Zeroizing<String>>, sqlx::Error> {
    let now = state.now_ms();
    if users::count_admins(state.db().pool()).await? > 0
        || auth_tokens::has_valid_setup_token(state.db().pool(), now).await?
    {
        return Ok(None);
    }
    issue_setup_token(state).await
}
