//! Database access: one code path for SQLite (default) and Postgres.
//!
//! We use sqlx's `Any` driver so the backend is chosen at runtime by
//! `DATABASE_URL`. That constrains the SQL we write, deliberately:
//!
//! * `$1`-style placeholders (SQLite and Postgres both accept them);
//! * only portable column types (BIGINT, TEXT); booleans as BIGINT 0/1;
//! * no compile-time checked `query!` macros (they bind to one backend);
//! * no `$n IS NULL` tests on untyped parameters (Postgres cannot infer them).
//!
//! All repository functions live in submodules and take `impl Executor` /
//! `&mut AnyConnection` so they compose inside transactions.

pub mod migrations;
pub mod repo;

use sqlx::any::{AnyConnectOptions, AnyPoolOptions};
use sqlx::{Any, AnyPool, Executor, Transaction};
use std::str::FromStr;
use std::time::Duration;

/// Which SQL backend a [`Db`] talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    /// The backend a database URL names, or `None` for any other scheme.
    pub fn from_url(url: &str) -> Option<Self> {
        if url.starts_with("sqlite:") {
            Some(Backend::Sqlite)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Some(Backend::Postgres)
        } else {
            None
        }
    }
}

/// What `doctor` and `serve` say about a Postgres database. The beta
/// supports SQLite only: the Postgres code paths are kept and compile-checked
/// ([`migrations`], [`repo`]), but nothing runs them in CI.
pub const POSTGRES_UNSUPPORTED: &str =
    "experimental, not supported in this release (the beta supports SQLite only)";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("unsupported database URL (expected sqlite: or postgres://)")]
    UnsupportedUrl,
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// A connection pool plus the backend it talks to.
#[derive(Debug, Clone)]
pub struct Db {
    pool: AnyPool,
    backend: Backend,
}

impl Db {
    /// Connect to `url`. For SQLite, applies WAL, foreign keys and a busy
    /// timeout to every pooled connection.
    pub async fn connect(url: &str) -> Result<Db, DbError> {
        sqlx::any::install_default_drivers();
        let backend = Backend::from_url(url).ok_or(DbError::UnsupportedUrl)?;
        let opts = AnyConnectOptions::from_str(url)?;
        let pool = match backend {
            Backend::Sqlite => {
                AnyPoolOptions::new()
                    // SQLite has one writer at a time; a handful of
                    // connections is plenty for concurrent readers.
                    .max_connections(8)
                    .acquire_timeout(Duration::from_secs(30))
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            conn.execute("PRAGMA busy_timeout = 10000").await?;
                            conn.execute("PRAGMA journal_mode = WAL").await?;
                            conn.execute("PRAGMA synchronous = NORMAL").await?;
                            Ok(())
                        })
                    })
                    .connect_with(opts)
                    .await?
            }
            Backend::Postgres => {
                AnyPoolOptions::new()
                    .max_connections(20)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_with(opts)
                    .await?
            }
        };
        Ok(Db { pool, backend })
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Apply embedded migrations for this backend.
    pub async fn migrate(&self) -> Result<(), DbError> {
        let migrator = migrations::migrator(self.backend).await?;
        migrator.run(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction that will write.
    ///
    /// On SQLite this is `BEGIN IMMEDIATE`, taking the write lock up front.
    /// A default (deferred) transaction that reads and then writes can fail
    /// with `SQLITE_BUSY` immediately (without honouring `busy_timeout`) if
    /// another writer committed in between; taking the lock first makes
    /// writers queue politely instead.
    pub async fn begin_write(&self) -> Result<Transaction<'static, Any>, sqlx::Error> {
        match self.backend {
            Backend::Sqlite => self.pool.begin_with("BEGIN IMMEDIATE").await,
            Backend::Postgres => self.pool.begin().await,
        }
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// BIGINT 0/1 encoding for booleans.
pub fn flag(b: bool) -> i64 {
    i64::from(b)
}

/// Convert a protocol `u64` (seq numbers, lengths) to a BIGINT, rejecting
/// values that do not fit rather than wrapping.
pub fn to_i64(v: u64) -> Option<i64> {
    i64::try_from(v).ok()
}

/// Convert a BIGINT read from the database back to `u64`. Negative values can
/// only come from corruption; treat them as such.
pub fn to_u64(v: i64) -> Result<u64, sqlx::Error> {
    u64::try_from(v).map_err(|_| sqlx::Error::Decode("negative value in unsigned column".into()))
}
