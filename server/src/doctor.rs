//! `faro-server doctor`: checks an instance's configuration and prints a
//! report (§9 "Secure defaults for operators").
//!
//! Read-only: it never creates the database, keys or directories (it tells
//! the admin to run `init` instead). Each check is `OK`, `WARN` (works, but
//! is risky or degraded) or `FAIL` (broken or unsafe); the command exits
//! non-zero if anything fails.

use crate::config::{Config, SmtpTls};
use crate::db::repo::instance;
use crate::db::{Db, POSTGRES_UNSUPPORTED};
use crate::identity::IDENTITY_FILE;
use crate::mailer::SmtpMailer;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "OK  ",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: &'static str, level: Level, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            level,
            detail: detail.into(),
        });
    }

    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.level == Level::Fail)
    }

    pub fn get(&self, name: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.name == name)
    }

    pub fn render(&self) -> String {
        let mut s = String::from("faro-server doctor\n\n");
        for c in &self.checks {
            s.push_str(&format!(
                "[{}] {:<14} {}\n",
                c.level.label(),
                c.name,
                c.detail
            ));
        }
        let (w, f) = self.checks.iter().fold((0, 0), |(w, f), c| match c.level {
            Level::Warn => (w + 1, f),
            Level::Fail => (w, f + 1),
            Level::Ok => (w, f),
        });
        s.push_str(&format!("\n{f} failure(s), {w} warning(s)\n"));
        s
    }
}

/// Group/other permission bits, on Unix.
#[cfg(unix)]
fn foreign_access(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o077)
}

#[cfg(not(unix))]
fn foreign_access(_path: &Path) -> Option<u32> {
    Some(0)
}

/// Bytes available to unprivileged users on the filesystem holding `path`.
#[cfg(unix)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    let s = rustix::fs::statvfs(path).ok()?;
    s.f_bavail.checked_mul(s.f_frsize)
}

#[cfg(not(unix))]
pub fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

const GIB: u64 = 1024 * 1024 * 1024;

/// Run every check. `check_smtp` connects to the SMTP server (no mail is
/// sent).
pub async fn run(cfg: &Config, check_smtp: bool) -> Report {
    let mut r = Report::default();

    // Public URL and TLS.
    if cfg.public_url.starts_with("https://") {
        r.push("public_url", Level::Ok, &cfg.public_url);
    } else {
        r.push(
            "public_url",
            Level::Warn,
            format!("{} is not https (allowed only in dev mode)", cfg.public_url),
        );
    }
    if let Some(d) = &cfg.tls.acme_domain {
        let staging = if cfg.tls.acme_production {
            ""
        } else {
            " (staging CA: browsers will not trust it)"
        };
        let level = if cfg.tls.acme_production {
            Level::Ok
        } else {
            Level::Warn
        };
        r.push(
            "tls",
            level,
            format!("automatic certificates for {d} via ACME{staging}; port must be reachable"),
        );
    } else if let (Some(c), Some(k)) = (&cfg.tls.cert_path, &cfg.tls.key_path) {
        match crate::tls::load_static(c, k) {
            Ok(_) => r.push(
                "tls",
                Level::Ok,
                format!("static certificate {}", c.display()),
            ),
            Err(e) => r.push("tls", Level::Fail, e.to_string()),
        }
    } else if cfg.behind_proxy {
        r.push(
            "tls",
            Level::Ok,
            "terminated by your reverse proxy / tunnel",
        );
    } else if cfg.dev {
        r.push("tls", Level::Warn, "plain HTTP (dev mode)");
    } else {
        r.push(
            "tls",
            Level::Fail,
            "plain HTTP with no proxy: set tls.acme_domain, tls.cert_path/key_path, \
             or behind_proxy",
        );
    }

    // Data directory and identity key.
    let dir = &cfg.data_dir;
    if !dir.is_dir() {
        r.push(
            "data_dir",
            Level::Fail,
            format!("{} does not exist (run `faro-server init`)", dir.display()),
        );
    } else {
        match foreign_access(dir) {
            Some(0) => r.push("data_dir", Level::Ok, format!("{} (0700)", dir.display())),
            Some(bits) => r.push(
                "data_dir",
                Level::Warn,
                format!(
                    "{} is accessible to group/others (mode bits {bits:o}); chmod 700 it",
                    dir.display()
                ),
            ),
            None => r.push("data_dir", Level::Fail, "cannot read permissions"),
        }
    }
    let key = dir.join(IDENTITY_FILE);
    match std::fs::metadata(&key) {
        Err(_) => r.push(
            "identity.key",
            Level::Fail,
            format!("{} missing (run `faro-server init`)", key.display()),
        ),
        Ok(m) if m.len() != 32 => r.push("identity.key", Level::Fail, "corrupt (not 32 bytes)"),
        Ok(_) => match foreign_access(&key) {
            Some(0) => r.push("identity.key", Level::Ok, "present, mode 0600"),
            Some(_) => r.push(
                "identity.key",
                Level::Fail,
                "readable by group/others: chmod 600 it (it is the instance's identity)",
            ),
            None => r.push("identity.key", Level::Fail, "cannot read permissions"),
        },
    }

    // Database.
    check_postgres(cfg, &mut r);
    check_database(cfg, &key, &mut r).await;

    // SMTP.
    if !cfg.smtp.is_configured() {
        r.push(
            "smtp",
            if cfg.dev { Level::Warn } else { Level::Fail },
            "not configured: sign-in links and alerts cannot be emailed",
        );
    } else {
        let host = cfg.smtp.host.clone().unwrap_or_default();
        let plain = cfg.smtp.tls == SmtpTls::None;
        match SmtpMailer::from_config(&cfg.smtp) {
            Err(e) => r.push("smtp", Level::Fail, e.to_string()),
            Ok(m) if check_smtp => {
                match tokio::time::timeout(Duration::from_secs(20), m.test_connection()).await {
                    Ok(Ok(())) if plain => r.push(
                        "smtp",
                        Level::Warn,
                        format!("{host} reachable, but without TLS"),
                    ),
                    Ok(Ok(())) => r.push("smtp", Level::Ok, format!("{host} reachable")),
                    Ok(Err(e)) => {
                        r.push("smtp", Level::Fail, format!("{host}: {} ({})", e, e.code()))
                    }
                    Err(_) => r.push("smtp", Level::Fail, format!("{host}: timed out")),
                }
            }
            Ok(_) => r.push(
                "smtp",
                Level::Ok,
                format!("configured for {host} (connection not tested)"),
            ),
        }
    }

    // Disk.
    let probe = if dir.is_dir() {
        dir.as_path()
    } else {
        Path::new(".")
    };
    match free_bytes(probe) {
        Some(b) if b < GIB / 2 => r.push(
            "disk",
            Level::Fail,
            format!("only {} MiB free", b / (1024 * 1024)),
        ),
        Some(b) if b < 2 * GIB => r.push(
            "disk",
            Level::Warn,
            format!("{:.1} GiB free", b as f64 / GIB as f64),
        ),
        Some(b) => r.push(
            "disk",
            Level::Ok,
            format!("{:.1} GiB free", b as f64 / GIB as f64),
        ),
        None => r.push("disk", Level::Warn, "could not determine free space"),
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    check_updates(cfg, now_ms, &mut r);

    r.push(
        "backups",
        Level::Ok,
        "not verifiable from here: schedule `faro-server backup --out …` and rotate copies",
    );
    r
}

/// The update mirror (§3.8, §9 "update freshness"): configured, refreshing,
/// and holding metadata clients will still accept.
pub fn check_updates(cfg: &Config, now_ms: i64, r: &mut Report) {
    let Some(root) = &cfg.updates.root else {
        r.push(
            "updates",
            Level::Warn,
            "off: clients get no updates through this instance (set updates.root)",
        );
        return;
    };
    match std::fs::read(root) {
        Err(e) => {
            r.push(
                "updates",
                Level::Fail,
                format!("cannot read root of trust {}: {e}", root.display()),
            );
            return;
        }
        Ok(b) => {
            if let Err(e) = faro_update::Updater::bootstrap(&b) {
                r.push(
                    "updates",
                    Level::Fail,
                    format!("{} is not a valid signed root: {e}", root.display()),
                );
                return;
            }
        }
    }
    let s = crate::updates::read_status(&cfg.data_dir.join(crate::updates::MIRROR_DIR));
    let error = s
        .last_error
        .as_deref()
        .map(|e| format!("; latest refresh failed: {e}"))
        .unwrap_or_default();
    let Some(expires) = s
        .timestamp_expires_ms
        .filter(|_| s.last_success_ms.is_some())
    else {
        r.push(
            "updates",
            Level::Warn,
            format!("no release mirrored yet{error}"),
        );
        return;
    };
    if expires <= now_ms {
        r.push(
            "updates",
            Level::Warn,
            format!(
                "the mirrored release metadata has expired, so clients will not update until \
                 the next successful refresh{error}"
            ),
        );
        return;
    }
    let summary = format!(
        "release metadata version {} ({} artifacts cached)",
        s.targets_version.unwrap_or(0),
        s.cached.len()
    );
    if error.is_empty() && s.failed.is_empty() {
        r.push("updates", Level::Ok, summary);
    } else if error.is_empty() {
        r.push(
            "updates",
            Level::Warn,
            format!("{summary}; not mirrored: {}", s.failed.join(", ")),
        );
    } else {
        r.push("updates", Level::Warn, format!("{summary}{error}"));
    }
}

/// Postgres is experimental and unsupported in the beta: a `WARN` line when
/// the database is Postgres, nothing for SQLite.
pub fn check_postgres(cfg: &Config, r: &mut Report) {
    if cfg.uses_postgres() {
        r.push("postgres", Level::Warn, POSTGRES_UNSUPPORTED);
    }
}

async fn check_database(cfg: &Config, key_path: &Path, r: &mut Report) {
    if cfg.database_url.is_none() && !cfg.data_dir.join("faro.db").is_file() {
        r.push(
            "database",
            Level::Fail,
            "SQLite database missing (run `faro-server init`)",
        );
        return;
    }
    let db = match tokio::time::timeout(Duration::from_secs(15), Db::connect(&cfg.database_url()))
        .await
    {
        Ok(Ok(db)) => db,
        Ok(Err(e)) => {
            r.push("database", Level::Fail, format!("cannot connect: {e}"));
            return;
        }
        Err(_) => {
            r.push("database", Level::Fail, "connection timed out");
            return;
        }
    };
    let backend = format!("{:?}", db.backend()).to_lowercase();
    let applied: Result<i64, sqlx::Error> = async {
        use sqlx::Row;
        sqlx::query("SELECT COUNT(*) AS n FROM _sqlx_migrations WHERE success = TRUE")
            .fetch_one(db.pool())
            .await?
            .try_get("n")
    }
    .await;
    let expected = crate::db::migrations::count(db.backend());
    match applied {
        Ok(n) if n >= expected => r.push(
            "database",
            Level::Ok,
            format!("{backend} reachable, schema up to date ({n} migrations)"),
        ),
        Ok(n) => r.push(
            "database",
            Level::Warn,
            format!("{backend} reachable; {n}/{expected} migrations (the rest apply at start)"),
        ),
        Err(e) => r.push("database", Level::Fail, format!("cannot query: {e}")),
    }
    match (instance::get(db.pool()).await, std::fs::read(key_path)) {
        (Ok(Some(row)), Ok(seed)) => match <[u8; 32]>::try_from(seed.as_slice()) {
            Ok(seed) => {
                let seed = faro_crypto::Zeroizing::new(seed);
                let pk = faro_crypto::SigningKey::from_bytes(&seed).public();
                if pk == row.identity_pubkey {
                    r.push(
                        "identity",
                        Level::Ok,
                        format!("instance {} matches identity.key", row.id),
                    );
                } else {
                    r.push(
                        "identity",
                        Level::Fail,
                        "identity.key does not match the database (wrong key or wrong database)",
                    );
                }
            }
            Err(_) => r.push("identity", Level::Fail, "identity.key is corrupt"),
        },
        (Ok(None), _) => r.push(
            "identity",
            Level::Fail,
            "no instance row (run `faro-server init`)",
        ),
        (Err(e), _) => r.push(
            "identity",
            Level::Fail,
            format!("cannot read instance: {e}"),
        ),
        (_, Err(_)) => {} // already reported above
    }
    match instance::settings_json(db.pool()).await {
        Ok(json) => {
            let stored = crate::settings::StoredSettings::from_json(&json).unwrap_or_default();
            match crate::settings::InstanceSettings::resolve(cfg, &stored) {
                Ok(s) => r.push(
                    "settings",
                    Level::Ok,
                    format!(
                        "registration {}, retention {}/{}/{} days (headers/blobs/alerts), \
                         liveness grace {} s",
                        s.registration.mode.as_str(),
                        s.retention.event_header_days,
                        s.retention.blob_days,
                        s.retention.alert_days,
                        s.liveness.grace_secs
                    ),
                ),
                Err(e) => r.push(
                    "settings",
                    Level::Warn,
                    format!("console settings conflict with the config file ({e}); the file wins"),
                ),
            }
        }
        Err(e) => r.push(
            "settings",
            Level::Fail,
            format!("cannot read settings: {e}"),
        ),
    }
    db.close().await;
}
