//! Instance configuration: `faro.toml` plus `FARO_*` environment overrides.
//!
//! Precedence (highest first): environment variables, the TOML file, built-in
//! defaults. Environment overrides exist because container deployments
//! (`docker compose`) are the primary install path for non-expert admins and
//! env vars are the idiom there; the TOML file is the idiom for a binary on a
//! Pi or VPS. Both are first-class.
//!
//! The parsed [`Config`] is validated once at startup ([`Config::validate`]) so
//! that a misconfiguration is a clear startup error rather than a confusing
//! runtime failure (e.g. insecure cookies on a non-HTTPS public URL).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Prefix for every environment override.
pub const ENV_PREFIX: &str = "FARO_";

/// Env vars with the prefix that are consumed elsewhere (CLI, logging) and
/// must not be reported as unknown.
const ENV_HANDLED_ELSEWHERE: &[&str] = &["FARO_CONFIG", "FARO_LOG"];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config file {path}: {source}")]
    Toml {
        path: PathBuf,
        /// Boxed: `toml::de::Error` is ~96 bytes, which made every
        /// `Result<_, ConfigError>` (and `CliError`) exceed clippy's
        /// `result_large_err` limit on Windows, where `PathBuf` is larger.
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("invalid value for {key}: {reason}")]
    Env { key: String, reason: String },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Who may create an account (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RegistrationMode {
    /// Accounts are created only by first-run setup or by invites (default).
    #[default]
    InviteOnly,
    /// Anyone whose email domain is on the allowlist may sign up with a magic link.
    Open,
    /// No new accounts at all; existing users can still sign in.
    Closed,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationMode::InviteOnly => "invite-only",
            RegistrationMode::Open => "open",
            RegistrationMode::Closed => "closed",
        }
    }
}

impl FromStr for RegistrationMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "invite-only" | "invite_only" | "invite" => Ok(Self::InviteOnly),
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "unknown registration mode {other:?} (expected invite-only, open or closed)"
            )),
        }
    }
}

/// SMTP transport security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpTls {
    /// STARTTLS on the submission port (587). The common case.
    #[default]
    Starttls,
    /// Implicit TLS (port 465).
    Tls,
    /// Plaintext. Only for a relay on localhost.
    None,
}

impl FromStr for SmtpTls {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::Starttls),
            "tls" => Ok(Self::Tls),
            "none" => Ok(Self::None),
            other => Err(format!(
                "unknown SMTP TLS mode {other:?} (expected starttls, tls or none)"
            )),
        }
    }
}

/// Outgoing mail settings. Consumed by the stage-B SMTP mailer.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// `From:` address, e.g. `"Faro <faro@church.example>"`.
    pub from: Option<String>,
    pub tls: SmtpTls,
}

impl SmtpConfig {
    pub fn is_configured(&self) -> bool {
        self.host.is_some() && self.from.is_some()
    }
}

impl fmt::Debug for SmtpConfig {
    // Hand-written so the password can never reach a log line via `{:?}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .field("tls", &self.tls)
            .finish()
    }
}

/// Retention windows (§8). Members may choose shorter, never longer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    pub event_header_days: u32,
    pub blob_days: u32,
    pub alert_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            event_header_days: 90,
            blob_days: 30,
            alert_days: 90,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistrationConfig {
    pub mode: RegistrationMode,
    /// Lowercase domains without `@`. `["*"]` allows any domain (must be explicit).
    pub allowed_email_domains: Vec<String>,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        RegistrationConfig {
            mode: RegistrationMode::InviteOnly,
            allowed_email_domains: Vec::new(),
        }
    }
}

impl RegistrationConfig {
    /// Whether an email address may self-register in `open` mode.
    pub fn domain_allowed(&self, email: &str) -> bool {
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        self.allowed_email_domains
            .iter()
            .any(|d| d == "*" || *d == domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LivenessConfig {
    /// How long a device may stay silent before allies get a missed-check-in alert.
    pub grace_secs: u64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        LivenessConfig {
            grace_secs: 3 * 3600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Sustained requests per minute per client IP on unauthenticated endpoints
    /// (setup, magic link, enrollment). The burst size equals this value.
    pub unauthenticated_per_minute: u32,
    /// Magic-link emails per address per hour, so the instance cannot be used
    /// to mail-bomb someone.
    pub magic_links_per_email_per_hour: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            unauthenticated_per_minute: 20,
            magic_links_per_email_per_hour: 5,
        }
    }
}

/// Limits on what one device (and one member) may push at the instance
/// (`[device_limits]`). Every limit is a token bucket whose burst equals its
/// per-period value, kept in memory per process like [`RateLimitConfig`].
///
/// Nothing a limit rejects is lost silently: excess alerts are folded into
/// one alert that counts them, and over-quota uploads raise an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceLimitsConfig {
    /// Event-batch and report requests per device per minute (HTTP 429).
    pub requests_per_minute: u32,
    /// Events per device per hour (HTTP 429 with `Retry-After`).
    pub events_per_device_per_hour: u32,
    /// Events per member per hour, across all of their devices.
    pub events_per_member_per_hour: u32,
    /// Reports per device per hour.
    pub reports_per_device_per_hour: u32,
    /// Alerts per device per hour; further alerts fold into one.
    pub alerts_per_device_per_hour: u32,
    /// Alerts per member per hour, across all of their devices.
    pub alerts_per_member_per_hour: u32,
    /// Repeats of one kind of rejected-upload alert (bad signature, fork,
    /// behind, bad report signature) and of quota alerts within this many
    /// seconds count on a single alert per device.
    pub alert_coalesce_secs: u64,
    /// At most one immediate email per recipient and member per this many
    /// seconds; whatever arrives meanwhile is sent together afterwards.
    /// 0 turns coalescing off: every alert is its own email.
    pub email_interval_secs: u64,
    /// Ciphertext a device may have stored (event bodies and reports), in
    /// MiB. Over it, new event bodies are not stored and new reports are
    /// refused, and allies get a `storage_quota` alert. 0 disables the quota.
    pub storage_quota_mib: u64,
}

impl Default for DeviceLimitsConfig {
    fn default() -> Self {
        DeviceLimitsConfig {
            requests_per_minute: 60,
            events_per_device_per_hour: 6_000,
            events_per_member_per_hour: 12_000,
            reports_per_device_per_hour: 24,
            alerts_per_device_per_hour: 30,
            alerts_per_member_per_hour: 60,
            alert_coalesce_secs: 3600,
            email_interval_secs: 60,
            storage_quota_mib: 2048,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InstanceConfig {
    /// Shown to clients at enrollment ("Enroll in *Grace Church Faro*?").
    pub name: String,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        InstanceConfig {
            name: "Faro".to_owned(),
        }
    }
}

/// Built-in HTTPS (§4.2 "Built-in ACME when given a domain").
///
/// Exactly one of three modes applies:
///
/// * `acme_domain` set: certificates are obtained and renewed automatically
///   from an ACME CA (Let's Encrypt by default) using the TLS-ALPN-01
///   challenge on the HTTPS port itself, so no port 80 listener is needed.
///   Certificates and the account key are cached in `<data_dir>/acme`.
/// * `cert_path` + `key_path` set: serve a static PEM certificate chain and
///   key (renewed by an external tool such as certbot; reloaded on restart).
/// * neither: plain HTTP, which is only acceptable with `--dev` or behind a
///   TLS-terminating proxy / tunnel (`--behind-proxy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub acme_domain: Option<String>,
    /// Contact email for the ACME account (expiry warnings from the CA).
    pub acme_contact: Option<String>,
    /// Use the CA's production directory. Set false to test against Let's
    /// Encrypt staging (untrusted certificates, generous rate limits).
    pub acme_production: bool,
    /// Override the ACME directory URL (another CA, or a test CA).
    pub acme_directory: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            acme_domain: None,
            acme_contact: None,
            acme_production: true,
            acme_directory: None,
            cert_path: None,
            key_path: None,
        }
    }
}

impl TlsConfig {
    /// Whether this server terminates TLS itself.
    pub fn enabled(&self) -> bool {
        self.acme_domain.is_some() || self.cert_path.is_some()
    }
}

/// The update mirror (§3.8, §4.1 item 7). See [`crate::updates`].
///
/// * `root` set, `upstream` set: the instance fetches signed releases from
///   the project and serves them to its clients.
/// * `root` set, no `upstream`: an air-gapped instance; releases are loaded
///   by hand with `faro-server updates import`.
/// * no `root`: the mirror is off and clients get no updates through this
///   instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdatesConfig {
    /// The project's root of trust: a signed root document
    /// (`1.root.json`), as shipped with the official container image and
    /// packages. The mirror only stores and serves what verifies against it.
    pub root: Option<PathBuf>,
    /// Base URL where the project publishes update metadata and artifacts.
    pub upstream: Option<String>,
    /// Seconds between checks of `upstream`.
    pub refresh_secs: u64,
    /// The release channel offered to this instance's clients: `stable`,
    /// `beta`, ... or the pin `stable-1` for managed fleets.
    pub channel: String,
}

/// Bounds on [`UpdatesConfig::refresh_secs`]. The project re-signs its
/// timestamp about daily, so checking less often than that would let
/// clients see expired metadata.
pub const MIN_UPDATE_REFRESH_SECS: u64 = 300;
pub const MAX_UPDATE_REFRESH_SECS: u64 = 6 * 3600;

impl Default for UpdatesConfig {
    fn default() -> Self {
        UpdatesConfig {
            root: None,
            upstream: None,
            refresh_secs: 3600,
            channel: faro_update::STABLE_CHANNEL.to_owned(),
        }
    }
}

/// Check an update channel string (a channel name or `stable-1`).
pub fn parse_update_channel(s: &str) -> Result<faro_update::Channel, ConfigError> {
    s.trim()
        .parse()
        .map_err(|e: faro_update::InvalidChannel| ConfigError::Invalid(e.to_string()))
}

/// The full server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where the identity key, SQLite database and blobs live.
    pub data_dir: PathBuf,
    /// `sqlite://…` or `postgres://…`. Defaults to `<data_dir>/faro.db`.
    /// The beta supports SQLite only: Postgres is experimental and
    /// unsupported, and `doctor` and `serve` warn about it.
    pub database_url: Option<String>,
    /// The externally visible base URL, e.g. `https://faro.example.org`.
    pub public_url: String,
    pub listen: SocketAddr,
    /// Trust `X-Forwarded-For` from the reverse proxy for client IPs.
    pub behind_proxy: bool,
    /// Development mode: allows `http://` public URLs, drops `Secure`/HSTS,
    /// and prints outgoing email (including login links) to stderr.
    pub dev: bool,
    pub instance: InstanceConfig,
    pub registration: RegistrationConfig,
    pub smtp: SmtpConfig,
    pub retention: RetentionConfig,
    pub liveness: LivenessConfig,
    pub rate_limit: RateLimitConfig,
    pub device_limits: DeviceLimitsConfig,
    pub tls: TlsConfig,
    pub updates: UpdatesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: PathBuf::from("./data"),
            database_url: None,
            public_url: "http://localhost:8080".to_owned(),
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            behind_proxy: false,
            dev: false,
            instance: InstanceConfig::default(),
            registration: RegistrationConfig::default(),
            smtp: SmtpConfig::default(),
            retention: RetentionConfig::default(),
            liveness: LivenessConfig::default(),
            rate_limit: RateLimitConfig::default(),
            device_limits: DeviceLimitsConfig::default(),
            tls: TlsConfig::default(),
            updates: UpdatesConfig::default(),
        }
    }
}

fn env_err(key: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Env {
        key: key.to_owned(),
        reason: reason.into(),
    }
}

fn parse_bool(key: &str, v: &str) -> Result<bool, ConfigError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(env_err(key, "expected true/false")),
    }
}

fn parse_num<T: FromStr>(key: &str, v: &str) -> Result<T, ConfigError> {
    v.trim()
        .parse()
        .map_err(|_| env_err(key, "expected a non-negative integer"))
}

fn non_empty(v: &str) -> Option<String> {
    let t = v.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

impl Config {
    /// Parse a TOML document.
    pub fn from_toml_str(s: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|source| ConfigError::Toml {
            path: path.to_owned(),
            source: Box::new(source),
        })
    }

    /// Load from an optional file, then apply overrides from `env`, then
    /// validate. `env` is passed in (rather than read from the process) so
    /// tests are hermetic; the CLI passes `std::env::vars()`.
    ///
    /// Returns the config and any unrecognised `FARO_*` variable names, which
    /// the caller should warn about (a typo there silently ignored would be a
    /// nasty surprise for an admin).
    pub fn load<I>(path: Option<&Path>, env: I) -> Result<(Self, Vec<String>), ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|source| ConfigError::Io {
                    path: p.to_owned(),
                    source,
                })?;
                Self::from_toml_str(&text, p)?
            }
            None => Config::default(),
        };
        let unknown = cfg.apply_env(env)?;
        cfg.validate()?;
        Ok((cfg, unknown))
    }

    /// Apply `FARO_*` overrides. Returns unrecognised variable names.
    pub fn apply_env<I>(&mut self, env: I) -> Result<Vec<String>, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut unknown = Vec::new();
        for (key, val) in env {
            let Some(name) = key.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let k = key.as_str();
            match name {
                "DATABASE_URL" => self.database_url = non_empty(&val),
                "DATA_DIR" => self.data_dir = PathBuf::from(val.trim()),
                "PUBLIC_URL" => self.public_url = val.trim().to_owned(),
                "LISTEN" => {
                    self.listen = val
                        .trim()
                        .parse()
                        .map_err(|_| env_err(k, "expected host:port, e.g. 0.0.0.0:8080"))?
                }
                "BEHIND_PROXY" => self.behind_proxy = parse_bool(k, &val)?,
                "DEV" => self.dev = parse_bool(k, &val)?,
                "INSTANCE_NAME" => self.instance.name = val.trim().to_owned(),
                "SMTP_HOST" => self.smtp.host = non_empty(&val),
                "SMTP_PORT" => self.smtp.port = Some(parse_num(k, &val)?),
                "SMTP_USERNAME" => self.smtp.username = non_empty(&val),
                "SMTP_PASSWORD" => self.smtp.password = non_empty(&val),
                "SMTP_FROM" => self.smtp.from = non_empty(&val),
                "SMTP_TLS" => self.smtp.tls = val.parse().map_err(|e: String| env_err(k, e))?,
                "RETENTION_EVENT_HEADER_DAYS" => {
                    self.retention.event_header_days = parse_num(k, &val)?
                }
                "RETENTION_BLOB_DAYS" => self.retention.blob_days = parse_num(k, &val)?,
                "RETENTION_ALERT_DAYS" => self.retention.alert_days = parse_num(k, &val)?,
                "LIVENESS_GRACE_SECS" => self.liveness.grace_secs = parse_num(k, &val)?,
                "REGISTRATION_MODE" => {
                    self.registration.mode = val.parse().map_err(|e: String| env_err(k, e))?
                }
                "ALLOWED_EMAIL_DOMAINS" => {
                    self.registration.allowed_email_domains =
                        val.split(',').filter_map(non_empty).collect::<Vec<_>>()
                }
                "TLS_ACME_DOMAIN" => self.tls.acme_domain = non_empty(&val),
                "TLS_ACME_CONTACT" => self.tls.acme_contact = non_empty(&val),
                "TLS_ACME_PRODUCTION" => self.tls.acme_production = parse_bool(k, &val)?,
                "TLS_CERT_PATH" => self.tls.cert_path = non_empty(&val).map(PathBuf::from),
                "TLS_KEY_PATH" => self.tls.key_path = non_empty(&val).map(PathBuf::from),
                "UPDATES_ROOT" => self.updates.root = non_empty(&val).map(PathBuf::from),
                "UPDATES_UPSTREAM" => self.updates.upstream = non_empty(&val),
                "UPDATES_REFRESH_SECS" => self.updates.refresh_secs = parse_num(k, &val)?,
                "UPDATES_CHANNEL" => self.updates.channel = val.trim().to_owned(),
                "RATE_LIMIT_PER_MINUTE" => {
                    self.rate_limit.unauthenticated_per_minute = parse_num(k, &val)?
                }
                "DEVICE_EVENTS_PER_HOUR" => {
                    self.device_limits.events_per_device_per_hour = parse_num(k, &val)?
                }
                "DEVICE_ALERTS_PER_HOUR" => {
                    self.device_limits.alerts_per_device_per_hour = parse_num(k, &val)?
                }
                "EMAIL_INTERVAL_SECS" => {
                    self.device_limits.email_interval_secs = parse_num(k, &val)?
                }
                "DEVICE_STORAGE_QUOTA_MIB" => {
                    self.device_limits.storage_quota_mib = parse_num(k, &val)?
                }
                _ if ENV_HANDLED_ELSEWHERE.contains(&k) => {}
                _ => unknown.push(key.clone()),
            }
        }
        Ok(unknown)
    }

    /// Normalise and check the configuration. Idempotent.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let invalid = |m: String| Err(ConfigError::Invalid(m));

        // public_url: scheme://host[:port][/path], no query/fragment, no trailing '/'.
        let url = self.public_url.trim().trim_end_matches('/').to_owned();
        let rest = if let Some(r) = url.strip_prefix("https://") {
            r
        } else if let Some(r) = url.strip_prefix("http://") {
            if !self.dev {
                return invalid(format!(
                    "public_url {url:?} must use https:// (session cookies are Secure); \
                     use dev = true only for local development"
                ));
            }
            r
        } else {
            return invalid(format!("public_url {url:?} must start with https://"));
        };
        if rest.is_empty()
            || rest.starts_with('/')
            || rest.contains(['?', '#', '@', ' '])
            || rest.chars().any(|c| c.is_control())
        {
            return invalid(format!("public_url {url:?} is not a valid base URL"));
        }
        self.public_url = url;

        if self.data_dir.as_os_str().is_empty() {
            return invalid("data_dir must not be empty".into());
        }
        if let Some(db) = &self.database_url {
            if !(db.starts_with("sqlite:")
                || db.starts_with("postgres://")
                || db.starts_with("postgresql://"))
            {
                return invalid(
                    "database_url must start with sqlite:, postgres:// or postgresql://".into(),
                );
            }
        }

        let name = self.instance.name.trim();
        if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
            return invalid("instance.name must be 1-80 printable characters".into());
        }
        self.instance.name = name.to_owned();

        let mut domains = Vec::new();
        for d in &self.registration.allowed_email_domains {
            let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
            if d.is_empty() {
                continue;
            }
            if d != "*"
                && !d
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return invalid(format!("allowed_email_domains entry {d:?} is not a domain"));
            }
            domains.push(d);
        }
        self.registration.allowed_email_domains = domains;
        if self.registration.mode == RegistrationMode::Open
            && self.registration.allowed_email_domains.is_empty()
        {
            return invalid(
                "registration mode \"open\" needs allowed_email_domains; \
                 use [\"*\"] to explicitly allow any domain"
                    .into(),
            );
        }

        let r = &self.retention;
        if r.event_header_days == 0 || r.blob_days == 0 || r.alert_days == 0 {
            return invalid("retention periods must be at least 1 day".into());
        }
        if self.liveness.grace_secs < 600 {
            return invalid(
                "liveness.grace_secs must be at least 600 (devices heartbeat every 5 minutes)"
                    .into(),
            );
        }
        self.validate_smtp()?;
        self.validate_tls()?;
        self.validate_updates()?;
        if self.rate_limit.unauthenticated_per_minute == 0
            || self.rate_limit.magic_links_per_email_per_hour == 0
        {
            return invalid("rate limits must be at least 1".into());
        }
        let d = &self.device_limits;
        if d.requests_per_minute == 0
            || d.events_per_device_per_hour == 0
            || d.events_per_member_per_hour == 0
            || d.reports_per_device_per_hour == 0
            || d.alerts_per_device_per_hour == 0
            || d.alerts_per_member_per_hour == 0
            || d.alert_coalesce_secs == 0
        {
            return invalid("device_limits values must be at least 1".into());
        }
        Ok(())
    }

    fn validate_smtp(&self) -> Result<(), ConfigError> {
        let s = &self.smtp;
        if s.host.is_some() != s.from.is_some() {
            return Err(ConfigError::Invalid(
                "smtp.host and smtp.from must be set together".into(),
            ));
        }
        if s.username.is_some() != s.password.is_some() {
            return Err(ConfigError::Invalid(
                "smtp.username and smtp.password must be set together".into(),
            ));
        }
        if let Some(host) = &s.host {
            if host.trim().is_empty() || host.chars().any(|c| c.is_whitespace() || c == '/') {
                return Err(ConfigError::Invalid("smtp.host is not a host name".into()));
            }
            // Plaintext SMTP would send sign-in links and passwords in the
            // clear; only a relay on this machine (or --dev) may use it.
            if s.tls == SmtpTls::None && !self.dev && !is_loopback_host(host) {
                return Err(ConfigError::Invalid(
                    "smtp.tls = \"none\" is only allowed for a relay on localhost \
                     (use starttls or tls)"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_tls(&mut self) -> Result<(), ConfigError> {
        let invalid = |m: &str| Err(ConfigError::Invalid(m.to_owned()));
        let t = &mut self.tls;
        if t.cert_path.is_some() != t.key_path.is_some() {
            return invalid("tls.cert_path and tls.key_path must be set together");
        }
        if t.acme_domain.is_some() && t.cert_path.is_some() {
            return invalid("set either tls.acme_domain or tls.cert_path/key_path, not both");
        }
        if let Some(d) = &t.acme_domain {
            let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
            let host = public_url_host(&self.public_url);
            if d.is_empty()
                || !d.contains('.')
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return invalid("tls.acme_domain is not a domain name");
            }
            // The certificate must be for the name clients use.
            if host.as_deref() != Some(d.as_str()) {
                return invalid("tls.acme_domain must be the host of public_url");
            }
            t.acme_domain = Some(d);
        }
        if t.enabled() && self.behind_proxy {
            return invalid(
                "behind_proxy and built-in TLS are mutually exclusive \
                 (the proxy terminates TLS)",
            );
        }
        Ok(())
    }

    fn validate_updates(&mut self) -> Result<(), ConfigError> {
        let invalid = |m: String| Err(ConfigError::Invalid(m));
        let dev = self.dev;
        let u = &mut self.updates;
        u.channel = parse_update_channel(&u.channel)?.to_string();
        if !(MIN_UPDATE_REFRESH_SECS..=MAX_UPDATE_REFRESH_SECS).contains(&u.refresh_secs) {
            return invalid(format!(
                "updates.refresh_secs must be from {MIN_UPDATE_REFRESH_SECS} to \
                 {MAX_UPDATE_REFRESH_SECS}"
            ));
        }
        if let Some(up) = &u.upstream {
            let up = up.trim().trim_end_matches('/').to_owned();
            let rest = match (up.strip_prefix("https://"), up.strip_prefix("http://")) {
                (Some(r), _) => r,
                (None, Some(r)) if dev => r,
                (None, Some(_)) => {
                    return invalid(format!(
                        "updates.upstream {up:?} must use https:// (dev = true allows http://)"
                    ))
                }
                _ => return invalid(format!("updates.upstream {up:?} must start with https://")),
            };
            if rest.is_empty()
                || rest.starts_with('/')
                || rest.contains(['?', '#', '@', ' '])
                || rest.chars().any(|c| c.is_control())
            {
                return invalid(format!("updates.upstream {up:?} is not a valid base URL"));
            }
            if u.root.is_none() {
                return invalid(
                    "updates.upstream needs updates.root: the mirror only serves releases \
                     it can verify against the project's root of trust"
                        .into(),
                );
            }
            u.upstream = Some(up);
        }
        Ok(())
    }

    /// The effective database URL (SQLite under `data_dir` unless overridden).
    pub fn database_url(&self) -> String {
        match &self.database_url {
            Some(u) => u.clone(),
            None => sqlite_url_for(&self.data_dir.join("faro.db")),
        }
    }

    /// Whether the database is Postgres, which this release doesn't support
    /// ([`crate::db::POSTGRES_UNSUPPORTED`]).
    pub fn uses_postgres(&self) -> bool {
        crate::db::Backend::from_url(&self.database_url()) == Some(crate::db::Backend::Postgres)
    }

    /// Whether cookies get `Secure` and responses get HSTS.
    pub fn secure_cookies(&self) -> bool {
        !self.dev
    }
}

/// Whether `host` names this machine (for the plaintext-SMTP exception).
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The lowercase host part of a validated public URL (no port).
pub fn public_url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split('/').next()?;
    let host = if authority.starts_with('[') {
        authority.split(']').next().map(|h| format!("{h}]"))?
    } else {
        authority.split(':').next()?.to_owned()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Build a SQLite URL that creates the file if missing.
///
/// sqlx's `Any` driver runs the URL through `Url::parse` before SQLite sees
/// it, so the form matters. An absolute Unix path uses `sqlite:///abs`. A
/// Windows path must not: `sqlite://C:\\…` parses `C` as a host and the rest
/// as a port, and connecting fails with `InvalidPort`. Every other path
/// (drive letters, UNC, relative) uses the authority-less `sqlite:<path>`.
/// sqlx's SQLite parser strips either prefix, so both forms name the same file.
pub fn sqlite_url_for(path: &Path) -> String {
    let mut encoded = String::new();
    for ch in path.to_string_lossy().chars() {
        match ch {
            '%' => encoded.push_str("%25"),
            '?' => encoded.push_str("%3F"),
            '#' => encoded.push_str("%23"),
            ' ' => encoded.push_str("%20"),
            c => encoded.push(c),
        }
    }
    if encoded.starts_with('/') {
        format!("sqlite://{encoded}?mode=rwc")
    } else {
        format!("sqlite:{encoded}?mode=rwc")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_fail_without_https_unless_dev() {
        let mut c = Config::default();
        assert!(c.validate().is_err());
        c.dev = true;
        c.validate().unwrap();
    }

    #[test]
    fn env_overrides_toml() {
        let toml = r#"
            public_url = "https://faro.example.org/"
            [registration]
            mode = "closed"
        "#;
        let mut c = Config::from_toml_str(toml, Path::new("x")).unwrap();
        let unknown = c
            .apply_env(env(&[
                ("FARO_REGISTRATION_MODE", "open"),
                ("FARO_ALLOWED_EMAIL_DOMAINS", "@College.edu, example.org"),
                ("FARO_LISTEN", "0.0.0.0:9000"),
                ("FARO_BEHIND_PROXY", "yes"),
                ("FARO_SMTP_USERNAME", "faro"),
                ("FARO_SMTP_PASSWORD", "hunter2"),
                ("FARO_TYPO", "1"),
                ("FARO_CONFIG", "/etc/faro.toml"),
                ("HOME", "/root"),
            ]))
            .unwrap();
        assert_eq!(unknown, vec!["FARO_TYPO".to_owned()]);
        c.validate().unwrap();
        assert_eq!(c.public_url, "https://faro.example.org");
        assert_eq!(c.registration.mode, RegistrationMode::Open);
        assert_eq!(
            c.registration.allowed_email_domains,
            vec!["college.edu", "example.org"]
        );
        assert!(c.behind_proxy);
        assert_eq!(c.listen.port(), 9000);
        assert!(c.registration.domain_allowed("Sam@COLLEGE.edu"));
        assert!(!c.registration.domain_allowed("sam@evil.edu"));
        assert!(!c.registration.domain_allowed("college.edu"));
    }

    #[test]
    fn smtp_password_never_debug_printed() {
        let mut c = Config::default();
        c.smtp.password = Some("hunter2".into());
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn open_mode_requires_explicit_domains() {
        let mut c = Config {
            dev: true,
            ..Config::default()
        };
        c.registration.mode = RegistrationMode::Open;
        assert!(c.validate().is_err());
        c.registration.allowed_email_domains = vec!["*".into()];
        c.validate().unwrap();
        assert!(c.registration.domain_allowed("a@anything.example"));
    }

    #[test]
    fn rejects_bad_values() {
        let mut c = Config::default();
        assert!(c.apply_env(env(&[("FARO_DEV", "maybe")])).is_err());
        assert!(c
            .apply_env(env(&[("FARO_LIVENESS_GRACE_SECS", "-1")]))
            .is_err());
        assert!(c
            .apply_env(env(&[("FARO_REGISTRATION_MODE", "anyone")]))
            .is_err());
        let mut c = Config {
            dev: true,
            public_url: "https://user@host".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err());
        let mut c = Config {
            dev: true,
            database_url: Some("mysql://x".into()),
            ..Config::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn smtp_plaintext_only_for_loopback() {
        let base = || {
            let mut c = Config {
                public_url: "https://faro.example.org".into(),
                ..Config::default()
            };
            c.smtp.host = Some("smtp.example.org".into());
            c.smtp.from = Some("Faro <faro@example.org>".into());
            c
        };
        let mut c = base();
        c.validate().unwrap();
        c.smtp.tls = SmtpTls::None;
        assert!(c.validate().is_err());
        let mut c = base();
        c.smtp.tls = SmtpTls::None;
        c.smtp.host = Some("127.0.0.1".into());
        c.validate().unwrap();
        let mut c = base();
        c.smtp.from = None;
        assert!(c.validate().is_err(), "host without from");
        let mut c = base();
        c.smtp.username = Some("u".into());
        assert!(c.validate().is_err(), "username without password");
    }

    #[test]
    fn tls_modes_are_exclusive_and_match_public_url() {
        let base = || Config {
            public_url: "https://Faro.Example.org:8443/".into(),
            ..Config::default()
        };
        let mut c = base();
        c.tls.acme_domain = Some("faro.example.org".into());
        c.validate().unwrap();
        assert!(c.tls.enabled());
        let mut c = base();
        c.tls.acme_domain = Some("other.example.org".into());
        assert!(c.validate().is_err(), "domain must match public_url");
        let mut c = base();
        c.tls.acme_domain = Some("faro.example.org".into());
        c.tls.cert_path = Some("c.pem".into());
        c.tls.key_path = Some("k.pem".into());
        assert!(c.validate().is_err(), "acme and static are exclusive");
        let mut c = base();
        c.tls.cert_path = Some("c.pem".into());
        assert!(c.validate().is_err(), "cert without key");
        let mut c = base();
        c.tls.cert_path = Some("c.pem".into());
        c.tls.key_path = Some("k.pem".into());
        c.behind_proxy = true;
        assert!(c.validate().is_err(), "proxy and built-in TLS");
        assert_eq!(
            public_url_host("https://[::1]:8443/x").as_deref(),
            Some("[::1]")
        );
    }

    #[test]
    fn unknown_toml_keys_are_rejected() {
        assert!(Config::from_toml_str("pubilc_url = \"x\"", Path::new("x")).is_err());
    }

    /// Parse `url` exactly as `db::Db::connect` does (`Any`, then SQLite).
    fn sqlite_filename_via_any(url: &str) -> PathBuf {
        use sqlx::ConnectOptions;
        use std::str::FromStr;
        let any = sqlx::any::AnyConnectOptions::from_str(url).expect("Any parses the URL");
        sqlx::sqlite::SqliteConnectOptions::from_url(&any.database_url)
            .expect("SQLite parses the URL")
            .get_filename()
            .to_path_buf()
    }

    #[test]
    fn sqlite_url_round_trips_through_the_any_driver() {
        // A Windows drive path, a UNC path, and a Unix path with characters
        // that need escaping. On Unix the first two are just odd relative
        // filenames, so this checks the Windows URL form on every platform.
        for p in [
            r"C:\Users\runneradmin\AppData\Local\Temp\.tmpX\faro.db",
            r"\\server\share\faro\faro.db",
            "/tmp/my dir/faro?#%.db",
        ] {
            let url = sqlite_url_for(Path::new(p));
            assert_eq!(sqlite_filename_via_any(&url), Path::new(p), "{url}");
        }
    }

    #[test]
    fn sqlite_url_escapes_path() {
        assert_eq!(
            sqlite_url_for(Path::new("/tmp/my dir/faro?.db")),
            "sqlite:///tmp/my%20dir/faro%3F.db?mode=rwc"
        );
    }

    #[test]
    fn updates_validation() {
        let base = || Config {
            public_url: "https://faro.example.org".into(),
            ..Config::default()
        };
        let mut c = base();
        c.apply_env(env(&[
            ("FARO_UPDATES_ROOT", "/usr/share/faro/update-root.json"),
            ("FARO_UPDATES_UPSTREAM", "https://updates.example.org/faro/"),
            ("FARO_UPDATES_REFRESH_SECS", "1800"),
            ("FARO_UPDATES_CHANNEL", " stable-1 "),
        ]))
        .unwrap();
        c.validate().unwrap();
        assert_eq!(
            c.updates.upstream.as_deref(),
            Some("https://updates.example.org/faro")
        );
        assert_eq!(c.updates.channel, "stable-1");
        assert_eq!(c.updates.refresh_secs, 1800);

        let bad: [fn(&mut Config); 6] = [
            // An upstream the mirror couldn't verify.
            |c| c.updates.upstream = Some("https://u.example.org".into()),
            // Plain HTTP outside dev mode.
            |c| {
                c.updates.root = Some("/r.json".into());
                c.updates.upstream = Some("http://u.example.org".into());
            },
            |c| {
                c.updates.root = Some("/r.json".into());
                c.updates.upstream = Some("https://user@u.example.org".into());
            },
            |c| c.updates.channel = "stable-2".into(),
            |c| c.updates.refresh_secs = MIN_UPDATE_REFRESH_SECS - 1,
            |c| c.updates.refresh_secs = MAX_UPDATE_REFRESH_SECS + 1,
        ];
        for (i, tweak) in bad.into_iter().enumerate() {
            let mut c = base();
            tweak(&mut c);
            assert!(c.validate().is_err(), "case {i} should be rejected");
        }

        // Air-gapped: a root without an upstream. Dev mode allows http.
        let mut c = base();
        c.updates.root = Some("/r.json".into());
        c.validate().unwrap();
        c.dev = true;
        c.updates.upstream = Some("http://127.0.0.1:9000".into());
        c.validate().unwrap();
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../faro.example.toml");
        let mut c = Config::from_toml_str(text, Path::new("faro.example.toml")).unwrap();
        c.validate().unwrap();
    }
}
