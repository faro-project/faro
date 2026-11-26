//! `faro-service diagnose`: a problem report a member can send.
//!
//! [`collect`] gathers what helps debug a problem into a [`Report`]: the
//! `status` output, versions, the macOS version and hardware model, the
//! launchd jobs' state, the package receipt, the installed files and the
//! socket and state directories (names and permissions only), the
//! configuration and the last lines of the service's and the member's
//! agent's logs. Every file passes through a [`Redactor`] when it is made
//! (no other constructor exists), which takes out URLs, email addresses,
//! host names other than the instance's and the values of private log
//! fields such as window titles ([`redact`]).
//!
//! **Never in a report:** the device key or any other key, tokens, the
//! enrollment and endorsement records, the outbox (events, reports,
//! thumbnails), frames, or another account's agent log. Nothing reads
//! the state directory's files except the status the service writes and
//! the update installer's log: it is listed by name and size only.
//! (`config.txt` is `service.toml` as the service reads it, which can
//! hold `[member_settings]`: the capture interval and the like, which
//! allies see anyway.)
//!
//! The CLI shows the member what is in the report and writes it only
//! once they say so ([`Report::summary`], [`Report::full_text`]);
//! [`write_zip`] then writes `faro-report-<time>.zip` (macOS: `ditto`;
//! Windows: a stored zip built in memory, `zipw`) to their Desktop.
//!
//! **Windows.** The command runs in an elevated terminal; the Windows
//! counterparts of the macOS sources (the Service Control Manager's state,
//! the login sessions, the installed product, each signed-in account's
//! agent log) are in `windows`. The report goes to the Desktop of the
//! account whose elevated token runs it, and nothing is written by default
//! when that is LocalSystem (`--output` names a folder then).
//!
//! **Reading as root, for an account.** The agent log lives in the
//! member's home, which they control, so it is opened without following a
//! symbolic link and read only if it is a regular file the account owns:
//! a link to the device key, say, is refused. The report is written the
//! same way: to a new file (never over an existing one or through a
//! link), in a Desktop folder the account owns, and then given to the
//! account.

pub mod redact;
#[cfg(windows)]
mod windows;
#[cfg(any(windows, test))]
mod zipw;

pub use redact::Redactor;

use crate::config::Config;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// Lines from the end of each log, unless `--lines` says otherwise.
pub const DEFAULT_LINES: usize = 2000;

/// Lines from the end of the update installer's log.
const UPDATE_LOG_LINES: usize = 300;

/// The most read from the end of one log file. A log rotates at 5 MiB.
const MAX_LOG_READ: u64 = 8 * 1024 * 1024;

/// One log a report takes its last lines from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSource {
    /// The current file; rotated ones are `<path>.1` … `<path>.<keep>`.
    pub path: PathBuf,
    /// Rotated files to look in when the current one is short.
    pub keep: u32,
    /// The only owner a file is read from (Unix). `None` takes any.
    pub owner: Option<u32>,
}

/// The account whose agent log goes in the report and on whose Desktop it
/// lands: the one running `sudo`, or else the one at the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// What [`collect`] reads.
#[derive(Debug, Clone)]
pub struct Sources {
    /// The config file the service was loaded from (named in the report).
    pub config_file: PathBuf,
    pub service_log: Option<LogSource>,
    /// Agent logs, each with the account it belongs to: the member's on
    /// macOS, every signed-in account's on Windows.
    pub agent_logs: Vec<(String, LogSource)>,
    /// Lines from the end of each log.
    pub lines: usize,
    /// Directories listed by name, size and permissions only.
    pub listings: Vec<PathBuf>,
    /// Ask the system (macOS: `sw_vers`, `sysctl`, `launchctl`,
    /// `pkgutil`, `codesign`; Windows: the registry, the Service Control
    /// Manager, the session list). Off in tests.
    pub system: bool,
    /// The uid whose launchd session the agent's job is looked up in.
    pub agent_uid: Option<u32>,
    /// Why some agent logs are missing (Windows), shown in the README.
    pub agent_log_notes: String,
}

impl Sources {
    /// What the packaged service on this computer reads, for `member`.
    pub fn installed(
        config: &Config,
        config_file: PathBuf,
        member: Option<&Member>,
        lines: usize,
    ) -> Sources {
        let mut listings = vec![config.state_dir.clone()];
        if let Some(dir) = config.ipc.socket_path.parent() {
            listings.push(dir.to_path_buf());
        }
        #[allow(unused_mut)]
        let mut s = Sources {
            config_file,
            service_log: None,
            agent_logs: Vec::new(),
            lines,
            listings,
            system: cfg!(any(target_os = "macos", windows)),
            agent_uid: member.map(|m| m.uid),
            agent_log_notes: String::new(),
        };
        #[cfg(target_os = "macos")]
        {
            use faro_platform_macos::pkg_layout as layout;
            s.service_log = Some(LogSource {
                path: layout::SERVICE_LOG.into(),
                keep: layout::LOG_KEEP,
                owner: Some(0),
            });
            if let Some(m) = member {
                s.agent_logs.push((
                    m.name.clone(),
                    LogSource {
                        path: layout::agent_log(&m.home),
                        keep: layout::LOG_KEEP,
                        owner: Some(m.uid),
                    },
                ));
                s.listings.push(m.home.join(layout::AGENT_LOG_DIR_IN_HOME));
            }
            s.listings.push(layout::LOG_DIR.into());
            s.listings.push("/Library/Faro".into());
            s.listings.push("/Library/Faro/bin".into());
            s.listings.push("/Library/Faro/models/opennsfw".into());
            s.listings.push("/Library/Faro/domains".into());
        }
        #[cfg(windows)]
        {
            use faro_platform_windows::layout;
            let _ = member;
            s.service_log = Some(LogSource {
                path: layout::SERVICE_LOG.into(),
                keep: layout::LOG_KEEP,
                owner: None,
            });
            let (logs, dirs, notes) = windows::agent_logs();
            s.agent_logs = logs;
            s.agent_log_notes = notes;
            s.listings.extend(dirs);
            s.listings.push(layout::LOG_DIR.into());
            s.listings.push(layout::PROGRAM_DIR.into());
            s.listings.push(layout::NOTICES_DIR.into());
        }
        s
    }
}

/// One file in a report. Its text is redacted when it is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFile {
    /// Its path in the report (`logs/faro-service.log`).
    pub name: String,
    /// What it is, for the member.
    pub about: String,
    text: String,
}

impl ReportFile {
    /// Plain text: the status, command output, listings.
    pub fn text(name: &str, about: impl Into<String>, raw: &str, r: &Redactor) -> Self {
        ReportFile {
            name: name.to_owned(),
            about: about.into(),
            text: r.text(raw),
        }
    }

    /// A log written by `tracing_subscriber` ([`Redactor::log`]).
    pub fn log(name: &str, about: impl Into<String>, raw: &str, r: &Redactor) -> Self {
        ReportFile {
            name: name.to_owned(),
            about: about.into(),
            text: r.log(raw),
        }
    }

    /// The redacted text, exactly as it is written.
    pub fn contents(&self) -> &str {
        &self.text
    }
}

/// A problem report: a folder of text files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The folder's (and the zip's) name: `faro-report-20261125-101500Z`.
    pub name: String,
    /// The instance's host name, the one host the report keeps.
    pub instance_host: Option<String>,
    pub files: Vec<ReportFile>,
    /// When it was made, ms since the epoch (the zip's file times).
    pub made_ms: i64,
}

impl Report {
    /// The file named `name`.
    pub fn file(&self, name: &str) -> Option<&ReportFile> {
        self.files.iter().find(|f| f.name == name)
    }

    /// What the member sees before anything is written: each file, its
    /// size and what it is, and what was taken out.
    pub fn summary(&self) -> String {
        let mut o = String::new();
        let width = self.files.iter().map(|f| f.name.len()).max().unwrap_or(0);
        for f in &self.files {
            let _ = writeln!(
                o,
                "  {:width$}  {:>7}  {}",
                f.name,
                size(f.text.len()),
                f.about
            );
        }
        let _ = writeln!(o);
        let _ = writeln!(o, "{}", taken_out(self.instance_host.as_deref()));
        o
    }

    /// Everything in the report, file after file.
    pub fn full_text(&self) -> String {
        let mut o = String::new();
        for f in &self.files {
            let _ = writeln!(o, "===== {} ({}) =====", f.name, f.about);
            o.push_str(&f.text);
            if !f.text.ends_with('\n') {
                o.push('\n');
            }
            o.push('\n');
        }
        o
    }
}

fn taken_out(instance_host: Option<&str>) -> String {
    let keep = instance_host.map_or_else(String::new, |h| format!(" (except your instance, {h})"));
    let never = if cfg!(windows) {
        "keys, tokens, the outbox (events and reports), screenshots or thumbnails"
    } else {
        "keys, tokens, the outbox (events and reports), screenshots, thumbnails, or other \
         accounts' logs"
    };
    format!(
        "Taken out of every file: web addresses, email addresses, host names and IP addresses{keep}, \
         window titles, app names and other private values in the logs, and other libraries' \
         debug output. Never in the report: {never}."
    )
}

fn size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

/// Gather a report at `now_ms` ([module docs](self)).
pub fn collect(config: &Config, sources: &Sources, now_ms: i64) -> Report {
    let view = crate::status_view::gather(config, now_ms);
    let instance_host = view
        .as_ref()
        .ok()
        .and_then(|v| v.enrollment.as_ref())
        .and_then(|e| url::Url::parse(&e.instance_url).ok())
        .and_then(|u| u.host_str().map(str::to_owned));
    let r = Redactor::new(instance_host.as_deref());
    let name = format!("faro-report-{}", compact_utc(now_ms));
    let mut files = Vec::new();

    files.push(ReportFile::text(
        "README.txt",
        "what this report is",
        &readme(now_ms, sources, instance_host.as_deref()),
        &r,
    ));
    match &view {
        Ok(v) => {
            files.push(ReportFile::text(
                "status.txt",
                "what `faro-service status` shows",
                &v.text(now_ms),
                &r,
            ));
            let json = serde_json::to_string_pretty(v).unwrap_or_else(|e| e.to_string());
            files.push(ReportFile::text(
                "status.json",
                "the same, as `status --json`",
                &json,
                &r,
            ));
            if cfg!(not(windows)) {
                files.push(ReportFile::text(
                    "permissions.txt",
                    "Screen Recording and Accessibility, as the agent reported them",
                    &permissions(v),
                    &r,
                ));
            }
        }
        Err(e) => files.push(ReportFile::text(
            "status.txt",
            "why the status couldn't be read",
            &format!("The status could not be read: {e}\n"),
            &r,
        )),
    }
    files.push(ReportFile::text(
        "system.txt",
        if cfg!(windows) {
            "versions, Windows version, hardware model, disk space"
        } else {
            "versions, macOS version, hardware model, disk space"
        },
        &system(sources, view.as_ref().ok()),
        &r,
    ));
    if sources.system && cfg!(windows) {
        files.push(ReportFile::text(
            "service.txt",
            "whether the Faro service is running, and the login sessions and their agents",
            &service_windows(),
            &r,
        ));
        files.push(ReportFile::text(
            "package.txt",
            "the installed product's version and the programs' signatures",
            &package(),
            &r,
        ));
    } else if sources.system {
        files.push(ReportFile::text(
            "launchd.txt",
            "whether the service and agent jobs are loaded, running or disabled",
            &launchd(sources.agent_uid),
            &r,
        ));
        files.push(ReportFile::text(
            "package.txt",
            "the installer's receipt and the programs' code signatures",
            &package(),
            &r,
        ));
    }
    files.push(ReportFile::text(
        "files.txt",
        "names, sizes and permissions in Faro's folders, never what is in the files",
        &listings(&sources.listings, &sources.config_file),
        &r,
    ));
    let config_text = toml::to_string_pretty(config).unwrap_or_else(|e| e.to_string());
    files.push(ReportFile::text(
        "config.txt",
        "the service's settings",
        &format!(
            "# {}, as the service reads it\n{config_text}",
            sources.config_file.display()
        ),
        &r,
    ));
    if let Some(src) = &sources.service_log {
        files.push(ReportFile::log(
            "logs/faro-service.log",
            format!("the last {} lines of the service's log", sources.lines),
            &tail_text(src, sources.lines),
            &r,
        ));
    }
    for (account, src) in &sources.agent_logs {
        let name = if sources.agent_logs.len() == 1 {
            "logs/faro-agent.log".to_owned()
        } else {
            format!("logs/faro-agent-{}.log", file_part(account))
        };
        files.push(ReportFile::log(
            &name,
            format!("the last {} lines of {account}'s agent log", sources.lines),
            &tail_text(src, sources.lines),
            &r,
        ));
    }
    let update_log = config.state_dir.join(crate::update::INSTALL_LOG);
    if update_log.exists() {
        let src = LogSource {
            path: update_log,
            keep: 0,
            owner: None,
        };
        files.push(ReportFile::text(
            "logs/update-install.log",
            format!("the last {UPDATE_LOG_LINES} lines of the update installer's log"),
            &tail_text(&src, UPDATE_LOG_LINES),
            &r,
        ));
    }
    Report {
        name,
        instance_host,
        files,
        made_ms: now_ms,
    }
}

/// `alex` stays `alex`; anything but letters, digits, `-`, `_` and `.`
/// becomes `_`, for a file name.
fn file_part(account: &str) -> String {
    let s: String = account
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.trim_start_matches('.').to_owned()
}

fn readme(now_ms: i64, s: &Sources, instance_host: Option<&str>) -> String {
    let (computer, jobs) = if cfg!(windows) {
        ("PC", "the Faro service's state and the login sessions")
    } else {
        ("Mac", "the launchd jobs")
    };
    let mut o = format!(
        "A Faro problem report, made by `faro-service diagnose` ({}) at {} UTC.\n\
         \n\
         It holds what helps find out why Faro isn't working on this {computer}: what the service \
         is doing, versions, {jobs}, the installed files and the last {} lines of \
         Faro's logs. Every file is plain text; read any of them before you send it.\n\
         \n\
         {}\n",
        env!("CARGO_PKG_VERSION"),
        iso_utc(now_ms),
        s.lines,
        taken_out(instance_host),
    );
    if !s.agent_log_notes.is_empty() {
        o.push('\n');
        o.push_str(&s.agent_log_notes);
    }
    o
}

fn permissions(v: &crate::status_view::StatusView) -> String {
    let Some(r) = &v.service else {
        return "No status from the service yet, so no permissions reported.\n".to_owned();
    };
    let p = &r.permissions;
    format!(
        "Account:          {}\nScreen Recording: {}\nAccessibility:    {}\n",
        p.account.as_deref().unwrap_or("(none reported)"),
        p.screen_recording
            .map_or("not reported".to_owned(), |s| format!("{s:?}")),
        p.accessibility
            .map_or("not reported", |a| if a { "granted" } else { "denied" }),
    )
}

fn system(s: &Sources, view: Option<&crate::status_view::StatusView>) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "faro-service (this command): {} ({}-{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    if let Some(r) = view.and_then(|v| v.service.as_ref()) {
        let _ = writeln!(o, "faro-service (running):      {}", r.service_version);
        for sess in &r.sessions {
            if let Some(v) = &sess.agent_version {
                let _ = writeln!(o, "faro-agent ({}):  {v}", sess.account);
            }
        }
    }
    if s.system {
        system_macos(&mut o);
        system_windows(&mut o);
    }
    o
}

#[cfg(windows)]
fn system_windows(o: &mut String) {
    windows::system(o);
}

#[cfg(not(windows))]
fn system_windows(_: &mut String) {}

#[cfg(windows)]
fn service_windows() -> String {
    windows::service_text()
}

#[cfg(not(windows))]
fn service_windows() -> String {
    String::new()
}

#[cfg(target_os = "macos")]
fn system_macos(o: &mut String) {
    let plist = format!(
        "{}/Contents/Info.plist",
        faro_platform_macos::pkg_layout::AGENT_APP
    );
    for (label, key) in [
        ("Faro Agent.app version", "CFBundleShortVersionString"),
        ("Faro Agent.app build", "CFBundleVersion"),
    ] {
        let v = output(
            "/usr/bin/plutil",
            &["-extract", key, "raw", "-o", "-", &plist],
        );
        let _ = writeln!(o, "{label}: {}", v.trim());
    }
    let _ = writeln!(o);
    o.push_str(&command("/usr/bin/sw_vers", &[]));
    for (label, name) in [
        ("Model", "hw.model"),
        ("Architecture", "hw.machine"),
        ("Processor", "machdep.cpu.brand_string"),
        ("Memory (bytes)", "hw.memsize"),
        ("Running under Rosetta", "sysctl.proc_translated"),
        ("Booted", "kern.boottime"),
    ] {
        let v = output("/usr/sbin/sysctl", &["-n", name]);
        let _ = writeln!(o, "{label}: {}", v.trim());
    }
    let _ = writeln!(o);
    o.push_str(&command("/bin/df", &["-h", "/", "/Library"]));
}

#[cfg(not(target_os = "macos"))]
fn system_macos(_: &mut String) {}

/// The keys of `launchctl print` kept: the job's state, never its
/// environment (which could hold anything someone set with `launchctl
/// setenv`).
const LAUNCHD_KEYS: &[&str] = &[
    "state",
    "pid",
    "program",
    "path",
    "type",
    "runs",
    "active count",
    "spawn type",
    "immediate reason",
    "job state",
    "last exit code",
    "last exit reason",
    "last terminating signal",
    "forks",
    "execs",
    "properties",
];

/// `launchctl print`'s output, cut to [`LAUNCHD_KEYS`].
pub fn launchd_fields(print: &str) -> String {
    let mut o = String::new();
    for line in print.lines() {
        // Top-level fields are indented by exactly one tab.
        let Some(rest) = line.strip_prefix('\t') else {
            continue;
        };
        if rest.starts_with(['\t', ' ']) {
            continue;
        }
        let Some((key, _)) = rest.split_once(" = ") else {
            continue;
        };
        if LAUNCHD_KEYS.contains(&key.trim()) {
            let _ = writeln!(o, "  {}", rest.trim());
        }
    }
    o
}

#[cfg(target_os = "macos")]
fn launchd(agent_uid: Option<u32>) -> String {
    use faro_platform_macos::{AGENT_LABEL, DAEMON_LABEL};
    let mut o = String::new();
    let mut jobs = vec![
        format!("system/{DAEMON_LABEL}"),
        format!("system/{}", faro_platform_macos::update_job::UPDATE_LABEL),
    ];
    if let Some(uid) = agent_uid {
        jobs.push(format!("gui/{uid}/{AGENT_LABEL}"));
    }
    for job in &jobs {
        let _ = writeln!(o, "{job}:");
        match std::process::Command::new("/bin/launchctl")
            .args(["print", job])
            .output()
        {
            Ok(out) if out.status.success() => {
                o.push_str(&launchd_fields(&String::from_utf8_lossy(&out.stdout)));
            }
            Ok(out) => {
                let _ = writeln!(
                    o,
                    "  not loaded ({}; {})",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => {
                let _ = writeln!(o, "  launchctl failed: {e}");
            }
        }
        let _ = writeln!(o);
    }
    let mut domains = vec!["system".to_owned()];
    if let Some(uid) = agent_uid {
        domains.push(format!("gui/{uid}"));
    }
    for d in domains {
        let disabled = output("/bin/launchctl", &["print-disabled", &d]);
        let faro: Vec<&str> = disabled
            .lines()
            .filter(|l| l.contains("org.faro."))
            .map(str::trim)
            .collect();
        let _ = writeln!(
            o,
            "Disabled in {d}: {}",
            if faro.is_empty() {
                "no Faro job".to_owned()
            } else {
                faro.join(", ")
            }
        );
    }
    o
}

#[cfg(not(target_os = "macos"))]
fn launchd(_: Option<u32>) -> String {
    String::new()
}

#[cfg(target_os = "macos")]
fn package() -> String {
    use faro_platform_macos::pkg_layout as layout;
    let mut o = command(
        "/usr/sbin/pkgutil",
        &["--pkg-info", crate::update::package_version::PKG_IDENTIFIER],
    );
    o.push('\n');
    for p in [layout::SERVICE_PROGRAM, layout::AGENT_APP] {
        o.push_str(&command("/usr/bin/codesign", &["-dv", "--verbose=2", p]));
        o.push('\n');
    }
    for p in [layout::DAEMON_PLIST, layout::AGENT_PLIST] {
        match std::fs::read_to_string(p) {
            Ok(t) => {
                let _ = writeln!(o, "{p}:\n{t}");
            }
            Err(e) => {
                let _ = writeln!(o, "{p}: {e}");
            }
        }
    }
    o
}

#[cfg(windows)]
fn package() -> String {
    windows::package()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn package() -> String {
    String::new()
}

/// `$ program args`, then what it printed and how it exited.
#[cfg(target_os = "macos")]
fn command(program: &str, args: &[&str]) -> String {
    let mut o = format!("$ {program} {}\n", args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => {
            o.push_str(&String::from_utf8_lossy(&out.stdout));
            o.push_str(&String::from_utf8_lossy(&out.stderr));
            if !out.status.success() {
                let _ = writeln!(o, "({})", out.status);
            }
        }
        Err(e) => {
            let _ = writeln!(o, "(could not run it: {e})");
        }
    }
    o
}

/// What `program` printed on stdout, or why not.
#[cfg(target_os = "macos")]
fn output(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        Ok(out) => format!("unknown ({})", out.status),
        Err(e) => format!("unknown ({e})"),
    }
}

/// Each directory's entries (not recursive) with type, permissions,
/// owner, size and name; then the config file's.
fn listings(dirs: &[PathBuf], config_file: &Path) -> String {
    let mut o = String::new();
    for d in dirs {
        let _ = writeln!(o, "{}:", d.display());
        match std::fs::symlink_metadata(d) {
            Ok(m) => {
                let _ = writeln!(o, "  {}  .", entry(&m));
            }
            Err(e) => {
                let _ = writeln!(o, "  {e}");
                o.push('\n');
                continue;
            }
        }
        match std::fs::read_dir(d) {
            Ok(rd) => {
                let mut entries: Vec<_> = rd
                    .flatten()
                    .map(|e| {
                        let name = e.file_name().to_string_lossy().into_owned();
                        let line = match e.metadata() {
                            Ok(m) => format!("  {}  {name}", entry(&m)),
                            Err(err) => format!("  ?  {name} ({err})"),
                        };
                        (name, line)
                    })
                    .collect();
                entries.sort();
                for (_, line) in entries {
                    let _ = writeln!(o, "{line}");
                }
            }
            Err(e) => {
                let _ = writeln!(o, "  cannot list it: {e}");
            }
        }
        o.push('\n');
    }
    let _ = writeln!(o, "{}:", config_file.display());
    match std::fs::symlink_metadata(config_file) {
        Ok(m) => {
            let _ = writeln!(o, "  {}", entry(&m));
        }
        Err(e) => {
            let _ = writeln!(o, "  {e}");
        }
    }
    o
}

/// `drwx------  0:0  4 KB`, like a short `ls -l`. `DirEntry::metadata`
/// doesn't follow links, so a link shows as `l`.
fn entry(m: &std::fs::Metadata) -> String {
    let kind = if m.file_type().is_symlink() {
        'l'
    } else if m.is_dir() {
        'd'
    } else if is_socket(m) {
        's'
    } else {
        '-'
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{kind}{}  {}:{}  {:>8}",
            mode_string(m.mode()),
            m.uid(),
            m.gid(),
            m.len()
        )
    }
    #[cfg(not(unix))]
    {
        format!("{kind}  {:>8}", m.len())
    }
}

#[cfg(unix)]
fn is_socket(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    m.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket(_: &std::fs::Metadata) -> bool {
    false
}

/// `0o750` → `rwxr-x---`.
pub fn mode_string(mode: u32) -> String {
    let mut s = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// The last `lines` lines of a log, from its rotated files too when the
/// current one is shorter. What can't be read says why, in the text.
pub fn tail_text(src: &LogSource, lines: usize) -> String {
    let mut chunks = Vec::new();
    let mut have = 0;
    let mut notes = String::new();
    for path in faro_platform::logfile::log_files(
        &src.path,
        &faro_platform::logfile::Rotation {
            max_bytes: 0,
            keep: src.keep,
            mode: 0,
        },
    ) {
        if have >= lines {
            break;
        }
        match read_tail(&path, src.owner) {
            Ok(Some(text)) => {
                have += text.lines().count();
                chunks.push(text);
            }
            Ok(None) => {}
            Err(e) => {
                let _ = writeln!(notes, "[{}: not read: {e}]", path.display());
            }
        }
    }
    let mut all: Vec<&str> = chunks.iter().rev().flat_map(|c| c.lines()).collect();
    let skip = all.len().saturating_sub(lines);
    all.drain(..skip);
    let mut out = notes;
    if all.is_empty() && out.is_empty() {
        let _ = writeln!(out, "[{}: no log yet]", src.path.display());
    }
    for l in all {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// The end of a log file (at most [`MAX_LOG_READ`]), or `None` if there is
/// none. Refuses a symbolic link, anything but a regular file and, with
/// `owner`, a file someone else owns.
fn read_tail(path: &Path, owner: Option<u32>) -> io::Result<Option<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match open_no_follow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    #[cfg(unix)]
    if let Some(want) = owner {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != want {
            return Err(io::Error::other(format!(
                "owned by uid {}, not {want}",
                m.uid()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    let start = m.len().saturating_sub(MAX_LOG_READ);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(MAX_LOG_READ).read_to_end(&mut buf)?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        // The first line is cut.
        text = text
            .split_once('\n')
            .map_or_else(String::new, |(_, r)| r.to_owned());
    }
    Ok(Some(text))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                io::Error::other("it is a symbolic link")
            } else {
                e
            }
        })
}

/// Opens a link itself (not what it points to), so that a link in an
/// account's profile folder is seen as one and refused, whether it is a
/// symbolic link or a junction.
#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if f.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("it is a symbolic link"));
    }
    Ok(f)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn utc_parts(ms: i64) -> (i64, u32, u32, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    (y, mo, d, t / 3600, t / 60 % 60, t % 60)
}

/// `2026-11-25 10:15:00`.
pub fn iso_utc(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(ms);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// `20261125-101500Z`, for file names.
pub fn compact_utc(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(ms);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}Z")
}

/// The account `faro-service diagnose` works for: `SUDO_UID`'s, else
/// (run as root without `sudo`) the one at the screen, else this
/// process's own if it isn't root.
#[cfg(unix)]
pub fn member() -> Option<Member> {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse::<u32>().ok())
        .or_else(console_uid)
        .or_else(|| {
            // SAFETY: getuid has no preconditions.
            let me = unsafe { libc::getuid() };
            (me != 0).then_some(me)
        })?;
    if uid == 0 {
        return None;
    }
    passwd(uid)
}

#[cfg(windows)]
pub fn member() -> Option<Member> {
    windows::member()
}

#[cfg(not(any(unix, windows)))]
pub fn member() -> Option<Member> {
    None
}

/// The owner of `/dev/console`: the account at the screen (macOS).
#[cfg(target_os = "macos")]
fn console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/dev/console").ok()?.uid();
    (uid != 0).then_some(uid)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn console_uid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn passwd(uid: u32) -> Option<Member> {
    use std::ffi::CStr;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and `buf` outlives the
    // strings `pw` points into, which are copied out below.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pw.pw_name.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so both are NUL-terminated strings in `buf`.
    let (name, home) = unsafe {
        (
            CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned(),
            CStr::from_ptr(pw.pw_dir).to_string_lossy().into_owned(),
        )
    };
    Some(Member {
        name,
        uid,
        gid: pw.pw_gid,
        home: PathBuf::from(home),
    })
}

/// Why a report couldn't be written.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("{0}")]
    Folder(String),
    #[error("cannot write {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot make the zip: {0}")]
    Zip(String),
}

/// `member`'s Desktop, if it is a real folder they own.
pub fn desktop(member: &Member) -> Result<PathBuf, WriteError> {
    #[cfg(windows)]
    {
        // The elevated token's own Desktop (which may be redirected, to
        // OneDrive say), from the shell, not guessed from the profile.
        let _ = member;
        let d = windows::desktop_folder()
            .map_err(|e| WriteError::Folder(format!("{e}; choose a folder with --output")))?;
        match std::fs::metadata(&d) {
            Ok(m) if m.is_dir() => Ok(d),
            _ => Err(WriteError::Folder(format!(
                "{} is not a folder; choose one with --output",
                d.display()
            ))),
        }
    }
    #[cfg(not(windows))]
    desktop_in_home(member)
}

#[cfg(not(windows))]
fn desktop_in_home(member: &Member) -> Result<PathBuf, WriteError> {
    let d = member.home.join("Desktop");
    let m = std::fs::symlink_metadata(&d).map_err(|e| {
        WriteError::Folder(format!(
            "{}: {e}; choose a folder with --output",
            d.display()
        ))
    })?;
    if !m.is_dir() {
        return Err(WriteError::Folder(format!(
            "{} is not a folder; choose one with --output",
            d.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != member.uid {
            return Err(WriteError::Folder(format!(
                "{} doesn't belong to {}; choose a folder with --output",
                d.display(),
                member.name
            )));
        }
    }
    Ok(d)
}

/// Write `report` as `<dir>/<report.name>.zip`, a new file that `owner`
/// (uid, gid) is then given. Returns its path.
#[cfg(target_os = "macos")]
pub fn write_zip(
    report: &Report,
    dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<PathBuf, WriteError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let io_err = |path: &Path| {
        let path = path.to_path_buf();
        move |source| WriteError::Io {
            path: path.clone(),
            source,
        }
    };
    // Staged in a private folder of our own, zipped there, then copied.
    let stage = std::env::temp_dir().join(format!("{}-{}", report.name, std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&stage)
        .map_err(io_err(&stage))?;
    let result = (|| {
        let root = stage.join(&report.name);
        for f in &report.files {
            let path = root.join(&f.name);
            if let Some(parent) = path.parent() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(io_err(parent))?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut file| file.write_all(f.contents().as_bytes()))
                .map_err(io_err(&path))?;
        }
        let zip = stage.join(format!("{}.zip", report.name));
        let out = std::process::Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--norsrc", "--keepParent"])
            .arg(&root)
            .arg(&zip)
            .output()
            .map_err(|e| WriteError::Zip(e.to_string()))?;
        if !out.status.success() {
            return Err(WriteError::Zip(format!(
                "ditto: {} {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let bytes = std::fs::read(&zip).map_err(io_err(&zip))?;
        let dest = dir.join(format!("{}.zip", report.name));
        // create_new: never over an existing file, nor through a link.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)
            .map_err(io_err(&dest))?;
        file.write_all(&bytes).map_err(io_err(&dest))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid)).map_err(io_err(&dest))?;
        }
        Ok(dest)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result
}

/// Write `report` as `<dir>/<report.name>.zip`: a stored zip built in
/// memory (nothing is staged on disk), then written to a new file, never
/// over an existing one or through a link. `owner` is unused: the file
/// inherits the folder's permissions.
#[cfg(windows)]
pub fn write_zip(
    report: &Report,
    dir: &Path,
    _owner: Option<(u32, u32)>,
) -> Result<PathBuf, WriteError> {
    use std::io::Write;
    let paths: Vec<String> = report
        .files
        .iter()
        .map(|f| format!("{}/{}", report.name, f.name))
        .collect();
    let entries: Vec<zipw::Entry<'_>> = report
        .files
        .iter()
        .zip(&paths)
        .map(|(f, name)| zipw::Entry {
            name,
            data: f.contents().as_bytes(),
        })
        .collect();
    let bytes = zipw::stored_zip(&entries, zipw::dos_datetime(report.made_ms))
        .map_err(|e| WriteError::Zip(e.to_string()))?;
    let dest = dir.join(format!("{}.zip", report.name));
    let io_err = |source| WriteError::Io {
        path: dest.clone(),
        source,
    };
    // create_new: never over an existing file, nor through a link.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest)
        .map_err(io_err)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = std::fs::remove_file(&dest);
        return Err(io_err(e));
    }
    Ok(dest)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn write_zip(_: &Report, _: &Path, _: Option<(u32, u32)>) -> Result<PathBuf, WriteError> {
    Err(WriteError::Zip(
        "problem reports are written on macOS only; use --print".into(),
    ))
}

#[cfg(test)]
mod tests;
