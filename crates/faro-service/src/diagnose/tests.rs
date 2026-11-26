use super::*;

/// Private things a log may hold at `debug`, none of which may reach a
/// report.
const SECRETS: &[&str] = &[
    "Secret Window",
    "Secret Chat",
    "chat.example.net",
    "alex@example.com",
    "https://private.example/path",
    "Alexs-MacBook-Pro.local",
    "192.168.7.20",
    "com.example.Secret",
    "the notice body",
    "ABCD-1234",
];

/// Log lines as `tracing_subscriber`'s formatter writes them (with the
/// shapes of Faro's own `debug!` calls), produced by the formatter itself.
fn formatted_log() -> String {
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let foreground: (Option<String>, Option<String>) = (
            Some("com.example.Secret".into()),
            Some("Secret Window — chat.example.net".into()),
        );
        tracing::debug!(target: "faro_agent::run", app = ?foreground.0, title = ?foreground.1, "foreground");
        let (title, body) = ("Faro is on", "the notice body\nwith a second line");
        tracing::debug!(target: "faro_agent::notice", title, body, "service notice body");
        tracing::info!(target: "faro_service::cli", instance = "https://faro.example.org/", "starting");
        tracing::warn!(
            target: "faro_service::runtime",
            error = "error sending request for url (https://private.example/path?x=1)",
            "upload failed"
        );
        tracing::error!(target: "faro_service::enroll", "mail alex@example.com about Alexs-MacBook-Pro.local");
        tracing::debug!(target: "hyper_util::client::legacy", "connecting to 192.168.7.20:443 for faro://enroll?c=ABCD-1234");
        tracing::trace!(target: "rustls::client", "Secret Chat bytes");
        tracing::debug!(target: "faro_service::runtime::core", seq = 7, kind = "flag", "event committed");
    });
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn the_formatter_s_output_loses_every_private_value() {
    let raw = formatted_log();
    for s in ["Secret Window", "the notice body", "alex@example.com"] {
        assert!(raw.contains(s), "the fixture should hold {s:?}:\n{raw}");
    }
    let out = Redactor::new(Some("faro.example.org")).log(&raw);
    for s in SECRETS {
        assert!(!out.contains(s), "{s:?} left in:\n{out}");
    }
    assert!(!out.contains("with a second line"), "{out}");
    for keep in [
        "DEBUG faro_agent::run: foreground app=[redacted] title=[redacted]",
        "DEBUG faro_agent::notice: service notice body title=[redacted] body=[redacted]",
        "INFO faro_service::cli: starting instance=\"https://faro.example.org/\"",
        "WARN faro_service::runtime: upload failed error=\"error sending request for url ([url])\"",
        "ERROR faro_service::enroll: mail [email] about [host]",
        "DEBUG hyper_util::client::legacy: [another library's debug output, left out]",
        "TRACE rustls::client: [another library's debug output, left out]",
        "DEBUG faro_service::runtime::core: event committed seq=7 kind=\"flag\"",
    ] {
        assert!(out.contains(keep), "missing {keep:?} in:\n{out}");
    }
    assert_eq!(out.lines().count(), 8, "{out}");
}

fn source(path: PathBuf) -> LogSource {
    LogSource {
        path,
        keep: 3,
        owner: None,
    }
}

#[test]
fn the_tail_reads_back_through_rotated_files() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("x.log");
    std::fs::write(dir.path().join("x.log.2"), "1\n2\n").unwrap();
    std::fs::write(dir.path().join("x.log.1"), "3\n4\n5\n").unwrap();
    std::fs::write(&log, "6\n7\n").unwrap();
    assert_eq!(tail_text(&source(log.clone()), 4), "4\n5\n6\n7\n");
    assert_eq!(tail_text(&source(log.clone()), 2), "6\n7\n");
    assert_eq!(
        tail_text(&source(log.clone()), 100),
        "1\n2\n3\n4\n5\n6\n7\n"
    );
    let none = tail_text(&source(dir.path().join("missing.log")), 10);
    assert!(none.contains("no log yet"), "{none}");
}

#[cfg(unix)]
#[test]
fn a_log_is_never_read_through_a_link_or_from_another_owner() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("device.key");
    std::fs::write(&key, "SECRET KEY BYTES\n").unwrap();
    let log = dir.path().join("faro-agent.log");
    std::os::unix::fs::symlink(&key, &log).unwrap();
    let t = tail_text(&source(log.clone()), 10);
    assert!(!t.contains("SECRET"), "{t}");
    assert!(t.contains("symbolic link"), "{t}");

    std::fs::remove_file(&log).unwrap();
    std::fs::write(&log, "mine\n").unwrap();
    let me = std::fs::metadata(&log).unwrap().uid();
    let mut src = source(log.clone());
    src.owner = Some(me);
    assert_eq!(tail_text(&src, 10), "mine\n");
    src.owner = Some(me + 1);
    let t = tail_text(&src, 10);
    assert!(!t.contains("mine") && t.contains("owned by uid"), "{t}");
}

#[test]
fn launchd_output_keeps_the_state_and_drops_the_environment() {
    let print = "system/org.faro.service = {\n\
                 \tactive count = 1\n\
                 \tpath = /Library/LaunchDaemons/org.faro.service.plist\n\
                 \tstate = running\n\
                 \tprogram = /Library/Faro/bin/faro-service\n\
                 \tenvironment = {\n\
                 \t\tGITHUB_TOKEN => ghp_secret\n\
                 \t}\n\
                 \tinherited environment = {\n\
                 \t\tSSH_AUTH_SOCK => /private/tmp/x\n\
                 \t}\n\
                 \truns = 3\n\
                 \tpid = 412\n\
                 \tlast exit code = (never exited)\n\
                 }\n";
    let kept = launchd_fields(print);
    assert_eq!(
        kept,
        "  active count = 1\n  path = /Library/LaunchDaemons/org.faro.service.plist\n  \
         state = running\n  program = /Library/Faro/bin/faro-service\n  runs = 3\n  \
         pid = 412\n  last exit code = (never exited)\n"
    );
}

#[test]
fn times_and_modes() {
    // 2026-11-25 10:15:00 UTC.
    let ms = 1_795_601_700_000;
    assert_eq!(iso_utc(ms), "2026-11-25 10:15:00");
    assert_eq!(compact_utc(ms), "20261125-101500Z");
    assert_eq!(iso_utc(0), "1970-01-01 00:00:00");
    assert_eq!(compact_utc(951_782_400_000), "20000229-000000Z");
    assert_eq!(mode_string(0o750), "rwxr-x---");
    assert_eq!(mode_string(0o600), "rw-------");
}

/// A computer with the service's files in a temporary folder, its logs
/// full of private data.
struct Fixture {
    _dir: tempfile::TempDir,
    config: Config,
    sources: Sources,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        state_dir: dir.path().join("state"),
        ..Config::default()
    };
    config.ipc.socket_path = dir.path().join("run/agent.sock");
    std::fs::create_dir_all(dir.path().join("run")).unwrap();
    std::fs::write(dir.path().join("run/agent.501.sock"), "").unwrap();
    // State files: listed, never read.
    std::fs::create_dir_all(&config.state_dir).unwrap();
    std::fs::write(config.state_dir.join("device.key"), "KEY-MATERIAL-1234").unwrap();
    std::fs::write(config.state_dir.join("outbox.sqlite3"), "EVENT-CONTENT").unwrap();
    std::fs::write(
        config.state_dir.join(crate::update::INSTALL_LOG),
        "installer: Package name is Faro\ninstaller: upgrade successful\n",
    )
    .unwrap();
    let log = formatted_log();
    std::fs::write(dir.path().join("faro-service.log"), &log).unwrap();
    std::fs::write(dir.path().join("faro-agent.log"), &log).unwrap();
    let sources = Sources {
        config_file: dir.path().join("service.toml"),
        service_log: Some(source(dir.path().join("faro-service.log"))),
        agent_log: Some(("alex".into(), source(dir.path().join("faro-agent.log")))),
        lines: 50,
        listings: vec![config.state_dir.clone(), dir.path().join("run")],
        system: false,
        agent_uid: None,
    };
    Fixture {
        _dir: dir,
        config,
        sources,
    }
}

#[test]
fn a_report_holds_what_helps_and_nothing_private() {
    let f = fixture();
    let report = collect(&f.config, &f.sources, 1_795_601_700_000);
    assert_eq!(report.name, "faro-report-20261125-101500Z");
    let names: Vec<_> = report.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "README.txt",
            "status.txt",
            "status.json",
            "permissions.txt",
            "system.txt",
            "files.txt",
            "config.txt",
            "logs/faro-service.log",
            "logs/faro-agent.log",
            "logs/update-install.log",
        ]
    );
    let all = report.full_text();
    for s in SECRETS.iter().chain(&["KEY-MATERIAL", "EVENT-CONTENT"]) {
        assert!(!all.contains(s), "{s:?} is in the report:\n{all}");
    }
    let status = report.file("status.txt").unwrap().contents();
    assert!(status.starts_with("Not enrolled."), "{status}");
    let files = report.file("files.txt").unwrap().contents();
    for want in [
        "device.key",
        "outbox.sqlite3",
        "agent.501.sock",
        "drwx------",
    ] {
        assert!(files.contains(want), "missing {want:?} in\n{files}");
    }
    let agent = report.file("logs/faro-agent.log").unwrap();
    assert_eq!(agent.about, "the last 50 lines of alex's agent log");
    assert!(agent.contents().contains("app=[redacted]"));
    assert!(report
        .file("logs/update-install.log")
        .unwrap()
        .contents()
        .contains("upgrade successful"));
    let summary = report.summary();
    assert!(summary.contains("logs/faro-service.log"), "{summary}");
    assert!(
        summary.contains("Never in the report: keys, tokens"),
        "{summary}"
    );
}

#[test]
fn the_tail_is_limited_to_the_lines_asked_for() {
    let mut f = fixture();
    f.sources.lines = 2;
    let report = collect(&f.config, &f.sources, 0);
    let log = report.file("logs/faro-service.log").unwrap().contents();
    assert_eq!(log.lines().count(), 2, "{log}");
    assert!(log.contains("event committed"), "{log}");
}

#[cfg(target_os = "macos")]
#[test]
fn the_zip_holds_the_files_as_shown_and_never_replaces_one() {
    let f = fixture();
    let report = collect(&f.config, &f.sources, 1_795_601_700_000);
    let out = tempfile::tempdir().unwrap();
    let zip = write_zip(&report, out.path(), None).unwrap();
    assert_eq!(zip, out.path().join("faro-report-20261125-101500Z.zip"));
    let unpacked = tempfile::tempdir().unwrap();
    let st = std::process::Command::new("/usr/bin/ditto")
        .args(["-x", "-k"])
        .arg(&zip)
        .arg(unpacked.path())
        .status()
        .unwrap();
    assert!(st.success());
    let root = unpacked.path().join(&report.name);
    for file in &report.files {
        let got = std::fs::read_to_string(root.join(&file.name)).unwrap();
        assert_eq!(got, file.contents(), "{}", file.name);
    }
    let mut count = 0;
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                count += 1;
            }
        }
    }
    assert_eq!(count, report.files.len(), "nothing but the report's files");
    let again = write_zip(&report, out.path(), None).unwrap_err();
    assert!(again.to_string().contains("exists"), "{again}");
}

#[cfg(unix)]
#[test]
fn the_desktop_must_be_the_member_s_own_folder() {
    use std::os::unix::fs::MetadataExt;
    let home = tempfile::tempdir().unwrap();
    let uid = std::fs::metadata(home.path()).unwrap().uid();
    let m = Member {
        name: "alex".into(),
        uid,
        gid: 20,
        home: home.path().to_path_buf(),
    };
    assert!(desktop(&m).is_err(), "no Desktop yet");
    std::os::unix::fs::symlink("/", home.path().join("Desktop")).unwrap();
    assert!(desktop(&m)
        .unwrap_err()
        .to_string()
        .contains("not a folder"));
    std::fs::remove_file(home.path().join("Desktop")).unwrap();
    std::fs::create_dir(home.path().join("Desktop")).unwrap();
    assert_eq!(desktop(&m).unwrap(), home.path().join("Desktop"));
    let other = Member { uid: uid + 1, ..m };
    assert!(desktop(&other)
        .unwrap_err()
        .to_string()
        .contains("doesn't belong"));
}
