//! Several processes append to one chain (docs/IOS.md §13 "One chain,
//! several processes").
//!
//! The parent enrolls and approves a phone against the real instance, then
//! starts copies of this test binary as child processes, the way the app
//! and the packet tunnel share the app group container. Each child opens
//! its own `FaroCore` on the same directory and appends events while the
//! parent appends too. The whole chain must then verify (strict `seq`,
//! every `prev_hash` the hash of the event before it, every signature
//! good), and the instance must accept all of it without a gap or a fork.

mod support;

use faro_crypto::SigningKey;
use faro_mobile::keys::DEVICE_KEY;
use faro_mobile::{KeyStore, KeyStoreError, SettingChangeRecord, Tamper};
use faro_proto::{DeviceId, InstanceId};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::{approved_phone, blocking, core_at, Phone, World};

const CHILD_DIR: &str = "FARO_MOBILE_TEST_CHILD_DIR";
const CHILD_KEYS: &str = "FARO_MOBILE_TEST_CHILD_KEYS";
const CHILD_ID: &str = "FARO_MOBILE_TEST_CHILD_ID";
const PER_PROCESS: u64 = 25;
const CHILDREN: u64 = 4;
const GO_FILE: &str = "go";

/// A key store in a directory, so child processes see the parent's keys
/// (as the app and the tunnel share a Keychain access group).
struct DirKeyStore(PathBuf);

impl KeyStore for DirKeyStore {
    fn load(&self, name: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        match std::fs::read(self.0.join(name)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeyStoreError::Failed {
                message: e.to_string(),
            }),
        }
    }
    fn store(&self, name: String, value: Vec<u8>) -> Result<(), KeyStoreError> {
        let fail = |e: std::io::Error| KeyStoreError::Failed {
            message: e.to_string(),
        };
        std::fs::create_dir_all(&self.0).map_err(fail)?;
        let tmp = self.0.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, value).map_err(fail)?;
        std::fs::rename(&tmp, self.0.join(name)).map_err(fail)
    }
    fn delete(&self, name: String) -> Result<(), KeyStoreError> {
        match std::fs::remove_file(self.0.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(KeyStoreError::Failed {
                message: e.to_string(),
            }),
            _ => Ok(()),
        }
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < deadline, "no go signal");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// `n` events from one process: tamper and settings changes in turn, a
/// millisecond or two apart (neither the app nor the tunnel appends in a
/// tight loop), so the processes take turns at the lock.
fn append_events(core: &faro_mobile::FaroCore, who: &str, n: u64) {
    let salt = who.bytes().map(u64::from).sum::<u64>();
    for i in 0..n {
        std::thread::sleep(Duration::from_micros(500 + (i * 7 + salt) % 4 * 500));
        if i % 2 == 0 {
            core.record_tamper(Tamper::IntegrityFailure {
                component: format!("{who} {i}"),
            })
            .expect("tamper appended");
        } else {
            core.record_settings_change(
                vec![SettingChangeRecord {
                    key: "test.counter".into(),
                    old_value: Some(who.into()),
                    new_value: Some(i.to_string()),
                }],
                None,
            )
            .expect("settings change appended");
        }
    }
}

/// The child process's body. Does nothing in a normal test run: it only
/// appends when the parent starts this binary with the environment set.
#[test]
fn child_appender() {
    let (Some(dir), Some(keys), Some(id)) = (
        std::env::var_os(CHILD_DIR),
        std::env::var_os(CHILD_KEYS),
        std::env::var(CHILD_ID).ok(),
    ) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let core = core_at(&dir, Arc::new(DirKeyStore(PathBuf::from(keys))));
    wait_for(&dir.join(GO_FILE));
    append_events(&core, &format!("child {id}"), PER_PROCESS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn several_processes_append_to_one_strict_chain() {
    let w = World::new().await;
    let keys_tmp = tempfile::tempdir().unwrap();
    let keys_dir = keys_tmp.path().join("keychain");
    let phone = Phone::with_keys(Arc::new(DirKeyStore(keys_dir.clone())));
    let (core, device_id) = approved_phone(&w, &phone).await;

    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..CHILDREN)
        .map(|i| {
            Command::new(&exe)
                .args([
                    "--exact",
                    "child_appender",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_DIR, &phone.dir)
                .env(CHILD_KEYS, &keys_dir)
                .env(CHILD_ID, i.to_string())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("start a child process")
        })
        .collect();
    // Let them all open the database first, then start at once, with the
    // parent appending too.
    std::thread::sleep(Duration::from_millis(300));
    std::fs::write(phone.dir.join(GO_FILE), b"").unwrap();
    let c = core.clone();
    blocking(move || append_events(&c, "parent", PER_PROCESS)).await;
    for mut child in children {
        let status = blocking(move || child.wait().expect("child exits")).await;
        assert!(status.success(), "a child failed: {status}");
    }

    let total = PER_PROCESS * (CHILDREN + 1);
    let c = core.clone();
    let events = blocking(move || c.pending_events(10_000).unwrap()).await;
    assert_eq!(events.len() as u64, total);
    assert_eq!(
        events.iter().map(|e| e.header.seq).collect::<Vec<_>>(),
        (0..total).collect::<Vec<_>>()
    );
    // Who wrote each event, from the sealed bodies. Five writers in blocks
    // would switch four times; more means the appends interleaved.
    let writers: Vec<String> = events
        .iter()
        .map(
            |e| match faro_core::open_event_body(e, &w.member, &w.member_keys.enc).unwrap() {
                faro_proto::body::EventBody::Tamper {
                    signal: faro_proto::body::TamperSignal::IntegrityFailure { component },
                    ..
                } => component.rsplit_once(' ').unwrap().0.to_owned(),
                faro_proto::body::EventBody::SettingsChange { changes, .. } => {
                    changes[0].old.clone().unwrap()
                }
                other => panic!("unexpected body {other:?}"),
            },
        )
        .collect();
    for who in ["parent", "child 0", "child 1", "child 2", "child 3"] {
        assert_eq!(
            writers.iter().filter(|w| *w == who).count() as u64,
            PER_PROCESS,
            "{who}"
        );
    }
    let switches = writers.windows(2).filter(|p| p[0] != p[1]).count();
    eprintln!("{total} events from 5 processes, {switches} writer switches");
    assert!(switches > 4, "the processes never took turns: {writers:?}");
    let device_key = {
        let seed: [u8; 32] = std::fs::read(keys_dir.join(DEVICE_KEY))
            .unwrap()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&seed).public()
    };
    let (head, gaps) = faro_crypto::verify_chain(
        &InstanceId::new(w.t.instance_id().to_string()),
        &DeviceId::new(device_id.clone()),
        &device_key,
        &events,
        true,
    )
    .expect("the whole chain verifies");
    assert!(gaps.is_empty());
    let c = core.clone();
    let status = blocking(move || c.status().unwrap()).await;
    assert_eq!(status.next_seq, head.next_seq);

    // The instance takes all of it, in order, with no gap or fork alert.
    let c = core.clone();
    let up = blocking(move || c.upload_pending().unwrap()).await;
    assert_eq!(up.acked_through, Some(total - 1));
    assert_eq!(up.pending_events, 0);
    assert_eq!(
        w.stored_seqs(&device_id).await,
        (0..total as i64).collect::<Vec<_>>()
    );
    let kinds = w.alert_kinds().await;
    assert!(
        !kinds
            .iter()
            .any(|k| k == "chain_gap" || k == "invalid_signature"),
        "{kinds:?}"
    );
}
