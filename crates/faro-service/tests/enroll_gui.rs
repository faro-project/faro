//! Enrolling from the agent (issue #62): `faro_service::enroll_server`
//! against the real instance, with a fake administrator.
//!
//! The approver is faked here: a real one shows the system's password
//! dialog, which a test can't answer (`faro_platform_macos::authorization`
//! has the no-dialog checks of the real mechanism). Everything after the
//! approval is the CLI's own enrollment (`faro_service::enroll::enroll`).

#![cfg(unix)]

// Shared with tests/e2e.rs; not every helper is used here.
#[allow(dead_code)]
mod e2e_support;

use e2e_support::*;
use faro_ipc::{
    AllowSameUid, EnrollClientConnection, EnrollRequest, EnrollResponse, EnrollTarget, FailureKind,
    IpcClient,
};
use faro_service::accounts::{enrollment_notice, Accounts};
use faro_service::client::ClientOptions;
use faro_service::enroll_server::{ApprovalError, Approver, EnrollServer, EnrollService};
use faro_service::state::{DEVICE_KEY_FILE, ENROLLMENT_FILE};
use faro_service::Phase;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const AUTH: [u8; 32] = [42; 32];

/// What the fake administrator does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    Deny,
    /// Keep the dialog open until released.
    Hold,
}

struct FakeAdmin {
    answer: Mutex<Answer>,
    prompts: Mutex<Vec<String>>,
    authorizations: Mutex<Vec<[u8; 32]>>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl FakeAdmin {
    fn new(answer: Answer) -> Arc<FakeAdmin> {
        Arc::new(FakeAdmin {
            answer: Mutex::new(answer),
            prompts: Mutex::default(),
            authorizations: Mutex::default(),
            release: Mutex::default(),
        })
    }

    fn asked(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }
}

impl Approver for FakeAdmin {
    fn approve(
        &self,
        authorization: &[u8; 32],
        prompt: &str,
        _subject: &faro_service::enroll_server::ApprovalSubject<'_>,
    ) -> Result<(), ApprovalError> {
        self.prompts.lock().unwrap().push(prompt.to_owned());
        self.authorizations.lock().unwrap().push(*authorization);
        let answer = *self.answer.lock().unwrap();
        match answer {
            Answer::Approve => Ok(()),
            Answer::Deny => Err(ApprovalError::NotApproved),
            Answer::Hold => {
                let rx = self.release.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.recv();
                }
                Err(ApprovalError::NotApproved)
            }
        }
    }
}

fn sample_accounts() -> Accounts {
    Accounts {
        names: vec!["alex".into(), "sam".into()],
        guest_enabled: true,
    }
}

/// A state directory of its own, and the enroll service over it.
struct Computer {
    tmp: tempfile::TempDir,
    state_dir: PathBuf,
}

impl Computer {
    fn new() -> Computer {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        Computer { tmp, state_dir }
    }

    fn service(&self, admin: &Arc<FakeAdmin>) -> EnrollService {
        EnrollService::new(&self.state_dir, ClientOptions::default(), admin.clone())
            .with_accounts(|| Some(sample_accounts()))
            .with_device_name(DEVICE_NAME)
    }

    fn has(&self, file: &str) -> bool {
        self.state_dir.join(file).exists()
    }
}

fn encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// A fresh enrollment link from the member's web app, with `m` if given.
async fn link(w: &World, member_key: Option<&str>) -> String {
    let code = w.t.enroll_code(&w.member_session).await;
    link_with_code(w, &code, member_key)
}

fn link_with_code(w: &World, code: &str, member_key: Option<&str>) -> String {
    let mut l = format!(
        "faro://enroll?i={}&c={}",
        encode(w.gate.url().as_str()),
        encode(code)
    );
    if let Some(m) = member_key {
        l.push_str(&format!("&m={m}"));
    }
    l
}

async fn preview(svc: &EnrollService, target: &EnrollTarget) -> faro_ipc::EnrollPreview {
    match svc.handle(EnrollRequest::Preview(target.clone())).await {
        EnrollResponse::Preview(p) => p,
        other => panic!("expected a preview, got {other:?}"),
    }
}

fn enroll_req(target: &EnrollTarget, p: &faro_ipc::EnrollPreview) -> EnrollRequest {
    EnrollRequest::Enroll {
        target: target.clone(),
        confirmed_instance: p.instance_id.clone(),
        confirmed_identity: p.identity_key,
        authorization: AUTH,
    }
}

fn failed(r: &EnrollResponse) -> FailureKind {
    match r {
        EnrollResponse::Failed { kind, .. } => *kind,
        other => panic!("expected a failure, got {other:?}"),
    }
}

/// The whole flow: preview, approval, enrollment; then the running service
/// takes over exactly as after `faro-service enroll`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preview_approve_enroll_then_activation_continues() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = b.service(&admin);
    let target = EnrollTarget::Link(link(&w, Some(&w.member_key_id())).await);

    let p = preview(&svc, &target).await;
    assert_eq!(p.instance_id, w.t.instance_id().as_str());
    assert_eq!(&p.identity_key, w.t.state.identity().public().as_bytes());
    assert_eq!(p.instance_url, w.gate.url().as_str());
    assert_eq!(p.device_name, DEVICE_NAME);
    assert_eq!(
        p.accounts.as_deref(),
        Some(&["alex".to_owned(), "sam".to_owned()][..])
    );
    assert!(p.guest_enabled && p.member_key_in_link);
    assert!(!b.has(DEVICE_KEY_FILE), "a preview writes nothing");
    assert_eq!(admin.asked(), 0, "a preview asks nobody");

    // The agent shows what the CLI prints about the accounts.
    let screen = faro_agent::enroll::confirm_screen(&p);
    for line in enrollment_notice(Some(&sample_accounts())).lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            screen.body.contains(&line),
            "missing {line:?} in {}",
            screen.body
        );
    }

    let done = match svc.handle(enroll_req(&target, &p)).await {
        EnrollResponse::Enrolled(d) => d,
        other => panic!("not enrolled: {other:?}"),
    };
    assert!(done.member_key_checked);
    assert_eq!(done.member_fingerprint, w.member_key_id());
    // The administrator was asked once, with the agent's authorization and
    // a prompt naming the instance the service discovered.
    assert_eq!(admin.authorizations.lock().unwrap().as_slice(), [AUTH]);
    let prompt = admin.prompts.lock().unwrap()[0].clone();
    assert!(
        prompt.contains(&w.t.state.config().instance.name),
        "{prompt}"
    );
    assert!(prompt.contains("127.0.0.1"), "{prompt}");

    match svc.handle(EnrollRequest::Status).await {
        EnrollResponse::Status(s) => assert!(s.enrolled && !s.endorsed),
        other => panic!("{other:?}"),
    }

    // Activation continues unchanged: the member endorses, the service
    // runs on the pinned keys.
    let Computer { tmp, state_dir } = b;
    let mut dev = w.adopt_device(tmp, state_dir);
    assert_eq!(dev.fingerprint(), done.device_fingerprint);
    assert_eq!(
        dev.enrollment.member_sign_pubkey,
        w.member_keys.sign.public()
    );
    assert_eq!(
        dev.enrollment.instance_identity_pubkey,
        w.t.state.identity().public()
    );
    dev.start(quiet_classifier());
    dev.wait("awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    let anchor = w.endorse(&dev).await;
    let st = dev
        .wait("running", |s| {
            s.phase == Phase::Running && s.manifest.is_some()
        })
        .await;
    assert_eq!(st.manifest, Some(anchor));
    dev.shutdown().await;
}

/// No approval, no enrollment: nothing is written, and the one-time code
/// still works afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_denial_writes_nothing_and_leaves_the_code_unspent() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Deny);
    let svc = b.service(&admin);
    let target = EnrollTarget::Link(link(&w, Some(&w.member_key_id())).await);
    let p = preview(&svc, &target).await;

    let r = svc.handle(enroll_req(&target, &p)).await;
    assert_eq!(failed(&r), FailureKind::NotApproved);
    assert_eq!(admin.asked(), 1);
    assert!(!b.has(ENROLLMENT_FILE) && !b.has(DEVICE_KEY_FILE));

    *admin.answer.lock().unwrap() = Answer::Approve;
    let r = svc.handle(enroll_req(&target, &p)).await;
    assert!(matches!(r, EnrollResponse::Enrolled(_)), "{r:?}");
}

/// The instance must still be the one the person confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identity_other_than_the_confirmed_one_is_refused() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = b.service(&admin);
    let target = EnrollTarget::Link(link(&w, None).await);
    let p = preview(&svc, &target).await;

    // As if the instance answered with another key after the preview:
    // what the person confirmed no longer matches.
    let mut other_key = p.clone();
    other_key.identity_key[0] ^= 1;
    let r = svc.handle(enroll_req(&target, &other_key)).await;
    assert_eq!(failed(&r), FailureKind::InstanceChanged);
    let mut other_id = p.clone();
    other_id.instance_id.push('x');
    let r = svc.handle(enroll_req(&target, &other_id)).await;
    assert_eq!(failed(&r), FailureKind::InstanceChanged);

    assert_eq!(
        admin.asked(),
        0,
        "nobody is asked to approve another instance"
    );
    assert!(!b.has(ENROLLMENT_FILE) && !b.has(DEVICE_KEY_FILE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_code_is_reported_as_such() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = b.service(&admin);
    let target = EnrollTarget::Link(link_with_code(&w, "ZZZZ-ZZZZ", None));
    // The code is only checked when it is used, after approval.
    let p = preview(&svc, &target).await;
    let r = svc.handle(enroll_req(&target, &p)).await;
    assert_eq!(failed(&r), FailureKind::WrongCode);
    assert!(!b.has(ENROLLMENT_FILE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolled_computer_is_not_enrolled_again() {
    let w = World::new().await;
    // Enrolled with the CLI's path.
    let dev = w.enroll_device().await;
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = EnrollService::new(&dev.state_dir, ClientOptions::default(), admin.clone());
    match svc.handle(EnrollRequest::Status).await {
        EnrollResponse::Status(s) => {
            assert!(s.enrolled);
            assert_eq!(s.instance_url.as_deref(), Some(w.gate.url().as_str()));
        }
        other => panic!("{other:?}"),
    }
    let target = EnrollTarget::Link(link(&w, None).await);
    let r = svc.handle(EnrollRequest::Preview(target.clone())).await;
    assert_eq!(failed(&r), FailureKind::AlreadyEnrolled);
    let r = svc
        .handle(EnrollRequest::Enroll {
            target,
            confirmed_instance: w.t.instance_id().as_str().to_owned(),
            confirmed_identity: *w.t.state.identity().public().as_bytes(),
            authorization: AUTH,
        })
        .await;
    assert_eq!(failed(&r), FailureKind::AlreadyEnrolled);
    assert_eq!(admin.asked(), 0);
}

/// The link's `m` is checked exactly as for the CLI (invariant 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_key_other_than_the_links_is_refused() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = b.service(&admin);
    let wrong = "0123456789abcdef";
    assert_ne!(wrong, w.member_key_id());
    let target = EnrollTarget::Link(link(&w, Some(wrong)).await);
    let p = preview(&svc, &target).await;
    let r = svc.handle(enroll_req(&target, &p)).await;
    assert_eq!(failed(&r), FailureKind::MemberKeyMismatch);
    assert!(!b.has(ENROLLMENT_FILE), "nothing pinned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_input_and_unreachable_instances() {
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let svc = b.service(&admin);
    for target in [
        EnrollTarget::Link("faro://enroll?c=ABCD-1234".into()),
        EnrollTarget::Link("https://faro.example.org".into()),
        EnrollTarget::Manual {
            instance: "http://faro.example.org".into(),
            code: "ABCD-1234".into(),
        },
        EnrollTarget::Manual {
            instance: "https://faro.example.org".into(),
            code: "nope".into(),
        },
    ] {
        let r = svc.handle(EnrollRequest::Preview(target)).await;
        assert_eq!(failed(&r), FailureKind::BadInput);
    }
    // Nothing listens on port 1.
    let r = svc
        .handle(EnrollRequest::Preview(EnrollTarget::Manual {
            instance: "http://127.0.0.1:1".into(),
            code: "ABCD-1234".into(),
        }))
        .await;
    assert_eq!(failed(&r), FailureKind::Unreachable);
}

/// One enrollment at a time, and a dialog nobody answers times out
/// without enrolling. A dialog still open after the timeout keeps others
/// out until it closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_enrollment_at_a_time_and_unanswered_dialogs_time_out() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Hold);
    let (release, rx) = std::sync::mpsc::channel();
    *admin.release.lock().unwrap() = Some(rx);
    let svc = b
        .service(&admin)
        .with_approval_timeout(Duration::from_millis(300));
    let target = EnrollTarget::Link(link(&w, None).await);
    let p = preview(&svc, &target).await;

    let r = svc.handle(enroll_req(&target, &p)).await;
    assert_eq!(failed(&r), FailureKind::NotApproved);
    // The dialog is still up: a second attempt is turned away.
    let r = svc.handle(enroll_req(&target, &p)).await;
    assert_eq!(failed(&r), FailureKind::Busy);
    assert_eq!(admin.asked(), 1);

    release.send(()).unwrap();
    *admin.answer.lock().unwrap() = Answer::Approve;
    let mut tries = 0;
    let r = loop {
        let r = svc.handle(enroll_req(&target, &p)).await;
        match &r {
            EnrollResponse::Failed {
                kind: FailureKind::Busy,
                ..
            } if tries < 100 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            _ => break r,
        }
    };
    assert!(matches!(r, EnrollResponse::Enrolled(_)), "{r:?}");
}

async fn ask(path: &Path, req: &EnrollRequest) -> EnrollResponse {
    let mut conn: EnrollClientConnection<_> =
        IpcClient::connect_verified_typed(path, &AllowSameUid)
            .await
            .expect("connect");
    conn.send(req).await.expect("send");
    conn.recv().await.expect("answer")
}

/// The socket the service listens on before enrollment: a request and its
/// answer over the real transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_enroll_socket_answers_before_enrollment() {
    let w = World::new().await;
    let b = Computer::new();
    let admin = FakeAdmin::new(Answer::Approve);
    let mut config = faro_service::Config {
        state_dir: b.state_dir.clone(),
        ..Default::default()
    };
    // The sockets go next to the state directory, in the test's private
    // tempdir (macOS socket paths are limited to 104 bytes).
    config.ipc.socket_path = b.tmp.path().join("agent.sock");
    let server = EnrollServer::new(b.service(&admin), &config).single_socket();
    let path = server.socket_path(None);
    let task = tokio::spawn(server.run());
    for _ in 0..200 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    match ask(&path, &EnrollRequest::Status).await {
        EnrollResponse::Status(s) => assert!(!s.enrolled),
        other => panic!("{other:?}"),
    }
    let target = EnrollTarget::Link(link(&w, None).await);
    let p = match ask(&path, &EnrollRequest::Preview(target.clone())).await {
        EnrollResponse::Preview(p) => p,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.instance_id, w.t.instance_id().as_str());
    let r = ask(&path, &enroll_req(&target, &p)).await;
    assert!(matches!(r, EnrollResponse::Enrolled(_)), "{r:?}");
    assert!(b.has(ENROLLMENT_FILE));
    task.abort();
}
