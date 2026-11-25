//! The agent's enrollment flow (`faro_agent::enroll::run_flow`) against a
//! fake service on a real enroll socket, with the screens and the
//! authorization faked: which requests are sent, in what order, with what,
//! and what the person is shown.
#![cfg(unix)]

use faro_agent::enroll::{run_flow, Authorizer, EnrollUi, PasteScreen, Screen};
use faro_agent::ServiceTrust;
use faro_ipc::{
    AllowSameUid, EnrollDone, EnrollPreview, EnrollRequest, EnrollResponse,
    EnrollServerConnection, EnrollStatus, EnrollTarget, FailureKind, IpcServer,
};
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const LINK: &str = "faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=ABCD-1234";

fn preview() -> EnrollPreview {
    EnrollPreview {
        instance_name: "Sam's Faro".into(),
        instance_url: "https://faro.example.org/".into(),
        instance_id: "inst_a".into(),
        identity_key: [5; 32],
        device_name: "Laptop".into(),
        accounts: Some(vec!["sam".into()]),
        guest_enabled: false,
        member_key_in_link: true,
    }
}

fn status(enrolled: bool) -> EnrollResponse {
    EnrollResponse::Status(EnrollStatus {
        enrolled,
        instance_name: enrolled.then(|| "Sam's Faro".into()),
        instance_url: enrolled.then(|| "https://faro.example.org/".into()),
        endorsed: false,
    })
}

fn enrolled() -> EnrollResponse {
    EnrollResponse::Enrolled(EnrollDone {
        device_fingerprint: "0123456789abcdef".into(),
        member_fingerprint: "fedcba9876543210".into(),
        member_key_checked: true,
    })
}

/// A service that answers each request from a script and records them.
struct FakeService {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<EnrollRequest>>>,
    _dir: tempfile::TempDir,
    _thread: std::thread::JoinHandle<()>,
}

impl FakeService {
    fn start(answers: Vec<EnrollResponse>) -> FakeService {
        let dir = tempfile::tempdir().unwrap();
        let socket = faro_ipc::enroll_socket_path(&dir.path().join("agent.sock"), None);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (path, log) = (socket.clone(), seen.clone());
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let server = IpcServer::bind(&path, AllowSameUid).unwrap();
                ready_tx.send(()).unwrap();
                let mut answers: VecDeque<_> = answers.into();
                while let Some(answer) = answers.pop_front() {
                    let mut conn: EnrollServerConnection<_> = server.accept_typed().await.unwrap();
                    // A client that hangs up unanswered (it refused us)
                    // doesn't use up an answer.
                    let Ok(req) = conn.recv().await else {
                        answers.push_front(answer);
                        continue;
                    };
                    log.lock().unwrap().push(req);
                    conn.send(&answer).await.unwrap();
                }
            });
        });
        ready_rx.recv().unwrap();
        FakeService {
            socket,
            seen,
            _dir: dir,
            _thread: thread,
        }
    }

    fn requests(&self) -> Vec<EnrollRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct FakeUi {
    pastes: RefCell<VecDeque<Option<(String, String)>>>,
    confirm_answer: bool,
    log: RefCell<Vec<String>>,
}

impl EnrollUi for FakeUi {
    fn ask_target(&self, s: &PasteScreen) -> Option<(String, String)> {
        self.log.borrow_mut().push(format!("paste: {}", s.title));
        self.pastes.borrow_mut().pop_front().flatten()
    }

    fn confirm(&self, s: &Screen, ok: &str, _cancel: &str) -> bool {
        self.log
            .borrow_mut()
            .push(format!("confirm [{ok}]: {}", s.title));
        self.confirm_answer
    }

    fn show(&self, s: &Screen, problem: bool) {
        let kind = if problem { "problem" } else { "message" };
        self.log
            .borrow_mut()
            .push(format!("{kind}: {} | {}", s.title, s.body));
    }
}

/// Records whether the authorization is still alive.
struct Hold(Rc<RefCell<bool>>);

impl Drop for Hold {
    fn drop(&mut self) {
        *self.0.borrow_mut() = false;
    }
}

#[derive(Default)]
struct FakeAuthorizer {
    created: RefCell<u32>,
    alive: Rc<RefCell<bool>>,
}

impl Authorizer for FakeAuthorizer {
    fn create(&self) -> Result<(Box<dyn Any>, [u8; 32]), String> {
        *self.created.borrow_mut() += 1;
        *self.alive.borrow_mut() = true;
        Ok((Box::new(Hold(self.alive.clone())), [42; 32]))
    }
}

fn run(svc: &FakeService, ui: &FakeUi, auth: &FakeAuthorizer, link: Option<&str>) {
    run_flow(
        ui,
        auth,
        &svc.socket,
        ServiceTrust::SameUid,
        link.map(str::to_owned),
    );
}

#[test]
fn a_link_is_confirmed_then_enrolled_with_the_confirmed_identity() {
    let svc = FakeService::start(vec![EnrollResponse::Preview(preview()), enrolled()]);
    let ui = FakeUi {
        confirm_answer: true,
        ..FakeUi::default()
    };
    let auth = FakeAuthorizer::default();
    run(&svc, &ui, &auth, Some(LINK));

    let reqs = svc.requests();
    assert_eq!(
        reqs[0],
        EnrollRequest::Preview(EnrollTarget::Link(LINK.into()))
    );
    assert_eq!(
        reqs[1],
        EnrollRequest::Enroll {
            target: EnrollTarget::Link(LINK.into()),
            confirmed_instance: "inst_a".into(),
            confirmed_identity: [5; 32],
            authorization: [42; 32],
        }
    );
    assert_eq!(*auth.created.borrow(), 1);
    assert!(!*auth.alive.borrow(), "the authorization is freed after the answer");
    let log = ui.log.borrow();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].starts_with("confirm [Enroll]: Enroll this computer with \u{201c}Sam's Faro\u{201d}?"));
    assert!(log[1].starts_with("message: This computer is enrolled"));
    assert!(log[1].contains("0123456789abcdef"));
}

#[test]
fn cancelling_the_confirmation_sends_nothing_more() {
    let svc = FakeService::start(vec![EnrollResponse::Preview(preview())]);
    let ui = FakeUi::default();
    let auth = FakeAuthorizer::default();
    run(&svc, &ui, &auth, Some(LINK));
    assert_eq!(svc.requests().len(), 1);
    assert_eq!(*auth.created.borrow(), 0, "no authorization without consent");
    assert_eq!(ui.log.borrow().len(), 1);
}

#[test]
fn the_menu_on_an_enrolled_computer_only_says_so() {
    let svc = FakeService::start(vec![status(true)]);
    let ui = FakeUi::default();
    run(&svc, &ui, &FakeAuthorizer::default(), None);
    assert_eq!(svc.requests(), [EnrollRequest::Status]);
    let log = ui.log.borrow();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("message: This computer is already enrolled"));
}

#[test]
fn the_menu_asks_for_the_link_until_it_has_one() {
    let svc = FakeService::start(vec![
        status(false),
        EnrollResponse::failed(FailureKind::WrongCode, "invalid_enroll_code"),
    ]);
    let ui = FakeUi {
        pastes: RefCell::new(
            [
                Some((String::new(), String::new())),
                Some(("faro.example.org".into(), "abcd-1234".into())),
            ]
            .into(),
        ),
        confirm_answer: true,
        ..FakeUi::default()
    };
    run(&svc, &ui, &FakeAuthorizer::default(), None);
    assert_eq!(
        svc.requests(),
        [
            EnrollRequest::Status,
            EnrollRequest::Preview(EnrollTarget::Manual {
                instance: "https://faro.example.org".into(),
                code: "abcd-1234".into()
            })
        ]
    );
    let log = ui.log.borrow();
    assert!(log[0].starts_with("paste: "));
    assert!(log[1].starts_with("problem: Paste the link first"));
    assert!(log[2].starts_with("paste: "));
    assert!(log[3].starts_with("problem: The code didn't work"));
}

#[test]
fn a_refused_enrollment_is_explained() {
    let svc = FakeService::start(vec![
        EnrollResponse::Preview(preview()),
        EnrollResponse::failed(FailureKind::NotApproved, "no administrator approved"),
    ]);
    let ui = FakeUi {
        confirm_answer: true,
        ..FakeUi::default()
    };
    let auth = FakeAuthorizer::default();
    run(&svc, &ui, &auth, Some(LINK));
    assert!(!*auth.alive.borrow());
    let log = ui.log.borrow();
    assert!(log.last().unwrap().starts_with("problem: Not approved"), "{log:?}");
}

#[test]
fn no_service_is_explained() {
    let dir = tempfile::tempdir().unwrap();
    let ui = FakeUi::default();
    run_flow(
        &ui,
        &FakeAuthorizer::default(),
        &dir.path().join("enroll.sock"),
        ServiceTrust::SameUid,
        Some(LINK.into()),
    );
    let log = ui.log.borrow();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("problem: Faro isn't answering"));
}

#[test]
fn only_root_counts_as_the_service_in_production() {
    // The fake service runs as the test's uid, so `Root` trust refuses it
    // (unless the tests run as root) before sending the link.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let svc = FakeService::start(vec![status(false)]);
    let ui = FakeUi::default();
    run_flow(
        &ui,
        &FakeAuthorizer::default(),
        &svc.socket,
        ServiceTrust::Root,
        Some(LINK.into()),
    );
    assert!(svc.requests().is_empty(), "nothing sent to a non-root listener");
    assert!(ui.log.borrow()[0].starts_with("problem: Faro isn't answering"));
}
