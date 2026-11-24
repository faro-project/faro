//! Outgoing email.
//!
//! Implementations:
//!
//! * [`SmtpMailer`]: real delivery through any SMTP server (church Google
//!   Workspace / Microsoft 365, Mailgun, SES, a local relay) via lettre, with
//!   STARTTLS, implicit TLS, or plaintext for a localhost relay.
//! * [`LogMailer`]: in `--dev` it prints each message (including sign-in
//!   links) to **stderr** so a developer can click them; otherwise it only
//!   logs that a message was dropped because SMTP is not configured. It never
//!   uses `tracing` for message content, so sign-in tokens cannot end up in
//!   structured logs that get shipped elsewhere.
//! * [`TestMailer`]: records messages in memory for integration tests, and
//!   can be told to fail (for retry tests).
//!
//! Errors are reduced to a short code ([`MailError::code`]) before they are
//! stored or logged: SMTP server responses can echo recipient addresses.
//!
//! Notification email must stay content-free (§5.4): callers only ever pass
//! text like "Urgent: new alert for Sam on Laptop-X. Open Faro to view."

use crate::config::{SmtpConfig, SmtpTls};
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A plain-text email.
#[derive(Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
}

impl std::fmt::Debug for Email {
    // Bodies can contain sign-in links: keep them out of Debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Email")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    #[error("email delivery is not configured")]
    NotConfigured,
    /// The recipient or sender address does not parse. Retrying won't help.
    #[error("invalid email address")]
    InvalidAddress,
    /// The server permanently refused **this recipient** (unknown mailbox,
    /// mailbox name not allowed, ...). Retrying won't help.
    #[error("recipient rejected by the SMTP server")]
    RecipientRejected,
    /// The server temporarily refused this recipient (mailbox busy or
    /// full, greylisting). Retried with backoff, counted against the row.
    #[error("recipient temporarily refused by the SMTP server")]
    RecipientDeferred,
    /// The server refused for a reason that is not about the recipient: bad
    /// credentials (535), authentication required (530), relaying denied,
    /// a refused sender, a syntax error. This is the instance's SMTP
    /// configuration, so it says nothing about the row being sent and is
    /// retried until an admin fixes it.
    #[error("email refused by the SMTP server")]
    Rejected,
    /// A transient failure: connection, TLS, timeout or a 4xx response.
    #[error("email delivery failed ({0})")]
    Transport(&'static str),
}

impl MailError {
    /// Short machine code stored in `notifications.last_error`.
    pub fn code(&self) -> &'static str {
        match self {
            MailError::NotConfigured => "not_configured",
            MailError::InvalidAddress => "invalid_address",
            MailError::RecipientRejected => "recipient_rejected",
            MailError::RecipientDeferred => "recipient_deferred",
            MailError::Rejected => "rejected",
            MailError::Transport(c) => c,
        }
    }

    /// Whether retrying this recipient can never succeed.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            MailError::InvalidAddress | MailError::RecipientRejected
        )
    }

    /// Whether the failure is about the instance's mail setup or its
    /// connection to the SMTP server rather than about one message: every
    /// other message would fail the same way right now. The notifier pauses
    /// instead of charging an attempt to each queued notification, so an
    /// outage (an expired app password, a down relay) never makes alerts
    /// raised during it fail permanently.
    pub fn is_instance_wide(&self) -> bool {
        matches!(
            self,
            MailError::NotConfigured | MailError::Rejected | MailError::Transport(_)
        )
    }
}

/// Classify a negative SMTP reply by its basic code and, when the server
/// sent one, its enhanced status code (RFC 3463 `class.subject.detail`).
///
/// Only replies that are about the *recipient* are charged to the message:
/// enhanced subjects 1 (addressing, except the sender codes x.1.7/x.1.8) and
/// 2 (mailbox), or, without an enhanced code, 550/551/553 (permanent) and
/// 450/452 (temporary). Everything else (530/535 authentication, 5.7.x
/// policy such as "relaying denied", 421 service unavailable, 5.0.x syntax)
/// is the instance's problem and classified as instance-wide.
pub fn classify_reply(code: u16, enhanced: Option<(u8, u16, u16)>) -> MailError {
    let permanent = (500..600).contains(&code);
    let recipient = match enhanced {
        Some((_, 1, detail)) => !matches!(detail, 7 | 8),
        Some((_, 2, _)) => true,
        Some(_) => false,
        None => matches!(code, 450 | 452 | 550 | 551 | 553),
    };
    match (recipient, permanent) {
        (true, true) => MailError::RecipientRejected,
        (true, false) => MailError::RecipientDeferred,
        (false, true) => MailError::Rejected,
        (false, false) => MailError::Transport("temporary_rejection"),
    }
}

/// The RFC 3463 enhanced status code at the start of an SMTP reply text
/// (`5.1.1 User unknown`), if any. Only digits are read; the text itself is
/// never stored or logged (it can echo addresses).
pub fn enhanced_status(text: &str) -> Option<(u8, u16, u16)> {
    // lettre renders the reply as "<code> <text>" or just the text; take the
    // first token shaped like d.ddd.ddd.
    text.split_whitespace().take(3).find_map(|tok| {
        let mut it = tok.split('.');
        let class: u8 = it.next()?.parse().ok()?;
        let subject: u16 = it.next()?.parse().ok()?;
        let detail: u16 = it.next()?.parse().ok()?;
        (it.next().is_none() && matches!(class, 2 | 4 | 5) && subject < 1000 && detail < 1000)
            .then_some((class, subject, detail))
    })
}

pub type MailFuture<'a> = Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>>;

pub trait Mailer: Send + Sync + std::fmt::Debug + 'static {
    fn send(&self, email: Email) -> MailFuture<'_>;
}

/// Development / unconfigured mailer. See module docs.
#[derive(Debug, Clone, Copy)]
pub struct LogMailer {
    reveal_content: bool,
}

impl LogMailer {
    /// `reveal_content` must only be true in `--dev`.
    pub fn new(reveal_content: bool) -> Self {
        LogMailer { reveal_content }
    }
}

impl Mailer for LogMailer {
    fn send(&self, email: Email) -> MailFuture<'_> {
        let reveal = self.reveal_content;
        Box::pin(async move {
            if reveal {
                eprintln!(
                    "\n----- [dev] email to {} -----\nSubject: {}\n\n{}\n-----------------------------\n",
                    email.to, email.subject, email.text
                );
                Ok(())
            } else {
                tracing::warn!(
                    subject = %email.subject,
                    "email not sent: SMTP is not configured"
                );
                Err(MailError::NotConfigured)
            }
        })
    }
}

/// Real SMTP delivery (lettre, tokio, rustls with the ring provider).
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    host: String,
}

impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailer")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// Per-attempt SMTP timeout, so a hung server cannot stall the notifier.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

impl SmtpMailer {
    /// Build a transport from validated config. Does not connect.
    pub fn from_config(cfg: &SmtpConfig) -> Result<Self, MailError> {
        let (Some(host), Some(from)) = (&cfg.host, &cfg.from) else {
            return Err(MailError::NotConfigured);
        };
        let from: Mailbox = from.parse().map_err(|_| MailError::InvalidAddress)?;
        let builder = match cfg.tls {
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|_| MailError::Transport("tls_setup"))?,
            SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|_| MailError::Transport("tls_setup"))?,
            // Plaintext is only accepted by config validation for a relay on
            // localhost (or --dev).
            SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        };
        let mut builder = builder.timeout(Some(SMTP_TIMEOUT));
        if let Some(port) = cfg.port {
            builder = builder.port(port);
        }
        if let (Some(u), Some(p)) = (&cfg.username, &cfg.password) {
            builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
        }
        Ok(SmtpMailer {
            transport: builder.build(),
            from,
            host: host.clone(),
        })
    }

    /// Connect and authenticate without sending anything (`doctor`).
    pub async fn test_connection(&self) -> Result<(), MailError> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(MailError::Transport("connection_refused")),
            Err(e) => Err(classify(&e)),
        }
    }
}

/// Reduce a lettre error to a code without its text.
fn classify(e: &lettre::transport::smtp::Error) -> MailError {
    if let Some(code) = e.status() {
        // The reply text is only scanned for its enhanced status code.
        let enhanced = std::error::Error::source(e).and_then(|s| enhanced_status(&s.to_string()));
        return classify_reply(u16::from(code), enhanced);
    }
    if e.is_timeout() {
        MailError::Transport("timeout")
    } else if e.is_tls() {
        MailError::Transport("tls")
    } else {
        MailError::Transport("connection")
    }
}

impl Mailer for SmtpMailer {
    fn send(&self, email: Email) -> MailFuture<'_> {
        Box::pin(async move {
            let to: Mailbox = email.to.parse().map_err(|_| MailError::InvalidAddress)?;
            let msg = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(email.subject)
                .header(ContentType::TEXT_PLAIN)
                .body(email.text)
                .map_err(|_| MailError::InvalidAddress)?;
            self.transport
                .send(msg)
                .await
                .map(|_| ())
                .map_err(|e| classify(&e))
        })
    }
}

/// In-memory mailer for tests. Clones share the same outbox.
#[derive(Debug, Clone, Default)]
pub struct TestMailer {
    sent: Arc<Mutex<Vec<Email>>>,
    notify: Arc<tokio::sync::Notify>,
    failure: Arc<Mutex<Option<MailError>>>,
}

impl TestMailer {
    pub fn new() -> Self {
        Self::default()
    }

    /// While set, every send fails with a transient transport error (an
    /// instance-wide outage).
    pub fn set_failing(&self, failing: bool) {
        self.fail_with(failing.then_some(MailError::Transport("test_failure")));
    }

    /// While `Some`, every send fails with that error.
    pub fn fail_with(&self, failure: Option<MailError>) {
        if let Ok(mut f) = self.failure.lock() {
            *f = failure;
        }
    }

    /// Forget everything sent so far.
    pub fn clear(&self) {
        if let Ok(mut v) = self.sent.lock() {
            v.clear();
        }
    }

    /// Everything sent so far.
    pub fn sent(&self) -> Vec<Email> {
        self.sent.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Wait until an email to `to` has been sent (sending is asynchronous so
    /// that response timing does not reveal whether an account exists).
    pub async fn wait_for(&self, to: &str, timeout: Duration) -> Option<Email> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            if let Some(e) = self.sent().into_iter().rev().find(|e| e.to == to) {
                return Some(e);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }
}

impl Mailer for TestMailer {
    fn send(&self, email: Email) -> MailFuture<'_> {
        Box::pin(async move {
            let failure = self.failure.lock().ok().and_then(|f| *f);
            if let Some(e) = failure {
                return Err(e);
            }
            if let Ok(mut v) = self.sent.lock() {
                v.push(email);
            }
            self.notify.notify_waiters();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mailer_wait_for() {
        let m = TestMailer::new();
        let m2 = m.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            m2.send(Email {
                to: "a@example.org".into(),
                subject: "hi".into(),
                text: "body".into(),
            })
            .await
            .unwrap();
        });
        let got = m
            .wait_for("a@example.org", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got.text, "body");
        assert!(m
            .wait_for("b@example.org", Duration::from_millis(30))
            .await
            .is_none());
    }

    #[test]
    fn smtp_mailer_requires_valid_config() {
        let mut c = SmtpConfig::default();
        assert!(matches!(
            SmtpMailer::from_config(&c),
            Err(MailError::NotConfigured)
        ));
        c.host = Some("smtp.example.org".into());
        c.from = Some("not an address".into());
        assert!(matches!(
            SmtpMailer::from_config(&c),
            Err(MailError::InvalidAddress)
        ));
        c.from = Some("Faro <faro@example.org>".into());
        c.username = Some("u".into());
        c.password = Some("hunter2".into());
        for tls in [SmtpTls::Starttls, SmtpTls::Tls, SmtpTls::None] {
            c.tls = tls;
            let m = SmtpMailer::from_config(&c).unwrap();
            assert!(!format!("{m:?}").contains("hunter2"));
        }
    }

    #[tokio::test]
    async fn smtp_send_rejects_bad_recipient_without_network() {
        let c = SmtpConfig {
            host: Some("127.0.0.1".into()),
            port: Some(1),
            from: Some("faro@example.org".into()),
            tls: SmtpTls::None,
            ..SmtpConfig::default()
        };
        let m = SmtpMailer::from_config(&c).unwrap();
        let r = m
            .send(Email {
                to: "not an address".into(),
                subject: "s".into(),
                text: "t".into(),
            })
            .await;
        assert!(matches!(r, Err(MailError::InvalidAddress)));
        assert!(r.unwrap_err().is_permanent());
        // Port 1 on localhost refuses: a transient transport error, no text.
        let r = m
            .send(Email {
                to: "a@example.org".into(),
                subject: "s".into(),
                text: "t".into(),
            })
            .await
            .unwrap_err();
        assert!(!r.is_permanent());
        assert!(!r.code().contains("example.org"));
    }

    #[tokio::test]
    async fn test_mailer_can_fail() {
        let m = TestMailer::new();
        m.set_failing(true);
        let e = Email {
            to: "a@example.org".into(),
            subject: "s".into(),
            text: "t".into(),
        };
        assert!(m.send(e.clone()).await.is_err());
        assert!(m.sent().is_empty());
        m.set_failing(false);
        m.send(e).await.unwrap();
        assert_eq!(m.sent().len(), 1);
    }

    #[test]
    fn only_recipient_replies_are_charged_to_the_message() {
        use MailError::*;
        // Authentication and policy failures are the instance's problem.
        assert_eq!(classify_reply(535, Some((5, 7, 8))), Rejected);
        assert_eq!(classify_reply(535, None), Rejected);
        assert_eq!(classify_reply(530, Some((5, 7, 0))), Rejected);
        assert_eq!(
            classify_reply(550, Some((5, 7, 1))),
            Rejected,
            "relay denied"
        );
        assert_eq!(classify_reply(554, None), Rejected);
        assert_eq!(classify_reply(501, Some((5, 1, 7))), Rejected, "bad sender");
        assert_eq!(classify_reply(553, Some((5, 1, 8))), Rejected, "bad sender");
        assert_eq!(classify_reply(421, None), Transport("temporary_rejection"));
        // Recipient-specific replies.
        assert_eq!(classify_reply(550, Some((5, 1, 1))), RecipientRejected);
        assert_eq!(classify_reply(550, None), RecipientRejected);
        assert_eq!(classify_reply(553, None), RecipientRejected);
        assert_eq!(classify_reply(552, Some((5, 2, 2))), RecipientRejected);
        assert_eq!(classify_reply(450, Some((4, 2, 1))), RecipientDeferred);
        assert_eq!(classify_reply(452, None), RecipientDeferred);
        for e in [Rejected, Transport("x"), NotConfigured] {
            assert!(e.is_instance_wide() && !e.is_permanent(), "{e:?}");
        }
        for e in [RecipientRejected, InvalidAddress] {
            assert!(e.is_permanent() && !e.is_instance_wide(), "{e:?}");
        }
        assert!(!RecipientDeferred.is_permanent() && !RecipientDeferred.is_instance_wide());
    }

    #[test]
    fn enhanced_status_codes_are_parsed_strictly() {
        assert_eq!(
            enhanced_status("5.7.8 Username and Password not accepted"),
            Some((5, 7, 8))
        );
        assert_eq!(enhanced_status("535 5.7.8 bad"), Some((5, 7, 8)));
        assert_eq!(enhanced_status("User unknown"), None);
        assert_eq!(enhanced_status("5.7"), None);
        assert_eq!(enhanced_status("1.2.3 x"), None);
        assert_eq!(enhanced_status("5.1.1.1 x"), None);
        assert_eq!(enhanced_status(""), None);
    }

    #[test]
    fn email_debug_hides_body() {
        let e = Email {
            to: "a@example.org".into(),
            subject: "Sign in".into(),
            text: "token=SECRET".into(),
        };
        let d = format!("{e:?}");
        assert!(!d.contains("SECRET") && !d.contains("a@example.org"));
    }
}
