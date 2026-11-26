//! The notifier (§4.1 item 5, §5.4): tells people *that* something happened,
//! never *what*.
//!
//! Three steps, each a function the worker loop calls (and tests call
//! directly with a [`crate::clock::ManualClock`]):
//!
//! 1. [`dispatch`]: fan every new alert (and report) out to its recipients
//!    (the member, the member's **active** allies, and an alert's extra
//!    recipient: the ally who was just removed; minus an alert's skip
//!    recipient: the ally who was just added and is told by a notice). Each recipient's preference
//!    for that member and urgency picks `immediate`, `digest` or `off`
//!    (defaults: urgent → immediate, normal → digest, none → never);
//!    tamper-class alerts cannot be `off` and fall back to `digest`
//!    ([`policy::effective_mode`]). Quiet hours push the due time out.
//! 2. [`send_immediate`]: email each due immediate notification.
//! 3. [`send_digests`]: bundle each recipient's due digest items into a
//!    single email once their oldest pending item is an hour old. Checked
//!    every minute, so the hourly cadence survives restarts (a fixed hourly
//!    timer would never fire on an instance restarted more often than that).
//!
//! **Content-free text.** Messages name only the member, the device and an
//! urgency word, e.g. *"Urgent: new alert for Sam on Laptop-X. Open Faro to
//! view."* Nothing derived from an event body exists on the server to leak,
//! and nothing from headers beyond urgency is used either (not even the
//! event kind), so a mailbox compromise reveals no more than "something
//! happened".
//!
//! **Account status is the exception.** When an admin disables or
//! re-enables an account (`account_disabled` / `account_enabled` on that
//! person, `ally_disabled` / `ally_enabled` on each member they are an ally
//! for), the email says so in words: it reports a decision made on the
//! server about an account, nothing a device recorded, and the people
//! affected must understand it from the email alone (the disabled person
//! cannot sign in to read the feed). The disabled person is the one
//! recipient told although their account is disabled. Deletion notices
//! (`account_deleted` on the person, `ally_deleted` on each member they are
//! an ally for, and `account_deletion_cancelled` on both) are worded the
//! same way, with the dates taken from the alert's detail (§12). When an
//! admin asked for the deletion (`requested_by=admin`), they say the
//! account is "being deleted by the instance administrator", and a
//! disabled person is told too: it is their data.
//!
//! **Admin log entries** are told the same way, in words: role changes to
//! the person and every other admin ([`crate::roles`]), deletions an admin
//! asked for and their cancellation to every admin, and disabling or
//! re-enabling an account to every admin but the one who did it. They are
//! not alerts: no member's feed shows them and no ally hears of them.
//! [`crate::roles::tell`] writes their notification rows itself, always
//! immediate, so there is nothing to fan out.
//!
//! **Delivery.** A failure about one recipient (an unknown mailbox, a full
//! one) is charged to that notification: retried with exponential backoff
//! ([`policy::backoff_ms`]) up to [`policy::MAX_ATTEMPTS`], then marked
//! `failed`; a permanent recipient rejection fails at once. A failure about
//! the instance's own mail setup (no connection, TLS, 535 bad credentials,
//! relaying denied: [`crate::mailer::MailError::is_instance_wide`]) is not
//! about any one message, so the pass stops and every row it would have
//! sent is postponed by [`policy::OUTAGE_RETRY_MS`] **without** being
//! charged an attempt. An SMTP outage therefore never makes alerts raised
//! during it (tamper-class ones included) fail for good; they go out once
//! the admin fixes the configuration. Only a short error code is stored;
//! admins see counts only.
//!
//! **Single sender.** Sends are not claimed with row locks, so exactly one
//! process may run the notifier (the default single-binary deployment).

pub mod policy;

use crate::db::repo::admin_log::{Action, Via};
use crate::db::repo::notifications::{
    self as notif, AdminLogNotice, DueNotification, NewNotification, Target,
};
use crate::db::repo::{alerts, allies, reports, users};
use crate::error::AppError;
use crate::mailer::Email;
use crate::state::AppState;
use faro_proto::api::ServerAlertKind;
use faro_proto::{Urgency, UserId};
use policy::Mode;
use std::collections::{BTreeMap, HashMap};

/// Alerts / reports fanned out per pass.
const DISPATCH_BATCH: i64 = 200;
/// Immediate notifications sent per pass.
const SEND_BATCH: i64 = 100;
/// Digest items considered per pass (all recipients together).
const DIGEST_BATCH: i64 = 5000;

/// How often the dispatcher and immediate sender run.
pub const NOTIFY_INTERVAL_SECS: u64 = 10;
/// A recipient's digest goes out once their oldest pending item is this old.
pub const DIGEST_INTERVAL_SECS: u64 = 3600;
/// How often the digest worker checks.
pub const DIGEST_CHECK_SECS: u64 = 60;

/// Fan out undispatched alerts and reports. Returns notifications created.
pub async fn dispatch(state: &AppState) -> Result<usize, AppError> {
    let mut created = 0;
    for a in alerts::undispatched(state.db().pool(), DISPATCH_BATCH).await? {
        let tamper = policy::is_tamper_class(&a.source, &a.kind, a.urgency);
        created += fan_out(
            state,
            &Target::Alert(a.id.clone()),
            &a.member_id,
            a.urgency,
            tamper,
            a.extra_recipient.as_ref(),
            a.skip_recipient.as_ref(),
        )
        .await?;
    }
    // Reports are routine: they notify at urgency `none`, i.e. not at all
    // unless a recipient opts in (to a digest line, typically).
    for r in reports::undispatched(state.db().pool(), DISPATCH_BATCH).await? {
        created += fan_out(
            state,
            &Target::Report(r.id.clone()),
            &r.member_id,
            Urgency::None,
            false,
            None,
            None,
        )
        .await?;
    }
    Ok(created)
}

async fn fan_out(
    state: &AppState,
    target: &Target,
    member: &UserId,
    urgency: Urgency,
    tamper: bool,
    extra: Option<&UserId>,
    skip: Option<&UserId>,
) -> Result<usize, AppError> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    // The member is always told; `skip` only ever removes an ally.
    let mut recipients = vec![member.clone()];
    for a in allies::active_ally_ids(&mut *tx, member).await? {
        if Some(&a) != skip && !recipients.contains(&a) {
            recipients.push(a);
        }
    }
    if let Some(x) = extra {
        if !recipients.contains(x) {
            recipients.push(x.clone());
        }
    }
    let mut created = 0;
    for r in &recipients {
        let prefs = notif::get_prefs(&mut *tx, r, member).await?;
        // Telling a removed ally about their removal cannot be switched off
        // either: that notice is the whole point (§3.7).
        let floor = tamper || extra == Some(r);
        let mode = policy::effective_mode(prefs.stored_mode(urgency), urgency, floor);
        let due = policy::quiet_until(now, prefs.quiet.as_ref()).unwrap_or(now);
        if notif::insert(
            &mut *tx,
            &NewNotification {
                target,
                recipient: r,
                urgency,
                mode: (mode != Mode::Off).then_some(mode),
                due_at_ms: due,
                now_ms: now,
            },
        )
        .await?
        {
            created += 1;
        }
    }
    match target {
        Target::Alert(id) => alerts::mark_dispatched(&mut *tx, id, now).await?,
        Target::Report(id) => reports::mark_dispatched(&mut *tx, id, now).await?,
        // Written with their recipients by `crate::roles` and
        // `crate::groups`; never fanned out.
        Target::AdminLog(_) | Target::GroupNotice(_) => {}
    }
    tx.commit().await?;
    Ok(created)
}

/// Whether a due row must be dropped rather than sent. A disabled account
/// hears nothing, except that it was disabled, and that an admin is
/// deleting it (or cancelled that): it is their data.
fn undeliverable(n: &DueNotification) -> bool {
    let told_while_disabled = n.recipient_id == n.member_id
        && matches!(
            account_status(n),
            Some(
                ServerAlertKind::AccountDisabled
                    | ServerAlertKind::AccountDeleted
                    | ServerAlertKind::AccountDeletionCancelled
            )
        );
    (n.recipient_disabled && !told_while_disabled) || !n.entitled
}

/// Whether an alert's `key=value;…` detail has `key=value`.
fn detail_is(n: &DueNotification, key: &str, value: &str) -> bool {
    n.alert_detail.as_deref().is_some_and(|d| {
        d.split(';')
            .any(|part| part.strip_prefix(key).and_then(|r| r.strip_prefix('=')) == Some(value))
    })
}

/// The account-status kind of an alert notification, if it is one.
fn account_status(n: &DueNotification) -> Option<ServerAlertKind> {
    let (source, kind) = n.alert.as_ref()?;
    if source != "server" {
        return None;
    }
    ServerAlertKind::parse(kind).filter(|k| {
        matches!(
            k,
            ServerAlertKind::AccountDisabled
                | ServerAlertKind::AccountEnabled
                | ServerAlertKind::AllyDisabled
                | ServerAlertKind::AllyEnabled
                | ServerAlertKind::AccountDeleted
                | ServerAlertKind::AllyDeleted
                | ServerAlertKind::AccountDeletionCancelled
        )
    })
}

/// A millisecond value from an alert's `key=value;…` detail code.
fn detail_ms(n: &DueNotification, key: &str) -> Option<i64> {
    n.alert_detail
        .as_deref()?
        .split(';')
        .find_map(|part| part.strip_prefix(key)?.strip_prefix('='))
        .and_then(|v| v.parse().ok())
}

fn utc(ms: i64) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000)).ok()
}

/// `2 December 2026` (UTC).
pub fn utc_date(ms: i64) -> String {
    utc(ms).map_or_else(
        || "an unknown date".to_owned(),
        |t| format!("{} {} {}", t.day(), t.month(), t.year()),
    )
}

/// `25 November 2026 at 14:03 UTC`.
pub fn utc_time(ms: i64) -> String {
    utc(ms).map_or_else(
        || "an unknown time".to_owned(),
        |t| {
            format!(
                "{} {} {} at {:02}:{:02} UTC",
                t.day(),
                t.month(),
                t.year(),
                t.hour(),
                t.minute()
            )
        },
    )
}

/// Subject and text of a deletion notice: `account_deleted`,
/// `ally_deleted` or `account_deletion_cancelled` (§12). The dates come
/// from the alert itself, so a notice still says what was decided when it
/// was raised, whatever happened since.
fn deletion_text(instance: &str, n: &DueNotification, k: ServerAlertKind) -> (String, String) {
    let member = &n.member_name;
    let to_member = n.recipient_id == n.member_id;
    let ally = n.about_name.as_deref().unwrap_or("an ally");
    let date = detail_ms(n, "purge_after").map_or_else(|| "in 7 days".to_owned(), utc_date);
    let requested = detail_ms(n, "requested").map_or_else(|| "earlier".to_owned(), utc_time);
    let cancelled = n
        .alert_created_at_ms
        .map_or_else(|| "later".to_owned(), utc_time);
    let about_ally = n.about_name.is_some();
    if detail_is(n, "requested_by", "admin") {
        return admin_deletion_text(instance, n, k);
    }
    match (k, about_ally, to_member) {
        (ServerAlertKind::AccountDeleted, _, true) => (
            format!("Your Faro account on {instance} will be deleted on {date}"),
            format!(
                "You asked for your Faro account on {instance} to be deleted. On {date}, \
                 everything this server stores about you is permanently deleted: your \
                 computers, activity, alerts, reports, keys, allies and settings. Until then \
                 nothing changes: your computers are still monitored and your allies still \
                 receive alerts. Everyone in an accountability partnership with you has been \
                 told. You can cancel until then: sign in and choose Cancel deletion. After \
                 {date}, {instance} no longer accepts anything from your computers, so \
                 uninstall Faro from them. Copies in the operator's backups last until those \
                 backups are rotated out. If you didn't ask for this, sign in, cancel the \
                 deletion and contact the people who run {instance}."
            ),
        ),
        (ServerAlertKind::AccountDeleted, _, false) => (
            format!("{member} is deleting their Faro account on {instance}"),
            format!(
                "{member} asked for their Faro account on {instance} to be deleted. Until \
                 {date} nothing changes: their computers are still monitored, you still \
                 receive alerts about them, and {member} can still cancel. On {date}, \
                 everything about {member} is permanently deleted from this server, and their \
                 computers are no longer monitored through {instance}, even if Faro is still \
                 installed on them."
            ),
        ),
        (ServerAlertKind::AllyDeleted, _, true) => (
            format!("Your ally {ally} is deleting their Faro account"),
            format!(
                "{ally}, one of your allies on {instance}, asked for their Faro account to be \
                 deleted. Until {date} they are still your ally, and they can still cancel. On \
                 {date} they stop being your ally and can no longer see anything about you. \
                 Then open Faro and confirm your updated ally list: until you do, your \
                 computers keep encrypting new items to a key that no longer exists."
            ),
        ),
        (ServerAlertKind::AllyDeleted, _, false) => (
            format!("{ally}, also an ally for {member}, is deleting their Faro account"),
            format!(
                "{ally}, who is also an ally for {member} on {instance}, asked for their Faro \
                 account to be deleted. On {date} they stop being an ally for {member}. You \
                 still receive {member}'s alerts."
            ),
        ),
        (_, false, true) => (
            format!("You cancelled the deletion of your Faro account on {instance}"),
            format!(
                "You asked for your Faro account on {instance} to be deleted on {requested} \
                 and cancelled it on {cancelled}. Nothing will be deleted. Everyone in an \
                 accountability partnership with you has been told. If you didn't do this, \
                 contact the people who run {instance}."
            ),
        ),
        (_, false, false) => (
            format!("{member} cancelled the deletion of their Faro account"),
            format!(
                "{member} asked for their Faro account on {instance} to be deleted on \
                 {requested} and cancelled it on {cancelled}. Nothing will be deleted, and you \
                 still receive alerts about them."
            ),
        ),
        (_, true, true) => (
            format!("Your ally {ally} cancelled the deletion of their Faro account"),
            format!(
                "{ally}, one of your allies, asked for their Faro account on {instance} to be \
                 deleted on {requested} and cancelled it on {cancelled}. They stay your ally."
            ),
        ),
        (_, true, false) => (
            format!("{ally}, also an ally for {member}, cancelled the deletion of their account"),
            format!(
                "{ally}, who is also an ally for {member}, asked for their Faro account on \
                 {instance} to be deleted on {requested} and cancelled it on {cancelled}. They \
                 stay an ally for {member}."
            ),
        ),
    }
}

/// [`deletion_text`] for a deletion an admin asked for
/// (`requested_by=admin`): "deleted by the instance administrator". The
/// admin is not named: the admin log says who.
fn admin_deletion_text(
    instance: &str,
    n: &DueNotification,
    k: ServerAlertKind,
) -> (String, String) {
    const ADMIN: &str = "the instance administrator";
    let member = &n.member_name;
    let to_member = n.recipient_id == n.member_id;
    let ally = n.about_name.as_deref().unwrap_or("an ally");
    let about_ally = n.about_name.is_some();
    let date = detail_ms(n, "purge_after").map_or_else(|| "in 7 days".to_owned(), utc_date);
    let requested = detail_ms(n, "requested").map_or_else(|| "earlier".to_owned(), utc_time);
    let cancelled = n
        .alert_created_at_ms
        .map_or_else(|| "later".to_owned(), utc_time);
    // Who cancelled, as the start of a sentence.
    let by_admin = detail_is(n, "cancelled_by", "admin");
    let canceller = match (by_admin, about_ally, to_member) {
        (true, _, _) => "The instance administrator".to_owned(),
        (false, true, _) => ally.to_owned(),
        (false, false, true) => "You".to_owned(),
        (false, false, false) => member.clone(),
    };
    match (k, about_ally, to_member) {
        (ServerAlertKind::AccountDeleted, _, true) => {
            // A disabled person can't sign in to cancel.
            let keep = if n.recipient_disabled {
                format!(
                    "Your account is disabled, so you can't sign in. To keep your account, \
                     contact the people who run {instance} before {date}."
                )
            } else {
                format!(
                    "To keep your account, sign in before {date} and choose Cancel deletion, or \
                     ask the people who run {instance}."
                )
            };
            (
                format!("Your Faro account on {instance} is being deleted by {ADMIN}"),
                format!(
                    "Your Faro account on {instance} is being deleted by {ADMIN}. On {date}, \
                     everything this server stores about you is permanently deleted: your \
                     computers, activity, alerts, reports, keys, allies and settings. Until then \
                     nothing changes: your computers are still monitored and your allies still \
                     receive alerts. Everyone in an accountability partnership with you has been \
                     told. {keep} After {date}, {instance} no longer accepts anything from your \
                     computers, so uninstall Faro from them. Copies in the operator's backups \
                     last until those backups are rotated out."
                ),
            )
        }
        (ServerAlertKind::AccountDeleted, _, false) => (
            format!("{member}'s Faro account on {instance} is being deleted by {ADMIN}"),
            format!(
                "{member}'s Faro account on {instance} is being deleted by {ADMIN}. Until \
                 {date} nothing changes: their computers are still monitored, you still receive \
                 alerts about them, and the deletion can still be cancelled. On {date}, \
                 everything about {member} is permanently deleted from this server, and their \
                 computers are no longer monitored through {instance}, even if Faro is still \
                 installed on them."
            ),
        ),
        (ServerAlertKind::AllyDeleted, _, true) => (
            format!("Your ally {ally}'s Faro account is being deleted by {ADMIN}"),
            format!(
                "The Faro account of {ally}, one of your allies on {instance}, is being deleted \
                 by {ADMIN}. Until {date} they are still your ally, and the deletion can still \
                 be cancelled. On {date} they stop being your ally and can no longer see \
                 anything about you. Then open Faro and confirm your updated ally list: until \
                 you do, your computers keep encrypting new items to a key that no longer \
                 exists."
            ),
        ),
        (ServerAlertKind::AllyDeleted, _, false) => (
            format!(
                "The Faro account of {ally}, also an ally for {member}, is being deleted by \
                 {ADMIN}"
            ),
            format!(
                "The Faro account of {ally}, who is also an ally for {member} on {instance}, is \
                 being deleted by {ADMIN}. On {date} they stop being an ally for {member}. You \
                 still receive {member}'s alerts."
            ),
        ),
        (_, false, true) => {
            let subject = if by_admin {
                format!("The deletion of your Faro account on {instance} was cancelled")
            } else {
                format!("You cancelled the deletion of your Faro account on {instance}")
            };
            let unexpected = if by_admin {
                String::new()
            } else {
                format!(" If you didn't do this, contact the people who run {instance}.")
            };
            (
                subject,
                format!(
                    "On {requested}, {ADMIN} asked for your Faro account on {instance} to be \
                     deleted. {canceller} cancelled it on {cancelled}. Nothing will be deleted. \
                     Everyone in an accountability partnership with you has been told.\
                     {unexpected}"
                ),
            )
        }
        (_, false, false) => (
            format!("The deletion of {member}'s Faro account was cancelled"),
            format!(
                "On {requested}, {ADMIN} asked for {member}'s Faro account on {instance} to be \
                 deleted. {canceller} cancelled it on {cancelled}. Nothing will be deleted, and \
                 you still receive alerts about them."
            ),
        ),
        (_, true, true) => (
            format!("The deletion of your ally {ally}'s Faro account was cancelled"),
            format!(
                "On {requested}, {ADMIN} asked for the Faro account of {ally}, one of your \
                 allies on {instance}, to be deleted. {canceller} cancelled it on {cancelled}. \
                 They stay your ally."
            ),
        ),
        (_, true, false) => (
            format!(
                "The deletion of the account of {ally}, also an ally for {member}, was cancelled"
            ),
            format!(
                "On {requested}, {ADMIN} asked for the Faro account of {ally}, who is also an \
                 ally for {member} on {instance}, to be deleted. {canceller} cancelled it on \
                 {cancelled}. They stay an ally for {member}."
            ),
        ),
    }
}

fn is_deletion_notice(k: ServerAlertKind) -> bool {
    matches!(
        k,
        ServerAlertKind::AccountDeleted
            | ServerAlertKind::AllyDeleted
            | ServerAlertKind::AccountDeletionCancelled
    )
}

/// Subject and text of an account-status notification (see the module docs).
fn account_status_text(
    instance: &str,
    n: &DueNotification,
    k: ServerAlertKind,
) -> (String, String) {
    if is_deletion_notice(k) {
        return deletion_text(instance, n, k);
    }
    let member = &n.member_name;
    let to_member = n.recipient_id == n.member_id;
    let ally = n.about_name.as_deref().unwrap_or("an ally");
    match (k, to_member) {
        (ServerAlertKind::AccountDisabled, true) => (
            format!("Your account on {instance} was disabled"),
            format!(
                "An administrator of {instance} disabled your Faro account, so you can no \
                 longer sign in. Everyone in an accountability partnership with you has been \
                 told. Your computers are still monitored, and your allies still receive alerts \
                 about them. If you think this is a mistake, contact the people who run \
                 {instance}."
            ),
        ),
        (ServerAlertKind::AccountDisabled, false) => (
            format!("{member}'s account on {instance} was disabled"),
            format!(
                "An administrator of {instance} disabled {member}'s Faro account, so {member} \
                 can no longer sign in. {member}'s computers are still monitored, and you will \
                 still receive alerts about them."
            ),
        ),
        (ServerAlertKind::AccountEnabled, true) => (
            format!("Your account on {instance} was re-enabled"),
            format!("An administrator of {instance} re-enabled your Faro account. You can sign in again."),
        ),
        (ServerAlertKind::AccountEnabled, false) => (
            format!("{member}'s account on {instance} was re-enabled"),
            format!(
                "An administrator of {instance} re-enabled {member}'s Faro account. {member} can \
                 sign in again."
            ),
        ),
        (ServerAlertKind::AllyDisabled, true) => (
            format!("Your ally {ally}'s account on {instance} was disabled"),
            format!(
                "An administrator of {instance} disabled the Faro account of {ally}, one of your \
                 allies, so {ally} can no longer sign in to see your alerts and reports. Your \
                 other allies still receive them."
            ),
        ),
        (ServerAlertKind::AllyDisabled, false) => (
            format!("{ally}'s account on {instance} was disabled"),
            format!(
                "An administrator of {instance} disabled the Faro account of {ally}, who is \
                 also an ally for {member}. {ally} can no longer sign in. You still receive \
                 {member}'s alerts."
            ),
        ),
        (ServerAlertKind::AllyEnabled, true) => (
            format!("Your ally {ally}'s account on {instance} was re-enabled"),
            format!(
                "An administrator of {instance} re-enabled the Faro account of {ally}, one of \
                 your allies. {ally} can sign in again and see your alerts and reports."
            ),
        ),
        (_, _) => (
            format!("{ally}'s account on {instance} was re-enabled"),
            format!(
                "An administrator of {instance} re-enabled the Faro account of {ally}, who is \
                 also an ally for {member}."
            ),
        ),
    }
}

/// Subject, text and link of an admin role notice (see the module docs).
fn admin_log_text(
    instance: &str,
    url: &str,
    n: &DueNotification,
    a: &AdminLogNotice,
) -> (String, String, String) {
    let person = &n.member_name;
    let email = &a.user_email;
    let by_you = a.actor_id.as_ref() == Some(&n.recipient_id);
    let who = match (a.via, by_you, a.actor_name.as_deref()) {
        (Via::CommandLine, _, _) => "Someone with access to the server".to_owned(),
        (Via::Console, true, _) => "You".to_owned(),
        (Via::Console, false, Some(name)) => name.to_owned(),
        (Via::Console, false, None) => "An admin".to_owned(),
    };
    let how = match a.via {
        Via::CommandLine => " from the server's command line",
        Via::Console => "",
    };
    let people = format!("{url}/admin/people");
    let no_content = "Being an admin gives no access to anyone's reports, alerts or screenshots.";
    // Deletions (§12): only admins get these; the person and their
    // partners have their own notices.
    match a.action {
        Action::DeletionRequested => {
            let date = utc_date(n.created_at_ms.saturating_add(crate::api::account::HOLD_MS));
            return (
                format!("{person}'s account on {instance} is being deleted"),
                format!(
                    "{who} asked for the Faro account of {person} ({email}) on {instance} to be \
                     deleted. {person} and everyone in an accountability partnership with them \
                     have been told. It is deleted on {date}. Until then, {person} or any admin \
                     can cancel it. Every admin is told about deletions an admin asks for. If you \
                     didn't expect this, check the People page:"
                ),
                people,
            );
        }
        Action::DeletionCancelled => {
            let line = if a.actor_id.as_ref() == Some(&n.member_id) {
                format!(
                    "{person} ({email}) cancelled the deletion of their Faro account on {instance}"
                )
            } else {
                format!(
                    "{who} cancelled the deletion of the Faro account of {person} ({email}) on \
                     {instance}"
                )
            };
            return (
                format!("The deletion of {person}'s account on {instance} was cancelled"),
                format!(
                    "{line}. An admin had asked for it. Nothing will be deleted. {person} and \
                     everyone in an accountability partnership with them have been told. The \
                     admin log on the People page shows who asked:"
                ),
                people,
            );
        }
        // `faro-server admin grant --create`: the person's welcome. The
        // role notice follows separately.
        Action::AccountCreated if n.recipient_id == n.member_id => {
            return (
                format!("A Faro account was created for you on {instance}"),
                format!(
                    "{who} created a Faro account for you on {instance}{how}, with this email \
                     address. To sign in, open the link below and enter this address: Faro \
                     emails you a sign-in link. No password is needed. If you didn't expect \
                     this, contact the people who run {instance}."
                ),
                format!("{url}/signin"),
            );
        }
        Action::AccountCreated => {
            return (
                format!("An account was created for {person} on {instance}"),
                format!("{who} created a Faro account for {person} ({email}) on {instance}{how}."),
                people,
            );
        }
        // Disabling and re-enabling: only the other admins get these; the
        // person and their partners have their own notices (invariant 6).
        Action::AccountDisabled => {
            return (
                format!("{person}'s account on {instance} was disabled"),
                format!(
                    "{who} disabled the Faro account of {person} ({email}) on {instance}. \
                     {person} can't sign in, but their computers keep reporting. {person} and \
                     everyone in an accountability partnership with them have been told. Every \
                     admin is told when an account is disabled or re-enabled. If you didn't \
                     expect this, check the People page:"
                ),
                people,
            );
        }
        Action::AccountEnabled => {
            return (
                format!("{person}'s account on {instance} was re-enabled"),
                format!(
                    "{who} re-enabled the Faro account of {person} ({email}) on {instance}. \
                     {person} can sign in again. {person} and everyone in an accountability \
                     partnership with them have been told. Every admin is told when an account \
                     is disabled or re-enabled. If you didn't expect this, check the People \
                     page:"
                ),
                people,
            );
        }
        // Never queued as a notification (participants have their own
        // content-free notice); worded in case it ever is.
        Action::GroupArchived => {
            return (
                format!("A group on {instance} was archived"),
                format!("{who} archived a group on {instance}."),
                people,
            );
        }
        Action::AdminGranted | Action::AdminRevoked => {}
    }
    if n.recipient_id == n.member_id {
        let (subject, line) = match a.action {
            Action::AdminGranted => (
                format!("You are now an admin of {instance}"),
                format!(
                    "{who} made you an admin of {instance}{how}. You can now change its \
                     settings, invite people and disable accounts. {no_content} Every other admin \
                     has been told. If you didn't expect this, contact the other admins of \
                     {instance}."
                ),
            ),
            // Deletions, new accounts and account status were worded above.
            Action::AdminRevoked
            | Action::DeletionRequested
            | Action::DeletionCancelled
            | Action::AccountCreated
            | Action::AccountDisabled
            | Action::AccountEnabled
            | Action::GroupArchived => (
                format!("You are no longer an admin of {instance}"),
                format!(
                    "{who} removed your admin role on {instance}{how}. You can still sign in, and \
                     nothing else about your account changed. Every other admin has been told. If \
                     you think this is a mistake, contact the other admins of {instance}."
                ),
            ),
        };
        return (subject, line, url.to_owned());
    }
    let (subject, line) = match a.action {
        Action::AdminGranted => (
            format!("{person} is now an admin of {instance}"),
            format!(
                "{who} made {person} ({email}) an admin of {instance}{how}. {no_content} Every \
                 admin is told when someone becomes an admin or stops being one. If you didn't \
                 expect this, check who is an admin on the People page:"
            ),
        ),
        // Deletions, new accounts and account status were worded above.
        Action::AdminRevoked
        | Action::DeletionRequested
        | Action::DeletionCancelled
        | Action::AccountCreated
        | Action::AccountDisabled
        | Action::AccountEnabled
        | Action::GroupArchived => (
            format!("{person} is no longer an admin of {instance}"),
            format!(
                "{who} removed the admin role from {person} ({email}) on {instance}{how}. Every \
                 admin is told when someone becomes an admin or stops being one. If you didn't \
                 expect this, check who is an admin on the People page:"
            ),
        ),
    };
    (subject, line, people)
}

/// Re-check quiet hours at send time (a retry or a digest may fall inside
/// them). Returns the deferral instant, if any.
async fn quiet_deferral(
    state: &AppState,
    cache: &mut HashMap<(UserId, UserId), Option<i64>>,
    recipient: &UserId,
    member: &UserId,
    now: i64,
) -> Result<Option<i64>, AppError> {
    let key = (recipient.clone(), member.clone());
    if let Some(v) = cache.get(&key) {
        return Ok(*v);
    }
    let prefs = notif::get_prefs(state.db().pool(), recipient, member).await?;
    let v = policy::quiet_until(now, prefs.quiet.as_ref());
    cache.insert(key, v);
    Ok(v)
}

/// Outcome counts of a send pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendSummary {
    pub sent: usize,
    pub failed_attempts: usize,
    pub deferred: usize,
    pub dropped: usize,
    /// Rows postponed, uncharged, because the mail setup itself failed.
    pub paused: usize,
}

/// The mail setup failed (see the module docs): postpone `ids` without
/// charging them an attempt.
async fn pause_for_outage(
    state: &AppState,
    ids: &[String],
    err: &crate::mailer::MailError,
    now: i64,
) -> Result<(), AppError> {
    let next = now.saturating_add(policy::OUTAGE_RETRY_MS);
    for id in ids {
        notif::postpone(state.db().pool(), id, err.code(), next).await?;
    }
    tracing::warn!(
        code = err.code(),
        postponed = ids.len(),
        "email delivery is failing for every message; check the SMTP settings"
    );
    Ok(())
}

/// A failure about one recipient: charge an attempt, give up when it can
/// never succeed or after [`policy::MAX_ATTEMPTS`].
async fn record_failure(
    state: &AppState,
    ids: &[String],
    attempts_before: i64,
    err: &crate::mailer::MailError,
    now: i64,
) -> Result<(), AppError> {
    debug_assert!(!err.is_instance_wide());
    let attempts = attempts_before + 1;
    let give_up = err.is_permanent() || attempts >= policy::MAX_ATTEMPTS;
    let next = now.saturating_add(policy::backoff_ms(attempts));
    for id in ids {
        notif::mark_attempt_failed(state.db().pool(), id, err.code(), next, give_up).await?;
    }
    tracing::warn!(
        code = err.code(),
        attempts,
        give_up,
        count = ids.len(),
        "notification delivery failed"
    );
    Ok(())
}

/// Send every due immediate notification.
pub async fn send_immediate(state: &AppState) -> Result<SendSummary, AppError> {
    let now = state.now_ms();
    let mut s = SendSummary::default();
    let mut quiet = HashMap::new();
    let due = notif::due(state.db().pool(), Mode::Immediate, now, SEND_BATCH).await?;
    let mut rows = due.into_iter();
    while let Some(n) = rows.next() {
        if undeliverable(&n) {
            notif::suppress(state.db().pool(), &n.id).await?;
            s.dropped += 1;
            continue;
        }
        if let Some(until) =
            quiet_deferral(state, &mut quiet, &n.recipient_id, &n.member_id, now).await?
        {
            notif::defer(state.db().pool(), &n.id, until).await?;
            s.deferred += 1;
            continue;
        }
        let email = compose_immediate(state, &n);
        match state.mailer().send(email).await {
            Ok(()) => {
                notif::mark_sent(state.db().pool(), &n.id, now).await?;
                s.sent += 1;
            }
            Err(e) if e.is_instance_wide() => {
                // Nothing else would get through either: stop the pass.
                let ids: Vec<String> = std::iter::once(n.id).chain(rows.map(|r| r.id)).collect();
                pause_for_outage(state, &ids, &e, now).await?;
                s.failed_attempts += 1;
                s.paused += ids.len();
                break;
            }
            Err(e) => {
                record_failure(state, std::slice::from_ref(&n.id), n.attempts, &e, now).await?;
                s.failed_attempts += 1;
            }
        }
    }
    Ok(s)
}

/// Send one digest per recipient with due digest items.
pub async fn send_digests(state: &AppState) -> Result<SendSummary, AppError> {
    let now = state.now_ms();
    let mut s = SendSummary::default();
    let mut quiet = HashMap::new();
    let due = notif::due(state.db().pool(), Mode::Digest, now, DIGEST_BATCH).await?;
    let mut by_recipient: BTreeMap<String, Vec<DueNotification>> = BTreeMap::new();
    for n in due {
        if undeliverable(&n) {
            notif::suppress(state.db().pool(), &n.id).await?;
            s.dropped += 1;
            continue;
        }
        if let Some(until) =
            quiet_deferral(state, &mut quiet, &n.recipient_id, &n.member_id, now).await?
        {
            notif::defer(state.db().pool(), &n.id, until).await?;
            s.deferred += 1;
            continue;
        }
        by_recipient
            .entry(n.recipient_id.as_str().to_owned())
            .or_default()
            .push(n);
    }
    let ripe_before = now.saturating_sub(DIGEST_INTERVAL_SECS as i64 * 1000);
    // Wait until the oldest item has waited a full interval; everything
    // queued since rides along.
    let ripe: Vec<&Vec<DueNotification>> = by_recipient
        .values()
        .filter(|items| items.iter().map(|n| n.created_at_ms).min().unwrap_or(now) <= ripe_before)
        .collect();
    for (i, items) in ripe.iter().enumerate() {
        let Some(first) = items.first() else { continue };
        let email = compose_digest(state, &first.recipient_email, items);
        let ids: Vec<String> = items.iter().map(|n| n.id.clone()).collect();
        match state.mailer().send(email).await {
            Ok(()) => {
                for id in &ids {
                    notif::mark_sent(state.db().pool(), id, now).await?;
                }
                s.sent += 1;
            }
            Err(e) if e.is_instance_wide() => {
                // Nothing else would get through either: stop the pass.
                let ids: Vec<String> = ripe[i..]
                    .iter()
                    .flat_map(|items| items.iter().map(|n| n.id.clone()))
                    .collect();
                pause_for_outage(state, &ids, &e, now).await?;
                s.failed_attempts += 1;
                s.paused += ids.len();
                break;
            }
            Err(e) => {
                let attempts = items.iter().map(|n| n.attempts).max().unwrap_or(0);
                record_failure(state, &ids, attempts, &e, now).await?;
                s.failed_attempts += 1;
            }
        }
    }
    Ok(s)
}

/// Subject and text of a group notice. **Never names the group or anything
/// about it** (GROUPS.md principle 7): email passes through third parties,
/// and a group's name is often sensitive. The name is shown only inside
/// Faro, after sign-in.
pub(crate) fn group_notice_text(
    instance: &str,
    g: &crate::db::repo::notifications::GroupNoticeInfo,
) -> (String, String) {
    use crate::db::repo::group_notices::NoticeKind;
    let who = g.actor_name.as_deref().unwrap_or("Someone");
    let (subject, line) = match (NoticeKind::parse(&g.kind), g.summary) {
        (Some(NoticeKind::GroupJoined | NoticeKind::GroupLeft), true) => (
            format!("People joined or left a group you facilitate on {instance}"),
            "People joined or left a group you facilitate today. Open Faro to see who.".to_owned(),
        ),
        (Some(NoticeKind::GroupJoined), false) => (
            format!("Someone joined a group you facilitate on {instance}"),
            "Someone joined your group. Open Faro to see who.".to_owned(),
        ),
        (Some(NoticeKind::GroupLeft), false) => (
            format!("Someone left a group you facilitate on {instance}"),
            "Someone left your group. Open Faro to see who.".to_owned(),
        ),
        (Some(NoticeKind::GroupRemoved), _) => (
            format!("You were removed from a group on {instance}"),
            "You were removed from a group. Your alliances are not affected.".to_owned(),
        ),
        (Some(NoticeKind::GroupArchived), _) => (
            format!("A group you are in on {instance} was closed"),
            "A group you're in was closed. It stays readable for 30 days. Your alliances are \
             not affected."
                .to_owned(),
        ),
        (Some(NoticeKind::GroupFacilitatorOffered), _) => (
            format!("You were offered to facilitate a group on {instance}"),
            "A group you're in has no facilitator. Open Faro to take it on, within 14 days."
                .to_owned(),
        ),
        // Proposals name the person (never the group): "Sam asked you to
        // be their ally."
        (Some(NoticeKind::AllianceRequested), _) => (
            format!("{who} asked you to be their ally on {instance}"),
            format!("{who} asked you to be their ally. Open Faro to answer."),
        ),
        (Some(NoticeKind::AllianceOffered), _) => (
            format!("{who} offered to be your ally on {instance}"),
            format!("{who} offered to be your ally. Open Faro to answer."),
        ),
        (Some(NoticeKind::AlliancePartnership), _) => (
            format!("{who} asked to partner up on {instance}"),
            format!("{who} asked to partner up: to be each other's allies. Open Faro to answer."),
        ),
        (Some(NoticeKind::AllianceAccepted), _) => (
            format!("{who} accepted on {instance}"),
            format!("{who} accepted. Compare safety codes with them in Faro to finish."),
        ),
        (None, _) => (
            format!("News about a group on {instance}"),
            "There is news about a group you're in. Open Faro to see.".to_owned(),
        ),
    };
    (subject, line)
}

fn on_device(n: &DueNotification) -> String {
    match &n.device_name {
        Some(d) => format!(" on {d}"),
        None => String::new(),
    }
}

/// Word one immediate notification. Content-free by construction: the only
/// inputs are names, the urgency and whether it is a report.
pub fn compose_immediate(state: &AppState, n: &DueNotification) -> Email {
    let cfg = state.config();
    let instance = &cfg.instance.name;
    let url = &cfg.public_url;
    let member = &n.member_name;
    if let Some(a) = &n.admin_log {
        let (subject, line, link) = admin_log_text(instance, url, n, a);
        return Email {
            to: n.recipient_email.clone(),
            subject,
            text: format!("{line}\n\n{link}\n"),
        };
    }
    if let Some(g) = &n.group_notice {
        let (subject, line) = group_notice_text(instance, g);
        return Email {
            to: n.recipient_email.clone(),
            subject,
            text: format!("{line}\n\n{url}\n"),
        };
    }
    if let Some(k) = account_status(n) {
        let (subject, line) = account_status_text(instance, n, k);
        return Email {
            to: n.recipient_email.clone(),
            subject,
            text: format!("{line}\n\n{url}\n"),
        };
    }
    let (subject, line) = if n.to_extra_recipient {
        (
            format!("You are no longer {member}'s ally on {instance}"),
            format!(
                "{member} removed you as an ally on {instance}. \
                 You will not receive further alerts about them."
            ),
        )
    } else if n.alert.is_none() {
        (
            format!("New report for {member}"),
            format!(
                "New report for {member}{}. Open Faro to view.",
                on_device(n)
            ),
        )
    } else if n.urgency == Urgency::Urgent {
        (
            format!("Urgent: new alert for {member}"),
            format!(
                "Urgent: new alert for {member}{}. Open Faro to view.",
                on_device(n)
            ),
        )
    } else {
        (
            format!("New alert for {member}"),
            format!("New alert for {member}{}. Open Faro to view.", on_device(n)),
        )
    };
    Email {
        to: n.recipient_email.clone(),
        subject,
        text: format!("{line}\n\n{url}\n\n{FOOTER}"),
    }
}

const FOOTER: &str = "Faro notifications never contain details. \
                      Details are only visible after you unlock Faro.";

/// Word one digest: per member, counts only.
pub fn compose_digest(state: &AppState, to: &str, items: &[DueNotification]) -> Email {
    #[derive(Default)]
    struct Counts {
        name: String,
        urgent: usize,
        alerts: usize,
        reports: usize,
        removed: bool,
        /// Account-status sentences (see the module docs).
        status: Vec<String>,
    }
    let cfg = state.config();
    let mut per: BTreeMap<&str, Counts> = BTreeMap::new();
    // Group notices (content-free, one line each).
    let mut group_lines: Vec<String> = Vec::new();
    for n in items {
        if let Some(g) = &n.group_notice {
            let (subject, _) = group_notice_text(&cfg.instance.name, g);
            group_lines.push(format!("- {subject}."));
            continue;
        }
        let c = per.entry(n.member_id.as_str()).or_default();
        c.name.clone_from(&n.member_name);
        if let Some(a) = &n.admin_log {
            // Always sent immediately (`crate::roles`); worded in full if a
            // digest ever carries one.
            let (subject, line, _) = admin_log_text(&cfg.instance.name, &cfg.public_url, n, a);
            c.status.push(format!("{subject}. {line}"));
        } else if let Some(k) = account_status(n) {
            let (subject, line) = account_status_text(&cfg.instance.name, n, k);
            // A deletion notice's dates and what to do are the point of
            // it, so the digest carries its whole text.
            c.status.push(if is_deletion_notice(k) {
                format!("{subject}. {line}")
            } else {
                format!("{subject}.")
            });
        } else if n.to_extra_recipient {
            c.removed = true;
        } else if n.alert.is_none() {
            c.reports += 1;
        } else if n.urgency == Urgency::Urgent {
            c.urgent += 1;
        } else {
            c.alerts += 1;
        }
    }
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    let mut lines = group_lines;
    for c in per.values() {
        if c.removed {
            lines.push(format!("- You are no longer an ally for {}.", c.name));
        }
        for s in &c.status {
            lines.push(format!("- {s}"));
        }
        let mut parts = Vec::new();
        if c.urgent > 0 {
            parts.push(plural(c.urgent, "urgent alert", "urgent alerts"));
        }
        if c.alerts > 0 {
            parts.push(plural(c.alerts, "alert", "alerts"));
        }
        if c.reports > 0 {
            parts.push(plural(c.reports, "new report", "new reports"));
        }
        if !parts.is_empty() {
            lines.push(format!("- {}: {}", c.name, parts.join(", ")));
        }
    }
    let total = items.len();
    Email {
        to: to.to_owned(),
        subject: format!(
            "{} digest: {}",
            cfg.instance.name,
            plural(total, "new item", "new items")
        ),
        text: format!(
            "Since your last digest on {}:\n\n{}\n\nOpen Faro to view: {}\n\n{FOOTER}",
            cfg.instance.name,
            lines.join("\n"),
            cfg.public_url
        ),
    }
}

/// Send a one-off, content-free notice straight away (outside the alert
/// pipeline), e.g. "someone accepted your invite". Best effort: failures are
/// logged by code only.
pub fn send_notice(state: &AppState, to_user: &UserId, subject: String, line: String) {
    let state = state.clone();
    let to_user = to_user.clone();
    tokio::spawn(async move {
        let user = match users::by_id(state.db().pool(), &to_user).await {
            Ok(Some(u)) if !u.disabled => u,
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(error = %e, "could not load notice recipient");
                return;
            }
        };
        let email = Email {
            to: user.email,
            subject,
            text: format!("{line}\n\n{}\n", state.config().public_url),
        };
        if let Err(e) = state.mailer().send(email).await {
            tracing::warn!(code = e.code(), "could not send notice");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-11-25T14:03:00Z and seven days later.
    const REQUESTED: i64 = 1_795_615_380_000;
    const PURGE: i64 = REQUESTED + 7 * 24 * 3600 * 1000;

    fn due(
        kind: ServerAlertKind,
        to_member: bool,
        about: Option<&str>,
        detail: &str,
    ) -> DueNotification {
        DueNotification {
            id: "n".into(),
            recipient_id: UserId::new(if to_member { "usr_m" } else { "usr_r" }),
            recipient_email: "r@example.org".into(),
            recipient_disabled: false,
            entitled: true,
            member_id: UserId::new("usr_m"),
            member_name: "Sam".into(),
            device_id: None,
            device_name: None,
            urgency: kind.urgency(),
            attempts: 0,
            created_at_ms: REQUESTED,
            alert: Some(("server".into(), kind.as_str().into())),
            to_extra_recipient: false,
            about_name: about.map(str::to_owned),
            alert_detail: Some(detail.to_owned()),
            alert_created_at_ms: Some(REQUESTED + 3600 * 1000),
            admin_log: None,
            group_notice: None,
        }
    }

    fn text(n: &DueNotification) -> (String, String) {
        let k = account_status(n).expect("an account-status kind");
        account_status_text("Faro Test", n, k)
    }

    #[test]
    fn dates_are_utc_words() {
        assert_eq!(utc_date(REQUESTED), "25 November 2026");
        assert_eq!(utc_time(REQUESTED), "25 November 2026 at 14:03 UTC");
        assert_eq!(utc_date(PURGE), "2 December 2026");
    }

    #[test]
    fn deletion_notices_name_the_date_and_who() {
        let d = format!("purge_after={PURGE}");
        let (s, t) = text(&due(ServerAlertKind::AccountDeleted, true, None, &d));
        assert_eq!(
            s,
            "Your Faro account on Faro Test will be deleted on 2 December 2026"
        );
        assert!(t.contains("Cancel deletion"), "{t}");
        assert!(t.contains("still monitored"), "{t}");
        assert!(t.contains("backups"), "{t}");

        let (s, t) = text(&due(ServerAlertKind::AccountDeleted, false, None, &d));
        assert_eq!(s, "Sam is deleting their Faro account on Faro Test");
        assert!(t.contains("Until 2 December 2026 nothing changes"), "{t}");

        let d = format!("ally=usr_a;purge_after={PURGE}");
        let (s, t) = text(&due(ServerAlertKind::AllyDeleted, true, Some("Pat"), &d));
        assert_eq!(s, "Your ally Pat is deleting their Faro account");
        assert!(t.contains("confirm your updated ally list"), "{t}");
        let (s, t) = text(&due(ServerAlertKind::AllyDeleted, false, Some("Pat"), &d));
        assert_eq!(
            s,
            "Pat, also an ally for Sam, is deleting their Faro account"
        );
        assert!(t.contains("You still receive Sam's alerts"), "{t}");
    }

    #[test]
    fn admin_deletion_notices_say_the_instance_administrator() {
        let by = "deleted by the instance administrator";
        let d = format!("purge_after={PURGE};requested_by=admin");
        let mut n = due(ServerAlertKind::AccountDeleted, true, None, &d);
        let (s, t) = text(&n);
        assert_eq!(
            s,
            "Your Faro account on Faro Test is being deleted by the instance administrator"
        );
        assert!(t.contains("On 2 December 2026"), "{t}");
        assert!(t.contains("sign in before 2 December 2026"), "{t}");
        assert!(!t.contains("You asked"), "{t}");
        // A disabled person can't sign in to cancel.
        n.recipient_disabled = true;
        let (_, t) = text(&n);
        assert!(t.contains("Your account is disabled"), "{t}");
        assert!(!t.contains("sign in before"), "{t}");
        assert!(!undeliverable(&n), "a disabled person is told");

        let (s, t) = text(&due(ServerAlertKind::AccountDeleted, false, None, &d));
        assert!(s.contains(by) && s.starts_with("Sam's"), "{s}");
        assert!(t.contains("Until 2 December 2026 nothing changes"), "{t}");
        let d = format!("ally=usr_a;purge_after={PURGE};requested_by=admin");
        for to_member in [true, false] {
            let (s, t) = text(&due(
                ServerAlertKind::AllyDeleted,
                to_member,
                Some("Pat"),
                &d,
            ));
            assert!(s.contains(by) && s.contains("Pat"), "{s}");
            assert!(!t.contains("asked for their"), "{t}");
        }

        let k = ServerAlertKind::AccountDeletionCancelled;
        let d = format!("requested={REQUESTED};requested_by=admin");
        let (s, t) = text(&due(k, true, None, &d));
        assert_eq!(
            s,
            "You cancelled the deletion of your Faro account on Faro Test"
        );
        assert!(
            t.contains("On 25 November 2026 at 14:03 UTC, the instance administrator asked"),
            "{t}"
        );
        let mut n = due(k, true, None, &format!("{d};cancelled_by=admin"));
        let (s, t) = text(&n);
        assert_eq!(
            s,
            "The deletion of your Faro account on Faro Test was cancelled"
        );
        assert!(
            t.contains("The instance administrator cancelled it on 25 November 2026 at 15:03"),
            "{t}"
        );
        n.recipient_disabled = true;
        assert!(!undeliverable(&n), "a disabled person is told");
        let (s, t) = text(&due(k, false, None, &d));
        assert_eq!(s, "The deletion of Sam's Faro account was cancelled");
        assert!(t.contains("Sam cancelled it on"), "{t}");
        let d = format!("ally=usr_a;{d}");
        let (s, t) = text(&due(k, true, Some("Pat"), &d));
        assert_eq!(
            s,
            "The deletion of your ally Pat's Faro account was cancelled"
        );
        assert!(t.contains("Pat cancelled it on"), "{t}");

        // Other notices still drop for a disabled recipient.
        let mut n = due(ServerAlertKind::AllyDeleted, true, Some("Pat"), &d);
        n.recipient_disabled = true;
        assert!(undeliverable(&n));
    }

    #[test]
    fn cancellation_notices_give_both_times() {
        let k = ServerAlertKind::AccountDeletionCancelled;
        let d = format!("requested={REQUESTED}");
        let (s, t) = text(&due(k, true, None, &d));
        assert_eq!(
            s,
            "You cancelled the deletion of your Faro account on Faro Test"
        );
        assert!(
            t.contains("deleted on 25 November 2026 at 14:03 UTC"),
            "{t}"
        );
        assert!(
            t.contains("cancelled it on 25 November 2026 at 15:03 UTC"),
            "{t}"
        );
        let (s, _) = text(&due(k, false, None, &d));
        assert_eq!(s, "Sam cancelled the deletion of their Faro account");
        let d = format!("ally=usr_a;requested={REQUESTED}");
        let (s, t) = text(&due(k, true, Some("Pat"), &d));
        assert_eq!(
            s,
            "Your ally Pat cancelled the deletion of their Faro account"
        );
        assert!(t.contains("They stay your ally"), "{t}");
        let (s, _) = text(&due(k, false, Some("Pat"), &d));
        assert_eq!(
            s,
            "Pat, also an ally for Sam, cancelled the deletion of their account"
        );
    }
}
