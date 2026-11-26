//! Groups: the rules shared by the API, the admin console and the purge
//! (docs/GROUPS.md).
//!
//! The SQL is in [`crate::db::repo::groups`]; the routes are in
//! [`crate::api::groups`]. This module holds what both need:
//!
//! * **Notices** (§14). `group_joined` / `group_left` (to facilitators),
//!   `group_removed`, `group_archived`, `group_facilitator_offered` and the
//!   alliance kinds (`alliance_requested`, `alliance_offered`,
//!   `alliance_partnership`, `alliance_accepted`, which name the other
//!   person but never the group) are written as [`group_notices`] with a
//!   notification row each, sent by the notifier like any other email. They
//!   are ordinary "normal" notices (the recipient's preference for normal
//!   urgency applies, and they can be switched off), **never tamper-class**,
//!   and **never name the group or anything about it** (principle 7: email
//!   passes through third parties).
//!   Above [`LARGE_GROUP`] participants, join and leave notices become one
//!   daily summary per facilitator.
//! * **Archiving** ([`archive`]), used by a facilitator, an admin, and the
//!   last participant leaving. Nothing here ever touches `ally_links`
//!   (principle 4).
//!
//! Group invitations are the one email that names a person (the inviter) and
//! still never the group: "*Sam* invited you to join a group on *instance*."

use crate::db::repo::group_listing;
use crate::db::repo::group_notices::{self, NewNotice, NoticeKind};
use crate::db::repo::groups::{self, HistoryKind, LARGE_GROUP};
use crate::db::repo::notifications as notif;
use crate::notify::policy::{self, Mode};
use faro_proto::{Urgency, UserId};

const DAY_MS: i64 = 24 * 3600 * 1000;

/// The mode and due time for a "normal" group notice to `recipient`: their
/// preference about themself (default: the hourly digest, like any normal
/// alert), after their quiet hours.
async fn delivery(
    conn: &mut sqlx::AnyConnection,
    recipient: &UserId,
    now_ms: i64,
) -> Result<(Option<Mode>, i64), sqlx::Error> {
    let prefs = notif::get_prefs(&mut *conn, recipient, recipient).await?;
    let mode = policy::effective_mode(prefs.stored_mode(Urgency::Normal), Urgency::Normal, false);
    let due = policy::quiet_until(now_ms, prefs.quiet.as_ref()).unwrap_or(now_ms);
    Ok(((mode != Mode::Off).then_some(mode), due))
}

/// Write one notice to `recipient`. `summary_day` makes it the daily
/// summary: one per recipient, group and kind per UTC day, due after
/// midnight.
async fn tell(
    conn: &mut sqlx::AnyConnection,
    kind: NoticeKind,
    recipient: &UserId,
    actor: Option<&UserId>,
    summary_group: Option<&str>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let (mode, mut due_at_ms) = delivery(conn, recipient, now_ms).await?;
    let mut dedupe_key = None;
    if let Some(group) = summary_group {
        let day = now_ms.div_euclid(DAY_MS);
        dedupe_key = Some(format!("{}:{group}:{recipient}:{day}", kind.as_str()));
        due_at_ms = due_at_ms.max((day + 1) * DAY_MS);
    }
    group_notices::insert(
        conn,
        &NewNotice {
            kind,
            recipient,
            actor,
            summary: summary_group.is_some(),
            dedupe_key,
            detail: None,
            mode,
            due_at_ms,
            now_ms,
        },
    )
    .await?;
    Ok(())
}

/// `kind` (`group_joined` or `group_left`) to the group's facilitators,
/// except `except` (the person it is about). A group above [`LARGE_GROUP`]
/// participants gets a daily summary instead of one notice per change.
pub async fn tell_facilitators(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    kind: NoticeKind,
    except: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let large = groups::count_active(&mut *conn, group).await? > LARGE_GROUP;
    for f in groups::active_user_ids(&mut *conn, group, true).await? {
        if f != *except {
            tell(conn, kind, &f, Some(except), large.then_some(group), now_ms).await?;
        }
    }
    Ok(())
}

/// `group_removed` to the person a facilitator removed.
pub async fn tell_removed(
    conn: &mut sqlx::AnyConnection,
    removed: &UserId,
    by: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    tell(
        conn,
        NoticeKind::GroupRemoved,
        removed,
        Some(by),
        None,
        now_ms,
    )
    .await
}

/// `group_facilitator_offered` to the participant offered the role after
/// the last facilitator's account was deleted.
pub async fn tell_offered(
    conn: &mut sqlx::AnyConnection,
    offered: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    tell(
        conn,
        NoticeKind::GroupFacilitatorOffered,
        offered,
        None,
        None,
        now_ms,
    )
    .await
}

/// An alliance notice (`alliance_requested`, `alliance_offered`,
/// `alliance_partnership`, `alliance_accepted`) to `recipient`, naming
/// `actor` and never the group. Declines, expiries and withdrawals send
/// nothing (§14).
pub async fn tell_alliance(
    conn: &mut sqlx::AnyConnection,
    kind: NoticeKind,
    recipient: &UserId,
    actor: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    tell(conn, kind, recipient, Some(actor), None, now_ms).await
}

/// `group_join_requested` to each of the group's facilitators.
pub async fn tell_join_requested(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    requester: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    for f in groups::active_user_ids(&mut *conn, group, true).await? {
        tell(
            conn,
            NoticeKind::GroupJoinRequested,
            &f,
            Some(requester),
            None,
            now_ms,
        )
        .await?;
    }
    Ok(())
}

/// `group_join_accepted` to the person a facilitator let in.
pub async fn tell_join_accepted(
    conn: &mut sqlx::AnyConnection,
    requester: &UserId,
    by: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    tell(
        conn,
        NoticeKind::GroupJoinAccepted,
        requester,
        Some(by),
        None,
        now_ms,
    )
    .await
}

/// `group_unlisted` to each facilitator after an admin removed the group
/// from the directory.
pub async fn tell_unlisted(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    admin: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    for f in groups::active_user_ids(&mut *conn, group, true).await? {
        if f != *admin {
            tell(
                conn,
                NoticeKind::GroupUnlisted,
                &f,
                Some(admin),
                None,
                now_ms,
            )
            .await?;
        }
    }
    Ok(())
}

/// A meeting reminder for `occurrence_ms` (the meeting's start) to
/// `recipient`: always written (it is the in-app notice), and emailed only
/// when `email` is true and the recipient's own notification choices and
/// quiet hours allow it before the meeting starts. One per recipient, group
/// and meeting. Returns whether a notice was written (false: already sent).
///
/// Delivery is "immediate" (a reminder an hour late is no reminder). Web
/// Push does not exist yet, so the notice is the only non-email channel.
pub async fn tell_meeting_reminder(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    recipient: &UserId,
    occurrence_ms: i64,
    detail: String,
    email: bool,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let (mode, due_at_ms) = delivery(conn, recipient, now_ms).await?;
    let mode = (email && mode.is_some() && due_at_ms < occurrence_ms).then_some(Mode::Immediate);
    group_notices::insert(
        conn,
        &NewNotice {
            kind: NoticeKind::MeetingReminder,
            recipient,
            actor: None,
            summary: false,
            dedupe_key: Some(format!(
                "meeting_reminder:{group}:{recipient}:{occurrence_ms}"
            )),
            detail: Some(detail),
            mode,
            due_at_ms,
            now_ms,
        },
    )
    .await
}

/// Archive `group`: read-only for 30 days, then deleted by the retention
/// worker. Unlists it, withdraws a facilitator offer, writes the history
/// entry and tells everyone in it (`group_archived`) except `by`, who knows.
/// Open alliance proposals in it become void ([`groups::archive`]).
/// False if it was already archived (nothing is written then).
///
/// Never touches `ally_links`: alliances formed in the group stay, with
/// their `origin_group_id` label until the group is deleted.
pub async fn archive(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    by: Option<&UserId>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    if !groups::archive(&mut *conn, group, by, now_ms).await? {
        return Ok(false);
    }
    groups::add_history(&mut *conn, group, HistoryKind::Archived, None, by, now_ms).await?;
    group_listing::void_open(&mut *conn, group, now_ms).await?;
    for p in groups::active_user_ids(&mut *conn, group, false).await? {
        if Some(&p) != by {
            tell(conn, NoticeKind::GroupArchived, &p, by, None, now_ms).await?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::db::repo::group_notices::NoticeKind;
    use crate::notify::policy::is_tamper_class;
    use faro_proto::Urgency;

    /// §14: none of the group kinds is tamper-class, whatever the source
    /// or urgency, so a person can always switch them off.
    #[test]
    fn no_group_notice_is_tamper_class() {
        for k in NoticeKind::ALL {
            for source in ["server", "device"] {
                for u in [Urgency::Urgent, Urgency::Normal, Urgency::None] {
                    assert!(!is_tamper_class(source, k.as_str(), u), "{k:?}");
                }
            }
            assert_eq!(NoticeKind::parse(k.as_str()), Some(k));
        }
    }
}
