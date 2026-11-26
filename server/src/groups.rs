//! Groups: the rules shared by the API, the admin console and the purge
//! (docs/GROUPS.md).
//!
//! The SQL is in [`crate::db::repo::groups`]; the routes are in
//! [`crate::api::groups`]. This module holds what both need:
//!
//! * **Notices** (§14). `group_joined` / `group_left` (to facilitators),
//!   `group_removed`, `group_archived` and `group_facilitator_offered` are
//!   written as [`group_notices`] with a notification row each, sent by the
//!   notifier like any other email. They are ordinary "normal" notices (the
//!   recipient's preference for normal urgency applies, and they can be
//!   switched off), **never tamper-class**, and **never name the group or
//!   anything about it** (principle 7: email passes through third parties).
//!   Above [`LARGE_GROUP`] participants, join and leave notices become one
//!   daily summary per facilitator.
//! * **Archiving** ([`archive`]), used by a facilitator, an admin, and the
//!   last participant leaving. Nothing here ever touches `ally_links`
//!   (principle 4).
//!
//! Group invitations are the one email that names a person (the inviter) and
//! still never the group: "*Sam* invited you to join a group on *instance*."

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

/// Archive `group`: read-only for 30 days, then deleted by the retention
/// worker. Unlists it, withdraws a facilitator offer, writes the history
/// entry and tells everyone in it (`group_archived`) except `by`, who knows.
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
