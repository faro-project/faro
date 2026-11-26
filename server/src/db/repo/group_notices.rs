//! `group_notices`: content-free notices about groups, emailed by the
//! notifier (GROUPS.md §14).
//!
//! A notice names no group (principle 7): it holds only a kind, who it is
//! for, and who caused it. Its notification row is written with it, like
//! the admin log's ([`crate::roles::tell`]); there is nothing to fan out.

use super::notifications::{self, NewNotification, Target};
use crate::notify::policy::Mode;
use crate::tokens::new_hex_id;
use faro_proto::{Urgency, UserId};

/// What a notice says. None of these is tamper-class: they are ordinary
/// "normal" notices a person can switch off (GROUPS.md §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// Someone accepted an invitation. To the group's facilitators.
    GroupJoined,
    /// Someone left. To the group's facilitators.
    GroupLeft,
    /// A facilitator removed the person.
    GroupRemoved,
    /// The group was archived. To everyone in it.
    GroupArchived,
    /// The last facilitator's account was deleted and the person was
    /// offered the role.
    GroupFacilitatorOffered,
    /// Someone asked the person to be their ally (a request).
    AllianceRequested,
    /// Someone offered to be the person's ally.
    AllianceOffered,
    /// Someone asked the person to partner up.
    AlliancePartnership,
    /// The person's proposal was accepted: compare safety codes to finish.
    AllianceAccepted,
}

impl NoticeKind {
    pub const ALL: [NoticeKind; 9] = [
        NoticeKind::GroupJoined,
        NoticeKind::GroupLeft,
        NoticeKind::GroupRemoved,
        NoticeKind::GroupArchived,
        NoticeKind::GroupFacilitatorOffered,
        NoticeKind::AllianceRequested,
        NoticeKind::AllianceOffered,
        NoticeKind::AlliancePartnership,
        NoticeKind::AllianceAccepted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NoticeKind::GroupJoined => "group_joined",
            NoticeKind::GroupLeft => "group_left",
            NoticeKind::GroupRemoved => "group_removed",
            NoticeKind::GroupArchived => "group_archived",
            NoticeKind::GroupFacilitatorOffered => "group_facilitator_offered",
            NoticeKind::AllianceRequested => "alliance_requested",
            NoticeKind::AllianceOffered => "alliance_offered",
            NoticeKind::AlliancePartnership => "alliance_partnership",
            NoticeKind::AllianceAccepted => "alliance_accepted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// A notice to write.
pub struct NewNotice<'a> {
    pub kind: NoticeKind,
    pub recipient: &'a UserId,
    pub actor: Option<&'a UserId>,
    /// A daily summary: at most one per `dedupe_key`.
    pub summary: bool,
    pub dedupe_key: Option<String>,
    /// `None` records it as suppressed (the person switched it off).
    pub mode: Option<Mode>,
    pub due_at_ms: i64,
    pub now_ms: i64,
}

/// Write a notice and its notification. False if `dedupe_key` was already
/// used (nothing is written then).
pub async fn insert(
    conn: &mut sqlx::AnyConnection,
    n: &NewNotice<'_>,
) -> Result<bool, sqlx::Error> {
    let id = new_hex_id();
    let r = sqlx::query(
        "INSERT INTO group_notices (id, kind, recipient_id, actor_id, summary, dedupe_key, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (dedupe_key) DO NOTHING",
    )
    .bind(&id)
    .bind(n.kind.as_str())
    .bind(n.recipient.as_str())
    .bind(n.actor.map(|a| a.as_str().to_owned()))
    .bind(i64::from(n.summary))
    .bind(n.dedupe_key.clone())
    .bind(n.now_ms)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() == 0 {
        return Ok(false);
    }
    notifications::insert(
        &mut *conn,
        &NewNotification {
            target: &Target::GroupNotice(id),
            recipient: n.recipient,
            urgency: Urgency::Normal,
            mode: n.mode,
            due_at_ms: n.due_at_ms,
            now_ms: n.now_ms,
        },
    )
    .await?;
    Ok(true)
}
