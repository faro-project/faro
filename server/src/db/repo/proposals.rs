//! `alliance_proposals` and `proposal_blocks` (docs/GROUPS.md §7, §15).
//!
//! Only SQL and the state mapping live here; the rules are in
//! [`crate::api::proposals`].
//!
//! **Nothing here touches `ally_links`.** Accepting a proposal creates
//! pending links through the same code as accepting an email invitation
//! ([`crate::api::invites::accept_ally_link`]); only the member's signed
//! approval activates one.
//!
//! **Two views of one row.** The recipient sees what happened
//! ([`Proposal::recipient_state`]). The sender sees only what their own
//! actions and the clock explain ([`Proposal::sender_state`]): a proposal
//! that was declined, voided or hidden looks open until it would have
//! expired, then "not accepted", with the same cool-down. That is what
//! makes a decline indistinguishable from an expiry (principle 5), and
//! every sender-side rule (one open proposal per direction, the cool-down,
//! the live-invite limit) is computed from the sender's view.

use super::parse_col;
use crate::db::repo::group_notices::NoticeKind;
use crate::tokens::new_hex_id;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::any::AnyRow;
use sqlx::{Any, Executor, Row};

const DAY_MS: i64 = 24 * 3600 * 1000;
/// Proposals expire after 14 days.
pub const PROPOSAL_TTL_MS: i64 = 14 * DAY_MS;
/// After a proposal that wasn't accepted, the same kind can't be sent to the
/// same person for 30 days.
pub const COOLDOWN_MS: i64 = 30 * DAY_MS;
/// Proposals are pruned this long after they expire (GROUPS.md §18: 90
/// days after they are decided; keyed on the expiry so a decline is never
/// pruned earlier than an expiry would be).
pub const KEEP_MS: i64 = 90 * DAY_MS;

/// What a proposal asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The sender asks the recipient to be their ally.
    Request,
    /// The sender offers to be the recipient's ally.
    Offer,
    /// Each becomes the other's ally.
    Partnership,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Request, Kind::Offer, Kind::Partnership];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Request => "request",
            Kind::Offer => "offer",
            Kind::Partnership => "partnership",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The ally links accepting it starts, as `(member, ally)` pairs.
    pub fn links<'a>(self, from: &'a UserId, to: &'a UserId) -> Vec<(&'a UserId, &'a UserId)> {
        match self {
            Kind::Request => vec![(from, to)],
            Kind::Offer => vec![(to, from)],
            Kind::Partnership => vec![(from, to), (to, from)],
        }
    }

    /// The notice the recipient gets.
    pub fn notice(self) -> NoticeKind {
        match self {
            Kind::Request => NoticeKind::AllianceRequested,
            Kind::Offer => NoticeKind::AllianceOffered,
            Kind::Partnership => NoticeKind::AlliancePartnership,
        }
    }
}

/// The stored state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Accepted,
    NotAccepted,
    Withdrawn,
    Void,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Accepted => "accepted",
            State::NotAccepted => "not_accepted",
            State::Withdrawn => "withdrawn",
            State::Void => "void",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            State::Open,
            State::Accepted,
            State::NotAccepted,
            State::Withdrawn,
            State::Void,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }
}

/// What the sender sees. `NotAccepted` covers declined, expired, void and
/// hidden alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderState {
    Open,
    Accepted,
    NotAccepted,
    Withdrawn,
}

/// What the recipient sees: their own decisions as they made them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientState {
    Open,
    Accepted,
    Declined,
    Expired,
    Withdrawn,
    Void,
}

/// One proposal row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub id: String,
    pub group_id: String,
    pub from_id: UserId,
    pub to_id: UserId,
    pub kind: Kind,
    pub offer_ally_key_id: Option<String>,
    pub state: State,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub decided_at_ms: Option<i64>,
    pub cooldown_until_ms: i64,
    pub withdrawn_at_ms: Option<i64>,
    pub hidden: bool,
}

impl Proposal {
    /// The sender's view: only their own actions and the clock (module
    /// docs).
    pub fn sender_state(&self, now_ms: i64) -> SenderState {
        if self.withdrawn_at_ms.is_some() {
            SenderState::Withdrawn
        } else if self.state == State::Accepted {
            SenderState::Accepted
        } else if self.expires_at_ms > now_ms {
            SenderState::Open
        } else {
            SenderState::NotAccepted
        }
    }

    /// The recipient's view.
    pub fn recipient_state(&self, now_ms: i64) -> RecipientState {
        match self.state {
            State::Open if self.expires_at_ms > now_ms => RecipientState::Open,
            State::Open => RecipientState::Expired,
            State::NotAccepted if self.decided_at_ms.is_some() => RecipientState::Declined,
            State::NotAccepted => RecipientState::Expired,
            State::Accepted => RecipientState::Accepted,
            State::Withdrawn => RecipientState::Withdrawn,
            State::Void => RecipientState::Void,
        }
    }

    /// Whether the recipient can still accept or decline it.
    pub fn answerable(&self, now_ms: i64) -> bool {
        !self.hidden && self.state == State::Open && self.expires_at_ms > now_ms
    }

    /// Whether, in the sender's view, it holds back another proposal of
    /// this kind to this person: open, or not accepted and still in its
    /// cool-down.
    pub fn holds_back_sender(&self, now_ms: i64) -> bool {
        match self.sender_state(now_ms) {
            SenderState::Open => true,
            SenderState::NotAccepted => self.cooldown_until_ms > now_ms,
            SenderState::Accepted | SenderState::Withdrawn => false,
        }
    }
}

fn proposal_from_row(r: &AnyRow) -> Result<Proposal, sqlx::Error> {
    Ok(Proposal {
        id: r.try_get("id")?,
        group_id: r.try_get("group_id")?,
        from_id: UserId::new(r.try_get::<String, _>("from_id")?),
        to_id: UserId::new(r.try_get::<String, _>("to_id")?),
        kind: parse_col(r, "kind", Kind::parse)?,
        offer_ally_key_id: r.try_get("offer_ally_key_id")?,
        state: parse_col(r, "state", State::parse)?,
        created_at_ms: r.try_get("created_at")?,
        expires_at_ms: r.try_get("expires_at")?,
        decided_at_ms: r.try_get("decided_at")?,
        cooldown_until_ms: r.try_get("cooldown_until")?,
        withdrawn_at_ms: r.try_get("withdrawn_at")?,
        hidden: r.try_get::<i64, _>("hidden")? != 0,
    })
}

macro_rules! columns {
    () => {
        "a.id, a.group_id, a.from_id, a.to_id, a.kind, a.offer_ally_key_id, a.state,
         a.created_at, a.expires_at, a.decided_at, a.cooldown_until, a.withdrawn_at, a.hidden"
    };
}

/// A proposal to write.
pub struct NewProposal<'a> {
    pub group_id: &'a str,
    pub from: &'a UserId,
    pub to: &'a UserId,
    pub kind: Kind,
    pub offer_ally_key_id: Option<&'a str>,
    /// Never shown to the recipient (see the `hidden` column).
    pub hidden: bool,
    pub now_ms: i64,
}

/// Write a proposal: `open`, or `not_accepted` from the start if hidden.
/// Another open one for the same (from, to, kind) surfaces as a unique
/// violation.
pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    p: &NewProposal<'_>,
) -> Result<Proposal, sqlx::Error> {
    let expires_at_ms = p.now_ms.saturating_add(PROPOSAL_TTL_MS);
    let row = Proposal {
        id: new_hex_id(),
        group_id: p.group_id.to_owned(),
        from_id: p.from.clone(),
        to_id: p.to.clone(),
        kind: p.kind,
        offer_ally_key_id: p.offer_ally_key_id.map(str::to_owned),
        state: if p.hidden {
            State::NotAccepted
        } else {
            State::Open
        },
        created_at_ms: p.now_ms,
        expires_at_ms,
        decided_at_ms: None,
        cooldown_until_ms: expires_at_ms.saturating_add(COOLDOWN_MS),
        withdrawn_at_ms: None,
        hidden: p.hidden,
    };
    sqlx::query(
        "INSERT INTO alliance_proposals
            (id, group_id, from_id, to_id, kind, offer_ally_key_id, state, created_at,
             expires_at, cooldown_until, hidden)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&row.id)
    .bind(&row.group_id)
    .bind(row.from_id.as_str())
    .bind(row.to_id.as_str())
    .bind(row.kind.as_str())
    .bind(row.offer_ally_key_id.clone())
    .bind(row.state.as_str())
    .bind(row.created_at_ms)
    .bind(row.expires_at_ms)
    .bind(row.cooldown_until_ms)
    .bind(i64::from(row.hidden))
    .execute(e)
    .await?;
    Ok(row)
}

pub async fn by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<Option<Proposal>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM alliance_proposals a WHERE a.id = $1"
    ))
    .bind(id)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(proposal_from_row)
    .transpose()
}

/// Proposals from `from` to `to` that may still matter to a new one: open,
/// or within their cool-down.
pub async fn recent_between<'e>(
    e: impl Executor<'e, Database = Any>,
    from: &UserId,
    to: &UserId,
    now_ms: i64,
) -> Result<Vec<Proposal>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM alliance_proposals a
         WHERE a.from_id = $1 AND a.to_id = $2 AND a.cooldown_until > $3
         ORDER BY a.created_at, a.id"
    ))
    .bind(from.as_str())
    .bind(to.as_str())
    .bind(now_ms)
    .fetch_all(e)
    .await?
    .iter()
    .map(proposal_from_row)
    .collect()
}

/// Proposals `from` sent since `since_ms` (the daily rate limit counts
/// every one, whatever became of it).
pub async fn count_sent_since<'e>(
    e: impl Executor<'e, Database = Any>,
    from: &UserId,
    since_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM alliance_proposals WHERE from_id = $1 AND created_at > $2",
    )
    .bind(from.as_str())
    .bind(since_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Proposals that are open in `from`'s own view (they count toward the
/// live-invite limit with email invitations).
pub async fn count_open_by_sender<'e>(
    e: impl Executor<'e, Database = Any>,
    from: &UserId,
    now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM alliance_proposals
         WHERE from_id = $1 AND withdrawn_at IS NULL AND state <> 'accepted'
           AND expires_at > $2",
    )
    .bind(from.as_str())
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Mark `from`'s expired open proposals to `to` as `not_accepted`, so the
/// open-proposal index frees up. Expiry leaves `decided_at` NULL.
pub async fn expire_between<'e>(
    e: impl Executor<'e, Database = Any>,
    from: &UserId,
    to: &UserId,
    now_ms: i64,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE alliance_proposals SET state = 'not_accepted'
         WHERE from_id = $1 AND to_id = $2 AND state = 'open' AND expires_at <= $3",
    )
    .bind(from.as_str())
    .bind(to.as_str())
    .bind(now_ms)
    .execute(e)
    .await?
    .rows_affected())
}

/// The recipient's answer: open → `accepted` or `not_accepted`. False if
/// it was no longer answerable.
pub async fn answer<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    accepted: bool,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE alliance_proposals SET state = $1, decided_at = $2
         WHERE id = $3 AND state = 'open' AND hidden = 0 AND expires_at > $2",
    )
    .bind(if accepted {
        State::Accepted.as_str()
    } else {
        State::NotAccepted.as_str()
    })
    .bind(now_ms)
    .bind(id)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// The sender withdraws a proposal that is open in their view. A
/// proposal still really open becomes `withdrawn`; one already declined,
/// voided or hidden keeps its state for the recipient, and only records
/// the sender's withdrawal. False if it was not open in the sender's view.
pub async fn withdraw<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE alliance_proposals
         SET withdrawn_at = $1,
             decided_at = CASE WHEN state = 'open' THEN $1 ELSE decided_at END,
             state = CASE WHEN state = 'open' THEN 'withdrawn' ELSE state END
         WHERE id = $2 AND withdrawn_at IS NULL AND state <> 'accepted' AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(id)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Which open proposals [`void`] ends.
#[derive(Debug, Clone, Copy)]
pub enum VoidScope<'a> {
    /// Every one in a group (it was archived).
    Group(&'a str),
    /// Those to or from a person in a group (they left or were removed).
    InGroup(&'a str, &'a UserId),
    /// Those to or from a person anywhere (disabled, deletion hold).
    User(&'a UserId),
    /// Those from one person to another (the recipient blocked them).
    From { from: &'a UserId, to: &'a UserId },
}

/// End open proposals: `void`, with `decided_at` left NULL, and the
/// recipient's notice withdrawn if it hasn't gone out. Returns them.
/// Links already created are never touched (principle 4).
pub async fn void(
    conn: &mut sqlx::AnyConnection,
    scope: VoidScope<'_>,
) -> Result<Vec<Proposal>, sqlx::Error> {
    let q = match scope {
        VoidScope::Group(g) => sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM alliance_proposals a WHERE a.state = 'open' AND a.group_id = $1"
        ))
        .bind(g.to_owned()),
        VoidScope::InGroup(g, u) => sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM alliance_proposals a
             WHERE a.state = 'open' AND a.group_id = $1 AND (a.from_id = $2 OR a.to_id = $2)"
        ))
        .bind(g.to_owned())
        .bind(u.as_str().to_owned()),
        VoidScope::User(u) => sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM alliance_proposals a
             WHERE a.state = 'open' AND (a.from_id = $1 OR a.to_id = $1)"
        ))
        .bind(u.as_str().to_owned()),
        VoidScope::From { from, to } => sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM alliance_proposals a
             WHERE a.state = 'open' AND a.from_id = $1 AND a.to_id = $2"
        ))
        .bind(from.as_str().to_owned())
        .bind(to.as_str().to_owned()),
    };
    let found: Vec<Proposal> = q
        .fetch_all(&mut *conn)
        .await?
        .iter()
        .map(proposal_from_row)
        .collect::<Result<_, _>>()?;
    for p in &found {
        sqlx::query(
            "UPDATE alliance_proposals SET state = 'void' WHERE id = $1 AND state = 'open'",
        )
        .bind(&p.id)
        .execute(&mut *conn)
        .await?;
        suppress_notice(&mut *conn, p).await?;
    }
    Ok(found)
}

/// Withdraw the recipient's notice about `p` if it hasn't been sent yet
/// (a digest, or quiet hours): proposals that end before anyone answers
/// send nothing (GROUPS.md §14).
pub async fn suppress_notice<'e>(
    e: impl Executor<'e, Database = Any>,
    p: &Proposal,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE notifications SET status = 'suppressed'
         WHERE status = 'pending' AND recipient_id = $1
           AND group_notice_id IN (SELECT id FROM group_notices
                                   WHERE recipient_id = $1 AND actor_id = $2 AND kind = $3)",
    )
    .bind(p.to_id.as_str())
    .bind(p.from_id.as_str())
    .bind(p.kind.notice().as_str())
    .execute(e)
    .await?
    .rows_affected())
}

/// A proposal with what a list shows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub proposal: Proposal,
    /// The other person's display name.
    pub other_display_name: String,
    /// The group's name, while the caller is still in it.
    pub group_name: Option<String>,
}

/// Most proposals one list returns (each side).
pub const LIST_LIMIT: i64 = 200;

/// Proposals `user` sent (hidden ones included: the sender can't tell),
/// newest first.
pub async fn outgoing<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<Listed>, sqlx::Error> {
    list(e, user, true).await
}

/// Proposals sent to `user`, never hidden ones, newest first.
pub async fn incoming<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<Listed>, sqlx::Error> {
    list(e, user, false).await
}

async fn list<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    sent: bool,
) -> Result<Vec<Listed>, sqlx::Error> {
    let sql = if sent {
        concat!(
            "SELECT ",
            columns!(),
            ", o.display_name AS other_name,
               (SELECT g.name FROM accountability_groups g
                  JOIN group_participants p ON p.group_id = g.id
                 WHERE g.id = a.group_id AND p.user_id = $1 AND p.state = 'active')
                 AS group_name
             FROM alliance_proposals a JOIN users o ON o.id = a.to_id
             WHERE a.from_id = $1
             ORDER BY a.created_at DESC, a.id DESC LIMIT $2"
        )
    } else {
        concat!(
            "SELECT ",
            columns!(),
            ", o.display_name AS other_name,
               (SELECT g.name FROM accountability_groups g
                  JOIN group_participants p ON p.group_id = g.id
                 WHERE g.id = a.group_id AND p.user_id = $1 AND p.state = 'active')
                 AS group_name
             FROM alliance_proposals a JOIN users o ON o.id = a.from_id
             WHERE a.to_id = $1 AND a.hidden = 0
             ORDER BY a.created_at DESC, a.id DESC LIMIT $2"
        )
    };
    sqlx::query(sql)
        .bind(user.as_str())
        .bind(LIST_LIMIT)
        .fetch_all(e)
        .await?
        .iter()
        .map(|r| {
            Ok(Listed {
                proposal: proposal_from_row(r)?,
                other_display_name: r.try_get("other_name")?,
                group_name: r.try_get("group_name")?,
            })
        })
        .collect()
}

/// What the retention pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepSummary {
    pub expired: u64,
    pub pruned: u64,
}

/// The retention worker's part: mark expired open proposals, and forget
/// proposals [`KEEP_MS`] after they expired (GROUPS.md §18).
pub async fn sweep(
    conn: &mut sqlx::AnyConnection,
    now_ms: i64,
) -> Result<SweepSummary, sqlx::Error> {
    let expired = sqlx::query(
        "UPDATE alliance_proposals SET state = 'not_accepted'
         WHERE state = 'open' AND expires_at <= $1",
    )
    .bind(now_ms)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let pruned = sqlx::query("DELETE FROM alliance_proposals WHERE expires_at < $1")
        .bind(now_ms.saturating_sub(KEEP_MS))
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(SweepSummary { expired, pruned })
}

// ---- Blocks --------------------------------------------------------------------

/// `user` stops `blocked` from sending them proposals. Idempotent.
pub async fn block<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    blocked: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO proposal_blocks (user_id, blocked_id, created_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, blocked_id) DO NOTHING",
    )
    .bind(user.as_str())
    .bind(blocked.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// Idempotent.
pub async fn unblock<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    blocked: &UserId,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM proposal_blocks WHERE user_id = $1 AND blocked_id = $2")
        .bind(user.as_str())
        .bind(blocked.as_str())
        .execute(e)
        .await?;
    Ok(())
}

/// Whether `user` blocked `other`.
pub async fn is_blocked<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    other: &UserId,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 AS x FROM proposal_blocks WHERE user_id = $1 AND blocked_id = $2")
            .bind(user.as_str())
            .bind(other.as_str())
            .fetch_optional(e)
            .await?
            .is_some(),
    )
}

/// One person `user` blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub user_id: UserId,
    pub display_name: String,
    pub created_at_ms: i64,
}

/// Everyone `user` blocked, newest first.
pub async fn blocks_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<Block>, sqlx::Error> {
    sqlx::query(
        "SELECT b.blocked_id, b.created_at, u.display_name FROM proposal_blocks b
         JOIN users u ON u.id = b.blocked_id
         WHERE b.user_id = $1 ORDER BY b.created_at DESC, b.blocked_id",
    )
    .bind(user.as_str())
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| {
        Ok(Block {
            user_id: UserId::new(r.try_get::<String, _>("blocked_id")?),
            display_name: r.try_get("display_name")?,
            created_at_ms: r.try_get("created_at")?,
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: State, decided: Option<i64>, withdrawn: Option<i64>, hidden: bool) -> Proposal {
        Proposal {
            id: "p".into(),
            group_id: "g".into(),
            from_id: UserId::new("a"),
            to_id: UserId::new("b"),
            kind: Kind::Request,
            offer_ally_key_id: None,
            state,
            created_at_ms: 0,
            expires_at_ms: PROPOSAL_TTL_MS,
            decided_at_ms: decided,
            cooldown_until_ms: PROPOSAL_TTL_MS + COOLDOWN_MS,
            withdrawn_at_ms: withdrawn,
            hidden,
        }
    }

    /// The sender's view of a declined, voided, hidden or expired proposal
    /// depends on the clock only.
    #[test]
    fn sender_cannot_tell_decline_from_expiry() {
        let cases = [
            row(State::Open, None, None, false),
            row(State::NotAccepted, None, None, false),
            row(State::NotAccepted, Some(5), None, false),
            row(State::Void, None, None, false),
            row(State::NotAccepted, None, None, true),
        ];
        for now in [1, PROPOSAL_TTL_MS - 1, PROPOSAL_TTL_MS, PROPOSAL_TTL_MS + 1] {
            let views: Vec<_> = cases
                .iter()
                .map(|p| (p.sender_state(now), p.holds_back_sender(now)))
                .collect();
            assert!(views.windows(2).all(|w| w[0] == w[1]), "{now}: {views:?}");
        }
        let p = row(State::NotAccepted, Some(5), None, false);
        assert_eq!(p.sender_state(1), SenderState::Open);
        assert_eq!(p.sender_state(PROPOSAL_TTL_MS), SenderState::NotAccepted);
        assert_eq!(p.recipient_state(1), RecipientState::Declined);
        assert!(!p.holds_back_sender(PROPOSAL_TTL_MS + COOLDOWN_MS));
    }

    #[test]
    fn links_per_kind() {
        let (a, b) = (UserId::new("a"), UserId::new("b"));
        assert_eq!(Kind::Request.links(&a, &b), vec![(&a, &b)]);
        assert_eq!(Kind::Offer.links(&a, &b), vec![(&b, &a)]);
        assert_eq!(Kind::Partnership.links(&a, &b), vec![(&a, &b), (&b, &a)]);
    }
}
