//! `group_messages`, `reach_outs` and the reach-out settings
//! (`quiet_hours_bypass`, `reach_out_prefs`): GROUPS.md §8.3, §10.2, §15.
//!
//! A group message is stored as the author signed and sealed it. The
//! instance checked it on upload ([`crate::messages`]), but never relies on
//! that: every reader's browser checks the signature again.

use super::parse_col;
use crate::notify::policy::Mode;
use crate::tokens::new_hex_id;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage};
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::{Any, Executor, Row};

/// Reach outs one person may send per hour (Appendix A, section C).
pub const MAX_REACH_OUTS_PER_HOUR: i64 = 3;
/// Reach outs each side of `GET /v1/me/reach-outs` shows, newest first.
pub const LIST_LIMIT: i64 = 50;

// ---- Messages ------------------------------------------------------------------

/// Store a checked message and who may read it. A message id already used
/// surfaces as a unique violation.
pub async fn insert_message(
    conn: &mut sqlx::AnyConnection,
    sealed: &SealedGroupMessage,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let m = &sealed.message.body;
    sqlx::query(
        "INSERT INTO group_messages (id, kind, author_id, group_id, message_json, body_json,
                                     created_at, epoch)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&m.item_id)
    .bind(m.kind.as_str())
    .bind(m.author_id.as_str())
    .bind(m.group_id.clone())
    .bind(encode(&sealed.message))
    .bind(sealed.body.as_ref().map(encode))
    .bind(now_ms)
    .bind(m.epoch.map(|e| i64::try_from(e).unwrap_or(i64::MAX)))
    .execute(&mut *conn)
    .await?;
    for r in &m.recipients {
        sqlx::query(
            "INSERT INTO group_message_recipients (message_id, recipient_id, key_id)
             VALUES ($1, $2, $3)",
        )
        .bind(&m.item_id)
        .bind(r.user_id.as_str())
        .bind(faro_proto::keys::key_id(r.enc_pubkey.as_bytes()))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

fn encode<T: Serialize>(v: &T) -> String {
    // Serializing these types can't fail (no maps with non-string keys).
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_owned())
}

/// A stored message.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub kind: GroupMessageKind,
    pub author_id: UserId,
    pub group_id: Option<String>,
    pub sealed: SealedGroupMessage,
    pub created_at_ms: i64,
}

pub async fn message_by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<Option<StoredMessage>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT id, kind, author_id, group_id, message_json, body_json, created_at
         FROM group_messages WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    let message = parse_col(&r, "message_json", |s| serde_json::from_str(s).ok())?;
    let body: Option<String> = r.try_get("body_json")?;
    let body = body
        .map(|b| {
            serde_json::from_str(&b)
                .map_err(|_| sqlx::Error::Decode("invalid value in column body_json".into()))
        })
        .transpose()?;
    Ok(Some(StoredMessage {
        id: r.try_get("id")?,
        kind: parse_col(&r, "kind", GroupMessageKind::parse)?,
        author_id: UserId::new(r.try_get::<String, _>("author_id")?),
        group_id: r.try_get("group_id")?,
        sealed: SealedGroupMessage { message, body },
        created_at_ms: r.try_get("created_at")?,
    }))
}

/// Whether `user` is one of the message's signed recipients.
pub async fn is_recipient<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    user: &UserId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM group_message_recipients WHERE message_id = $1 AND recipient_id = $2",
    )
    .bind(id)
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    .is_some())
}

/// Whether the note `id` is on a proposal hidden from its recipient
/// (a block, a cool-down): then only its author may read it.
pub async fn is_on_hidden_proposal<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM alliance_proposals WHERE note_blob_ref = $1 AND hidden <> 0",
    )
    .bind(id)
    .fetch_optional(e)
    .await?
    .is_some())
}

/// Delete messages nothing uses any more (their proposal, join request or
/// reach out was pruned or purged), older than `before_ms`. They go with
/// what they belong to (GROUPS.md §18).
pub async fn sweep_unused<'e>(
    e: impl Executor<'e, Database = Any>,
    before_ms: i64,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM group_messages
         WHERE created_at < $1
           AND NOT EXISTS (SELECT 1 FROM alliance_proposals p
                           WHERE p.note_blob_ref = group_messages.id)
           AND NOT EXISTS (SELECT 1 FROM group_join_requests r
                           WHERE r.note_blob_ref = group_messages.id)
           AND NOT EXISTS (SELECT 1 FROM reach_outs o WHERE o.blob_ref = group_messages.id)",
    )
    .bind(before_ms)
    .execute(e)
    .await?
    .rows_affected())
}

// ---- Reach outs ------------------------------------------------------------------

/// How the sender chose the people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// Their own allies (the default).
    Allies,
    /// A group's facilitators.
    Facilitators,
    /// Up to 32 named people.
    People,
    /// The whole group, in a group of 32 or fewer (decision 10). The
    /// message is sealed with the group's epoch key.
    Group,
}

impl Audience {
    pub fn as_str(self) -> &'static str {
        match self {
            Audience::Allies => "allies",
            Audience::Facilitators => "facilitators",
            Audience::People => "people",
            Audience::Group => "group",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Audience::Allies,
            Audience::Facilitators,
            Audience::People,
            Audience::Group,
        ]
        .into_iter()
        .find(|a| a.as_str() == s)
    }
}

/// An answer to a reach out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// "I'll call."
    Call,
    /// "I'm here."
    Here,
}

impl Answer {
    pub fn as_str(self) -> &'static str {
        match self {
            Answer::Call => "call",
            Answer::Here => "here",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "call" => Some(Answer::Call),
            "here" => Some(Answer::Here),
            _ => None,
        }
    }
}

/// A reach out to write.
pub struct NewReachOut<'a> {
    pub sender: &'a UserId,
    pub group_id: Option<&'a str>,
    pub audience: Audience,
    /// The signed message's signature and id; `None` for an unverifiable,
    /// content-free reach out.
    pub sig: Option<String>,
    pub message_id: Option<&'a str>,
    pub recipients: &'a [UserId],
    pub now_ms: i64,
}

/// Write a reach out and its recipients. Returns its id.
pub async fn insert_reach_out(
    conn: &mut sqlx::AnyConnection,
    r: &NewReachOut<'_>,
) -> Result<String, sqlx::Error> {
    let id = new_hex_id();
    sqlx::query(
        "INSERT INTO reach_outs (id, sender_id, group_id, audience, created_at, sig, blob_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(r.sender.as_str())
    .bind(r.group_id)
    .bind(r.audience.as_str())
    .bind(r.now_ms)
    .bind(r.sig.clone())
    .bind(r.message_id)
    .execute(&mut *conn)
    .await?;
    for to in r.recipients {
        sqlx::query(
            "INSERT INTO reach_out_recipients (reach_out_id, recipient_id) VALUES ($1, $2)",
        )
        .bind(&id)
        .bind(to.as_str())
        .execute(&mut *conn)
        .await?;
    }
    Ok(id)
}

/// Reach outs `sender` sent since `since_ms`, oldest first (their times).
pub async fn sent_since<'e>(
    e: impl Executor<'e, Database = Any>,
    sender: &UserId,
    since_ms: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT created_at FROM reach_outs WHERE sender_id = $1 AND created_at > $2
         ORDER BY created_at",
    )
    .bind(sender.as_str())
    .bind(since_ms)
    .fetch_all(e)
    .await?;
    rows.iter().map(|r| r.try_get("created_at")).collect()
}

/// One reach out as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachOut {
    pub id: String,
    pub sender_id: UserId,
    pub sender_name: String,
    pub group_id: Option<String>,
    /// While the viewer is an active participant of the group.
    pub group_name: Option<String>,
    pub audience: Audience,
    pub created_at_ms: i64,
    pub signed: bool,
    pub message_id: Option<String>,
}

/// One recipient's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    pub user_id: UserId,
    pub display_name: String,
    pub answer: Option<Answer>,
    pub answered_at_ms: Option<i64>,
}

fn reach_out_from_row(r: &sqlx::any::AnyRow) -> Result<ReachOut, sqlx::Error> {
    Ok(ReachOut {
        id: r.try_get("id")?,
        sender_id: UserId::new(r.try_get::<String, _>("sender_id")?),
        sender_name: r.try_get("sender_name")?,
        group_id: r.try_get("group_id")?,
        group_name: r.try_get("group_name")?,
        audience: parse_col(r, "audience", Audience::parse)?,
        created_at_ms: r.try_get("created_at")?,
        signed: r.try_get::<Option<String>, _>("sig")?.is_some(),
        message_id: r.try_get("blob_ref")?,
    })
}

macro_rules! reach_out_select {
    ($where:literal) => {
        concat!(
            "SELECT o.id, o.sender_id, u.display_name AS sender_name, o.group_id,
                    CASE WHEN gp.user_id IS NULL THEN NULL ELSE g.name END AS group_name,
                    o.audience, o.created_at, o.sig, o.blob_ref
             FROM reach_outs o
             JOIN users u ON u.id = o.sender_id
             LEFT JOIN accountability_groups g ON g.id = o.group_id
             LEFT JOIN group_participants gp ON gp.group_id = o.group_id
                  AND gp.user_id = $1 AND gp.state = 'active'
             WHERE ",
            $where,
            " ORDER BY o.created_at DESC, o.id LIMIT $2"
        )
    };
}

/// Reach outs sent to `user`, newest first.
pub async fn incoming<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<ReachOut>, sqlx::Error> {
    sqlx::query(reach_out_select!(
        "EXISTS (SELECT 1 FROM reach_out_recipients rr
                 WHERE rr.reach_out_id = o.id AND rr.recipient_id = $1)"
    ))
    .bind(user.as_str())
    .bind(LIST_LIMIT)
    .fetch_all(e)
    .await?
    .iter()
    .map(reach_out_from_row)
    .collect()
}

/// Reach outs `user` sent, newest first.
pub async fn outgoing<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<ReachOut>, sqlx::Error> {
    sqlx::query(reach_out_select!("o.sender_id = $1"))
        .bind(user.as_str())
        .bind(LIST_LIMIT)
        .fetch_all(e)
        .await?
        .iter()
        .map(reach_out_from_row)
        .collect()
}

/// One reach out by id, as `viewer` sees its group.
pub async fn reach_out_by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    viewer: &UserId,
) -> Result<Option<ReachOut>, sqlx::Error> {
    sqlx::query(reach_out_select!("o.id = $3"))
        .bind(viewer.as_str())
        .bind(1_i64)
        .bind(id)
        .fetch_optional(e)
        .await?
        .as_ref()
        .map(reach_out_from_row)
        .transpose()
}

/// Everyone a reach out went to, with their answers, in name order.
pub async fn recipients_of<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<Vec<RecipientRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT rr.recipient_id, u.display_name, rr.answer, rr.answered_at
         FROM reach_out_recipients rr JOIN users u ON u.id = rr.recipient_id
         WHERE rr.reach_out_id = $1
         ORDER BY u.display_name, rr.recipient_id",
    )
    .bind(id)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(RecipientRow {
                user_id: UserId::new(r.try_get::<String, _>("recipient_id")?),
                display_name: r.try_get("display_name")?,
                answer: super::parse_opt_col(r, "answer", Answer::parse)?,
                answered_at_ms: r.try_get("answered_at")?,
            })
        })
        .collect()
}

/// Record `user`'s answer (a later answer replaces it). `None` if they
/// aren't a recipient; otherwise whether this was their first answer.
pub async fn answer(
    conn: &mut sqlx::AnyConnection,
    id: &str,
    user: &UserId,
    answer: Answer,
    now_ms: i64,
) -> Result<Option<bool>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT answer FROM reach_out_recipients WHERE reach_out_id = $1 AND recipient_id = $2",
    )
    .bind(id)
    .bind(user.as_str())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let first = r.try_get::<Option<String>, _>("answer")?.is_none();
    sqlx::query(
        "UPDATE reach_out_recipients SET answer = $1, answered_at = $2
         WHERE reach_out_id = $3 AND recipient_id = $4",
    )
    .bind(answer.as_str())
    .bind(now_ms)
    .bind(id)
    .bind(user.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(Some(first))
}

/// Forget reach outs received before `before_ms` (alert retention). Their
/// messages go in [`sweep_unused`].
pub async fn prune<'e>(
    e: impl Executor<'e, Database = Any>,
    before_ms: i64,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM reach_outs WHERE created_at < $1")
        .bind(before_ms)
        .execute(e)
        .await?
        .rows_affected())
}

// ---- Settings ------------------------------------------------------------------

/// Whether `user` lets `sender`'s reach outs through quiet hours.
pub async fn has_bypass<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    sender: &UserId,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 AS x FROM quiet_hours_bypass WHERE user_id = $1 AND sender_id = $2")
            .bind(user.as_str())
            .bind(sender.as_str())
            .fetch_optional(e)
            .await?
            .is_some(),
    )
}

pub async fn set_bypass<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    sender: &UserId,
    on: bool,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    if on {
        sqlx::query(
            "INSERT INTO quiet_hours_bypass (user_id, sender_id, created_at) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, sender_id) DO NOTHING",
        )
        .bind(user.as_str())
        .bind(sender.as_str())
        .bind(now_ms)
        .execute(e)
        .await?;
    } else {
        sqlx::query("DELETE FROM quiet_hours_bypass WHERE user_id = $1 AND sender_id = $2")
            .bind(user.as_str())
            .bind(sender.as_str())
            .execute(e)
            .await?;
    }
    Ok(())
}

/// `user`'s chosen mode for `sender`'s reach outs, if not the default.
pub async fn mode_for<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    sender: &UserId,
) -> Result<Option<Mode>, sqlx::Error> {
    sqlx::query("SELECT mode FROM reach_out_prefs WHERE user_id = $1 AND sender_id = $2")
        .bind(user.as_str())
        .bind(sender.as_str())
        .fetch_optional(e)
        .await?
        .map(|r| parse_col(&r, "mode", Mode::parse))
        .transpose()
}

/// Set (or, with `None`, clear) `user`'s mode for `sender`'s reach outs.
pub async fn set_mode<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    sender: &UserId,
    mode: Option<Mode>,
) -> Result<(), sqlx::Error> {
    match mode {
        Some(m) => {
            sqlx::query(
                "INSERT INTO reach_out_prefs (user_id, sender_id, mode) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, sender_id) DO UPDATE SET mode = excluded.mode",
            )
            .bind(user.as_str())
            .bind(sender.as_str())
            .bind(m.as_str())
            .execute(e)
            .await?
        }
        None => {
            sqlx::query("DELETE FROM reach_out_prefs WHERE user_id = $1 AND sender_id = $2")
                .bind(user.as_str())
                .bind(sender.as_str())
                .execute(e)
                .await?
        }
    };
    Ok(())
}

/// One person `user` set something for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderSetting {
    pub user_id: UserId,
    pub display_name: String,
    /// `immediate` (the default), `digest` or `off`.
    pub mode: Mode,
    pub quiet_hours_bypass: bool,
}

/// Everyone `user` changed a reach-out setting for, by name.
pub async fn settings_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<SenderSetting>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT u.id, u.display_name,
                (SELECT mode FROM reach_out_prefs p WHERE p.user_id = $1 AND p.sender_id = u.id)
                    AS mode,
                (SELECT COUNT(*) FROM quiet_hours_bypass b
                 WHERE b.user_id = $1 AND b.sender_id = u.id) AS bypass
         FROM users u
         WHERE u.id IN (SELECT sender_id FROM reach_out_prefs WHERE user_id = $1)
            OR u.id IN (SELECT sender_id FROM quiet_hours_bypass WHERE user_id = $1)
         ORDER BY u.display_name, u.id",
    )
    .bind(user.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(SenderSetting {
                user_id: UserId::new(r.try_get::<String, _>("id")?),
                display_name: r.try_get("display_name")?,
                mode: super::parse_opt_col(r, "mode", Mode::parse)?.unwrap_or(Mode::Immediate),
                quiet_hours_bypass: r.try_get::<i64, _>("bypass")? > 0,
            })
        })
        .collect()
}
