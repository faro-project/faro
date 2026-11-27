//! `group_posts` and `group_post_recipients`: check-ins and private replies
//! in a group's feed (GROUPS.md §8.6, §15, §18; PROTOCOL.md §11).
//!
//! A post is stored as its author signed and sealed it. The instance
//! checked it on upload ([`crate::messages`]), but never relies on that:
//! every reader's browser checks the signature again.
//!
//! **Who is served what.** A post to named people (including "my allies in
//! this group" and "the facilitators", which are lists of people when it is
//! sent) is served to its author and its signed recipients. A post to the
//! whole group (`epoch` set) is served to its author and to whoever is an
//! active participant now and was one when it arrived
//! ([`super::group_roster::may_read_item`]'s rule, inlined into the feed's
//! query). Someone who left, or was removed, gets nothing at all.

use super::parse_col;
use faro_proto::group::SealedGroupMessage;
use faro_proto::UserId;
use serde::Serialize;
use sqlx::{Any, Executor, Row};

/// Posts one feed page shows (newest first).
pub const FEED_PAGE: i64 = 50;

/// Check-ins one person may post per day, so a feed can't be flooded
/// (the whole-group audience is one envelope however big the group is).
pub const MAX_CHECK_INS_PER_DAY: i64 = 10;
/// Replies one person may send per day.
pub const MAX_REPLIES_PER_DAY: i64 = 50;

/// What a post is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostKind {
    CheckIn,
    Reply,
}

impl PostKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PostKind::CheckIn => "check_in",
            PostKind::Reply => "reply",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "check_in" => Some(PostKind::CheckIn),
            "reply" => Some(PostKind::Reply),
            _ => None,
        }
    }
}

/// A stored post.
#[derive(Debug, Clone)]
pub struct Post {
    pub id: String,
    pub group_id: String,
    pub author_id: UserId,
    pub author_name: String,
    pub kind: PostKind,
    pub parent_id: Option<String>,
    pub epoch: Option<u64>,
    pub created_at_ms: i64,
    pub sealed: SealedGroupMessage,
}

/// A post to write: the checked message and the group it is filed under.
pub struct NewPost<'a> {
    pub group_id: &'a str,
    pub kind: PostKind,
    pub sealed: &'a SealedGroupMessage,
    pub now_ms: i64,
}

fn encode<T: Serialize>(v: &T) -> String {
    // Serializing these types can't fail (no maps with non-string keys).
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_owned())
}

/// Store a checked post and who may read it. A used id surfaces as a
/// unique violation.
pub async fn insert(conn: &mut sqlx::AnyConnection, p: &NewPost<'_>) -> Result<(), sqlx::Error> {
    let m = &p.sealed.message.body;
    sqlx::query(
        "INSERT INTO group_posts (id, group_id, author_id, kind, parent_id, epoch, created_at, sig,
                                  message_json, body_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&m.item_id)
    .bind(p.group_id)
    .bind(m.author_id.as_str())
    .bind(p.kind.as_str())
    .bind(m.parent_id.clone())
    .bind(m.epoch.map(|e| i64::try_from(e).unwrap_or(i64::MAX)))
    .bind(p.now_ms)
    .bind(p.sealed.message.sig.to_b64())
    .bind(encode(&p.sealed.message))
    .bind(p.sealed.body.as_ref().map(encode))
    .execute(&mut *conn)
    .await?;
    for r in &m.recipients {
        sqlx::query(
            "INSERT INTO group_post_recipients (post_id, recipient_id, key_id) VALUES ($1, $2, $3)",
        )
        .bind(&m.item_id)
        .bind(r.user_id.as_str())
        .bind(faro_proto::keys::key_id(r.enc_pubkey.as_bytes()))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `$1` is the group, `$2` the viewer. A post is visible to its author,
/// to a signed recipient, and, for a whole-group post, to someone in the
/// group now who was in it when the post arrived.
macro_rules! visible {
    () => {
        "(p.author_id = $2
     OR EXISTS (SELECT 1 FROM group_post_recipients r
                WHERE r.post_id = p.id AND r.recipient_id = $2)
     OR (p.epoch IS NOT NULL
         AND EXISTS (SELECT 1 FROM group_participants gp
                     WHERE gp.group_id = p.group_id AND gp.user_id = $2
                       AND gp.state = 'active' AND gp.joined_at <= p.created_at)))"
    };
}

/// The `SELECT … WHERE ` prefix, then `$tail`; spliced at compile time, so
/// the statements stay `&'static str`.
macro_rules! post_select {
    ($tail:literal) => {
        concat!(
            "SELECT p.id, p.group_id, p.author_id, u.display_name AS author_name, p.kind,
                    p.parent_id, p.epoch, p.created_at, p.message_json, p.body_json
             FROM group_posts p JOIN users u ON u.id = p.author_id
             WHERE p.group_id = $1 AND ",
            visible!(),
            $tail
        )
    };
}

fn from_row(r: &sqlx::any::AnyRow) -> Result<Post, sqlx::Error> {
    let message = parse_col(r, "message_json", |s| serde_json::from_str(s).ok())?;
    let body: Option<String> = r.try_get("body_json")?;
    let body = body
        .map(|b| {
            serde_json::from_str(&b)
                .map_err(|_| sqlx::Error::Decode("invalid value in column body_json".into()))
        })
        .transpose()?;
    let epoch: Option<i64> = r.try_get("epoch")?;
    Ok(Post {
        id: r.try_get("id")?,
        group_id: r.try_get("group_id")?,
        author_id: UserId::new(r.try_get::<String, _>("author_id")?),
        author_name: r.try_get("author_name")?,
        kind: parse_col(r, "kind", PostKind::parse)?,
        parent_id: r.try_get("parent_id")?,
        epoch: epoch.and_then(|e| u64::try_from(e).ok()),
        created_at_ms: r.try_get("created_at")?,
        sealed: SealedGroupMessage { message, body },
    })
}

/// One post, if `viewer` may read it, in `group`.
pub async fn visible_by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    viewer: &UserId,
    id: &str,
) -> Result<Option<Post>, sqlx::Error> {
    sqlx::query(post_select!(" AND p.id = $3"))
        .bind(group)
        .bind(viewer.as_str())
        .bind(id)
        .fetch_optional(e)
        .await?
        .as_ref()
        .map(from_row)
        .transpose()
}

/// A page of the feed `viewer` may read: newest first, check-ins and the
/// replies the viewer sent or received. `before` is `(created_at, id)` of
/// the last post of the previous page.
pub async fn feed<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    viewer: &UserId,
    before: Option<(i64, &str)>,
    limit: i64,
) -> Result<Vec<Post>, sqlx::Error> {
    let (b_at, b_id) = before.unwrap_or((i64::MAX, "~"));
    sqlx::query(post_select!(
        " AND (p.created_at < $3 OR (p.created_at = $3 AND p.id < $4))
         ORDER BY p.created_at DESC, p.id DESC LIMIT $5"
    ))
    .bind(group)
    .bind(viewer.as_str())
    .bind(b_at)
    .bind(b_id)
    .bind(limit)
    .fetch_all(e)
    .await?
    .iter()
    .map(from_row)
    .collect()
}

/// Posts `author` wrote since `since_ms` of one kind (for the daily limit).
pub async fn count_since<'e>(
    e: impl Executor<'e, Database = Any>,
    author: &UserId,
    kind: PostKind,
    since_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_posts
         WHERE author_id = $1 AND kind = $2 AND created_at > $3",
    )
    .bind(author.as_str())
    .bind(kind.as_str())
    .bind(since_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Whether `author` already replied to `parent`: one reply each is plenty
/// for a short, private "thinking of you".
pub async fn has_reply<'e>(
    e: impl Executor<'e, Database = Any>,
    author: &UserId,
    parent: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM group_posts WHERE author_id = $1 AND parent_id = $2 LIMIT 1",
    )
    .bind(author.as_str())
    .bind(parent)
    .fetch_optional(e)
    .await?
    .is_some())
}

/// Delete the sealed copies of epoch keys that nothing uses: an epoch
/// before a group's current one that no stored post or message was sealed
/// with (GROUPS.md §18). The current epoch's keys are always kept.
pub async fn prune_epoch_keys<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM group_epoch_keys
         WHERE epoch < (SELECT MAX(g.epoch) FROM group_epochs g
                        WHERE g.group_id = group_epoch_keys.group_id)
           AND NOT EXISTS (SELECT 1 FROM group_posts p
                           WHERE p.group_id = group_epoch_keys.group_id
                             AND p.epoch = group_epoch_keys.epoch)
           AND NOT EXISTS (SELECT 1 FROM group_messages m
                           WHERE m.group_id = group_epoch_keys.group_id
                             AND m.epoch = group_epoch_keys.epoch)",
    )
    .execute(e)
    .await?
    .rows_affected())
}
