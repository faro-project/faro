//! Account deletion (§12): `deleted_device_tokens`, the purge gate and the
//! final per-table statements of the purge ([`crate::deletion`]).
//!
//! The purge removes a user's content (blobs, reports, events, alerts)
//! through the retention code path first, then runs [`PURGE_BY_ID`] and
//! [`PURGE_BY_EMAIL`] in one transaction and deletes the user row last. The
//! foreign keys' cascades are a backstop, not the mechanism: every table
//! that names a user is listed in [`USER_COLUMNS`], and a test fails if a
//! migration adds a reference to `users` that is not.

use faro_proto::api::ServerAlertKind;
use faro_proto::UserId;
use sqlx::{Any, AnyConnection, Executor, Row};

/// Every `(table, column)` that holds a user id, and how the purge clears
/// it. Foreign keys to `users` and the two recipient index columns, which
/// name users without a foreign key.
pub const USER_COLUMNS: &[(&str, &str, Clears)] = &[
    ("sessions", "user_id", Clears::Rows),
    ("magic_links", "user_id", Clears::Rows),
    ("member_keys", "user_id", Clears::Rows),
    ("devices", "owner_user_id", Clears::Rows),
    ("enroll_codes", "member_id", Clears::Rows),
    ("ally_links", "member_id", Clears::Rows),
    ("ally_links", "ally_id", Clears::Rows),
    ("ally_keys", "user_id", Clears::Rows),
    ("invites", "inviter_id", Clears::Rows),
    ("invites", "used_by", Clears::SetNull),
    ("blobs", "owner_member_id", Clears::Content),
    ("events", "member_id", Clears::Rows),
    ("event_recipients", "recipient_id", Clears::Rows),
    ("reports", "member_id", Clears::Rows),
    ("report_recipients", "recipient_id", Clears::Rows),
    ("alerts", "member_id", Clears::Rows),
    ("alerts", "extra_recipient_id", Clears::SetNull),
    ("alerts", "skip_recipient_id", Clears::SetNull),
    ("alerts", "about_user_id", Clears::SetNull),
    ("notifications", "recipient_id", Clears::Rows),
    ("notification_prefs", "user_id", Clears::Rows),
    ("notification_prefs", "member_id", Clears::Rows),
    ("liveness_episodes", "member_id", Clears::Rows),
    ("retention_overrides", "member_id", Clears::Rows),
    ("member_manifests", "member_id", Clears::Rows),
    ("admin_log", "user_id", Clears::SetNull),
    ("admin_log", "actor_id", Clears::SetNull),
    ("accountability_groups", "created_by", Clears::SetNull),
    ("accountability_groups", "archived_by", Clears::SetNull),
    (
        "accountability_groups",
        "facilitator_offer_user_id",
        Clears::SetNull,
    ),
    ("group_participants", "user_id", Clears::Rows),
    ("group_participants", "invited_by", Clears::SetNull),
    ("group_history", "subject_id", Clears::SetNull),
    ("group_history", "actor_id", Clears::SetNull),
    ("group_invites", "inviter_id", Clears::Rows),
    ("group_invites", "user_id", Clears::Rows),
    ("group_invites", "used_by", Clears::SetNull),
    ("group_notices", "recipient_id", Clears::Rows),
    ("group_notices", "actor_id", Clears::SetNull),
    ("group_join_requests", "user_id", Clears::Rows),
    ("group_join_requests", "decided_by", Clears::SetNull),
    ("group_meeting_prefs", "user_id", Clears::Rows),
    ("alliance_proposals", "from_id", Clears::Rows),
    ("alliance_proposals", "to_id", Clears::Rows),
    ("proposal_blocks", "user_id", Clears::Rows),
    ("proposal_blocks", "blocked_id", Clears::Rows),
    ("participant_sign_keys", "user_id", Clears::Rows),
    ("group_epoch_keys", "user_id", Clears::Rows),
];

/// Columns holding the user's email address rather than their id.
pub const EMAIL_COLUMNS: &[(&str, &str)] = &[
    ("invites", "email"),
    ("magic_links", "email"),
    ("group_invites", "email"),
];

/// What happens to rows naming the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clears {
    /// They are deleted.
    Rows,
    /// Ciphertext: deleted through the retention code path, rows first,
    /// then files ([`crate::retention::purge_member`]). The final
    /// transaction refuses to run while any is left ([`blob_count`]).
    Content,
    /// The column is set to NULL; the row belongs to someone else (another
    /// member's alert that named this person, an invite they redeemed, an
    /// admin log entry that now names "a deleted account").
    SetNull,
}

/// The purge's statements on the user id (`$1`), in order. The user's
/// blobs, and with them their files, are already gone when these run.
pub const PURGE_BY_ID: &[&str] = &[
    "DELETE FROM notifications WHERE recipient_id = $1
        OR alert_id IN (SELECT id FROM alerts WHERE member_id = $1)
        OR report_id IN (SELECT id FROM reports WHERE member_id = $1)
        OR admin_log_id IN (SELECT id FROM admin_log WHERE user_id = $1)",
    // Index rows naming the user on other members' items. The signed
    // headers themselves are left alone (they are the other member's).
    "DELETE FROM event_recipients WHERE recipient_id = $1",
    "DELETE FROM report_recipients WHERE recipient_id = $1",
    "UPDATE alerts SET extra_recipient_id = NULL WHERE extra_recipient_id = $1",
    "UPDATE alerts SET skip_recipient_id = NULL WHERE skip_recipient_id = $1",
    "UPDATE alerts SET about_user_id = NULL WHERE about_user_id = $1",
    "UPDATE admin_log SET user_id = NULL WHERE user_id = $1",
    "UPDATE admin_log SET actor_id = NULL WHERE actor_id = $1",
    "DELETE FROM alerts WHERE member_id = $1",
    "DELETE FROM reports WHERE member_id = $1",
    "DELETE FROM events WHERE member_id = $1",
    "DELETE FROM liveness_episodes WHERE member_id = $1",
    "DELETE FROM enroll_codes WHERE member_id = $1",
    "DELETE FROM devices WHERE owner_user_id = $1",
    "DELETE FROM member_manifests WHERE member_id = $1",
    "DELETE FROM member_keys WHERE user_id = $1",
    "DELETE FROM ally_links WHERE member_id = $1 OR ally_id = $1",
    "DELETE FROM ally_keys WHERE user_id = $1",
    "DELETE FROM notification_prefs WHERE user_id = $1 OR member_id = $1",
    "DELETE FROM retention_overrides WHERE member_id = $1",
    "UPDATE invites SET used_by = NULL WHERE used_by = $1",
    "DELETE FROM invites WHERE inviter_id = $1",
    "DELETE FROM magic_links WHERE user_id = $1",
    "DELETE FROM sessions WHERE user_id = $1",
    // Groups (GROUPS.md §18). Alliances formed in a group are ally links,
    // removed above; history keeps its entries without the person
    // ("Someone left").
    "UPDATE accountability_groups SET created_by = NULL WHERE created_by = $1",
    "UPDATE accountability_groups SET archived_by = NULL WHERE archived_by = $1",
    "UPDATE accountability_groups SET facilitator_offer_user_id = NULL WHERE facilitator_offer_user_id = $1",
    "UPDATE group_history SET subject_id = NULL WHERE subject_id = $1",
    "UPDATE group_history SET actor_id = NULL WHERE actor_id = $1",
    "UPDATE group_participants SET invited_by = NULL WHERE invited_by = $1",
    "DELETE FROM group_participants WHERE user_id = $1",
    "UPDATE group_invites SET used_by = NULL WHERE used_by = $1",
    "DELETE FROM group_invites WHERE inviter_id = $1",
    "DELETE FROM group_invites WHERE user_id = $1",
    "UPDATE group_notices SET actor_id = NULL WHERE actor_id = $1",
    "DELETE FROM group_notices WHERE recipient_id = $1",
    "UPDATE group_join_requests SET decided_by = NULL WHERE decided_by = $1",
    "DELETE FROM group_join_requests WHERE user_id = $1",
    "DELETE FROM group_meeting_prefs WHERE user_id = $1",
    // Their proposals, sent and received, and blocks either way (§18).
    // Links started from a proposal are ally links, removed above.
    "DELETE FROM alliance_proposals WHERE from_id = $1 OR to_id = $1",
    "DELETE FROM proposal_blocks WHERE user_id = $1 OR blocked_id = $1",
    // Phase C: their sealed copies of group epoch keys and their group
    // signing key. Signed roster entries keep their opaque id and public
    // keys until a facilitator signs their removal.
    "DELETE FROM group_epoch_keys WHERE user_id = $1",
    "DELETE FROM participant_sign_keys WHERE user_id = $1",
];

/// The purge's statements on the user's email address (`$1`): invitations
/// to them and sign-in links for them.
pub const PURGE_BY_EMAIL: &[&str] = &[
    "DELETE FROM invites WHERE email = $1",
    "DELETE FROM magic_links WHERE email = $1",
    "DELETE FROM group_invites WHERE email = $1",
];

/// The notice kinds the purge waits for (see [`notices_final`]).
const NOTICE_KINDS: [ServerAlertKind; 3] = [
    ServerAlertKind::AccountDeleted,
    ServerAlertKind::AllyDeleted,
    ServerAlertKind::AccountDeletionCancelled,
];

/// Whether every deletion notice about `user` has reached a final status:
/// fanned out, and none of its notifications still `pending` (`sent`,
/// `failed` and `suppressed` are final). The purge waits until it is: the
/// notices name the person and are raised on their account, so deleting
/// the account first would drop or garble them.
pub async fn notices_final<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<bool, sqlx::Error> {
    let [a, b, c] = NOTICE_KINDS.map(ServerAlertKind::as_str);
    let n: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM alerts a
         WHERE a.source = 'server' AND a.kind IN ($2, $3, $4)
           AND (a.member_id = $1 OR a.about_user_id = $1)
           AND (a.dispatched_at IS NULL
                OR EXISTS (SELECT 1 FROM notifications n
                           WHERE n.alert_id = a.id AND n.status = 'pending'))",
    )
    .bind(user.as_str())
    .bind(a)
    .bind(b)
    .bind(c)
    .fetch_one(e)
    .await?
    .try_get("n")?;
    Ok(n == 0)
}

/// Record the token hash of every device `owner` has, so the devices are
/// refused with `account_deleted` from now on, even after their rows are
/// gone. Idempotent.
pub async fn insert_device_tombstones<'e>(
    e: impl Executor<'e, Database = Any>,
    owner: &UserId,
    now_ms: i64,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "INSERT INTO deleted_device_tokens (token_hash, deleted_at)
         SELECT token_hash, $2 FROM devices WHERE owner_user_id = $1
         ON CONFLICT (token_hash) DO NOTHING",
    )
    .bind(owner.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected())
}

/// Whether a device token (by its keyed hash) belonged to a deleted account.
pub async fn is_deleted_device_token<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 AS x FROM deleted_device_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(e)
            .await?
            .is_some(),
    )
}

/// Retention: forget tombstones older than `before_ms`.
pub async fn sweep_device_tombstones<'e>(
    e: impl Executor<'e, Database = Any>,
    before_ms: i64,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query("DELETE FROM deleted_device_tokens WHERE deleted_at < $1")
        .bind(before_ms)
        .execute(e)
        .await?;
    Ok(r.rows_affected())
}

/// Stop monitoring `owner`'s computers: every device is retired (its token
/// stops authenticating, the liveness monitor forgets it) and open
/// missed-check-in episodes close. No `device_removed` alert: the deletion
/// notices told everyone when this would happen.
pub async fn retire_devices(
    conn: &mut AnyConnection,
    owner: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET status = 'removed', removed_at = $2
         WHERE owner_user_id = $1 AND status <> 'removed'",
    )
    .bind(owner.as_str())
    .bind(now_ms)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE liveness_episodes SET closed_at = $2 WHERE member_id = $1 AND closed_at IS NULL",
    )
    .bind(owner.as_str())
    .bind(now_ms)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Blobs still owned by `user` (the purge's final transaction requires
/// none: their files can only be deleted after their rows).
pub async fn blob_count<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<i64, sqlx::Error> {
    sqlx::query("SELECT COUNT(*) AS n FROM blobs WHERE owner_member_id = $1")
        .bind(user.as_str())
        .fetch_one(e)
        .await?
        .try_get("n")
}

/// The purge's final statements, then the user row. Run inside one
/// transaction after the content is gone.
pub async fn delete_rows(
    conn: &mut AnyConnection,
    user: &UserId,
    email: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    // A device enrolled in a race with the start of the purge is refused
    // like the others.
    insert_device_tombstones(&mut *conn, user, now_ms).await?;
    // Groups first: a group the person was the last facilitator of is
    // offered to its earliest participant (GROUPS.md §9), who is told.
    for (_, offered) in super::groups::before_user_purge(&mut *conn, user, now_ms).await? {
        crate::groups::tell_offered(&mut *conn, &offered, now_ms).await?;
    }
    for &sql in PURGE_BY_ID {
        sqlx::query(sql)
            .bind(user.as_str())
            .execute(&mut *conn)
            .await?;
    }
    for &sql in PURGE_BY_EMAIL {
        sqlx::query(sql).bind(email).execute(&mut *conn).await?;
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.as_str())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every table and column the list names has a statement that clears it.
    #[test]
    fn every_listed_column_has_a_statement() {
        for (table, col, clears) in USER_COLUMNS {
            let want = match clears {
                Clears::Rows => format!("DELETE FROM {table} WHERE"),
                Clears::SetNull => format!("UPDATE {table} SET {col} = NULL WHERE {col} = $1"),
                Clears::Content => continue,
            };
            let found = PURGE_BY_ID
                .iter()
                .any(|s| s.contains(&want) && s.contains(&format!("{col} = $1")));
            assert!(found, "no purge statement for {table}.{col}");
        }
        for (table, col) in EMAIL_COLUMNS {
            let want = format!("DELETE FROM {table} WHERE {col} = $1");
            assert!(PURGE_BY_EMAIL.contains(&want.as_str()), "{table}.{col}");
        }
    }
}
