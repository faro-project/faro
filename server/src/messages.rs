//! Reach outs and signed, encrypted notes: the rules the routes share
//! (GROUPS.md §8.3, §10.2; PROTOCOL.md §11).
//!
//! * **Who a message may go to** ([`resolve_audience`]): the sender's own
//!   allies, a group's facilitators, or up to 32 named people (active
//!   participants of a group the sender is in, or, outside any group,
//!   people the sender has an active link with), or the whole group, only
//!   in a group of 32 or fewer (decision 10): those messages are sealed
//!   with the group's epoch key and name nobody (PROTOCOL.md §11). Check-ins
//!   ([`resolve_check_in_audience`]) use the same audiences, with "my allies"
//!   meaning the sender's allies in that group, and the whole group at any
//!   size.
//! * **Which key to seal to** ([`recipient_keys`]): an ally's key from the
//!   sender's own manifest, otherwise the person's member encryption key,
//!   otherwise their ally key. The browser trusts only the first without
//!   question (it is in the sender's own signed manifest); the others are
//!   marked "not yet verified" until participants have signed keys.
//! * **Checking an upload** ([`check_message`]): the instance verifies the
//!   author's signature and that the message is for this place and these
//!   people. It would gain nothing by skipping this (every reader verifies
//!   again in the browser), but refusing bad uploads keeps junk out.
//! * **Sending a reach out** ([`send_reach_out`]): at most
//!   [`MAX_REACH_OUTS_PER_HOUR`] per sender, an urgent, content-free notice
//!   to each recipient ([`crate::groups::tell_reach_out`]). A reach out
//!   without a signed message is the unverifiable kind ally-only senders
//!   use; the app marks it "Sent through the server. Can't be verified."

use crate::api::groups::{load_in_tx, require_writable};
use crate::db::repo::group_messages::{self, Audience, NewReachOut, MAX_REACH_OUTS_PER_HOUR};
use crate::db::repo::groups::LARGE_GROUP;
use crate::db::repo::{allies, groups, is_unique_violation, member_keys, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use faro_proto::api::REQUEST_MAX_SKEW_MS;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage, MAX_MESSAGE_RECIPIENTS};
use faro_proto::keys::key_id;
use faro_proto::{EncPublicKey, UserId};
use serde::{Deserialize, Serialize};

const HOUR_MS: i64 = 3600 * 1000;

/// Where a recipient's key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// Their ally key (in the sender's manifest, if they are the sender's ally).
    AllyKey,
    /// Their member encryption key.
    MemberKey,
}

/// One person to seal to, as the composer needs them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientKey {
    pub user_id: UserId,
    pub display_name: String,
    /// `None`: they have no keys yet. They are still told about a reach
    /// out, but can't read its message.
    pub enc_pubkey: Option<EncPublicKey>,
    pub key_id: Option<String>,
    pub source: Option<KeySource>,
    /// They are the sender's active ally, so this key is in the sender's
    /// own signed manifest.
    pub sender_ally: bool,
}

/// The key `sender` should seal to for `recipient` (module docs).
pub async fn recipient_key(
    conn: &mut sqlx::AnyConnection,
    sender: &UserId,
    recipient: &UserId,
) -> Result<(Option<(EncPublicKey, KeySource)>, bool), sqlx::Error> {
    let ally = allies::is_active(&mut *conn, sender, recipient).await?;
    if ally {
        if let Some(k) = allies::live_key(&mut *conn, recipient).await? {
            return Ok((Some((k.enc_pubkey, KeySource::AllyKey)), true));
        }
    }
    if let Some(k) = member_keys::get(&mut *conn, recipient).await? {
        return Ok((Some((k.enc_pubkey, KeySource::MemberKey)), ally));
    }
    if let Some(k) = allies::live_key(&mut *conn, recipient).await? {
        return Ok((Some((k.enc_pubkey, KeySource::AllyKey)), ally));
    }
    Ok((None, ally))
}

/// [`recipient_key`] and the display name for each of `people`.
pub async fn recipient_keys(
    conn: &mut sqlx::AnyConnection,
    sender: &UserId,
    people: &[UserId],
) -> AppResult<Vec<RecipientKey>> {
    let mut out = Vec::with_capacity(people.len());
    for p in people {
        let Some(u) = users::by_id(&mut *conn, p).await? else {
            continue;
        };
        let (key, sender_ally) = recipient_key(conn, sender, p).await?;
        out.push(RecipientKey {
            user_id: p.clone(),
            display_name: u.display_name,
            key_id: key.map(|(k, _)| key_id(k.as_bytes())),
            enc_pubkey: key.map(|(k, _)| k),
            source: key.map(|(_, s)| s),
            sender_ally,
        });
    }
    Ok(out)
}

/// Every key the instance knows for `user`: their member encryption key
/// and their live ally keys.
async fn known_keys(
    conn: &mut sqlx::AnyConnection,
    user: &UserId,
) -> Result<Vec<EncPublicKey>, sqlx::Error> {
    let mut keys = allies::live_enc_keys(&mut *conn, user).await?;
    if let Some(k) = member_keys::get(&mut *conn, user).await? {
        keys.push(k.enc_pubkey);
    }
    Ok(keys)
}

/// People who can be sent anything: not disabled, not being deleted.
async fn reachable(
    conn: &mut sqlx::AnyConnection,
    people: Vec<UserId>,
) -> Result<Vec<UserId>, sqlx::Error> {
    let mut out = Vec::with_capacity(people.len());
    for p in people {
        if let Some(u) = users::by_id(&mut *conn, &p).await? {
            if !u.disabled && u.deletion.is_none() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn no_recipients() -> AppError {
    AppError::conflict(
        "no_recipients",
        "there is nobody to send this to: choose other people",
    )
}

/// Everyone a reach out (or a message) from `sender` to `audience` goes
/// to (module docs). A group or person the sender can't see is `404`.
pub async fn resolve_audience(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    sender: &UserId,
    audience: Audience,
    group_id: Option<&str>,
    named: &[UserId],
) -> AppResult<Vec<UserId>> {
    if audience != Audience::People && !named.is_empty() {
        return Err(AppError::bad_request(
            "user_ids_not_needed",
            "only a reach out to named people lists them",
        ));
    }
    let people = match audience {
        Audience::Allies => {
            if group_id.is_some() {
                return Err(AppError::bad_request(
                    "group_not_needed",
                    "a reach out to your allies doesn't name a group",
                ));
            }
            allies::active_ally_ids(&mut *conn, sender).await?
        }
        Audience::Facilitators => {
            let gid = group_id.ok_or_else(|| {
                AppError::bad_request("group_required", "say which group's facilitators")
            })?;
            let (group, _) = load_in_tx(conn, sender, gid).await?;
            require_writable(state, &group)?;
            groups::active_user_ids(&mut *conn, gid, true)
                .await?
                .into_iter()
                .filter(|f| f != sender)
                .collect()
        }
        Audience::People => {
            if named.is_empty() || named.len() > MAX_MESSAGE_RECIPIENTS {
                return Err(AppError::bad_request(
                    "invalid_recipients",
                    format!("name 1 to {MAX_MESSAGE_RECIPIENTS} people"),
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for p in named {
                if !p.is_well_formed() {
                    return Err(AppError::NotFound);
                }
                if p == sender {
                    return Err(AppError::bad_request(
                        "cannot_reach_self",
                        "you can't reach out to yourself",
                    ));
                }
                if !seen.insert(p.clone()) {
                    return Err(AppError::bad_request(
                        "invalid_recipients",
                        "a person is named twice",
                    ));
                }
            }
            match group_id {
                Some(gid) => {
                    let (group, _) = load_in_tx(conn, sender, gid).await?;
                    require_writable(state, &group)?;
                    for p in named {
                        if groups::active_participant(&mut *conn, gid, p)
                            .await?
                            .is_none()
                        {
                            return Err(AppError::NotFound);
                        }
                    }
                }
                None => {
                    for p in named {
                        if !allies::is_active(&mut *conn, sender, p).await?
                            && !allies::is_active(&mut *conn, p, sender).await?
                        {
                            return Err(AppError::NotFound);
                        }
                    }
                }
            }
            named.to_vec()
        }
        Audience::Group => {
            let gid = group_id.ok_or_else(|| {
                AppError::bad_request("group_required", "say which group to reach out to")
            })?;
            let (group, _) = load_in_tx(conn, sender, gid).await?;
            require_writable(state, &group)?;
            if groups::count_active(&mut *conn, gid).await? > LARGE_GROUP {
                return Err(AppError::conflict(
                    "group_too_large",
                    format!(
                        "a reach out to the whole group is only for groups of {LARGE_GROUP} \
                         people or fewer: choose your allies, the facilitators or people by name"
                    ),
                ));
            }
            require_group_key(conn, state, gid).await?;
            groups::active_user_ids(&mut *conn, gid, false)
                .await?
                .into_iter()
                .filter(|p| p != sender)
                .collect()
        }
    };
    let people = reachable(conn, people).await?;
    if people.is_empty() {
        return Err(no_recipients());
    }
    if people.len() > MAX_MESSAGE_RECIPIENTS {
        return Err(AppError::conflict(
            "too_many_recipients",
            format!("a message can go to at most {MAX_MESSAGE_RECIPIENTS} people"),
        ));
    }
    Ok(people)
}

/// Whole-group posting needs the group's encryption set up, and waits while
/// a facilitator has roster work to do ("Waiting for a facilitator to
/// update the group", PROTOCOL.md §10.7). Returns the current epoch.
pub async fn require_group_key(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    group_id: &str,
) -> AppResult<u64> {
    let (pending, _) = crate::api::group_roster::pending_changes(conn, state, group_id).await?;
    if pending.epoch == 0 {
        return Err(AppError::conflict(
            "group_key_missing",
            "this group's encryption isn't set up yet: a facilitator's browser does it \
             when they open the group",
        ));
    }
    if pending.posting_paused {
        return Err(AppError::conflict(
            "posting_paused",
            "waiting for a facilitator to update the group: send to people by name for now",
        ));
    }
    Ok(pending.epoch)
}

/// Everyone a check-in from `sender` to `audience` in `group_id` goes to,
/// by the same rules as [`resolve_audience`], except that "my allies" means
/// the sender's allies who are in this group, and "the whole group" has no
/// size limit and names nobody (the empty list: it is sealed with the epoch
/// key, and whoever is in the group when it arrives may read it).
pub async fn resolve_check_in_audience(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    sender: &UserId,
    audience: Audience,
    group_id: &str,
    named: &[UserId],
) -> AppResult<Vec<UserId>> {
    match audience {
        Audience::Allies => {
            if !named.is_empty() {
                return Err(AppError::bad_request(
                    "user_ids_not_needed",
                    "only a post to named people lists them",
                ));
            }
            let (group, _) = load_in_tx(conn, sender, group_id).await?;
            require_writable(state, &group)?;
            let mut people = Vec::new();
            for a in allies::active_ally_ids(&mut *conn, sender).await? {
                if groups::active_participant(&mut *conn, group_id, &a)
                    .await?
                    .is_some()
                {
                    people.push(a);
                }
            }
            let people = reachable(conn, people).await?;
            if people.is_empty() {
                return Err(no_recipients());
            }
            Ok(people)
        }
        Audience::Group => {
            if !named.is_empty() {
                return Err(AppError::bad_request(
                    "user_ids_not_needed",
                    "only a post to named people lists them",
                ));
            }
            let (group, _) = load_in_tx(conn, sender, group_id).await?;
            require_writable(state, &group)?;
            require_group_key(conn, state, group_id).await?;
            Ok(Vec::new())
        }
        Audience::Facilitators | Audience::People => {
            resolve_audience(conn, state, sender, audience, Some(group_id), named).await
        }
    }
}

/// What an uploaded message must be, for where it is uploaded.
pub struct Expect<'a> {
    pub kind: GroupMessageKind,
    pub group_id: Option<&'a str>,
    /// Who it may be sealed to (a subset is fine: people without keys
    /// can't be).
    pub allowed: &'a [UserId],
    /// Sealed with the group's current epoch key and naming nobody
    /// (otherwise sealed to people, with no epoch).
    pub whole_group: bool,
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::bad_request("invalid_message", message)
}

/// Check a message `author` uploads (module docs): its structure and body,
/// that it is for this instance, place and people, recent, sealed to the
/// keys the instance knows for each, and signed by the author's member key.
pub async fn check_message(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    author: &UserId,
    sealed: &SealedGroupMessage,
    expect: &Expect<'_>,
) -> AppResult<()> {
    sealed.validate().map_err(|e| invalid(e.to_string()))?;
    let m = &sealed.message.body;
    if &m.instance_id != state.instance_id() {
        return Err(invalid("the message is for another instance"));
    }
    if &m.author_id != author {
        return Err(invalid("you can only send your own messages"));
    }
    if m.kind != expect.kind {
        return Err(invalid(format!("expected a {}", expect.kind.as_str())));
    }
    if m.group_id.as_deref() != expect.group_id {
        return Err(invalid("the message names another group"));
    }
    match (expect.whole_group, m.epoch) {
        (false, None) => {}
        (true, Some(epoch)) => {
            let gid = expect
                .group_id
                .ok_or_else(|| invalid("a whole-group message names its group"))?;
            let current = require_group_key(conn, state, gid).await?;
            if epoch != current {
                return Err(AppError::conflict(
                    "stale_epoch",
                    "the group's key changed: send it again",
                ));
            }
        }
        (true, None) => return Err(invalid("expected a message sealed with the group's key")),
        (false, Some(_)) => return Err(invalid("this message can't go to the whole group")),
    }
    if (state.now_ms() - m.issued_at_ms).abs() > REQUEST_MAX_SKEW_MS {
        return Err(AppError::bad_request(
            "clock_skew",
            "the message's time is too far from the server's: check your clock",
        ));
    }
    let keys = member_keys::get(&mut *conn, author).await?.ok_or_else(|| {
        AppError::conflict(
            "member_keys_required",
            "signing a message needs your member keys",
        )
    })?;
    faro_crypto::verify_group_message(&keys.sign_pubkey, sealed).map_err(|_| {
        AppError::bad_request(
            "bad_signature",
            "the message isn't signed with your member key",
        )
    })?;
    if let (Some(body), None) = (&sealed.body, m.epoch) {
        let mine = key_id(keys.enc_pubkey.as_bytes());
        if !body
            .envelopes
            .iter()
            .any(|e| &e.recipient == author && e.key_id == mine)
        {
            return Err(invalid("your own copy isn't sealed to your member key"));
        }
    }
    for r in &m.recipients {
        if !expect.allowed.contains(&r.user_id) {
            return Err(invalid("the message is sealed to someone it can't go to"));
        }
        if !known_keys(conn, &r.user_id).await?.contains(&r.enc_pubkey) {
            return Err(AppError::conflict(
                "stale_recipient_key",
                "someone's key changed: load the recipients again",
            ));
        }
    }
    Ok(())
}

/// Store a checked message under its item id.
pub async fn store_message(
    conn: &mut sqlx::AnyConnection,
    sealed: &SealedGroupMessage,
    now_ms: i64,
) -> AppResult<()> {
    match group_messages::insert_message(conn, sealed, now_ms).await {
        Ok(()) => Ok(()),
        Err(e) if is_unique_violation(&e) => Err(AppError::conflict(
            "message_exists",
            "a message with this id already exists",
        )),
        Err(e) => Err(e.into()),
    }
}

/// [`check_message`] then [`store_message`]: a note's whole upload.
pub async fn accept_message(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    author: &UserId,
    sealed: &SealedGroupMessage,
    expect: &Expect<'_>,
) -> AppResult<()> {
    check_message(conn, state, author, sealed, expect).await?;
    store_message(conn, sealed, state.now_ms()).await
}

/// Send a reach out from `sender` to `recipients` (already resolved, at
/// most 32), with an optional signed message: the rate limit, the message,
/// the rows, and an urgent notice to each recipient. Returns its id.
///
/// A whole-group reach out resolves its recipients (every active
/// participant but the sender, in a group of 32 or fewer) in
/// [`resolve_audience`] and calls this the same way.
pub async fn send_reach_out(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    sender: &UserId,
    audience: Audience,
    group_id: Option<&str>,
    recipients: &[UserId],
    message: Option<&SealedGroupMessage>,
) -> AppResult<String> {
    let now = state.now_ms();
    if recipients.is_empty() {
        return Err(no_recipients());
    }
    if recipients.len() > MAX_MESSAGE_RECIPIENTS {
        return Err(AppError::conflict(
            "too_many_recipients",
            format!("a message can go to at most {MAX_MESSAGE_RECIPIENTS} people"),
        ));
    }
    let recent = group_messages::sent_since(&mut *conn, sender, now - HOUR_MS).await?;
    if recent.len() as i64 >= MAX_REACH_OUTS_PER_HOUR {
        let oldest = recent.first().copied().unwrap_or(now);
        let wait_ms = (oldest + HOUR_MS - now).max(1000);
        return Err(AppError::TooManyRequests {
            retry_after_secs: u64::try_from((wait_ms + 999) / 1000).unwrap_or(3600),
        });
    }
    if let Some(m) = message {
        accept_message(
            conn,
            state,
            sender,
            m,
            &Expect {
                kind: GroupMessageKind::ReachOut,
                group_id,
                allowed: recipients,
                whole_group: audience == Audience::Group,
            },
        )
        .await?;
    }
    let id = group_messages::insert_reach_out(
        conn,
        &NewReachOut {
            sender,
            group_id,
            audience,
            sig: message.map(|m| m.message.sig.to_b64()),
            message_id: message.map(|m| m.message.body.item_id.as_str()),
            recipients,
            now_ms: now,
        },
    )
    .await?;
    for r in recipients {
        crate::groups::tell_reach_out(conn, r, sender, now).await?;
    }
    Ok(id)
}
