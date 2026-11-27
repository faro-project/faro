//! Alliance proposals in groups (docs/GROUPS.md §7): a **request** ("be my
//! ally"), an **offer** ("let me be your ally") or a **partnership** ("let's
//! be each other's allies") between two active participants of one group.
//!
//! * `POST /v1/groups/{id}/proposals` `{to, kind, ally_key?}` sends one.
//! * `GET /v1/me/proposals` lists the caller's incoming and outgoing ones.
//! * `POST /v1/proposals/{id}/accept` `{ally_key?}` and
//!   `POST /v1/proposals/{id}/decline` answer one (the recipient only).
//! * `DELETE /v1/proposals/{id}` withdraws one (the sender only).
//! * `GET /v1/me/proposal-blocks`, `PUT|DELETE /v1/me/proposal-blocks/{user_id}`:
//!   "Don't let them send me proposals".
//!
//! **Nothing here activates a link** (principle 2). Accepting creates
//! **pending** links through the same function as accepting an email
//! invitation ([`invites::accept_ally_link`]), labelled with the group
//! (`origin_group_id`). The member then compares safety codes and signs,
//! through the existing `POST /v1/me/allies/{ally_id}/approve`, which stays
//! the only way an `ally_links` row becomes `active`.
//!
//! **Nobody acts for anyone else** (principle 3). Every route works on the
//! caller's own proposals: a facilitator or admin has no route to send,
//! accept, decline or see anyone else's. Someone else's proposal is `404`.
//!
//! **Declining is private** (principle 5). The sender's view of a proposal
//! depends only on their own actions and the clock
//! ([`proposals::Proposal::sender_state`]): declined, expired, voided and
//! hidden proposals all look open until they would have expired, then "not
//! accepted" with the same "ask again on" date, byte for byte. A proposal to
//! someone who blocked the sender, can't receive proposals, or declined the
//! same kind recently (and the sender withdrew it since) is stored
//! **hidden**: the sender sees an ordinary proposal, the recipient never sees
//! it and isn't told.
//!
//! **Rules** (§7.6): one open proposal per direction (a partnership is both),
//! none where a live link already exists, 14-day expiry, a 30-day cool-down
//! per kind and person, at most 10 new proposals per sender per day, and
//! open proposals count toward the sender's live-invite limit
//! ([`invites::MAX_LIVE_INVITES`]). Room for another ally
//! ([`invites::MAX_ALLIES`]) is checked when accepting, and only the person
//! accepting is told. Leaving, removal, archiving, disabling and the deletion
//! hold void open proposals ([`proposals::void`]).

use super::groups::{load_in_tx, require_writable};
use super::invites::{self, accept_ally_link, ensure_ally_key, MAX_ALLIES, MAX_LIVE_INVITES};
use super::{ApiJson, OptionalApiJson};
use crate::auth::session::SessionUser;
use crate::db::repo::group_notices::NoticeKind;
use crate::db::repo::proposals::{
    self, Block, Kind, Listed, NewProposal, Proposal, RecipientState, SenderState, State, VoidScope,
};
use crate::db::repo::{allies, groups, is_unique_violation, member_keys, users};
use crate::error::{AppError, AppResult};
use crate::messages::{self, Expect};
use crate::state::AppState;
use axum::extract::{Path, State as AxState};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::AllyKeyUpload;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage};
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

/// New proposals one person may send per day, across all groups.
pub const MAX_PROPOSALS_PER_DAY: i64 = 10;
const DAY_MS: i64 = 24 * 3600 * 1000;

fn parse_user(id: &str) -> AppResult<UserId> {
    let id = UserId::new(id);
    if id.is_well_formed() {
        Ok(id)
    } else {
        Err(AppError::NotFound)
    }
}

fn closed() -> AppError {
    AppError::conflict("proposal_closed", "this proposal is no longer open")
}

// ---- Views -------------------------------------------------------------------

/// The other person in a proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonRef {
    pub user_id: UserId,
    pub display_name: String,
}

/// A proposal the caller sent, as the sender sees it: nothing in it tells a
/// decline from an expiry or a void (module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingProposal {
    pub id: String,
    pub group_id: String,
    /// While the caller is still in the group.
    pub group_name: Option<String>,
    pub to: PersonRef,
    pub kind: Kind,
    /// `open`, `accepted`, `not_accepted` or `withdrawn`.
    pub state: SenderState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub accepted_at_ms: Option<i64>,
    pub withdrawn_at_ms: Option<i64>,
    /// Not accepted: the same kind can be sent to this person again from
    /// this time ("You can ask again on *date*").
    pub ask_again_at_ms: Option<i64>,
    /// The caller's note (`GET /v1/group-messages/{id}`), if they wrote one.
    pub note_id: Option<String>,
}

/// A proposal sent to the caller, with their own decision as they made it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingProposal {
    pub id: String,
    pub group_id: String,
    /// While the caller is still in the group.
    pub group_name: Option<String>,
    pub from: PersonRef,
    pub kind: Kind,
    /// `open`, `accepted`, `declined`, `expired`, `withdrawn` or `void`.
    pub state: RecipientState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// When the caller accepted or declined, or the sender withdrew.
    pub decided_at_ms: Option<i64>,
    /// The sender's signed note (`GET /v1/group-messages/{id}`), if any.
    pub note_id: Option<String>,
}

fn outgoing_view(l: Listed, now: i64) -> OutgoingProposal {
    let p = l.proposal;
    let state = p.sender_state(now);
    OutgoingProposal {
        accepted_at_ms: (state == SenderState::Accepted)
            .then_some(p.decided_at_ms)
            .flatten(),
        withdrawn_at_ms: p.withdrawn_at_ms,
        note_id: p.note_id.clone(),
        ask_again_at_ms: (state == SenderState::NotAccepted && p.cooldown_until_ms > now)
            .then_some(p.cooldown_until_ms),
        state,
        id: p.id,
        group_id: p.group_id,
        group_name: l.group_name,
        to: PersonRef {
            user_id: p.to_id,
            display_name: l.other_display_name,
        },
        kind: p.kind,
        created_at_ms: p.created_at_ms,
        expires_at_ms: p.expires_at_ms,
    }
}

fn incoming_view(l: Listed, now: i64) -> IncomingProposal {
    let p = l.proposal;
    IncomingProposal {
        state: p.recipient_state(now),
        decided_at_ms: p.decided_at_ms,
        note_id: p.note_id.clone(),
        id: p.id,
        group_id: p.group_id,
        group_name: l.group_name,
        from: PersonRef {
            user_id: p.from_id,
            display_name: l.other_display_name,
        },
        kind: p.kind,
        created_at_ms: p.created_at_ms,
        expires_at_ms: p.expires_at_ms,
    }
}

/// `GET /v1/me/proposals` response, newest first on each side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyProposals {
    pub incoming: Vec<IncomingProposal>,
    pub outgoing: Vec<OutgoingProposal>,
}

/// `GET /v1/me/proposals`
pub async fn list_mine(
    AxState(state): AxState<AppState>,
    s: SessionUser,
) -> AppResult<Json<MyProposals>> {
    let pool = state.db().pool();
    let now = state.now_ms();
    let incoming = proposals::incoming(pool, &s.user.id).await?;
    let outgoing = proposals::outgoing(pool, &s.user.id).await?;
    Ok(Json(MyProposals {
        incoming: incoming
            .into_iter()
            .map(|l| incoming_view(l, now))
            .collect(),
        outgoing: outgoing
            .into_iter()
            .map(|l| outgoing_view(l, now))
            .collect(),
    }))
}

// ---- Create --------------------------------------------------------------------

/// `POST /v1/groups/{id}/proposals` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProposal {
    pub to: UserId,
    pub kind: Kind,
    /// Offers and partnerships, when the sender has no ally key yet: the
    /// one their browser just made (as when accepting an invitation).
    #[serde(default)]
    pub ally_key: Option<AllyKeyUpload>,
    /// A note to the recipient, at most 500 characters, signed with the
    /// sender's member key and sealed to the recipient in the browser
    /// (GROUPS.md §10.2).
    #[serde(default)]
    pub note: Option<SealedGroupMessage>,
}

/// Whether two sets of `(member, ally)` links share one.
fn overlap(a: &[(&UserId, &UserId)], b: &[(&UserId, &UserId)]) -> bool {
    a.iter().any(|x| b.contains(x))
}

/// `POST /v1/groups/{id}/proposals`: the caller proposes to another active
/// participant of the group.
pub async fn create(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(group_id): Path<String>,
    ApiJson(req): ApiJson<CreateProposal>,
) -> AppResult<(StatusCode, Json<OutgoingProposal>)> {
    s.require_not_being_deleted()?;
    let me = &s.user.id;
    let to = parse_user(req.to.as_str())?;
    let kind = req.kind;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    super::account::refuse_if_being_deleted(&mut *tx, me).await?;
    let (group, _) = load_in_tx(&mut tx, me, &group_id).await?;
    require_writable(&state, &group)?;
    if &to == me {
        return Err(AppError::bad_request(
            "cannot_propose_to_self",
            "you cannot be your own ally",
        ));
    }
    if groups::active_participant(&mut *tx, &group_id, &to)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }
    let recipient = users::by_id(&mut *tx, &to)
        .await?
        .ok_or(AppError::NotFound)?;
    proposals::expire_between(&mut *tx, me, &to, now).await?;

    // What each side needs (§7.1). Nothing here depends on anything the
    // sender can't already see.
    let i_am_member = matches!(kind, Kind::Request | Kind::Partnership);
    let i_am_ally = matches!(kind, Kind::Offer | Kind::Partnership);
    if i_am_member && member_keys::sign_pubkey(&mut *tx, me).await?.is_none() {
        return Err(AppError::conflict(
            "member_keys_required",
            "set up your member keys first: someone can only be your ally once you have them",
        ));
    }
    if !i_am_ally && req.ally_key.is_some() {
        return Err(AppError::bad_request(
            "ally_key_not_needed",
            "a request doesn't need your ally key",
        ));
    }
    if i_am_ally && member_keys::sign_pubkey(&mut *tx, &to).await?.is_none() {
        return Err(AppError::conflict(
            "cannot_propose",
            "this person can't take part in this kind of proposal",
        ));
    }
    let links = kind.links(me, &to);
    for (member, ally) in &links {
        if allies::live_state(&mut *tx, member, ally).await?.is_some() {
            return Err(AppError::conflict(
                "already_linked",
                "you are already linked this way (or the link is waiting for approval)",
            ));
        }
    }
    if i_am_member && allies::count_live(&mut *tx, me).await? >= MAX_ALLIES {
        return Err(AppError::conflict(
            "too_many_allies",
            format!("you already have {MAX_ALLIES} allies, the most Faro allows"),
        ));
    }

    // One open proposal per direction, and the cool-down: from the
    // sender's own view of their proposals.
    let mine = proposals::recent_between(&mut *tx, me, &to, now).await?;
    if mine.iter().any(|p| {
        p.sender_state(now) == SenderState::Open && overlap(&p.kind.links(me, &to), &links)
    }) {
        return Err(AppError::conflict(
            "already_proposed",
            "you already have an open proposal to this person that covers this",
        ));
    }
    if let Some(p) = mine
        .iter()
        .find(|p| p.kind == kind && p.holds_back_sender(now))
    {
        return Err(AppError::conflict(
            "proposal_cooldown",
            format!(
                "you can send this person this kind of proposal again from {} (Unix ms)",
                p.cooldown_until_ms
            ),
        ));
    }
    // Their open proposal to me covering the same link: answer that one.
    let theirs = proposals::recent_between(&mut *tx, &to, me, now).await?;
    if theirs
        .iter()
        .any(|p| p.answerable(now) && overlap(&p.kind.links(&to, me), &links))
    {
        return Err(AppError::conflict(
            "proposal_waiting",
            "this person already sent you a proposal for this: accept that one instead",
        ));
    }
    if proposals::count_sent_since(&mut *tx, me, now - DAY_MS).await? >= MAX_PROPOSALS_PER_DAY {
        return Err(AppError::conflict(
            "too_many_proposals",
            format!("you can send at most {MAX_PROPOSALS_PER_DAY} proposals a day"),
        ));
    }
    if invites::live_invites_and_proposals(&mut tx, me, now).await? >= MAX_LIVE_INVITES {
        return Err(AppError::conflict(
            "too_many_invites",
            "too many open invitations and proposals; wait for some to be answered or expire",
        ));
    }
    // The note: checked and stored before the proposal that points to it.
    // A hidden proposal keeps it too, for the sender's own view; the
    // recipient never gets it.
    let note_id = match &req.note {
        None => None,
        Some(note) => {
            messages::accept_message(
                &mut tx,
                &state,
                me,
                note,
                &Expect {
                    kind: GroupMessageKind::ProposalNote,
                    group_id: Some(&group_id),
                    allowed: std::slice::from_ref(&to),
                },
            )
            .await?;
            Some(note.message.body.item_id.clone())
        }
    };
    let offer_key = if i_am_ally {
        Some(ensure_ally_key(&mut tx, me, req.ally_key.as_ref(), now).await?)
    } else {
        None
    };

    // Silently hidden from the recipient (module docs): the sender's view
    // and this response are the same either way.
    let declined_recently = mine
        .iter()
        .any(|p| p.kind == kind && p.state == State::NotAccepted && p.decided_at_ms.is_some());
    let hidden = recipient.disabled
        || recipient.deletion.is_some()
        || declined_recently
        || proposals::is_blocked(&mut *tx, &to, me).await?;
    let row = match proposals::insert(
        &mut *tx,
        &NewProposal {
            group_id: &group_id,
            from: me,
            to: &to,
            kind,
            offer_ally_key_id: offer_key.as_deref(),
            hidden,
            note_id: note_id.as_deref(),
            now_ms: now,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "already_proposed",
                "you already have an open proposal to this person that covers this",
            ))
        }
        Err(e) => return Err(e.into()),
    };
    if !hidden {
        crate::groups::tell_alliance(&mut tx, kind.notice(), &to, me, now).await?;
    }
    tx.commit().await?;
    tracing::info!(group = %group_id, kind = kind.as_str(), "alliance proposal sent");
    Ok((
        StatusCode::CREATED,
        Json(outgoing_view(
            Listed {
                proposal: row,
                other_display_name: recipient.display_name,
                group_name: Some(group.name),
            },
            now,
        )),
    ))
}

// ---- Answer ----------------------------------------------------------------------

/// `POST /v1/proposals/{id}/accept` body (optional).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptProposal {
    /// Requests and partnerships, when the caller has no ally key yet: the
    /// one their browser just made. With an existing key, leave it out (or
    /// send that same key).
    #[serde(default)]
    pub ally_key: Option<AllyKeyUpload>,
}

/// A link accepting started. It is **pending**: the member (`member_id`)
/// compares safety codes and approves it with
/// `POST /v1/me/allies/{ally_id}/approve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartedLink {
    pub member_id: UserId,
    pub ally_id: UserId,
    pub state: allies::LinkState,
    /// The fingerprint of the ally key the member will endorse.
    pub ally_key_id: String,
}

/// `POST /v1/proposals/{id}/accept` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalAccepted {
    pub proposal: IncomingProposal,
    pub links: Vec<StartedLink>,
}

/// Load a proposal sent to the caller that they can still answer, inside
/// `tx`. Someone else's (or a hidden one) is `404`.
async fn load_incoming(
    tx: &mut sqlx::AnyConnection,
    me: &UserId,
    id: &str,
    now: i64,
) -> AppResult<Proposal> {
    let p = proposals::by_id(&mut *tx, id)
        .await?
        .filter(|p| &p.to_id == me && !p.hidden)
        .ok_or(AppError::NotFound)?;
    if !p.answerable(now) {
        return Err(closed());
    }
    Ok(p)
}

/// `POST /v1/proposals/{id}/accept`: the recipient accepts. Creates the
/// pending link(s), never an active one, and tells the sender.
pub async fn accept(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    OptionalApiJson(req): OptionalApiJson<AcceptProposal>,
) -> AppResult<(StatusCode, Json<ProposalAccepted>)> {
    s.require_not_being_deleted()?;
    let req = req.unwrap_or_default();
    let me = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    super::account::refuse_if_being_deleted(&mut *tx, me).await?;
    let p = load_incoming(&mut tx, me, &id, now).await?;
    // Leaving, archiving, disabling and deletion void a proposal; check
    // again rather than rely on it.
    let group = groups::by_id(&mut *tx, &p.group_id)
        .await?
        .ok_or_else(closed)?;
    require_writable(&state, &group)?;
    for u in [me, &p.from_id] {
        if groups::active_participant(&mut *tx, &p.group_id, u)
            .await?
            .is_none()
        {
            return Err(closed());
        }
    }
    let sender = users::by_id(&mut *tx, &p.from_id)
        .await?
        .ok_or_else(closed)?;
    if sender.disabled || sender.deletion.is_some() {
        return Err(closed());
    }
    let i_am_member = matches!(p.kind, Kind::Offer | Kind::Partnership);
    if i_am_member && member_keys::sign_pubkey(&mut *tx, me).await?.is_none() {
        return Err(AppError::conflict(
            "member_keys_required",
            "set up your member keys first, then accept",
        ));
    }
    if p.kind == Kind::Offer && req.ally_key.is_some() {
        return Err(AppError::bad_request(
            "ally_key_not_needed",
            "accepting an offer doesn't need your ally key",
        ));
    }
    let mut started = Vec::new();
    for (member, ally) in p.kind.links(&p.from_id, &p.to_id) {
        // The caller's own key comes from the request; the sender's is
        // their current one.
        let up = if ally == me {
            req.ally_key.as_ref()
        } else {
            None
        };
        let ally_key_id =
            accept_ally_link(&mut tx, member, ally, up, Some(&p.group_id), now).await?;
        started.push(StartedLink {
            member_id: member.clone(),
            ally_id: ally.clone(),
            state: allies::LinkState::Pending,
            ally_key_id,
        });
    }
    if !proposals::answer(&mut *tx, &p.id, true, now).await? {
        return Err(closed());
    }
    proposals::suppress_notice(&mut *tx, &p).await?;
    crate::groups::tell_alliance(&mut tx, NoticeKind::AllianceAccepted, &p.from_id, me, now)
        .await?;
    tx.commit().await?;
    tracing::info!(group = %p.group_id, kind = p.kind.as_str(), "alliance proposal accepted");
    let proposal = Proposal {
        state: State::Accepted,
        decided_at_ms: Some(now),
        ..p
    };
    Ok((
        StatusCode::CREATED,
        Json(ProposalAccepted {
            proposal: incoming_view(
                Listed {
                    proposal,
                    other_display_name: sender.display_name,
                    group_name: Some(group.name),
                },
                now,
            ),
            links: started,
        }),
    ))
}

/// `POST /v1/proposals/{id}/decline`: the recipient declines. The sender is
/// not told: to them it looks like an expiry (module docs).
pub async fn decline(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let p = load_incoming(&mut tx, &s.user.id, &id, now).await?;
    if !proposals::answer(&mut *tx, &p.id, false, now).await? {
        return Err(closed());
    }
    proposals::suppress_notice(&mut *tx, &p).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/proposals/{id}`: the sender withdraws a proposal that is open
/// in their view. The recipient sees "withdrawn" and isn't notified; a
/// notice not yet sent is withdrawn too.
pub async fn withdraw(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let p = proposals::by_id(&mut *tx, &id)
        .await?
        .filter(|p| p.from_id == s.user.id)
        .ok_or(AppError::NotFound)?;
    if p.sender_state(now) != SenderState::Open
        || !proposals::withdraw(&mut *tx, &p.id, now).await?
    {
        return Err(closed());
    }
    if p.state == State::Open {
        proposals::suppress_notice(&mut *tx, &p).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Blocks -----------------------------------------------------------------------

/// `GET /v1/me/proposal-blocks`: who the caller stopped from sending them
/// proposals (Settings).
pub async fn list_blocks(
    AxState(state): AxState<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<Block>>> {
    Ok(Json(
        proposals::blocks_of(state.db().pool(), &s.user.id).await?,
    ))
}

/// `PUT /v1/me/proposal-blocks/{user_id}`: stop someone sending the caller
/// proposals, in any group. Private: their open proposals to the caller end
/// quietly, and new ones are hidden from the caller (module docs).
/// Idempotent.
pub async fn put_block(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(user): Path<String>,
) -> AppResult<StatusCode> {
    let other = parse_user(&user)?;
    if other == s.user.id {
        return Err(AppError::bad_request(
            "cannot_block_self",
            "you cannot block yourself",
        ));
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    if users::by_id(&mut *tx, &other).await?.is_none() {
        return Err(AppError::NotFound);
    }
    proposals::block(&mut *tx, &s.user.id, &other, now).await?;
    proposals::void(
        &mut tx,
        VoidScope::From {
            from: &other,
            to: &s.user.id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/me/proposal-blocks/{user_id}`: unblock. Idempotent.
pub async fn delete_block(
    AxState(state): AxState<AppState>,
    s: SessionUser,
    Path(user): Path<String>,
) -> AppResult<StatusCode> {
    let other = parse_user(&user)?;
    proposals::unblock(state.db().pool(), &s.user.id, &other).await?;
    Ok(StatusCode::NO_CONTENT)
}
