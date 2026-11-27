//! `GET /v1/ally/feed` and `GET /v1/blobs/{id}` (§4.5, §6).
//!
//! **Who may read.** Feed and blobs of member M are readable by M and by
//! users with an **active** link to M, nobody else (admins included). The
//! member sees exactly what allies see (§6, §12 "full transparency").
//! Device-declared envelope recipients are routing hints, never access
//! control: a blob is served to an ally only if they hold an active link
//! *and* the item was wrapped to them *and* it was received while they held
//! an active link ([`feed::ally_may_read_blob`]). Removing an ally therefore
//! revokes feed and blob access at once, and approving them again later
//! never opens up ciphertext sealed to them while they were not an ally
//! (devices lag a removal until they accept the next manifest, PROTOCOL
//! §5.1 "Removal is forward-only").
//!
//! The feed itself is metadata (kinds, urgency, times), and every current
//! ally sees the member's whole retained history, as the member does: an
//! ally approved today can see that an urgent alert happened last week, but
//! not open it unless it was sealed to them while they were an ally.
//!
//! **Not found, not forbidden.** Every denial is a 404 indistinguishable
//! from a missing id, so ids cannot be probed for existence.
//!
//! The feed carries metadata only ([`FeedItem`]); content is fetched as a
//! blob (the serialized [`faro_proto::EncryptedItem`]) and decrypted in the
//! browser.
//!
//! **Readers check, rather than trust, events and reports.** Each carries its
//! device-signed header and signature, and the response carries the
//! member-signed endorsement of every device in it, so the browser checks
//! them against the member's key rather than taking the instance's word
//! (PROTOCOL.md §3.5). `GET /v1/ally/chain` serves a device's stored
//! headers in `seq` order, those the feed leaves out (urgency `none`)
//! included, so the browser can walk the hash chain between the items it
//! shows and see a gap where something was dropped.

use crate::auth::session::SessionUser;
use crate::blob::{BlobError, BlobId};
use crate::db::repo::feed::{self, Cursor, FeedRowKind};
use crate::db::repo::{allies, devices, events as ev_repo};
use crate::db::to_u64;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_proto::api::{ChainLink, FeedItem, Platform, ServerAlertKind};
use faro_proto::keys::{DeviceEndorsement, Signed};
use faro_proto::report::ReportHeader;
use faro_proto::{DeviceId, EventHeader, Signature, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_FEED_LIMIT: i64 = 100;
pub const MAX_FEED_LIMIT: i64 = 500;
pub const DEFAULT_CHAIN_LIMIT: i64 = 500;
pub const MAX_CHAIN_LIMIT: i64 = 1000;

#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    pub member_id: String,
    /// Items received after this time (Unix ms). Ignored with `cursor`.
    pub since_ms: Option<i64>,
    /// The `next_cursor` of a previous page.
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

/// A feed item with the instance's receive time (the ordering key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    pub received_at_ms: i64,
    #[serde(flatten)]
    pub item: FeedItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResponse {
    pub member_id: UserId,
    pub items: Vec<FeedEntry>,
    /// Pass back as `cursor` for the next page (or to poll for new items).
    pub next_cursor: Option<String>,
    /// More items may be available right now.
    pub has_more: bool,
    /// What each device in `items` is (`device_id` to platform), so a reader
    /// with no device list of their own, an ally, words an iPhone's alerts
    /// as an iPhone's. The instance already stores this (sent at enrollment)
    /// and it goes only to callers who can read the feed. Absent from older
    /// instances.
    #[serde(default)]
    pub device_platforms: BTreeMap<String, Platform>,
    /// The member-signed endorsement of each device in `items`
    /// (`device_id` to `Signed<DeviceEndorsement>`), as the member uploaded
    /// it: what the reader checks device signatures against. A device with
    /// none (never endorsed) is left out. Absent from older instances.
    #[serde(default)]
    pub device_endorsements: BTreeMap<String, Signed<DeviceEndorsement>>,
}

/// Whether `caller` may read `member`'s feed and blobs.
async fn can_read(state: &AppState, caller: &UserId, member: &UserId) -> AppResult<bool> {
    Ok(caller == member || allies::is_active(state.db().pool(), member, caller).await?)
}

/// `GET /v1/ally/feed?member_id=&since_ms=&cursor=&limit=`
pub async fn get_feed(
    State(state): State<AppState>,
    s: SessionUser,
    Query(q): Query<FeedQuery>,
) -> AppResult<Json<FeedResponse>> {
    let member = UserId::new(q.member_id);
    if !member.is_well_formed() || !can_read(&state, &s.user.id, &member).await? {
        return Err(AppError::NotFound);
    }
    let cursor = match &q.cursor {
        Some(c) => Cursor::decode(c)
            .ok_or_else(|| AppError::bad_request("invalid_cursor", "cursor is malformed"))?,
        None => Cursor::after_time(q.since_ms.unwrap_or(0)),
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_FEED_LIMIT)
        .clamp(1, MAX_FEED_LIMIT);

    let mut conn = state.db().pool().acquire().await?;
    let rows = feed::page(&mut conn, &member, &cursor, limit).await?;
    let has_more = rows.len() as i64 == limit;
    let next_cursor = rows.last().map(|r| r.cursor.encode()).or(q.cursor);
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        let item = match r.row {
            FeedRowKind::Event {
                device_id,
                seq,
                ts_ms,
                kind,
                urgency,
                blob_id,
                header_json,
                sig,
            } => FeedItem::Event {
                member_id: member.clone(),
                device_id,
                seq: to_u64(seq)?,
                ts_ms,
                kind,
                urgency,
                blob_id,
                header: parse_stored::<EventHeader>(&header_json).map(Box::new),
                sig: Signature::from_b64(&sig),
            },
            FeedRowKind::Report {
                id,
                device_id,
                period_start_ms,
                period_end_ms,
                blob_id,
                header_json,
                sig,
            } => FeedItem::Report {
                member_id: member.clone(),
                device_id,
                report_id: id,
                period_start_ms,
                period_end_ms,
                blob_id,
                header: parse_stored::<ReportHeader>(&header_json).map(Box::new),
                sig: Signature::from_b64(&sig),
            },
            FeedRowKind::Alert {
                id,
                device_id,
                kind,
                urgency,
                detail,
            } => {
                // Kinds unknown to this protocol version are skipped.
                let Some(kind) = ServerAlertKind::parse(&kind) else {
                    continue;
                };
                FeedItem::Alert {
                    member_id: member.clone(),
                    device_id,
                    alert_id: id,
                    kind,
                    urgency,
                    ts_ms: r.received_at_ms,
                    detail,
                }
            }
        };
        items.push(FeedEntry {
            received_at_ms: r.received_at_ms,
            item,
        });
    }
    let mut device_platforms = BTreeMap::new();
    let mut device_endorsements = BTreeMap::new();
    let wanted: std::collections::HashSet<&str> = items
        .iter()
        .filter_map(|e| match &e.item {
            FeedItem::Event { device_id, .. } | FeedItem::Report { device_id, .. } => {
                Some(device_id.as_str())
            }
            FeedItem::Alert { device_id, .. } => device_id.as_ref().map(|d| d.as_str()),
        })
        .collect();
    if !wanted.is_empty() {
        for (id, platform) in devices::platforms_for_owner(&mut *conn, &member).await? {
            if wanted.contains(id.as_str()) {
                device_platforms.insert(id.as_str().to_owned(), platform);
            }
        }
        for (id, json) in devices::endorsements_for_owner(&mut *conn, &member).await? {
            if wanted.contains(id.as_str()) {
                if let Some(e) = parse_stored::<Signed<DeviceEndorsement>>(&json) {
                    device_endorsements.insert(id.as_str().to_owned(), e);
                }
            }
        }
    }
    Ok(Json(FeedResponse {
        member_id: member,
        device_platforms,
        device_endorsements,
        items,
        next_cursor,
        has_more,
    }))
}

/// JSON the instance stored itself. A row that no longer parses is served
/// without it, and the reader treats the item as unsigned.
fn parse_stored<T: serde::de::DeserializeOwned>(json: &str) -> Option<T> {
    match serde_json::from_str(json) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "stored signed JSON does not parse");
            None
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainQuery {
    pub member_id: String,
    pub device_id: String,
    /// The first `seq` wanted (inclusive). Default 0.
    pub from_seq: Option<u64>,
    pub limit: Option<i64>,
}

/// `GET /v1/ally/chain`: one device's stored event headers, by `seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResponse {
    pub member_id: UserId,
    pub device_id: DeviceId,
    /// Ascending `seq`, from `from_seq`. A `seq` that is missing here was
    /// never stored (a gap the instance recorded) or has expired.
    pub links: Vec<ChainLink>,
    /// More headers may follow the last one: ask again from its `seq + 1`.
    pub has_more: bool,
}

/// `GET /v1/ally/chain?member_id=&device_id=&from_seq=&limit=`
///
/// Headers only, the ones the feed leaves out included: readable by whoever
/// may read the member's feed. Headers are metadata the instance holds
/// anyway (kinds, times, urgency), and they are what lets a reader verify
/// the hash chain between the feed's items (PROTOCOL.md §3.5).
pub async fn get_chain(
    State(state): State<AppState>,
    s: SessionUser,
    Query(q): Query<ChainQuery>,
) -> AppResult<Json<ChainResponse>> {
    let member = UserId::new(q.member_id);
    let device = DeviceId::new(q.device_id);
    if !member.is_well_formed()
        || !device.is_well_formed()
        || !can_read(&state, &s.user.id, &member).await?
    {
        return Err(AppError::NotFound);
    }
    let from = q.from_seq.unwrap_or(0);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_CHAIN_LIMIT)
        .clamp(1, MAX_CHAIN_LIMIT);
    let rows = ev_repo::headers_from(state.db().pool(), &member, &device, from, limit).await?;
    let has_more = rows.len() as i64 == limit;
    let mut links = Vec::with_capacity(rows.len());
    for r in rows {
        let (Some(header), Some(sig)) = (
            parse_stored::<EventHeader>(&r.header_json),
            Signature::from_b64(&r.sig),
        ) else {
            // Left out: the reader sees a gap at this seq.
            continue;
        };
        links.push(ChainLink {
            received_at_ms: r.received_at_ms,
            header,
            sig,
        });
    }
    Ok(Json(ChainResponse {
        member_id: member,
        device_id: device,
        links,
        has_more,
    }))
}

/// `GET /v1/blobs/{id}`: the ciphertext of one event body or report.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(id): Path<String>,
    s: SessionUser,
) -> AppResult<Response> {
    let id = BlobId::parse(&id).ok_or(AppError::NotFound)?;
    let pool = state.db().pool();
    let owner = feed::blob_owner(pool, id.as_str())
        .await?
        .ok_or(AppError::NotFound)?;
    let allowed = owner == s.user.id
        || (allies::is_active(pool, &owner, &s.user.id).await?
            && feed::ally_may_read_blob(pool, id.as_str(), &owner, &s.user.id).await?);
    if !allowed {
        return Err(AppError::NotFound);
    }
    let bytes = match state.blobs().get(&id).await {
        Ok(b) => b,
        // Row present, file gone (retention mid-run): same as missing.
        Err(BlobError::NotFound) => return Err(AppError::NotFound),
        Err(e) => return Err(e.into()),
    };
    let mut resp = bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(resp)
}
