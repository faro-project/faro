//! `member_manifests`: every [`SignedRecipientManifest`] a member uploaded
//! (PROTOCOL.md §5.1). The latest version is the one devices are served.
//!
//! Rows are only ever inserted, never updated: the history is what lets an
//! operator (or a future audit view) see which recipient list was current
//! when. The rules for what may be inserted live in
//! [`crate::api::manifests`]; this module only stores and loads.

use super::parse_col;
use crate::db::{to_i64, to_u64};
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::ManifestRef;
use faro_proto::{Hash32, UserId};
use sqlx::{Any, Executor, Row};

/// The latest stored manifest of a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    pub reference: ManifestRef,
    pub manifest: SignedRecipientManifest,
    pub received_at_ms: i64,
}

/// The member's latest manifest, if they have uploaded one.
///
/// The stored `version` and `hash` columns are checked against the document
/// itself: a mismatch can only come from corruption, and serving such a row
/// would hand devices a manifest whose identity differs from what the
/// endorsement anchor (`min_manifest`) was checked against.
pub async fn latest<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<Option<StoredManifest>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT version, hash, manifest_json, received_at FROM member_manifests
         WHERE member_id = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(member.as_str())
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    let reference = ManifestRef {
        version: to_u64(r.try_get("version")?)?,
        hash: parse_col(&r, "hash", Hash32::from_prefixed_hex)?,
    };
    let manifest: SignedRecipientManifest =
        parse_col(&r, "manifest_json", |s| serde_json::from_str(s).ok())?;
    if manifest.body.reference() != reference || &manifest.body.member_id != member {
        return Err(sqlx::Error::Decode(
            "stored recipient manifest does not match its version/hash columns".into(),
        ));
    }
    Ok(Some(StoredManifest {
        reference,
        manifest,
        received_at_ms: r.try_get("received_at")?,
    }))
}

/// Store a new version. Two concurrent inserts of the same version for one
/// member surface as a unique violation (primary key).
pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    m: &SignedRecipientManifest,
    now_ms: i64,
) -> Result<ManifestRef, sqlx::Error> {
    let reference = m.body.reference();
    let version = to_i64(reference.version)
        .ok_or_else(|| sqlx::Error::Encode("manifest version overflow".into()))?;
    let json = serde_json::to_string(m).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO member_manifests (member_id, version, hash, manifest_json, received_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(m.body.member_id.as_str())
    .bind(version)
    .bind(reference.hash.to_prefixed_hex())
    .bind(json)
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(reference)
}

/// Number of stored versions (history) for a member.
pub async fn count<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<i64, sqlx::Error> {
    sqlx::query("SELECT COUNT(*) AS n FROM member_manifests WHERE member_id = $1")
        .bind(member.as_str())
        .fetch_one(e)
        .await?
        .try_get("n")
}
