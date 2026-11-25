//! `branding`: the instance's branding settings and logo (one row, or none
//! for the defaults). See [`crate::branding`].

use crate::branding::BrandingSettings;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sqlx::{Any, Executor, Row};

/// The logo's metadata, without its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoInfo {
    pub id: String,
    pub width: u32,
    pub height: u32,
}

/// The branding row, without the logo's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BrandingRow {
    pub settings: BrandingSettings,
    pub logo: Option<LogoInfo>,
}

fn dim(v: i64) -> Result<u32, sqlx::Error> {
    u32::try_from(v).map_err(|_| sqlx::Error::Decode("invalid logo size".into()))
}

/// The branding in effect: the stored row, or the defaults.
pub async fn get<'e>(e: impl Executor<'e, Database = Any>) -> Result<BrandingRow, sqlx::Error> {
    let Some(row) =
        sqlx::query("SELECT settings_json, logo_id, logo_width, logo_height FROM branding")
            .fetch_optional(e)
            .await?
    else {
        return Ok(BrandingRow::default());
    };
    let json: String = row.try_get("settings_json")?;
    // A row this version can't read (a newer version wrote it and was then
    // rolled back) falls back to the defaults rather than failing pages.
    let settings = BrandingSettings::from_json(&json).unwrap_or_default();
    let id: Option<String> = row.try_get("logo_id")?;
    let logo = match id {
        Some(id) => Some(LogoInfo {
            id,
            width: dim(row.try_get("logo_width")?)?,
            height: dim(row.try_get("logo_height")?)?,
        }),
        None => None,
    };
    Ok(BrandingRow { settings, logo })
}

/// The logo's PNG bytes, if `id` is the current logo.
pub async fn logo_png<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row = sqlx::query("SELECT logo_png FROM branding WHERE logo_id = $1")
        .bind(id)
        .fetch_optional(e)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let b64: Option<String> = row.try_get("logo_png")?;
    b64.map(|s| {
        STANDARD
            .decode(s)
            .map_err(|_| sqlx::Error::Decode("invalid logo encoding".into()))
    })
    .transpose()
}

/// Store the settings, creating the row if needed.
pub async fn set_settings<'e>(
    e: impl Executor<'e, Database = Any>,
    settings: &BrandingSettings,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO branding (singleton, settings_json, updated_at) VALUES (1, $1, $2)
         ON CONFLICT (singleton) DO UPDATE
           SET settings_json = excluded.settings_json, updated_at = excluded.updated_at",
    )
    .bind(settings.to_json())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// Store a re-encoded logo (replacing any other), creating the row if
/// needed.
pub async fn set_logo<'e>(
    e: impl Executor<'e, Database = Any>,
    logo: &crate::branding::Logo,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO branding (singleton, logo_id, logo_png, logo_width, logo_height, updated_at)
         VALUES (1, $1, $2, $3, $4, $5)
         ON CONFLICT (singleton) DO UPDATE
           SET logo_id = excluded.logo_id, logo_png = excluded.logo_png,
               logo_width = excluded.logo_width, logo_height = excluded.logo_height,
               updated_at = excluded.updated_at",
    )
    .bind(&logo.id)
    .bind(STANDARD.encode(&logo.png))
    .bind(i64::from(logo.width))
    .bind(i64::from(logo.height))
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// Remove the logo. Returns whether there was one.
pub async fn remove_logo<'e>(
    e: impl Executor<'e, Database = Any>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE branding
            SET logo_id = NULL, logo_png = NULL, logo_width = NULL, logo_height = NULL,
                updated_at = $1
          WHERE logo_id IS NOT NULL",
    )
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() > 0)
}
