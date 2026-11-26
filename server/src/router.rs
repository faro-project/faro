//! The route table (§4.5) and the security middleware every response passes
//! through (§9 "secure defaults for operators").
//!
//! Layers, outermost first:
//!
//! 1. **Tracing** with a span of `method` + *matched route template* only.
//!    Raw URIs are never logged, so nothing a client puts in a path or query
//!    string (or a future handler mistakenly accepts there) reaches the logs;
//!    request bodies and headers (tokens, signatures, codes, ciphertext) are
//!    never logged at all.
//! 2. **Request body limit** ([`MAX_REQUEST_BYTES`]): a global backstop. Each
//!    extractor applies its own, tighter limit (64 KiB for browser JSON, per
//!    type for device uploads) *before* any parsing or signature work.
//! 3. **Security headers**, set only if a handler did not set its own (so the
//!    web app can send a page CSP): `nosniff`,
//!    `Referrer-Policy: no-referrer`, a deny-all CSP with
//!    `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
//!    `Cache-Control: no-store`, and HSTS unless `--dev`.
//!
//! Endpoints that take secrets from the URL or body before any session
//! exists, or send email (setup, magic link request/verify, device
//! enrollment, invite lookup/accept) are additionally wrapped in the per-IP
//! rate limiter ([`crate::ratelimit::limit_unauthenticated`]).
//!
//! Requests no API route matches fall through to the embedded web app
//! ([`crate::web`]), which sends its own, page-specific CSP. API paths it
//! does not know keep the JSON 404.
//!

use crate::api::{
    account, admin, allies, auth, branding, devices, events, feed, group_listing, groups,
    heartbeat, invites, keys, manifests, prefs, privacy, proposals, reports, setup, well_known,
};
use crate::error::AppError;
use crate::ratelimit;
use crate::state::AppState;
use crate::updates::api as updates;
use axum::extract::{MatchedPath, Request};
use axum::handler::Handler;
use axum::http::{header, HeaderName, HeaderValue};
use axum::routing::{delete, get, post, put};
use axum::Router;
use faro_proto::api::{UPDATES_PATH, WELL_KNOWN_PATH};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// Global request-body ceiling (largest per-endpoint limit plus headroom).
pub const MAX_REQUEST_BYTES: usize = 9 * 1024 * 1024;

/// API responses never embed or frame anything.
pub const API_CSP: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// One year, without `includeSubDomains`: a church or college often runs
/// other, possibly plain-HTTP, services on sibling subdomains, and forcing
/// HTTPS on them would be an unpleasant surprise from installing Faro.
pub const HSTS: &str = "max-age=31536000";

/// All routes, without the outer layers.
pub fn api_routes(state: &AppState) -> Router<AppState> {
    let limited =
        axum::middleware::from_fn_with_state(state.clone(), ratelimit::limit_unauthenticated);
    Router::new()
        // Discovery.
        .route(WELL_KNOWN_PATH, get(well_known::get))
        // First-run setup.
        .route(
            "/v1/setup",
            get(setup::status).post(setup::create_admin.layer(limited.clone())),
        )
        // Browser auth.
        .route(
            "/v1/auth/magic-link",
            post(auth::request_link.layer(limited.clone())),
        )
        .route(
            "/v1/auth/magic-link/verify",
            post(auth::verify_link.layer(limited.clone())),
        )
        .route("/v1/auth/logout", post(auth::logout))
        .route(
            "/v1/me",
            get(auth::me)
                .patch(auth::update_me)
                .delete(account::delete_me),
        )
        .route("/v1/me/deletion/cancel", post(account::cancel_deletion))
        // Member keys and the key directory.
        .route("/v1/me/keys", get(keys::get_my_keys).put(keys::put_my_keys))
        .route("/v1/me/keys/wrapped", put(keys::put_my_wrapped_keys))
        .route("/v1/members/{id}/keys", get(keys::member_keys_directory))
        // The member-signed recipient list devices encrypt to (PROTOCOL §5.1).
        .route("/v1/me/recipient-manifest", put(manifests::put_my_manifest))
        .route(
            "/v1/members/{id}/recipient-manifest",
            get(manifests::get_member_manifest),
        )
        // Enrollment.
        .route("/v1/me/enroll-codes", post(devices::create_enroll_code))
        .route("/v1/me/devices", get(devices::list_my_devices))
        .route("/v1/me/devices/{id}", delete(devices::remove_device))
        .route(
            "/v1/devices/enroll",
            post(devices::enroll.layer(limited.clone())),
        )
        .route("/v1/devices/self", get(devices::device_self))
        .route("/v1/devices/{id}/endorse", post(devices::endorse))
        // Device uploads.
        .route("/v1/events:batch", post(events::post_batch))
        .route("/v1/heartbeat", post(heartbeat::post))
        .route("/v1/reports", post(reports::post))
        // Allies: invitations, links, feed and ciphertext.
        .route("/v1/me/invites", post(invites::create_ally_invite))
        .route(
            "/v1/invites/{token}",
            get(invites::get_invite.layer(limited.clone())),
        )
        .route(
            "/v1/invites/{token}/accept",
            post(invites::accept.layer(limited.clone())),
        )
        .route("/v1/me/ally-key", get(invites::get_my_ally_key))
        .route(
            "/v1/me/ally-key/challenge",
            post(invites::ally_key_challenge),
        )
        .route(
            "/v1/me/ally-key/wrapped",
            put(invites::put_my_wrapped_ally_key),
        )
        .route("/v1/me/allies", get(allies::list_my_allies))
        .route("/v1/me/allies/{ally_id}", delete(allies::remove))
        .route("/v1/me/allies/{ally_id}/approve", post(allies::approve))
        .route("/v1/ally/members", get(allies::list_my_members))
        .route("/v1/ally/members/{member_id}", delete(allies::leave))
        .route("/v1/ally/feed", get(feed::get_feed))
        .route("/v1/blobs/{id}", get(feed::get_blob))
        // Groups (docs/GROUPS.md).
        .route("/v1/groups", get(groups::list_mine).post(groups::create))
        .route(
            "/v1/groups/{id}",
            get(groups::get)
                .patch(groups::patch)
                .delete(groups::archive),
        )
        .route("/v1/groups/{id}/participants", get(groups::roster))
        .route("/v1/groups/{id}/history", get(groups::history))
        .route(
            "/v1/groups/{id}/invites",
            get(groups::list_invites).post(groups::create_invites),
        )
        .route("/v1/groups/{id}/me", delete(groups::leave))
        .route(
            "/v1/groups/{id}/participants/{user_id}",
            delete(groups::remove),
        )
        .route(
            "/v1/groups/{id}/participants/{user_id}/role",
            put(groups::set_role),
        )
        .route(
            "/v1/groups/{id}/facilitator-offer/accept",
            post(groups::accept_facilitator_offer),
        )
        .route(
            "/v1/groups/{id}/facilitator-offer/decline",
            post(groups::decline_facilitator_offer),
        )
        // Alliance proposals (GROUPS.md §7). None of these activates a
        // link: only `POST /v1/me/allies/{ally_id}/approve` does.
        .route("/v1/groups/{id}/proposals", post(proposals::create))
        .route("/v1/me/proposals", get(proposals::list_mine))
        .route("/v1/proposals/{id}", delete(proposals::withdraw))
        .route("/v1/proposals/{id}/accept", post(proposals::accept))
        .route("/v1/proposals/{id}/decline", post(proposals::decline))
        .route("/v1/me/proposal-blocks", get(proposals::list_blocks))
        .route(
            "/v1/me/proposal-blocks/{user_id}",
            put(proposals::put_block).delete(proposals::delete_block),
        )
        .route("/v1/group-directory", get(group_listing::directory))
        .route(
            "/v1/groups/{id}/join-requests",
            get(group_listing::list_requests).post(group_listing::create_request),
        )
        .route(
            "/v1/groups/{id}/join-requests/me",
            delete(group_listing::withdraw_request),
        )
        .route("/v1/me/join-requests", get(group_listing::my_requests))
        .route(
            "/v1/join-requests/{id}/accept",
            post(group_listing::accept_request),
        )
        .route(
            "/v1/join-requests/{id}/decline",
            post(group_listing::decline_request),
        )
        .route(
            "/v1/groups/{id}/me/meeting-reminders",
            put(group_listing::set_reminders),
        )
        .route("/v1/me/group-invites", get(groups::my_invites))
        .route(
            "/v1/group-invites/{token}",
            get(groups::get_invite.layer(limited.clone())),
        )
        .route(
            "/v1/group-invites/{token}/accept",
            post(groups::accept_invite.layer(limited.clone())),
        )
        .route(
            "/v1/group-invites/{token}/decline",
            post(groups::decline_invite.layer(limited)),
        )
        // Preferences.
        .route(
            "/v1/me/notification-prefs",
            get(prefs::get_prefs).put(prefs::put_prefs),
        )
        .route(
            "/v1/me/retention",
            get(prefs::get_retention).put(prefs::put_retention),
        )
        .route("/v1/privacy-notice", get(privacy::get))
        // Instance branding: public, shown before sign-in.
        .route("/v1/branding", get(branding::get_public))
        .route("/v1/branding/logo/{file}", get(branding::get_logo))
        // The update mirror: public, project-signed releases (§3.8).
        .route(UPDATES_PATH, get(updates::info))
        .route(
            &format!("{UPDATES_PATH}/timestamp.json"),
            get(updates::timestamp),
        )
        .route(
            &format!("{UPDATES_PATH}/targets.json"),
            get(updates::targets),
        )
        .route(
            &format!("{UPDATES_PATH}/roots/{{file}}"),
            get(updates::root),
        )
        .route(
            &format!("{UPDATES_PATH}/targets/{{*name}}"),
            get(updates::artifact),
        )
        // Admin console: configuration and aggregate metadata only.
        .route("/admin/api/overview", get(admin::overview))
        .route("/admin/api/users", get(admin::list_users))
        .route("/admin/api/users/{id}/disable", post(admin::disable_user))
        .route("/admin/api/users/{id}/enable", post(admin::enable_user))
        .route("/admin/api/users/{id}", delete(admin::delete_user))
        .route(
            "/admin/api/users/{id}/deletion/cancel",
            post(admin::cancel_user_deletion),
        )
        .route("/admin/api/users/{id}/admin", put(admin::set_admin_role))
        .route("/admin/api/log", get(admin::log))
        .route("/admin/api/groups", get(admin::list_groups))
        .route("/admin/api/groups/{id}", delete(admin::archive_group))
        .route(
            "/admin/api/groups/{id}/listed",
            put(admin::set_group_listed),
        )
        .route(
            "/admin/api/settings",
            get(admin::get_settings).patch(admin::patch_settings),
        )
        .route(
            "/admin/api/branding",
            get(branding::admin_get).patch(branding::admin_patch),
        )
        .route(
            "/admin/api/branding/logo",
            put(branding::admin_put_logo).delete(branding::admin_delete_logo),
        )
        .route("/admin/api/smtp-test", post(admin::smtp_test))
        .route("/admin/api/invites", post(admin::invite_member))
        .fallback(crate::web::fallback)
        .method_not_allowed_fallback(|| async { AppError::MethodNotAllowed })
}

fn set_default(name: HeaderName, value: HeaderValue) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, value)
}

/// The complete application: routes plus the security stack.
pub fn build(state: AppState) -> Router {
    let hsts = !state.config().dev;
    let mut app = api_routes(&state)
        .layer(set_default(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(set_default(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(set_default(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(API_CSP),
        ))
        .layer(set_default(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(set_default(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));
    if hsts {
        app = app.layer(set_default(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        ));
    }
    app.layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request| {
            let route = req
                .extensions()
                .get::<MatchedPath>()
                .map(MatchedPath::as_str)
                .unwrap_or("<unmatched>");
            tracing::info_span!("http", method = %req.method(), route)
        }))
        .with_state(state)
}
