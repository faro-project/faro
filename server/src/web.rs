//! The embedded web app (ARCHITECTURE.md §4.5): the SvelteKit build in
//! `web/`, compiled into the binary by `build.rs` and served from the
//! instance's own origin by the router's fallback.
//!
//! * `/` serves `index.html`, `/setup` serves `setup.html`, and so on; every
//!   page is prerendered. `/setup/` redirects to `/setup` so the pages'
//!   relative asset URLs always resolve the same way.
//! * Files under `_app/immutable/` have content hashes in their names and
//!   are cached for a year; everything else is revalidated.
//! * Pages get their own CSP (the router's default is deny-all, for JSON):
//!   scripts, styles, images and fetches from this origin only, plus the
//!   SHA-256 of each inline script SvelteKit wrote into that page and of each
//!   constant `style="…"` attribute in the compiled templates. No other
//!   inline script or style, no framing, no form posts, no `<base>`.
//! * API paths (`/v1/…`, `/admin/api/…`, `/.well-known/…`) never fall
//!   through to the web app; unknown ones keep the API's JSON 404.
//! * Other unknown paths get `404.html` (SvelteKit's error page) with status
//!   404.
//!
//! A binary built without `web/build` (e.g. `cargo build` on a machine
//! without Node) still serves the API; page requests get a plain-text note.
//! Not built yet: project-signed web bundles (§9), which the server will
//! verify before serving.

use crate::error::AppError;
use axum::body::Body;
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

/// One file of the web app bundle.
#[derive(Debug)]
pub struct EmbeddedFile {
    /// Path relative to the bundle root, `/`-separated, e.g. `setup.html`.
    pub path: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
    /// For HTML pages: `'sha256-…'` for each inline script.
    pub inline_script_hashes: &'static [&'static str],
}

/// A web app bundle: its files (sorted by path) and the CSP hashes of the
/// constant inline style attributes its templates use.
#[derive(Debug)]
pub struct Bundle {
    pub files: &'static [EmbeddedFile],
    pub style_attr_hashes: &'static [&'static str],
}

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/web_bundle.rs"));
}

static EMBEDDED: Bundle = Bundle {
    files: embedded::FILES,
    style_attr_hashes: embedded::STYLE_ATTR_HASHES,
};

/// The bundle compiled into this binary (no files if built without one).
pub fn embedded() -> &'static Bundle {
    &EMBEDDED
}

/// Whether this binary includes the web app, so `serve` and `init` know
/// whether to point the admin at `/setup`.
pub fn is_embedded() -> bool {
    find(embedded().files, "setup.html").is_some()
}

/// Path prefixes that belong to the API and never serve the web app.
const API_PREFIXES: &[&str] = &["/v1/", "/admin/api/", "/.well-known/"];

/// Answer for builds without the web app.
const NOT_BUILT: &str = "This faro-server was built without its web app, so there are no pages \
to show. The API works. To create the admin account without the web app, follow \
\"First run: create the admin account\" in docs/SELF-HOSTING.md. To include the web app, \
run `npm ci && npm run build` in web/ before building faro-server.\n";

/// The router's fallback: everything no API route matched.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    serve(embedded(), &method, uri.path())
}

/// Serve `path` from `bundle`. Split out from [`fallback`] so tests can use
/// a bundle of their own.
pub fn serve(bundle: &Bundle, method: &Method, path: &str) -> Response {
    let files = bundle.files;
    if is_api_path(path) || (method != Method::GET && method != Method::HEAD) {
        return AppError::NotFound.into_response();
    }
    if files.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            NOT_BUILT,
        )
            .into_response();
    }

    let rel = path.strip_prefix('/').unwrap_or(path);
    if let Some(trimmed) = rel.strip_suffix('/').filter(|t| !t.is_empty()) {
        // `/setup/` → `/setup`, as a relative redirect so it also works when
        // the instance lives under a path prefix behind a proxy.
        if lookup(files, trimmed).is_some() {
            let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
            return redirect(&format!("../{last}"));
        }
    } else if let Some(file) = lookup(files, rel) {
        return respond(bundle, file, StatusCode::OK, method);
    }

    match find(files, "404.html") {
        Some(page) => respond(bundle, page, StatusCode::NOT_FOUND, method),
        None => AppError::NotFound.into_response(),
    }
}

fn is_api_path(path: &str) -> bool {
    API_PREFIXES
        .iter()
        .any(|p| path.starts_with(p) || path == p.trim_end_matches('/'))
}

fn find(files: &'static [EmbeddedFile], rel: &str) -> Option<&'static EmbeddedFile> {
    files
        .binary_search_by(|f| f.path.cmp(rel))
        .ok()
        .map(|i| &files[i])
}

/// A request path (without the leading `/`) to the file it means.
fn lookup(files: &'static [EmbeddedFile], rel: &str) -> Option<&'static EmbeddedFile> {
    if rel.is_empty() {
        return find(files, "index.html");
    }
    // Pages are addressed without `.html`; asking for `setup.html` itself
    // is refused so each page has exactly one URL.
    if rel.ends_with(".html") {
        return None;
    }
    find(files, rel).or_else(|| find(files, &format!("{rel}.html")))
}

fn respond(
    bundle: &Bundle,
    file: &'static EmbeddedFile,
    status: StatusCode,
    method: &Method,
) -> Response {
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(file.bytes)
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(file.content_type),
    );
    let cache = if file.path.starts_with("_app/immutable/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if file.path.ends_with(".html") {
        if let Ok(csp) = HeaderValue::from_str(&page_csp(
            file.inline_script_hashes,
            bundle.style_attr_hashes,
        )) {
            h.insert(header::CONTENT_SECURITY_POLICY, csp);
        }
    }
    resp
}

fn redirect(location: &str) -> Response {
    let mut resp = StatusCode::PERMANENT_REDIRECT.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// The CSP for a page of the web app.
pub fn page_csp(inline_script_hashes: &[&str], style_attr_hashes: &[&str]) -> String {
    let script_src = std::iter::once("'self'")
        .chain(inline_script_hashes.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    // `'unsafe-hashes'` only lets through style attributes whose exact value
    // has a listed hash; without hashes, none at all.
    let style_src_attr = if style_attr_hashes.is_empty() {
        "'none'".to_owned()
    } else {
        std::iter::once("'unsafe-hashes'")
            .chain(style_attr_hashes.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!(
        "default-src 'none'; script-src {script_src}; style-src 'self'; \
         style-src-attr {style_src_attr}; img-src 'self' data:; font-src 'self'; \
         connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sorted by path, as build.rs emits them.
    static BUNDLE: Bundle = Bundle {
        files: FILES,
        style_attr_hashes: &["'sha256-STYLE'"],
    };
    static FILES: &[EmbeddedFile] = &[
        EmbeddedFile {
            path: "404.html",
            content_type: "text/html; charset=utf-8",
            bytes: b"<p>not found</p>",
            inline_script_hashes: &["'sha256-NOTFOUND'"],
        },
        EmbeddedFile {
            path: "_app/immutable/entry/start.abc.js",
            content_type: "text/javascript; charset=utf-8",
            bytes: b"export {}",
            inline_script_hashes: &[],
        },
        EmbeddedFile {
            path: "admin/users.html",
            content_type: "text/html; charset=utf-8",
            bytes: b"<p>users</p>",
            inline_script_hashes: &[],
        },
        EmbeddedFile {
            path: "favicon.svg",
            content_type: "image/svg+xml",
            bytes: b"<svg/>",
            inline_script_hashes: &[],
        },
        EmbeddedFile {
            path: "index.html",
            content_type: "text/html; charset=utf-8",
            bytes: b"<p>home</p>",
            inline_script_hashes: &[],
        },
        EmbeddedFile {
            path: "setup.html",
            content_type: "text/html; charset=utf-8",
            bytes: b"<p>setup</p>",
            inline_script_hashes: &["'sha256-AAA'", "'sha256-BBB'"],
        },
    ];

    async fn body(r: Response) -> Vec<u8> {
        axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn get(path: &str) -> Response {
        serve(&BUNDLE, &Method::GET, path)
    }

    #[tokio::test]
    async fn pages_are_served_without_the_html_extension() {
        let r = get("/setup");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(body(r).await, b"<p>setup</p>");

        assert_eq!(body(get("/")).await, b"<p>home</p>");
        assert_eq!(body(get("/admin/users")).await, b"<p>users</p>");
    }

    #[tokio::test]
    async fn pages_get_a_csp_with_their_inline_script_hashes() {
        let r = get("/setup");
        let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(csp.contains("script-src 'self' 'sha256-AAA' 'sha256-BBB';"));
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("style-src 'self';"));
        assert!(csp.contains("style-src-attr 'unsafe-hashes' 'sha256-STYLE';"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
        // Without constant style attributes, none are allowed.
        assert!(page_csp(&[], &[]).contains("style-src-attr 'none';"));
    }

    #[tokio::test]
    async fn hashed_assets_are_cached_and_others_are_not() {
        let r = get("/_app/immutable/entry/start.abc.js");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert!(r.headers().get(header::CONTENT_SECURITY_POLICY).is_none());

        assert_eq!(
            get("/favicon.svg").headers()[header::CACHE_CONTROL],
            "no-cache"
        );
    }

    #[tokio::test]
    async fn trailing_slash_redirects_relatively() {
        let r = get("/setup/");
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(r.headers()[header::LOCATION], "../setup");
        assert_eq!(get("/admin/users/").headers()[header::LOCATION], "../users");
        // No redirect to a page that does not exist.
        assert_eq!(get("/nope/").status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_paths_get_the_404_page() {
        for path in [
            "/nope",
            "/setup.html",
            "/index.html",
            "/setup/extra",
            "/../etc/passwd",
        ] {
            let r = get(path);
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
            let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap();
            assert!(csp.contains("'sha256-NOTFOUND'"), "{path}");
            assert_eq!(body(r).await, b"<p>not found</p>", "{path}");
        }
    }

    #[tokio::test]
    async fn api_paths_and_other_methods_keep_the_json_404() {
        for (method, path) in [
            (Method::GET, "/v1/nope"),
            (Method::GET, "/v1"),
            (Method::GET, "/admin/api/nope"),
            (Method::GET, "/.well-known/nope"),
            (Method::POST, "/setup"),
            (Method::DELETE, "/"),
        ] {
            let r = serve(&BUNDLE, &method, path);
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        }
    }

    #[tokio::test]
    async fn head_has_headers_but_no_body() {
        let r = serve(&BUNDLE, &Method::HEAD, "/setup");
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(body(r).await.is_empty());
    }

    #[tokio::test]
    async fn a_build_without_the_web_app_says_so() {
        static EMPTY: Bundle = Bundle {
            files: &[],
            style_attr_hashes: &[],
        };
        let r = serve(&EMPTY, &Method::GET, "/setup");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(String::from_utf8(body(r).await)
            .unwrap()
            .contains("built without its web app"));
        // The API's own 404 is unchanged.
        let r = serve(&EMPTY, &Method::GET, "/v1/nope");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
    }

    #[test]
    fn embedded_bundle_is_sorted_for_binary_search() {
        assert!(embedded().files.windows(2).all(|w| w[0].path < w[1].path));
    }
}
