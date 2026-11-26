//! Nothing private reaches a log at `info` or above (issue #87).
//!
//! The service's log (`/Library/Logs/Faro/faro-service.log`) is readable by
//! every administrator of the Mac, and both logs default to `info`. So no
//! `info!`, `warn!` or `error!` call in the client crates (`crates/*`) may
//! log a URL, a window title, an email address, text or anything from a
//! frame. Those may go to `debug!` or `trace!`, which are off by default.
//!
//! This test reads the source of every client crate and checks the
//! arguments of each such call: the identifiers in its code and the
//! `{name}` placeholders in its format string. An identifier made of a
//! word from [`FORBIDDEN`] (`window_title`, `url`, `frames`, …) fails it,
//! unless [`ALLOWED`] lists that file and identifier with the reason it is
//! safe. It is a guard against mistakes, not a proof: a value that is
//! private but named otherwise gets through, so review log calls too.

use std::path::{Path, PathBuf};

/// Words that name private data. Matched against each `_`-separated word
/// of an identifier, ignoring case.
const FORBIDDEN: &[&str] = &[
    "title",
    "titles",
    "url",
    "urls",
    "email",
    "emails",
    "domain",
    "domains",
    "host",
    "hostname",
    "browser",
    "tab",
    "app",
    "apps",
    "window",
    "frame",
    "frames",
    "pixel",
    "pixels",
    "thumbnail",
    "image",
    "body",
    "text",
    "ocr",
    "clipboard",
    "keystroke",
    "keystrokes",
];

/// (file, identifier, why it is safe). Every entry must still match a log
/// call, so the list can't go stale.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/faro-agent/src/main.rs",
        "title",
        "service notices' titles are fixed text the service writes (the login notice); bodies go to debug",
    ),
    (
        "crates/faro-agent/src/notice.rs",
        "title",
        "service notices' titles are fixed text the service writes; bodies go to debug",
    ),
    (
        "crates/faro-service/src/source/in_process.rs",
        "title",
        "service notices' titles are fixed text the service writes",
    ),
    (
        "crates/faro-service/src/cli.rs",
        "instance_url",
        "the instance's address, from the enrollment record, not browsing",
    ),
    (
        "crates/faro-service/src/enroll_server.rs",
        "url",
        "info.url: the instance's address being enrolled with",
    ),
    (
        "crates/faro-service/src/runtime/core.rs",
        "body",
        "body.kind(): only the event's kind, never its content",
    ),
    (
        "crates/faro-service/src/update/artifacts.rs",
        "domains",
        "the number of entries in the domain list",
    ),
];

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    ident: String,
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The arguments of every `info!(`, `warn!(` and `error!(` call in `src`,
/// with the line each starts on.
fn log_calls(src: &str) -> Vec<(usize, &str)> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    for name in ["info!", "warn!", "error!"] {
        let mut from = 0;
        while let Some(at) = src[from..].find(name) {
            let start = from + at;
            from = start + name.len();
            if start > 0 && is_ident(bytes[start - 1]) {
                continue; // e.g. `eprintln!`
            }
            let mut i = from;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if bytes.get(i) != Some(&b'(') {
                continue;
            }
            let open = i + 1;
            let Some(close) = matching_paren(bytes, open) else {
                continue;
            };
            let line = src[..start].matches('\n').count() + 1;
            out.push((line, &src[open..close]));
        }
    }
    out
}

/// The index of the `)` closing a `(` just before `i`, skipping strings.
fn matching_paren(b: &[u8], mut i: usize) -> Option<usize> {
    let mut depth = 1;
    while i < b.len() {
        match b[i] {
            b'"' => i = string_end(b, i)?,
            b'r' if (i == 0 || !is_ident(b[i - 1]))
                && matches!(b.get(i + 1), Some(b'"' | b'#')) =>
            {
                i = string_end(b, i)?
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the closing quote of the (raw) string literal at `i`.
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    if b[i] == b'r' {
        let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
        let body = i + 1 + hashes + 1;
        let close: Vec<u8> = std::iter::once(b'"')
            .chain(std::iter::repeat_n(b'#', hashes))
            .collect();
        let rel = b[body..].windows(close.len()).position(|w| w == close)?;
        return Some(body + rel + close.len() - 1);
    }
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 1,
            b'"' => return Some(j),
            _ => {}
        }
        j += 1;
    }
    None
}

/// The identifiers a call's arguments log: those in its code and the
/// `{name}` placeholders in its string literals.
fn logged_idents(args: &str) -> Vec<String> {
    let b = args.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let raw = c == b'r'
            && (i == 0 || !is_ident(b[i - 1]))
            && matches!(b.get(i + 1), Some(b'"' | b'#'));
        if c == b'"' || raw {
            let end = string_end(b, i).unwrap_or(b.len() - 1);
            placeholders(&args[i..=end], &mut out);
            i = end + 1;
        } else if is_ident(c) {
            let s = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            if !b[s].is_ascii_digit() {
                out.push(args[s..i].to_owned());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn placeholders(lit: &str, out: &mut Vec<String>) {
    let mut rest = lit;
    while let Some(at) = rest.find('{') {
        rest = &rest[at + 1..];
        if rest.starts_with('{') {
            rest = &rest[1..];
            continue;
        }
        let name: String = rest
            .bytes()
            .take_while(|&c| is_ident(c))
            .map(char::from)
            .collect();
        if !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() {
            out.push(name);
        }
    }
}

fn forbidden(ident: &str) -> bool {
    ident
        .split('_')
        .any(|w| FORBIDDEN.iter().any(|f| f.eq_ignore_ascii_case(w)))
}

fn findings(file: &str, src: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line, args) in log_calls(src) {
        for ident in logged_idents(args) {
            if forbidden(&ident) {
                out.push(Finding {
                    file: file.to_owned(),
                    line,
                    ident,
                });
            }
        }
    }
    out
}

#[test]
fn no_private_data_is_logged_at_info_or_above() {
    let root = workspace();
    let mut files = Vec::new();
    let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
        panic!("no crates/ under {}", root.display());
    };
    for c in crates.flatten() {
        rust_files(&c.path().join("src"), &mut files);
    }
    files.sort();
    assert!(files.len() > 50, "found only {} source files", files.len());

    let mut used = vec![false; ALLOWED.len()];
    let mut bad = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let src = std::fs::read_to_string(f).unwrap();
        for finding in findings(&rel, &src) {
            match ALLOWED
                .iter()
                .position(|(file, ident, _)| *file == finding.file && *ident == finding.ident)
            {
                Some(k) => used[k] = true,
                None => bad.push(finding),
            }
        }
    }
    assert!(
        bad.is_empty(),
        "log calls at info or above that may log private data (move them to debug!, \
         or add them to ALLOWED with the reason they are safe):\n{}",
        bad.iter()
            .map(|f| format!("  {}:{}: {}", f.file, f.line, f.ident))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let stale: Vec<_> = ALLOWED
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|((f, i, _), _)| format!("{f}: {i}"))
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED entries that match nothing: {stale:?}"
    );
}

#[test]
fn the_scan_finds_what_it_should() {
    let src = r#"
        tracing::info!(title = %ctx.window_title, "foreground");
        tracing::warn!("visited {url}");
        info!(r"{0} {email:?}", x);
        tracing::error!(error = %e, "capture failed; frames dropped");
        tracing::debug!(%url, "fine at debug");
        eprintln!("{title}");
        tracing::info!(count = n, ")(\" {{text}}", "ok");
    "#;
    let got: Vec<_> = findings("x.rs", src)
        .into_iter()
        .map(|f| (f.line, f.ident))
        .collect();
    assert_eq!(
        got,
        vec![
            (2, "title".to_owned()),
            (2, "window_title".to_owned()),
            (4, "email".to_owned()),
            (3, "url".to_owned()),
        ]
    );
}
