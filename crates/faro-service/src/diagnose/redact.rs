//! What `diagnose` takes out of everything it puts in a report.
//!
//! Every file in a report goes through a [`Redactor`] before the member
//! sees it, and only what comes out is written. It removes:
//!
//! - **URLs**, whole, except the instance's own (`https://faro.example/api/v1/…`),
//!   whose query and fragment go. A URL with a user name or password goes
//!   even when it is the instance's.
//! - **Email addresses.**
//! - **Host names** other than the instance's (anything shaped like
//!   `name.tld`), and IPv4 addresses other than loopback. Faro's own names
//!   (`org.faro.service`), file names with the extensions Faro uses
//!   (`service.toml`, `faro-service.log`) and version numbers stay.
//! - **Windows user paths** (`C:\Users\alex\…` becomes `C:\Users\[user]\…`)
//!   and, when given with [`Redactor::with_local_names`], this computer's
//!   name, its domain and the account's name wherever they appear
//!   (`ALEX-PC`, `CORP\alex`, `\\ALEX-PC\share`).
//! - **The values of log fields that name private data**: a field whose
//!   name has a word from [`PRIVATE_LOG_WORDS`] (`title=…`, `app=…`,
//!   `body=…`) or [`EXTRA_PRIVATE_WORDS`], in `name=value` form or as a
//!   field inside a printed value (`Foreground { title: Some("…") }`). This
//!   is how window titles go: nothing in a title can be recognized by its
//!   shape, so Faro's `debug!` and `trace!` calls log them only as fields
//!   so named (`faro-platform`'s `log_privacy` test makes sure).
//! - **Other libraries' `debug` and `trace` lines**, all but their time,
//!   level and target: a library may log anything there, and Faro doesn't
//!   control what.
//!
//! At the default level (`info`) the logs hold none of this to begin with
//! (`log_privacy` checks the log calls); the redaction is what makes a
//! report safe when someone turned on `debug` to chase a problem.
//!
//! [`PRIVATE_LOG_WORDS`]: faro_platform::logfile::PRIVATE_LOG_WORDS

use faro_platform::logfile::is_private_log_name;

/// What a removed URL becomes.
pub const URL: &str = "[url]";
/// What a removed email address becomes.
pub const EMAIL: &str = "[email]";
/// What a removed host name becomes.
pub const HOST: &str = "[host]";
/// What a removed IP address becomes.
pub const IP: &str = "[ip]";
/// What a removed user name (in a path or `DOMAIN\user`) becomes.
pub const USER: &str = "[user]";
/// What a removed field value becomes.
pub const VALUE: &str = "[redacted]";
/// What is left of another library's `debug` or `trace` line.
pub const LIBRARY_DEBUG: &str = "[another library's debug output, left out]";

/// Field-name words that are private in a report, besides
/// [`PRIVATE_LOG_WORDS`](faro_platform::logfile::PRIVATE_LOG_WORDS).
/// (They are not in that list because `info!` calls use them for safe
/// values, such as a model's `name`.)
pub const EXTRA_PRIVATE_WORDS: &[&str] = &[
    "name",
    "bundle",
    "foreground",
    "notice",
    "content",
    "contents",
    "subject",
    "address",
    "password",
    "token",
    "secret",
    "key",
    "query",
];

/// File extensions that look like a top-level domain but are file names
/// Faro logs (`faro-service.log`, `service.toml`, `faro-service.exe`).
const FILE_EXTENSIONS: &[&str] = &[
    "log", "toml", "json", "plist", "sock", "pkg", "txt", "bin", "onnx", "lock", "zip", "sh", "rs",
    "gz", "sqlite", "sqlite3", "db", "xml", "html", "md", "tmp", "partial", "key", "pem",
    "default", "bak", "old", "new", "exe", "msi", "dll",
];

/// Removes private data from a report's text ([module docs](self)).
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// The instance's host name, lowercase, which stays.
    instance_host: Option<String>,
    /// This computer's names (computer, domain, account), lowercase, with
    /// what each becomes.
    local_names: Vec<(String, &'static str)>,
}

impl Redactor {
    /// A redactor that keeps `instance_host` (the enrolled instance's host
    /// name) and removes every other.
    pub fn new(instance_host: Option<&str>) -> Self {
        Redactor {
            instance_host: instance_host
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
            local_names: Vec::new(),
        }
    }

    /// Also remove these names of this computer wherever they appear as a
    /// word: host-like ones (computer name, domain names) become [`HOST`],
    /// the account's name becomes [`USER`]. Names that are too short to be
    /// told from words, and Windows' own (`SYSTEM`, `WORKGROUP`, ...), are
    /// ignored.
    pub fn with_local_names(mut self, hosts: &[&str], users: &[&str]) -> Self {
        const OWN: &[&str] = &[
            "system",
            "administrator",
            "administrators",
            "workgroup",
            "nt authority",
            "local service",
            "network service",
        ];
        for (names, with) in [(hosts, HOST), (users, USER)] {
            for n in names {
                let n = n.trim().trim_matches('\\').to_lowercase();
                if n.len() >= 3 && !OWN.contains(&n.as_str()) {
                    self.local_names.push((n, with));
                }
            }
        }
        self
    }

    /// Redact plain text (the status, command output), line by line.
    pub fn text(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for line in s.split_inclusive('\n') {
            let (body, nl) = split_newline(line);
            out.push_str(&self.line(body));
            out.push_str(nl);
        }
        out
    }

    /// Redact a log written by `tracing_subscriber`'s formatter: like
    /// [`Self::text`], and other libraries' `debug` and `trace` lines, with
    /// the lines that continue them, are cut to their time, level and
    /// target.
    pub fn log(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        // Inside another library's debug line (or a line continuing one).
        let mut dropping = false;
        for line in s.split_inclusive('\n') {
            let (body, nl) = split_newline(line);
            match parse_header(body) {
                Some(h) => {
                    dropping =
                        matches!(h.level, "DEBUG" | "TRACE") && !h.target.starts_with("faro");
                    if dropping {
                        out.push_str(&body[..h.target_end]);
                        out.push(' ');
                        out.push_str(LIBRARY_DEBUG);
                    } else {
                        out.push_str(&self.line(body));
                    }
                }
                None if dropping => continue,
                None => out.push_str(&self.line(body)),
            }
            out.push_str(nl);
        }
        out
    }

    fn line(&self, s: &str) -> String {
        let s = user_paths(s);
        let s = redact_fields(&s);
        let s = self.urls(&s);
        let s = emails(&s);
        let s = self.hosts(&s);
        // After the host-shaped names, so `pc.corp.example` is one host.
        self.names(&s)
    }

    /// The local names, as whole words, any case.
    fn names(&self, s: &str) -> String {
        if self.local_names.is_empty() {
            return s.to_owned();
        }
        let lower = s.to_lowercase();
        // Lowercasing can change byte lengths for odd characters; then the
        // offsets don't line up and the names are not matched.
        if lower.len() != s.len() {
            return s.to_owned();
        }
        let b = s.as_bytes();
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c >= 0x80;
        let mut hits: Vec<(usize, usize, &'static str)> = Vec::new();
        for (name, with) in &self.local_names {
            let mut from = 0;
            while let Some(at) = lower[from..].find(name.as_str()) {
                let start = from + at;
                let end = start + name.len();
                from = end;
                let before = start > 0 && word(b[start - 1]);
                let after = end < b.len() && word(b[end]);
                if !before && !after {
                    hits.push((start, end, with));
                }
            }
        }
        hits.sort_unstable_by_key(|h| (h.0, std::cmp::Reverse(h.1)));
        let mut out = String::with_capacity(s.len());
        let mut copied = 0;
        for (start, end, with) in hits {
            if start < copied {
                continue;
            }
            out.push_str(&s[copied..start]);
            out.push_str(with);
            copied = end;
        }
        out.push_str(&s[copied..]);
        out
    }

    fn is_instance(&self, host: &str) -> bool {
        self.instance_host
            .as_deref()
            .is_some_and(|i| host.trim_end_matches('.').eq_ignore_ascii_case(i))
    }

    /// Every `scheme://…`: the instance's keeps its origin and path,
    /// anything else becomes [`URL`].
    fn urls(&self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut copied = 0;
        let mut from = 0;
        while let Some(at) = s[from..].find("://") {
            let sep = from + at;
            from = sep + 3;
            let mut start = sep;
            while start > 0 && is_scheme_char(b[start - 1]) {
                start -= 1;
            }
            while start < sep && !b[start].is_ascii_alphabetic() {
                start += 1;
            }
            if start == sep || start < copied {
                continue;
            }
            let mut end = sep + 3;
            while end < b.len() && !ends_url(b[end]) {
                end += 1;
            }
            while end > sep + 3
                && matches!(
                    b[end - 1],
                    b'.' | b',' | b';' | b':' | b'!' | b')' | b']' | b'}'
                )
            {
                end -= 1;
            }
            out.push_str(&s[copied..start]);
            out.push_str(&self.url(&s[start..end], sep - start));
            copied = end;
            from = end.max(from);
        }
        out.push_str(&s[copied..]);
        out
    }

    fn url(&self, url: &str, scheme_len: usize) -> String {
        let rest = &url[scheme_len + 3..];
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        if authority.contains('@') {
            return URL.to_owned();
        }
        let host = match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => authority.split(':').next().unwrap_or(""),
        };
        if !self.is_instance(host) {
            return URL.to_owned();
        }
        let tail = &rest[auth_end..];
        let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
        let mut kept = format!(
            "{}://{}{}",
            &url[..scheme_len],
            authority,
            &tail[..path_end]
        );
        if tail[path_end..].starts_with('?') {
            kept.push('?');
            kept.push_str(VALUE);
        }
        kept
    }

    /// Dotted names shaped like host names, and IPv4 addresses.
    fn hosts(&self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        let mut copied = 0;
        while i < b.len() {
            if !is_name_char(b[i]) || (i > 0 && is_name_char(b[i - 1])) {
                i += 1;
                continue;
            }
            let mut end = i;
            while end < b.len() && is_name_char(b[end]) {
                end += 1;
            }
            // The name itself, without dots and dashes around it.
            let mut s0 = i;
            let mut e0 = end;
            while s0 < e0 && matches!(b[s0], b'.' | b'-') {
                s0 += 1;
            }
            while e0 > s0 && matches!(b[e0 - 1], b'.' | b'-') {
                e0 -= 1;
            }
            if let Some(with) = self.host_replacement(&s[s0..e0]) {
                out.push_str(&s[copied..s0]);
                out.push_str(with);
                copied = e0;
            }
            i = end;
        }
        out.push_str(&s[copied..]);
        out
    }

    fn host_replacement(&self, name: &str) -> Option<&'static str> {
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            return None;
        }
        if self.is_instance(name) {
            return None;
        }
        if labels.len() == 4
            && labels
                .iter()
                .all(|l| l.len() <= 3 && l.bytes().all(|c| c.is_ascii_digit()))
        {
            let first: u32 = labels[0].parse().ok()?;
            return (first != 127 && name != "0.0.0.0").then_some(IP);
        }
        // Versions and numbers with units: 0.1.0-beta.1, 1.5s, 00.123Z.
        if labels.iter().all(|l| l.as_bytes()[0].is_ascii_digit()) {
            return None;
        }
        let last = labels[labels.len() - 1];
        let tld = (last.len() >= 2 && last.bytes().all(|c| c.is_ascii_alphabetic()))
            || last.starts_with("xn--");
        if !tld {
            return None;
        }
        let lower = name.to_ascii_lowercase();
        if FILE_EXTENSIONS.iter().any(|e| last.eq_ignore_ascii_case(e))
            || lower.starts_with("org.faro.")
            || lower == "agent.app"
        {
            return None;
        }
        Some(HOST)
    }
}

/// `C:\Users\alex\…` and `C:/Users/alex/…`: the user folder becomes
/// [`USER`]. (`Public` and `Default` are not anyone's.)
fn user_paths(s: &str) -> String {
    let b = s.as_bytes();
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut from = 0;
    let sep = |c: u8| matches!(c, b'\\' | b'/');
    while from < lower.len() {
        let Some(at) = lower[from..].find("users") else {
            break;
        };
        let at = from + at;
        from = at + 5;
        let after = at + 5;
        if at == 0 || !sep(b[at - 1]) || after >= b.len() || !sep(b[after]) {
            continue;
        }
        let name_start = after + 1;
        let mut name_end = name_start;
        while name_end < b.len()
            && !sep(b[name_end])
            && !b[name_end].is_ascii_whitespace()
            && !matches!(b[name_end], b'"' | b'\'' | b'<' | b'>' | b'|' | b'*' | b'?')
        {
            name_end += 1;
        }
        let name = &lower[name_start..name_end];
        if name.is_empty() || matches!(name, "public" | "default" | "[user]") {
            continue;
        }
        out.push_str(&s[copied..name_start]);
        out.push_str(USER);
        copied = name_end;
        from = name_end;
    }
    out.push_str(&s[copied..]);
    out
}

/// `user@example.org` → [`EMAIL`].
fn emails(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(at) = s[from..].find('@') {
        let at = from + at;
        from = at + 1;
        let mut start = at;
        while start > copied && is_local_char(b[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < b.len() && (b[end].is_ascii_alphanumeric() || matches!(b[end], b'.' | b'-')) {
            end += 1;
        }
        while end > at + 1 && matches!(b[end - 1], b'.' | b'-') {
            end -= 1;
        }
        let domain = &s[at + 1..end];
        let tld = domain.rsplit('.').next().unwrap_or("");
        let valid = start < at
            && domain.contains('.')
            && tld.len() >= 2
            && tld.bytes().all(|c| c.is_ascii_alphabetic());
        if valid {
            out.push_str(&s[copied..start]);
            out.push_str(EMAIL);
            copied = end;
            from = end;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// `title=…`, `title: "…"`: the value goes when the name is private.
fn redact_fields(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while i < b.len() {
        let starts_ident =
            is_field_char(b[i]) && !b[i].is_ascii_digit() && (i == 0 || !is_field_char(b[i - 1]));
        if !starts_ident {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < b.len() && is_field_char(b[end]) {
            end += 1;
        }
        let name = &s[i..end];
        let value_at = if b.get(end) == Some(&b'=') && b.get(end + 1) != Some(&b'=') {
            Some(end + 1)
        } else if s[end..].starts_with(": ")
            && (s[end + 2..].starts_with('"')
                || s[end + 2..].starts_with("Some(")
                || s[end + 2..].starts_with('['))
        {
            Some(end + 2)
        } else {
            None
        };
        match value_at {
            Some(v) if is_private_name(name) && v < b.len() => {
                let v_end = value_end(b, v);
                out.push_str(&s[copied..v]);
                out.push_str(VALUE);
                copied = v_end;
                i = v_end;
            }
            _ => i = end,
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// Whether a field name is private in a report.
pub fn is_private_name(name: &str) -> bool {
    is_private_log_name(name)
        || name.split(['_', '.']).any(|w| {
            EXTRA_PRIVATE_WORDS
                .iter()
                .any(|p| p.eq_ignore_ascii_case(w))
        })
}

/// Where a printed value starting at `i` ends: a quoted string, or up to
/// whitespace, a `,` or an unmatched closing bracket, with brackets and
/// the strings in them kept whole (`Some("a b")`, `Foo { x: 1 }`).
fn value_end(b: &[u8], i: usize) -> usize {
    if b[i] == b'"' {
        return string_end(b, i);
    }
    let mut depth = 0usize;
    let mut j = i;
    while j < b.len() {
        match b[j] {
            b'"' if depth > 0 => {
                j = string_end(b, j);
                continue;
            }
            b'"' => return j,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return j;
                }
                depth -= 1;
            }
            b' ' | b'\t' | b',' if depth == 0 => return j,
            _ => {}
        }
        j += 1;
    }
    j
}

/// The index just past the closing quote of the string starting at `i`
/// (or the end of the text, if it never closes).
fn string_end(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

struct Header<'a> {
    level: &'a str,
    target: &'a str,
    /// Just past the `:` after the target.
    target_end: usize,
}

/// `2026-11-25T10:00:00.123456Z DEBUG faro_agent::run: …` → its level and
/// target. Lines that don't start with a timestamp continue the line
/// before.
fn parse_header(line: &str) -> Option<Header<'_>> {
    let b = line.as_bytes();
    if b.len() < 11 || !b[..4].iter().all(u8::is_ascii_digit) || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let ts_end = line.find(' ')?;
    let rest = &line[ts_end..];
    let level_start = ts_end + (rest.len() - rest.trim_start().len());
    let level_end = level_start + line[level_start..].find(' ')?;
    let level = &line[level_start..level_end];
    if !matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
        return None;
    }
    let target_start = level_end + 1;
    let colon = line[target_start..]
        .find(": ")
        .map(|k| target_start + k)
        .or_else(|| line.ends_with(':').then(|| line.len() - 1))?;
    Some(Header {
        level,
        target: line[target_start..colon].trim(),
        target_end: colon + 1,
    })
}

fn split_newline(line: &str) -> (&str, &str) {
    match line.strip_suffix('\n') {
        Some(l) => match l.strip_suffix('\r') {
            Some(l2) => (l2, "\r\n"),
            None => (l, "\n"),
        },
        None => (line, ""),
    }
}

fn is_scheme_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')
}

fn ends_url(c: u8) -> bool {
    c.is_ascii_whitespace()
        || c.is_ascii_control()
        || matches!(c, b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\')
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')
}

fn is_local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_field_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(Some("Faro.Example.org"))
    }

    #[test]
    fn windows_user_paths_lose_the_account() {
        let r = r();
        assert_eq!(
            r.text(r"opened C:\Users\Alex\AppData\Local\Faro\agent.log"),
            r"opened C:\Users\[user]\AppData\Local\Faro\agent.log"
        );
        assert_eq!(
            r.text(r"d:\users\alex.CORP\Desktop and C:/Users/bob/x"),
            r"d:\users\[user]\Desktop and C:/Users/[user]/x"
        );
        assert_eq!(
            r.text(r#"path="C:\Users\alex""#),
            r#"path="C:\Users\[user]""#
        );
        // Not anyone's, and not paths.
        assert_eq!(r.text(r"C:\Users\Public\x"), r"C:\Users\Public\x");
        assert_eq!(r.text(r"C:\Users"), r"C:\Users");
        assert_eq!(r.text("Users alex are fine"), "Users alex are fine");
        // Through the log path too.
        let log =
            r.log("2026-11-25T10:15:00Z  INFO faro_agent: using C:\\Users\\Alex\\AppData\\x\n");
        assert!(!log.contains("Alex"), "{log}");
    }

    #[test]
    fn local_names_go_wherever_they_are_a_word() {
        let r = Redactor::new(None)
            .with_local_names(&["ALEX-PC", "CORP", "SYSTEM", "pc"], &["Alexander"]);
        let out = r.text(
            r"host alex-pc, user CORP\alexander, share \\ALEX-PC\c$, ALEX-PCX and corporate stay",
        );
        assert_eq!(
            out,
            r"host [host], user [host]\[user], share \\[host]\c$, ALEX-PCX and corporate stay"
        );
        // Windows' own names and short ones are left alone.
        assert_eq!(r.text(r"NT AUTHORITY\SYSTEM pc"), r"NT AUTHORITY\SYSTEM pc");
        // A domain-joined name written as a host is a host.
        assert_eq!(r.text("alex-pc.corp.example"), "[host]");
    }

    #[test]
    fn urls_go_but_the_instance_keeps_its_path() {
        let t = r().text(
            "error sending request for url (https://faro.example.org/api/v1/heartbeat?sig=abc#x): \
             timed out; see http://evil.example/page?q=1, faro://enroll?i=x&c=ABCD-1234 and \
             https://user:pw@faro.example.org/ or ws://[::1]:80/x.\n",
        );
        assert_eq!(
            t,
            "error sending request for url (https://faro.example.org/api/v1/heartbeat?[redacted]): \
             timed out; see [url], [url] and [url] or [url].\n"
        );
    }

    #[test]
    fn emails_hosts_and_ips_go() {
        let t = r().text(
            "mail alex.smith+faro@mail.example.com from Alexs-MacBook-Pro.local at 192.168.1.20 \
             via faro.example.org, loopback 127.0.0.1, bundle com.example.Secret\n",
        );
        assert_eq!(
            t,
            "mail [email] from [host] at [ip] via faro.example.org, loopback 127.0.0.1, \
             bundle [host]\n"
        );
    }

    #[test]
    fn faro_names_files_versions_and_times_stay() {
        let keep = "2026-11-25T10:00:00.123456Z  INFO faro_service::cli: version 0.1.0-beta.1 \
                    (1.0.0+int8) wrote /Library/Logs/Faro/faro-service.log.1, service.toml, \
                    status.json, outbox.sqlite3 and /Library/LaunchDaemons/org.faro.service.plist \
                    for /Library/Faro/Faro Agent.app in 1.5s; e.g. 0.05; ipc.socket_path";
        assert_eq!(r().text(keep), keep);
    }

    #[test]
    fn private_fields_go_whatever_their_value() {
        let t = r().log(
            "2026-11-25T10:00:00.000001Z DEBUG faro_agent::run: foreground \
             app=Some(\"Secret Chat\") title=Some(\"Re: plans for \\\"Friday\\\", ok?\") n=3\n",
        );
        assert_eq!(
            t,
            "2026-11-25T10:00:00.000001Z DEBUG faro_agent::run: foreground \
             app=[redacted] title=[redacted] n=3\n"
        );
        let t = r().text(
            "outcome=Checked { window_title: Some(\"My (private) doc\"), count: 2 } \
             body=\"a b c\" device_name=Alex error=boom\n",
        );
        assert_eq!(
            t,
            "outcome=Checked { window_title: [redacted], count: 2 } body=[redacted] \
             device_name=[redacted] error=boom\n"
        );
    }

    #[test]
    fn other_libraries_debug_lines_go_with_their_continuations() {
        let log = "2026-11-25T10:00:00.1Z DEBUG hyper_util::client: connecting to 10.0.0.2:443\n\
                   more detail\n\
                   2026-11-25T10:00:00.2Z  INFO faro_service::runtime: heartbeat sent seq=4\n\
                   2026-11-25T10:00:00.3Z TRACE rustls::conn: secret bytes\n\
                   2026-11-25T10:00:00.4Z  WARN reqwest::x: retrying https://elsewhere.example/\n";
        assert_eq!(
            r().log(log),
            "2026-11-25T10:00:00.1Z DEBUG hyper_util::client: [another library's debug output, left out]\n\
             2026-11-25T10:00:00.2Z  INFO faro_service::runtime: heartbeat sent seq=4\n\
             2026-11-25T10:00:00.3Z TRACE rustls::conn: [another library's debug output, left out]\n\
             2026-11-25T10:00:00.4Z  WARN reqwest::x: retrying [url]\n"
        );
    }

    #[test]
    fn without_an_instance_every_host_goes() {
        let t = Redactor::new(None).text("instance https://faro.example.org/ faro.example.org");
        assert_eq!(t, "instance [url] [host]");
    }

    #[test]
    fn odd_input_does_not_panic() {
        for s in [
            "",
            "@",
            "a@",
            "@b.cd",
            "://",
            "x://",
            "title=",
            "title: \"",
            "title=\"open",
            "é@ü.de title=Ünï",
            "..",
            "a..b",
            "1.2.3.4.5",
            "[",
            "Some(",
            "\u{2028}://é",
        ] {
            let _ = r().text(s);
            let _ = r().log(s);
        }
        assert_eq!(r().text("title=\"open"), "title=[redacted]");
        assert_eq!(emails("é@ü.de"), "é@ü.de");
    }
}
