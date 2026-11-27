//! Enrollment links and codes (ARCHITECTURE.md §3.8).
//!
//! The member's web app shows a one-time code (`XXXX-XXXX`, Crockford
//! base32) and a link or QR code:
//!
//! ```text
//! faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=7Q2K-M9XD[&m=<member key id>]
//! ```
//!
//! Nothing in the link is trusted beyond "which instance to ask" and, when
//! present, `m`: the instance's identity is confirmed by the member (name
//! shown before enrolling) and pinned from `/.well-known/faro`, and
//! everything the device later trusts is signed by the member key it
//! receives at enrollment.
//!
//! **`m` binds that member key.** The enrollment response comes from the
//! (untrusted) instance, so without a check an instance could hand the
//! device its own "member" key and then sign endorsements and recipient
//! manifests that add an eavesdropping ally. `m` is the `key_id` of the
//! member's signing key, put into the link by the member's own browser
//! (which holds the key); the device refuses an enrollment whose member key
//! does not match it. Without `m` the device shows the member key's
//! fingerprint as a safety code for the member to compare instead.

use std::fmt;
use url::Url;

/// Longest instance URL accepted.
pub const MAX_INSTANCE_URL_LEN: usize = 2048;

/// Longest link accepted (a real one is ~100 bytes).
pub const MAX_LINK_LEN: usize = 4096;

/// Crockford base32 alphabet, the same as the server's.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("link is too long")]
    TooLong,
    #[error("not a faro://enroll link: {0}")]
    NotEnrollLink(String),
    #[error("link is missing the `{0}` parameter")]
    Missing(&'static str),
    #[error("link must not contain a fragment")]
    Fragment,
    #[error("link has more than one `{0}` parameter")]
    Duplicate(&'static str),
    #[error("invalid instance URL: {0}")]
    InstanceUrl(String),
    #[error("enrollment code must be 8 characters of Crockford base32, like ABCD-1234")]
    Code,
    #[error("member key fingerprint must be 16 hexadecimal characters")]
    MemberKey,
}

/// Normalize a member key fingerprint (`key_id`: 16 hex characters,
/// compared lowercase; spaces and hyphens ignored).
pub fn parse_member_key_id(input: &str) -> Result<String, LinkError> {
    if input.len() > 64 {
        return Err(LinkError::MemberKey);
    }
    let id: String = input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(LinkError::MemberKey);
    }
    Ok(id)
}

/// A normalized one-time enrollment code (8 canonical characters).
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollCode(String);

impl EnrollCode {
    /// Parse a user-typed code with Crockford's decoding rules (as the
    /// server does): case-insensitive, `I`/`L` read as `1`, `O` as `0`,
    /// hyphens and spaces ignored.
    pub fn parse(input: &str) -> Result<Self, LinkError> {
        if input.len() > 32 {
            return Err(LinkError::Code);
        }
        let mut out = String::with_capacity(8);
        for c in input.chars() {
            let c = match c.to_ascii_uppercase() {
                '-' | ' ' => continue,
                'I' | 'L' => '1',
                'O' => '0',
                c if c.is_ascii() && CROCKFORD.contains(&(c as u8)) => c,
                _ => return Err(LinkError::Code),
            };
            out.push(c);
        }
        if out.len() != 8 {
            return Err(LinkError::Code);
        }
        Ok(EnrollCode(out))
    }

    /// The `XXXX-XXXX` form sent to the instance.
    pub fn display_form(&self) -> String {
        format!("{}-{}", &self.0[..4], &self.0[4..])
    }
}

impl fmt::Display for EnrollCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_form())
    }
}

/// Codes are one-time secrets; keep them out of debug logs.
impl fmt::Debug for EnrollCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollCode(..)")
    }
}

/// A parsed `faro://enroll` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollLink {
    pub instance: Url,
    pub code: EnrollCode,
    /// The member key's `key_id`, if the link carries one (`m`).
    pub member_key: Option<String>,
}

/// Parse `faro://enroll?i=<instance url>&c=<code>[&m=<member key id>]`.
///
/// Unknown parameters are ignored so later link versions (for example one
/// carrying a manifest anchor) still enroll on older clients; `i` and `c`
/// must each appear exactly once.
pub fn parse_enroll_link(s: &str) -> Result<EnrollLink, LinkError> {
    let s = s.trim();
    if s.len() > MAX_LINK_LEN {
        return Err(LinkError::TooLong);
    }
    let url = Url::parse(s).map_err(|e| LinkError::NotEnrollLink(e.to_string()))?;
    if url.scheme() != "faro" {
        return Err(LinkError::NotEnrollLink(format!(
            "scheme is `{}`, expected `faro`",
            url.scheme()
        )));
    }
    if url.host_str() != Some("enroll") || !(url.path().is_empty() || url.path() == "/") {
        return Err(LinkError::NotEnrollLink(
            "expected faro://enroll?i=…&c=…".into(),
        ));
    }
    // A fragment can carry a second query (`#…&m=<other>`) that a lax
    // consumer might read in place of the member's: refuse the whole link.
    if url.fragment().is_some() {
        return Err(LinkError::Fragment);
    }
    let mut instance = None;
    let mut code = None;
    let mut member = None;
    for (k, v) in url.query_pairs() {
        let (slot, name) = match k.as_ref() {
            "i" => (&mut instance, "i"),
            "c" => (&mut code, "c"),
            "m" => (&mut member, "m"),
            _ => continue,
        };
        if slot.replace(v.into_owned()).is_some() {
            return Err(LinkError::Duplicate(name));
        }
    }
    let instance = parse_instance_url(&instance.ok_or(LinkError::Missing("i"))?)?;
    let code = EnrollCode::parse(&code.ok_or(LinkError::Missing("c"))?)?;
    let member_key = member.as_deref().map(parse_member_key_id).transpose()?;
    Ok(EnrollLink {
        instance,
        code,
        member_key,
    })
}

/// Validate and normalize an instance base URL.
///
/// * `https` is required. Plain `http` is accepted only for loopback hosts
///   (`localhost`, `127.0.0.0/8`, `::1`), for development and in-process
///   tests: the device token travels in every request.
/// * No credentials, query or fragment.
/// * The path is normalized to end in `/`, so API paths join under it
///   (an instance served under a path prefix keeps working).
pub fn parse_instance_url(s: &str) -> Result<Url, LinkError> {
    let s = s.trim();
    if s.len() > MAX_INSTANCE_URL_LEN {
        return Err(LinkError::InstanceUrl("too long".into()));
    }
    let mut url = Url::parse(s).map_err(|e| LinkError::InstanceUrl(e.to_string()))?;
    let bad = |m: &str| Err(LinkError::InstanceUrl(m.into()));
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => return bad("http is only allowed for localhost; use https"),
        other => {
            return Err(LinkError::InstanceUrl(format!(
                "unsupported scheme `{other}`"
            )))
        }
    }
    if url.host_str().is_none_or(str::is_empty) {
        return bad("missing host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return bad("must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return bad("must not contain a query or fragment");
    }
    if !url.path().ends_with('/') {
        let p = format!("{}/", url.path());
        url.set_path(&p);
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_generated_link() {
        // Exactly the shape faro-server's create_enroll_code produces.
        let l = parse_enroll_link("faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=7Q2K-M9XD")
            .unwrap();
        assert_eq!(l.instance.as_str(), "https://faro.example.org/");
        assert_eq!(l.code.display_form(), "7Q2K-M9XD");
    }

    #[test]
    fn code_normalization_matches_server_rules() {
        assert_eq!(
            EnrollCode::parse("7q2k m9xd").unwrap().display_form(),
            "7Q2K-M9XD"
        );
        assert_eq!(
            EnrollCode::parse("ilo0-AAAA").unwrap().display_form(),
            "1100-AAAA"
        );
        for bad in [
            "",
            "ABC-123",
            "ABCD-12345",
            "ABCD-123U",
            "ABCD_1234",
            "ÄBCD-1234",
        ] {
            assert_eq!(EnrollCode::parse(bad), Err(LinkError::Code), "{bad}");
        }
        assert_eq!(
            format!("{:?}", EnrollCode::parse("ABCD-1234").unwrap()),
            "EnrollCode(..)"
        );
    }

    #[test]
    fn rejects_malformed_links() {
        let cases = [
            ("https://enroll?i=https://a.example&c=ABCD-1234", "scheme"),
            ("faro://other?i=https://a.example&c=ABCD-1234", "host"),
            ("faro://enroll/x?i=https://a.example&c=ABCD-1234", "path"),
            ("faro://enroll?c=ABCD-1234", "missing i"),
            ("faro://enroll?i=https://a.example", "missing c"),
            (
                "faro://enroll?i=https://a.example&i=https://b.example&c=ABCD-1234",
                "dup i",
            ),
            ("faro://enroll?i=http://a.example&c=ABCD-1234", "http"),
            ("faro://enroll?i=https://a.example&c=nope", "code"),
            ("not a url", "garbage"),
        ];
        for (s, why) in cases {
            assert!(parse_enroll_link(s).is_err(), "{why}: {s}");
        }
        assert_eq!(
            parse_enroll_link(&format!("faro://enroll?c=ABCD-1234&i={}", "a".repeat(5000))),
            Err(LinkError::TooLong)
        );
    }

    #[test]
    fn ignores_unknown_parameters() {
        let l =
            parse_enroll_link("faro://enroll?i=https://a.example/&c=ABCD-1234&x=future").unwrap();
        assert_eq!(l.instance.as_str(), "https://a.example/");
        assert_eq!(l.member_key, None);
    }

    #[test]
    fn member_key_parameter() {
        let l =
            parse_enroll_link("faro://enroll?i=https://a.example/&c=ABCD-1234&m=0123456789ABCDEF")
                .unwrap();
        assert_eq!(l.member_key.as_deref(), Some("0123456789abcdef"));
        for bad in ["m=0123", "m=0123456789abcdeg", "m=a&m=b"] {
            assert!(
                parse_enroll_link(&format!(
                    "faro://enroll?i=https://a.example/&c=ABCD-1234&{bad}"
                ))
                .is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            parse_member_key_id("0123 4567-89ab cdef").unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn rejects_fragments() {
        for s in [
            "faro://enroll?i=https://a.example/&c=ABCD-1234#",
            "faro://enroll?i=https://a.example/&c=ABCD-1234#m=0123456789abcdef",
            "faro://enroll?i=https://a.example/&c=ABCD-1234&m=0123456789abcdef#m=fedcba9876543210",
            "faro://enroll?i=https://a.example/&c=ABCD-1234#&m=fedcba9876543210",
        ] {
            assert_eq!(parse_enroll_link(s), Err(LinkError::Fragment), "{s}");
        }
    }

    #[test]
    fn instance_url_rules() {
        assert_eq!(
            parse_instance_url("https://faro.example.org/base")
                .unwrap()
                .as_str(),
            "https://faro.example.org/base/"
        );
        assert!(parse_instance_url("http://127.0.0.1:8080").is_ok());
        assert!(parse_instance_url("http://localhost:1").is_ok());
        assert!(parse_instance_url("http://[::1]:1").is_ok());
        assert!(parse_instance_url("http://10.0.0.1").is_err());
        assert!(parse_instance_url("https://user:pw@faro.example.org").is_err());
        assert!(parse_instance_url("https://faro.example.org/?x=1").is_err());
        assert!(parse_instance_url("https://faro.example.org/#x").is_err());
        assert!(parse_instance_url("ftp://faro.example.org").is_err());
        assert!(parse_instance_url("faro.example.org").is_err());
    }
}
