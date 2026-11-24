//! Browser authentication for members, allies and admins.
//!
//! * [`session`]: the session cookie and the [`session::SessionUser`] extractor.
//! * Magic links (email sign-in) are handled in [`crate::api::auth`].
//! * [`passkey`]: WebAuthn, the intended primary login (§4.5); not yet built.
//!
//! Devices never use sessions; they authenticate every request with a device
//! token plus an Ed25519 request signature ([`crate::device_auth`]).

pub mod passkey;
pub mod session;

/// Normalise an email address for storage and lookup: trimmed and lowercased.
///
/// Lowercasing the local part is technically lossy (RFC 5321 allows
/// case-sensitive local parts) but no mainstream provider uses that, and it
/// prevents duplicate accounts that differ only in case.
pub fn normalize_email(input: &str) -> Option<String> {
    let e = input.trim().to_lowercase();
    if e.len() > 254 || e.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (local, domain) = e.rsplit_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || local.contains('@')
        || domain.len() < 3
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(e)
}

/// Validate a human display name: 1–64 printable characters after trimming.
pub fn normalize_display_name(input: &str) -> Option<String> {
    let n = input.trim();
    let len = n.chars().count();
    ((1..=64).contains(&len) && !n.chars().any(char::is_control)).then(|| n.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails() {
        assert_eq!(
            normalize_email("  Sam@Example.ORG ").as_deref(),
            Some("sam@example.org")
        );
        for bad in [
            "",
            "sam",
            "@example.org",
            "sam@",
            "sam@localhost",
            "sam@exa mple.org",
            "sam@@example.org",
            "sam@example..org",
            "sam@.example.org",
            "sam@example.org.",
            "sa\u{0}m@example.org",
            "sam@exam_ple.org",
        ] {
            assert!(normalize_email(bad).is_none(), "{bad:?}");
        }
        assert!(normalize_email(&format!("{}@example.org", "a".repeat(65))).is_none());
    }

    #[test]
    fn display_names() {
        assert_eq!(normalize_display_name("  Sam ").as_deref(), Some("Sam"));
        assert!(normalize_display_name("   ").is_none());
        assert!(normalize_display_name("a\nb").is_none());
        assert!(normalize_display_name(&"x".repeat(65)).is_none());
        assert!(normalize_display_name(&"é".repeat(64)).is_some());
    }
}
