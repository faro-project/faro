//! Arbitrary bytes as a role payload (root, targets, timestamp: what the
//! verifier parses once the signatures check out), as a persisted
//! `TrustedState` (the client's state file, the mirror's `trust.json`), and
//! as the strings the metadata rules parse (target names, channels, OS
//! versions).
//!
//! Must never panic. Whatever decodes must encode and decode back to the
//! same value, with the same validation result, and anything that
//! validates must survive being signed into an envelope.
#![no_main]

use faro_update::metadata::{is_valid_channel_name, is_valid_target_name, parse_os_version};
use faro_update::{Channel, RoleMetadata, Root, Targets, Timestamp, TrustedState};
use faro_update_fuzz::{persist_roundtrip, project};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;
use std::sync::LazyLock;

static PROJECT: LazyLock<faro_update::testing::ToyProject> = LazyLock::new(project);

fn role_payload<T: RoleMetadata + PartialEq + Debug>(data: &[u8]) {
    let Ok(meta) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let valid = meta.validate();
    let json = serde_json::to_vec(&meta).expect("payload serializes");
    let back: T = serde_json::from_slice(&json).expect("re-encoded payload decodes");
    assert_eq!(back, meta);
    assert_eq!(back.validate(), valid);
    if valid.is_ok() {
        // Signing the re-encoded payload is how the project publishes it;
        // it must come back out of an envelope intact.
        let env = PROJECT.sign_raw(T::ROLE, &json);
        let parsed = faro_update::Envelope::parse(T::ROLE, &env).expect("envelope parses");
        assert_eq!(parsed.unverified_payload().expect("payload"), json);
    }
}

fn strings(s: &str) {
    if is_valid_target_name(s) {
        // Safe as a mirror path: relative, no `.`/`..` or empty segments.
        assert!(s.len() <= 255 && !s.contains('\\'));
        assert!(s
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".."));
    }
    if is_valid_channel_name(s) {
        assert!(!s.contains('-'));
    }
    if let Ok(c) = s.parse::<Channel>() {
        assert_eq!(c.to_string(), s);
    }
    if let Some(v) = parse_os_version(s) {
        assert!(v.pre.is_empty() && v.build.is_empty());
    }
}

fuzz_target!(|data: &[u8]| {
    role_payload::<Root>(data);
    role_payload::<Targets>(data);
    role_payload::<Timestamp>(data);
    if let Ok(state) = serde_json::from_slice::<TrustedState>(data) {
        persist_roundtrip(&state);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        strings(s);
    }
});
