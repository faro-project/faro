//! Arbitrary bytes as a served envelope of each role, and as the root a
//! client or server bootstraps from (`Updater::bootstrap`: the installer's
//! embedded root, or the mirror's `updates.root`, the one place a payload
//! is parsed before its signatures are checked).
//!
//! Must never panic; the size cap must hold before parsing; whatever parses
//! must re-serialize to an envelope that parses back the same; and a root
//! that bootstraps must be valid and self-signed.
#![no_main]

use faro_update::metadata::RoleMetadata;
use faro_update::{Envelope, Role, UpdateError, Updater};
use faro_update_fuzz::check_persist;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for role in [Role::Root, Role::Targets, Role::Timestamp] {
        let max = role.max_envelope_bytes();
        match Envelope::parse(role, data) {
            Ok(env) => {
                assert!(data.len() <= max);
                let _ = env.unverified_payload();
                let bytes = env.to_bytes();
                if bytes.len() <= max {
                    let back = Envelope::parse(role, &bytes).expect("re-parse");
                    assert_eq!(back, env);
                }
            }
            Err(UpdateError::TooLarge { len, .. }) => assert!(len > max),
            Err(_) => assert!(data.len() <= max),
        }
    }

    if let Ok(u) = Updater::bootstrap(data) {
        let s = u.state();
        assert!(s.root().validate().is_ok());
        assert!(s.timestamp().is_none() && s.targets().is_none());
        // Self-signed: the same bytes are a (rejected, not newer) rotation.
        let mut again = u.clone();
        assert!(matches!(
            again.update_root(data),
            Err(UpdateError::Rollback { .. })
        ));
        check_persist(s);
    }
});
