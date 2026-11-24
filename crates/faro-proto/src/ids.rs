//! Opaque, prefixed identifiers (`inst_…`, `dev_…`, `usr_…`).

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Wrap an existing identifier string. No validation beyond what
            /// [`Self::is_well_formed`] checks; callers at trust boundaries
            /// (the server) should call that.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Build a fresh identifier from random bytes (caller supplies
            /// entropy so this crate stays RNG-free).
            pub fn from_random(bytes: &[u8; 16]) -> Self {
                Self(format!("{}{}", $prefix, hex::encode(bytes)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }

            /// `prefix` + 1..=64 chars of `[A-Za-z0-9_-]`.
            pub fn is_well_formed(&self) -> bool {
                match self.0.strip_prefix($prefix) {
                    Some(rest) => {
                        !rest.is_empty()
                            && rest.len() <= 64
                            && rest
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    }
                    None => false,
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    /// Identifies one Faro instance.
    InstanceId,
    "inst_"
);
id_type!(
    /// Identifies one enrolled device.
    DeviceId,
    "dev_"
);
id_type!(
    /// Identifies a user account (member, ally or admin) within an instance.
    UserId,
    "usr_"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed() {
        assert!(DeviceId::new("dev_abc-1_2").is_well_formed());
        assert!(!DeviceId::new("dev_").is_well_formed());
        assert!(!DeviceId::new("usr_abc").is_well_formed());
        assert!(!DeviceId::new("dev_a/b").is_well_formed());
        assert!(DeviceId::from_random(&[7; 16]).is_well_formed());
    }

    #[test]
    fn transparent_json() {
        let u = UserId::new("usr_x");
        assert_eq!(serde_json::to_string(&u).unwrap(), "\"usr_x\"");
    }
}
