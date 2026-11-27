//! Pure notification policy (§5.4): delivery modes, the tamper floor, quiet
//! hours and retry backoff. No I/O, so every rule is unit- and
//! property-tested in isolation.

use faro_proto::api::ServerAlertKind;
use faro_proto::{EventKind, Urgency};
use serde::{Deserialize, Serialize};

/// How a recipient wants one urgency level delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// An email as soon as possible (after quiet hours).
    Immediate,
    /// Bundled into the next hourly digest.
    Digest,
    /// Not notified (the item is still in the feed).
    Off,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Immediate => "immediate",
            Mode::Digest => "digest",
            Mode::Off => "off",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "immediate" => Some(Self::Immediate),
            "digest" => Some(Self::Digest),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Defaults (§5.4): urgent → immediate, normal → next hourly digest, none →
/// only in the daily report (never notified).
pub fn default_mode(u: Urgency) -> Mode {
    match u {
        Urgency::Urgent => Mode::Immediate,
        Urgency::Normal => Mode::Digest,
        Urgency::None => Mode::Off,
    }
}

/// Whether an alert belongs to the class that **cannot be turned off**, only
/// moved to the digest, "so tamper can't be silenced quietly" (§5.4):
///
/// * device events of kind `tamper` and `goodbye` (uninstall / move);
/// * server alerts `chain_gap`, `invalid_signature`, `missed_checkin` (when
///   urgent; the normal-urgency "back online" follow-up is not tamper),
///   `upload_stalled` (the device is alive but not uploading what it
///   records), `ally_removed` (removing an ally is the most direct way to
///   stop being watched, so the people affected are always told),
///   `device_removed` (retiring a monitored device stops its monitoring
///   just as directly), and `account_disabled` / `ally_disabled` (an admin
///   disabling an account is always told to that person and every
///   accountability partner), and `account_deleted` / `ally_deleted` /
///   `account_deletion_cancelled` (deleting an account, or cancelling the
///   deletion, is told to the same people).
///
/// ARCHITECTURE.md §5.4 lists the same kinds; keep the two in step.
///
/// `source` is the alert row's source column (`device` / `server`).
pub fn is_tamper_class(source: &str, kind: &str, urgency: Urgency) -> bool {
    match source {
        "device" => matches!(
            EventKind::parse(kind),
            Some(EventKind::Tamper | EventKind::Goodbye)
        ),
        "server" => match ServerAlertKind::parse(kind) {
            Some(ServerAlertKind::ChainGap | ServerAlertKind::InvalidSignature) => true,
            Some(ServerAlertKind::MissedCheckin) => urgency == Urgency::Urgent,
            Some(
                ServerAlertKind::AllyRemoved
                | ServerAlertKind::DeviceRemoved
                | ServerAlertKind::UploadStalled
                | ServerAlertKind::AlertsCoalesced
                | ServerAlertKind::StorageQuota
                | ServerAlertKind::AccountDisabled
                | ServerAlertKind::AllyDisabled
                | ServerAlertKind::AccountDeleted
                | ServerAlertKind::AllyDeleted
                | ServerAlertKind::AccountDeletionCancelled,
            ) => true,
            _ => false,
        },
        _ => false,
    }
}

/// The mode actually used: the stored preference (or the default), with
/// tamper-class `off` coerced to `digest`.
pub fn effective_mode(stored: Option<Mode>, urgency: Urgency, tamper: bool) -> Mode {
    let m = stored.unwrap_or_else(|| default_mode(urgency));
    if tamper && m == Mode::Off {
        Mode::Digest
    } else {
        m
    }
}

/// Minutes in a day.
pub const DAY_MIN: i64 = 24 * 60;
/// UTC offsets in use range from -12:00 to +14:00.
pub const MAX_TZ_OFFSET_MIN: i64 = 14 * 60;

/// A daily quiet window in the recipient's local time.
///
/// `start_min` / `end_min` are minutes after local midnight in `0..1440`.
/// `start > end` wraps midnight (22:00–07:00); `start == end` is an empty
/// window (no quiet hours). `tz_offset_min` is a fixed offset east of UTC,
/// supplied by the browser: we deliberately carry no time-zone database, so
/// a DST change shifts quiet hours by an hour until the app refreshes the
/// offset (it does so whenever preferences are opened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietHours {
    pub start_min: u16,
    pub end_min: u16,
    pub tz_offset_min: i16,
}

impl QuietHours {
    pub fn is_valid(&self) -> bool {
        i64::from(self.start_min) < DAY_MIN
            && i64::from(self.end_min) < DAY_MIN
            && i64::from(self.tz_offset_min).abs() <= MAX_TZ_OFFSET_MIN
    }

    /// Local minute-of-day at `now_ms`.
    fn local_minute(&self, now_ms: i64) -> i64 {
        (now_ms.div_euclid(60_000) + i64::from(self.tz_offset_min)).rem_euclid(DAY_MIN)
    }

    /// Whether `now_ms` falls inside the quiet window.
    pub fn contains(&self, now_ms: i64) -> bool {
        let (s, e) = (i64::from(self.start_min), i64::from(self.end_min));
        let m = self.local_minute(now_ms);
        match s.cmp(&e) {
            std::cmp::Ordering::Equal => false,
            std::cmp::Ordering::Less => s <= m && m < e,
            std::cmp::Ordering::Greater => m >= s || m < e,
        }
    }
}

/// If `now_ms` is inside quiet hours, the instant they end (the start of
/// the local minute `end_min`); otherwise `None`.
///
/// Quiet hours defer **every** notification, tamper-class included: an
/// urgent tamper alert at 02:00 is delivered at the end of quiet hours
/// rather than waking the ally. Tamper alerts still cannot be dropped, and
/// the feed shows them immediately.
pub fn quiet_until(now_ms: i64, q: Option<&QuietHours>) -> Option<i64> {
    let q = q?;
    if !q.contains(now_ms) {
        return None;
    }
    let m = q.local_minute(now_ms);
    let delta_min = (i64::from(q.end_min) - m).rem_euclid(DAY_MIN);
    let minute_start = now_ms - now_ms.rem_euclid(60_000);
    Some(minute_start + delta_min * 60_000)
}

/// Delivery attempts before a notification is marked `failed`.
pub const MAX_ATTEMPTS: i64 = 8;
/// While the mail setup itself fails (no connection, bad credentials), the
/// notifier tries again this often. Such failures are never charged to a
/// notification, so they can't make one fail for good.
pub const OUTAGE_RETRY_MS: i64 = 60_000;
const BACKOFF_BASE_MS: i64 = 60_000;
const BACKOFF_CAP_MS: i64 = 6 * 3600 * 1000;

/// Delay before retry number `attempts` (1-based: the delay after the first
/// failure is one minute), doubling each time, capped at six hours. Eight
/// attempts span roughly two hours before giving up.
pub fn backoff_ms(attempts: i64) -> i64 {
    let exp = attempts.clamp(1, 32) - 1;
    BACKOFF_BASE_MS
        .saturating_mul(1i64 << exp)
        .min(BACKOFF_CAP_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn defaults_follow_the_architecture() {
        assert_eq!(default_mode(Urgency::Urgent), Mode::Immediate);
        assert_eq!(default_mode(Urgency::Normal), Mode::Digest);
        assert_eq!(default_mode(Urgency::None), Mode::Off);
        assert_eq!(
            effective_mode(None, Urgency::Urgent, false),
            Mode::Immediate
        );
        assert_eq!(
            effective_mode(Some(Mode::Off), Urgency::Urgent, false),
            Mode::Off
        );
    }

    #[test]
    fn tamper_cannot_be_turned_off() {
        for stored in [
            None,
            Some(Mode::Off),
            Some(Mode::Digest),
            Some(Mode::Immediate),
        ] {
            for u in [Urgency::None, Urgency::Normal, Urgency::Urgent] {
                assert_ne!(effective_mode(stored, u, true), Mode::Off, "{stored:?} {u}");
            }
        }
        assert_eq!(
            effective_mode(Some(Mode::Off), Urgency::Urgent, true),
            Mode::Digest
        );
        assert_eq!(
            effective_mode(Some(Mode::Immediate), Urgency::Urgent, true),
            Mode::Immediate,
            "an explicit choice other than off is kept"
        );
    }

    #[test]
    fn tamper_class_membership() {
        assert!(is_tamper_class("device", "tamper", Urgency::Urgent));
        assert!(is_tamper_class("device", "goodbye", Urgency::Urgent));
        // iPhone signals (screen_time_revoked, filter_off, settings_cleared)
        // are `tamper` events, so they are tamper-class by kind.
        assert!(is_tamper_class("device", "tamper", Urgency::None));
        assert!(!is_tamper_class("device", "flag", Urgency::Urgent));
        assert!(!is_tamper_class(
            "device",
            "settings_change",
            Urgency::Normal
        ));
        assert!(is_tamper_class("server", "chain_gap", Urgency::Urgent));
        assert!(is_tamper_class("server", "upload_stalled", Urgency::Urgent));
        assert!(is_tamper_class(
            "server",
            "invalid_signature",
            Urgency::Urgent
        ));
        assert!(is_tamper_class("server", "missed_checkin", Urgency::Urgent));
        assert!(!is_tamper_class(
            "server",
            "missed_checkin",
            Urgency::Normal
        ));
        assert!(is_tamper_class("server", "ally_removed", Urgency::Normal));
        assert!(is_tamper_class("server", "device_removed", Urgency::Urgent));
        // Disabling an account is never silent; re-enabling may be.
        assert!(is_tamper_class(
            "server",
            "account_disabled",
            Urgency::Urgent
        ));
        assert!(is_tamper_class("server", "ally_disabled", Urgency::Urgent));
        assert!(!is_tamper_class(
            "server",
            "account_enabled",
            Urgency::Normal
        ));
        assert!(!is_tamper_class("server", "ally_enabled", Urgency::Normal));
        // Deleting an account is never silent, and neither is cancelling it.
        assert!(is_tamper_class(
            "server",
            "account_deleted",
            Urgency::Urgent
        ));
        assert!(is_tamper_class("server", "ally_deleted", Urgency::Normal));
        assert!(is_tamper_class(
            "server",
            "account_deletion_cancelled",
            Urgency::Normal
        ));
        assert!(!is_tamper_class(
            "device",
            "account_deleted",
            Urgency::Urgent
        ));
        // A device cannot smuggle a server kind (or vice versa).
        assert!(!is_tamper_class("device", "chain_gap", Urgency::Urgent));
        assert!(!is_tamper_class("server", "tamper", Urgency::Urgent));
        assert!(!is_tamper_class("other", "tamper", Urgency::Urgent));
    }

    #[test]
    fn new_server_kinds_are_not_tamper_class() {
        // Adding an ally and shortening retention are announced (normal
        // urgency) but, unlike removal, may be moved to `off`.
        assert!(!is_tamper_class("server", "ally_added", Urgency::Normal));
        assert!(!is_tamper_class(
            "server",
            "member_settings_changed",
            Urgency::Normal
        ));
        assert!(!is_tamper_class("server", "no_such_kind", Urgency::Urgent));
    }

    const MIN: i64 = 60_000;
    // 2026-01-01T00:00:00Z
    const MIDNIGHT: i64 = 1_767_225_600_000;

    #[test]
    fn quiet_hours_wrapping_midnight() {
        let q = QuietHours {
            start_min: 22 * 60,
            end_min: 7 * 60,
            tz_offset_min: 0,
        };
        assert_eq!(quiet_until(MIDNIGHT + 21 * 60 * MIN, Some(&q)), None);
        assert_eq!(
            quiet_until(MIDNIGHT + 23 * 60 * MIN + 30_123, Some(&q)),
            Some(MIDNIGHT + 31 * 60 * MIN)
        );
        assert_eq!(
            quiet_until(MIDNIGHT + 2 * 60 * MIN, Some(&q)),
            Some(MIDNIGHT + 7 * 60 * MIN)
        );
        assert_eq!(
            quiet_until(MIDNIGHT + 7 * 60 * MIN, Some(&q)),
            None,
            "end is exclusive"
        );
        assert_eq!(quiet_until(MIDNIGHT, None), None);
    }

    #[test]
    fn quiet_hours_respect_offset() {
        // 22:00-07:00 in UTC-5 is 03:00-12:00 UTC.
        let q = QuietHours {
            start_min: 22 * 60,
            end_min: 7 * 60,
            tz_offset_min: -300,
        };
        assert_eq!(quiet_until(MIDNIGHT + 2 * 60 * MIN, Some(&q)), None);
        assert_eq!(
            quiet_until(MIDNIGHT + 4 * 60 * MIN, Some(&q)),
            Some(MIDNIGHT + 12 * 60 * MIN)
        );
        let empty = QuietHours {
            start_min: 600,
            end_min: 600,
            tz_offset_min: 0,
        };
        assert!(!empty.contains(MIDNIGHT + 600 * MIN));
    }

    #[test]
    fn validity() {
        let ok = QuietHours {
            start_min: 0,
            end_min: 1439,
            tz_offset_min: 840,
        };
        assert!(ok.is_valid());
        assert!(!QuietHours {
            start_min: 1440,
            ..ok
        }
        .is_valid());
        assert!(!QuietHours {
            tz_offset_min: -841,
            ..ok
        }
        .is_valid());
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff_ms(1), MIN);
        assert_eq!(backoff_ms(2), 2 * MIN);
        assert_eq!(backoff_ms(5), 16 * MIN);
        assert_eq!(backoff_ms(100), 6 * 3600 * 1000);
        assert_eq!(backoff_ms(0), MIN);
        assert_eq!(backoff_ms(-3), MIN);
    }

    proptest! {
        #[test]
        fn quiet_until_lands_outside_quiet_hours(
            now in 0i64..4_000_000_000_000,
            start in 0u16..1440,
            end in 0u16..1440,
            tz in -840i16..=840,
        ) {
            let q = QuietHours { start_min: start, end_min: end, tz_offset_min: tz };
            match quiet_until(now, Some(&q)) {
                None => prop_assert!(!q.contains(now)),
                Some(t) => {
                    prop_assert!(q.contains(now));
                    prop_assert!(t > now);
                    prop_assert!(t - now <= 24 * 3600 * 1000);
                    prop_assert!(!q.contains(t), "deferred into quiet hours");
                    // And it is the *first* such minute: one minute earlier
                    // was still quiet.
                    prop_assert!(t - MIN < now || q.contains(t - MIN));
                }
            }
        }

        #[test]
        fn backoff_is_monotonic(a in 1i64..40) {
            prop_assert!(backoff_ms(a + 1) >= backoff_ms(a));
            prop_assert!(backoff_ms(a) > 0);
        }
    }
}
