//! Group meetings and their reminders (docs/GROUPS.md §8.4, §14, Appendix A
//! section B).
//!
//! A meeting is a weekly or fortnightly weekday and a time at a **fixed UTC
//! offset** (the server has no time-zone database, as with quiet hours), plus
//! an optional place. It is stored as JSON in `accountability_groups.meeting_json`:
//!
//! ```json
//! {"cadence": "weekly", "weekday": 1, "minute_of_day": 1140,
//!  "tz_offset_min": -300, "place": "Room 104", "anchor_ms": 1767225600000}
//! ```
//!
//! `weekday` is 0 for Monday to 6 for Sunday, `minute_of_day` counts from
//! local midnight, `tz_offset_min` is the minutes east of UTC. `anchor_ms`
//! is set by the server: the first meeting after the schedule was saved, so a
//! fortnightly group knows which weeks it meets. Changing only the place
//! keeps it.
//!
//! **Reminders.** [`run_once`] (a worker) finds each group whose next
//! meeting starts within [`REMINDER_LEAD_MS`] and writes one
//! `meeting_reminder` notice per participant who wants one. In a group of
//! more than 32 participants email is off unless the person turned it on
//! (decision 10). The email says only "Your group on *instance* meets at
//! 7:00 pm today", never the group's name (principle 7). Web Push is not
//! implemented in this server yet, so "in-app" is the notice itself.

use crate::db::repo::group_listing::{self, MeetingPrefs};
use crate::db::repo::groups::LARGE_GROUP;
use crate::error::AppError;
use crate::state::AppState;
use serde::{Deserialize, Serialize};

const MINUTE_MS: i64 = 60_000;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Reminders go out this long before a meeting.
pub const REMINDER_LEAD_MS: i64 = 2 * 3600 * 1000;
/// How often the worker looks (reminders are sent within this of 2 hours
/// before).
pub const REMINDER_INTERVAL_SECS: u64 = 60;
/// Longest place text.
pub const MAX_PLACE_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    Weekly,
    Fortnightly,
}

impl Cadence {
    fn period_ms(self) -> i64 {
        match self {
            Cadence::Weekly => 7 * DAY_MS,
            Cadence::Fortnightly => 14 * DAY_MS,
        }
    }
}

/// What a facilitator sends (`PATCH /v1/groups/{id}`, field `meeting`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeetingInput {
    pub cadence: Cadence,
    /// 0 = Monday ... 6 = Sunday.
    pub weekday: u8,
    /// Minutes after local midnight, 0 to 1439.
    pub minute_of_day: u16,
    /// Minutes east of UTC, -840 to 840.
    pub tz_offset_min: i32,
    #[serde(default)]
    pub place: Option<String>,
}

/// A stored meeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meeting {
    pub cadence: Cadence,
    pub weekday: u8,
    pub minute_of_day: u16,
    pub tz_offset_min: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    pub anchor_ms: i64,
}

impl Meeting {
    pub fn parse(raw: &str) -> Option<Meeting> {
        serde_json::from_str(raw).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }

    /// The first start at or after `from_ms`.
    pub fn next_start(&self, from_ms: i64) -> i64 {
        if from_ms <= self.anchor_ms {
            return self.anchor_ms;
        }
        let period = self.cadence.period_ms();
        let k = (from_ms - self.anchor_ms + period - 1) / period;
        self.anchor_ms + k * period
    }

    /// Whether `other` has the same schedule (place aside).
    fn same_schedule(&self, other: &MeetingInput) -> bool {
        self.cadence == other.cadence
            && self.weekday == other.weekday
            && self.minute_of_day == other.minute_of_day
            && self.tz_offset_min == other.tz_offset_min
    }
}

/// Check a facilitator's input and build the meeting to store, keeping
/// `current`'s anchor when the schedule is unchanged. `Err` is a message
/// for the facilitator.
pub fn build(
    input: &MeetingInput,
    current: Option<&Meeting>,
    now_ms: i64,
) -> Result<Meeting, &'static str> {
    if input.weekday > 6 {
        return Err("weekday is 0 (Monday) to 6 (Sunday)");
    }
    if input.minute_of_day > 1439 {
        return Err("minute_of_day is 0 to 1439");
    }
    if !(-840..=840).contains(&input.tz_offset_min) {
        return Err("tz_offset_min is -840 to 840");
    }
    let place = match input.place.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(p) if p.chars().count() > MAX_PLACE_CHARS || p.chars().any(char::is_control) => {
            return Err("the place is at most 200 characters");
        }
        Some(p) => Some(p.to_owned()),
    };
    let anchor_ms = match current.filter(|c| c.same_schedule(input)) {
        Some(c) => c.anchor_ms,
        None => first_start(input, now_ms),
    };
    Ok(Meeting {
        cadence: input.cadence,
        weekday: input.weekday,
        minute_of_day: input.minute_of_day,
        tz_offset_min: input.tz_offset_min,
        place,
        anchor_ms,
    })
}

/// The first start strictly after `now_ms` on the schedule's weekday.
fn first_start(m: &MeetingInput, now_ms: i64) -> i64 {
    let offset = i64::from(m.tz_offset_min) * MINUTE_MS;
    let local_day = (now_ms + offset).div_euclid(DAY_MS);
    // 1970-01-01 was a Thursday: with Monday = 0, day 0 has weekday 3.
    let weekday_of = |d: i64| (d + 3).rem_euclid(7);
    let ahead = (i64::from(m.weekday) - weekday_of(local_day)).rem_euclid(7);
    let at = |d: i64| d * DAY_MS + i64::from(m.minute_of_day) * MINUTE_MS - offset;
    let mut start = at(local_day + ahead);
    if start <= now_ms {
        start += 7 * DAY_MS;
    }
    start
}

/// `detail` of a reminder notice: "<minute of day>:<0 today | 1 tomorrow>"
/// in the meeting's own time zone.
pub fn reminder_detail(m: &Meeting, start_ms: i64, now_ms: i64) -> String {
    let offset = i64::from(m.tz_offset_min) * MINUTE_MS;
    let tomorrow = (start_ms + offset).div_euclid(DAY_MS) > (now_ms + offset).div_euclid(DAY_MS);
    format!("{}:{}", m.minute_of_day, i32::from(tomorrow))
}

/// "at 7:00 pm today" from a reminder's `detail` (a generic phrase if it is
/// missing or malformed).
pub fn reminder_words(detail: Option<&str>) -> String {
    let parsed = detail.and_then(|d| {
        let (minute, day) = d.split_once(':')?;
        Some((minute.parse::<u32>().ok()?, day == "1"))
    });
    match parsed {
        Some((minute, tomorrow)) if minute < 1440 => {
            let (h, mm) = (minute / 60, minute % 60);
            let (h12, suffix) = match h {
                0 => (12, "am"),
                1..=11 => (h, "am"),
                12 => (12, "pm"),
                _ => (h - 12, "pm"),
            };
            format!(
                "at {h12}:{mm:02} {suffix} {}",
                if tomorrow { "tomorrow" } else { "today" }
            )
        }
        _ => "soon".to_owned(),
    }
}

/// Whether a person in a group of `participants` is emailed: their choice,
/// else on up to 32 participants and off above.
pub fn email_wanted(prefs: MeetingPrefs, participants: usize) -> bool {
    prefs.email.unwrap_or(participants as i64 <= LARGE_GROUP)
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub notices: u64,
}

/// Write the reminders that are due: for every open group whose next
/// meeting starts within [`REMINDER_LEAD_MS`], one notice per participant
/// who wants one (once per meeting). Safe to run as often as you like.
pub async fn run_once(state: &AppState) -> Result<Summary, AppError> {
    let mut summary = Summary::default();
    if !state.settings().groups.enabled {
        return Ok(summary);
    }
    let now = state.now_ms();
    let candidates = group_listing::groups_with_meetings(state.db().pool()).await?;
    for (group, raw) in candidates {
        let Some(meeting) = Meeting::parse(&raw) else {
            continue;
        };
        let start = meeting.next_start(now);
        if start <= now || start - now > REMINDER_LEAD_MS {
            continue;
        }
        let mut tx = state.db().begin_write().await?;
        let people = group_listing::remindees(&mut *tx, &group).await?;
        let detail = reminder_detail(&meeting, start, now);
        for p in &people {
            if !p.prefs.reminders {
                continue;
            }
            let email = email_wanted(p.prefs, people.len());
            if crate::groups::tell_meeting_reminder(
                &mut tx,
                &group,
                &p.user_id,
                start,
                detail.clone(),
                email,
                now,
            )
            .await?
            {
                summary.notices += 1;
            }
        }
        tx.commit().await?;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600 * 1000;

    fn input(weekday: u8, minute: u16, tz: i32, cadence: Cadence) -> MeetingInput {
        MeetingInput {
            cadence,
            weekday,
            minute_of_day: minute,
            tz_offset_min: tz,
            place: None,
        }
    }

    #[test]
    fn first_start_is_the_next_matching_weekday() {
        // 1970-01-05 00:00 UTC was a Monday; 4 days after epoch.
        let monday = 4 * DAY_MS;
        let tuesday_7pm = monday + DAY_MS + 19 * HOUR;
        let m = build(&input(1, 19 * 60, 0, Cadence::Weekly), None, monday).unwrap();
        assert_eq!(m.anchor_ms, tuesday_7pm);
        // Asked on Tuesday after the time: next week.
        let m = build(
            &input(1, 19 * 60, 0, Cadence::Weekly),
            None,
            tuesday_7pm + 1,
        )
        .unwrap();
        assert_eq!(m.anchor_ms, tuesday_7pm + 7 * DAY_MS);
        // The same meeting at UTC-5 starts at midnight UTC the next day.
        let m = build(&input(1, 19 * 60, -300, Cadence::Weekly), None, monday).unwrap();
        assert_eq!(m.anchor_ms, monday + 2 * DAY_MS);
    }

    #[test]
    fn fortnightly_alternates_and_place_edits_keep_the_anchor() {
        let now = 4 * DAY_MS;
        let m = build(&input(1, 0, 0, Cadence::Fortnightly), None, now).unwrap();
        let first = m.anchor_ms;
        assert_eq!(m.next_start(first + 1), first + 14 * DAY_MS);
        assert_eq!(m.next_start(first), first);
        let mut edit = input(1, 0, 0, Cadence::Fortnightly);
        edit.place = Some(" Room 104 ".into());
        let again = build(&edit, Some(&m), now + 20 * DAY_MS).unwrap();
        assert_eq!(again.anchor_ms, first);
        assert_eq!(again.place.as_deref(), Some("Room 104"));
        let moved = build(&input(2, 0, 0, Cadence::Fortnightly), Some(&m), now).unwrap();
        assert_ne!(moved.anchor_ms, first);
    }

    #[test]
    fn rejects_bad_input() {
        let now = 0;
        assert!(build(&input(7, 0, 0, Cadence::Weekly), None, now).is_err());
        assert!(build(&input(0, 1440, 0, Cadence::Weekly), None, now).is_err());
        assert!(build(&input(0, 0, 841, Cadence::Weekly), None, now).is_err());
    }

    #[test]
    fn words() {
        assert_eq!(reminder_words(Some("1140:0")), "at 7:00 pm today");
        assert_eq!(reminder_words(Some("30:1")), "at 12:30 am tomorrow");
        assert_eq!(reminder_words(Some("720:0")), "at 12:00 pm today");
        assert_eq!(reminder_words(None), "soon");
        assert_eq!(reminder_words(Some("zzz")), "soon");
    }

    #[test]
    fn email_default_flips_above_32() {
        let d = MeetingPrefs::default();
        assert!(email_wanted(d, 32));
        assert!(!email_wanted(d, 33));
        let on = MeetingPrefs {
            reminders: true,
            email: Some(true),
        };
        assert!(email_wanted(on, 500));
    }
}
