//! Reads behind `GET /v1/ally/feed` and `GET /v1/blobs/{id}`.
//!
//! The feed merges three sources for one member, ordered by the instance's
//! **receive** time (device clocks are not trusted for ordering):
//!
//! | rank | source | rows |
//! |---|---|---|
//! | 0 | `events` | effective urgency ≥ normal |
//! | 1 | `reports` | with ciphertext still stored |
//! | 2 | `alerts` | `source = 'server'` (device alerts mirror events) |
//!
//! Paging uses a composite cursor `(received_at, rank, key1, key2)` so that
//! rows sharing a millisecond (a batch upload) are never skipped or
//! repeated across pages.

use super::parse_col;
use faro_proto::{DeviceId, EventKind, Urgency, UserId};
use sqlx::{Any, Executor, Row};
use std::cmp::Ordering;

/// A position in the feed: everything strictly after it is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub ts_ms: i64,
    pub rank: u8,
    /// `device_id` for events, the row id otherwise.
    pub key1: String,
    /// `seq` for events, 0 otherwise.
    pub key2: i64,
}

impl Cursor {
    /// "Everything received after `ts_ms`" (the `since_ms` parameter).
    pub fn after_time(ts_ms: i64) -> Self {
        Cursor {
            ts_ms,
            rank: u8::MAX,
            key1: String::new(),
            key2: 0,
        }
    }

    pub fn encode(&self) -> String {
        format!("{}.{}.{}.{}", self.ts_ms, self.rank, self.key1, self.key2)
    }

    /// Strict parse; ids never contain '.'.
    pub fn decode(s: &str) -> Option<Self> {
        let mut it = s.splitn(4, '.');
        let ts_ms = it.next()?.parse().ok()?;
        let rank: u8 = it.next()?.parse().ok()?;
        let key1 = it.next()?.to_owned();
        let key2 = it.next()?.parse().ok()?;
        let key_ok = key1.len() <= 64
            && key1
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        (rank <= 2 && key_ok).then_some(Cursor {
            ts_ms,
            rank,
            key1,
            key2,
        })
    }

    fn cmp_key(&self, other: &Cursor) -> Ordering {
        (self.ts_ms, self.rank, &self.key1, self.key2).cmp(&(
            other.ts_ms,
            other.rank,
            &other.key1,
            other.key2,
        ))
    }
}

/// One feed row as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedRowKind {
    Event {
        device_id: DeviceId,
        seq: i64,
        ts_ms: i64,
        kind: EventKind,
        urgency: Urgency,
        blob_id: Option<String>,
    },
    Report {
        id: String,
        device_id: DeviceId,
        period_start_ms: i64,
        period_end_ms: i64,
        blob_id: String,
    },
    Alert {
        id: String,
        device_id: Option<DeviceId>,
        kind: String,
        urgency: Urgency,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedRow {
    pub cursor: Cursor,
    pub received_at_ms: i64,
    pub row: FeedRowKind,
}

/// How the rows of one source relate to the cursor position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// The source sorts before the cursor's source at equal time: only
    /// strictly later times qualify (`ts > $2`). Binds `$1, $2`, limit `$3`.
    Later,
    /// The source sorts after the cursor's source: equal times qualify too
    /// (`ts >= $2`). Binds `$1, $2`, limit `$3`.
    SameOrLater,
    /// The cursor is in this source: ties at `ts = $2` are broken by the
    /// row keys (`$3`, and `$4` for events). The limit is the last parameter.
    Keyed,
}

impl After {
    fn of(rank: u8, c: &Cursor) -> Self {
        match rank.cmp(&c.rank) {
            Ordering::Less => After::Later,
            Ordering::Greater => After::SameOrLater,
            Ordering::Equal => After::Keyed,
        }
    }
}

// Each feed source has one fixed query per `After` case. They are written
// out (via `concat!` of literals) rather than formatted at run time so that
// every statement is a `&'static str` and nothing dynamic, not even the page
// size, is ever spliced into SQL: the limit is a bound parameter.

macro_rules! events_sql {
    ($pred:literal, $limit:literal) => {
        concat!(
            "SELECT device_id, seq, ts_ms, kind, effective_urgency, blob_id, received_at
             FROM events
             WHERE member_id = $1 AND effective_urgency IN ('normal', 'urgent') AND ",
            $pred,
            " ORDER BY received_at, device_id, seq LIMIT ",
            $limit
        )
    };
}

macro_rules! reports_sql {
    ($pred:literal, $limit:literal) => {
        concat!(
            "SELECT id, device_id, period_start_ms, period_end_ms, blob_id, received_at
             FROM reports
             WHERE member_id = $1 AND blob_id IS NOT NULL AND ",
            $pred,
            " ORDER BY received_at, id LIMIT ",
            $limit
        )
    };
}

macro_rules! alerts_sql {
    ($pred:literal, $limit:literal) => {
        concat!(
            "SELECT id, device_id, kind, urgency, detail, created_at FROM alerts
             WHERE member_id = $1 AND source = 'server' AND ",
            $pred,
            " ORDER BY created_at, id LIMIT ",
            $limit
        )
    };
}

fn events_query(a: After) -> &'static str {
    match a {
        After::Later => events_sql!("received_at > $2", "$3"),
        After::SameOrLater => events_sql!("received_at >= $2", "$3"),
        After::Keyed => events_sql!(
            "(received_at > $2 OR (received_at = $2 AND
              (device_id > $3 OR (device_id = $3 AND seq > $4))))",
            "$5"
        ),
    }
}

fn reports_query(a: After) -> &'static str {
    match a {
        After::Later => reports_sql!("received_at > $2", "$3"),
        After::SameOrLater => reports_sql!("received_at >= $2", "$3"),
        After::Keyed => reports_sql!("(received_at > $2 OR (received_at = $2 AND id > $3))", "$4"),
    }
}

fn alerts_query(a: After) -> &'static str {
    match a {
        After::Later => alerts_sql!("created_at > $2", "$3"),
        After::SameOrLater => alerts_sql!("created_at >= $2", "$3"),
        After::Keyed => alerts_sql!("(created_at > $2 OR (created_at = $2 AND id > $3))", "$4"),
    }
}

/// Up to `limit` feed rows for `member` after `c`, merged in order.
pub async fn page(
    conn: &mut sqlx::AnyConnection,
    member: &UserId,
    c: &Cursor,
    limit: i64,
) -> Result<Vec<FeedRow>, sqlx::Error> {
    let mut out = Vec::new();

    let a = After::of(0, c);
    let mut q = sqlx::query(events_query(a))
        .bind(member.as_str())
        .bind(c.ts_ms);
    if a == After::Keyed {
        q = q.bind(c.key1.clone()).bind(c.key2);
    }
    for r in q.bind(limit).fetch_all(&mut *conn).await? {
        let device: String = r.try_get("device_id")?;
        let seq: i64 = r.try_get("seq")?;
        let received: i64 = r.try_get("received_at")?;
        // Kinds this server version does not know are skipped, not fatal.
        let Some(kind) = EventKind::parse(&r.try_get::<String, _>("kind")?) else {
            continue;
        };
        out.push(FeedRow {
            cursor: Cursor {
                ts_ms: received,
                rank: 0,
                key1: device.clone(),
                key2: seq,
            },
            received_at_ms: received,
            row: FeedRowKind::Event {
                device_id: DeviceId::new(device),
                seq,
                ts_ms: r.try_get("ts_ms")?,
                kind,
                urgency: parse_col(&r, "effective_urgency", Urgency::parse)?,
                blob_id: r.try_get("blob_id")?,
            },
        });
    }

    let a = After::of(1, c);
    let mut q = sqlx::query(reports_query(a))
        .bind(member.as_str())
        .bind(c.ts_ms);
    if a == After::Keyed {
        q = q.bind(c.key1.clone());
    }
    for r in q.bind(limit).fetch_all(&mut *conn).await? {
        let id: String = r.try_get("id")?;
        let received: i64 = r.try_get("received_at")?;
        let Some(blob_id) = r.try_get::<Option<String>, _>("blob_id")? else {
            continue;
        };
        out.push(FeedRow {
            cursor: Cursor {
                ts_ms: received,
                rank: 1,
                key1: id.clone(),
                key2: 0,
            },
            received_at_ms: received,
            row: FeedRowKind::Report {
                id,
                device_id: DeviceId::new(r.try_get::<String, _>("device_id")?),
                period_start_ms: r.try_get("period_start_ms")?,
                period_end_ms: r.try_get("period_end_ms")?,
                blob_id,
            },
        });
    }

    let a = After::of(2, c);
    let mut q = sqlx::query(alerts_query(a))
        .bind(member.as_str())
        .bind(c.ts_ms);
    if a == After::Keyed {
        q = q.bind(c.key1.clone());
    }
    for r in q.bind(limit).fetch_all(&mut *conn).await? {
        let id: String = r.try_get("id")?;
        let created: i64 = r.try_get("created_at")?;
        out.push(FeedRow {
            cursor: Cursor {
                ts_ms: created,
                rank: 2,
                key1: id.clone(),
                key2: 0,
            },
            received_at_ms: created,
            row: FeedRowKind::Alert {
                id,
                device_id: r
                    .try_get::<Option<String>, _>("device_id")?
                    .map(DeviceId::new),
                kind: r.try_get("kind")?,
                urgency: parse_col(&r, "urgency", Urgency::parse)?,
                detail: r.try_get("detail")?,
            },
        });
    }

    out.sort_by(|a, b| a.cursor.cmp_key(&b.cursor));
    out.truncate(usize::try_from(limit).unwrap_or(0));
    Ok(out)
}

/// The member who owns a blob, if the blob exists.
pub async fn blob_owner<'e>(
    e: impl Executor<'e, Database = Any>,
    blob_id: &str,
) -> Result<Option<UserId>, sqlx::Error> {
    sqlx::query("SELECT owner_member_id FROM blobs WHERE id = $1")
        .bind(blob_id)
        .fetch_optional(e)
        .await?
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("owner_member_id")?)))
        .transpose()
}

/// Whether `ally` may read this blob of `owner`'s: they hold an envelope in
/// the event or report stored in it (device-declared), **and** the item was
/// received while a link between `owner` and `ally` was active
/// (`activated_at <= received_at < removed_at`).
///
/// The interval check is what makes removal forward-only (PROTOCOL §5.1):
/// after an ally is removed or leaves, devices may keep sealing items to them
/// until they accept the next manifest. Those items are stored with the
/// departed ally as a recipient, but they were received outside every active
/// interval, so a later re-approval never makes them readable. Items received
/// during an earlier active link stay readable after a re-approval: the ally
/// could already decrypt those.
///
/// The caller must separately require the link to be active *now*.
pub async fn ally_may_read_blob<'e>(
    e: impl Executor<'e, Database = Any>,
    blob_id: &str,
    owner: &UserId,
    ally: &UserId,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT 1 AS x WHERE EXISTS (
            SELECT 1 FROM events ev
            JOIN event_recipients er ON er.device_id = ev.device_id AND er.seq = ev.seq
            JOIN ally_links l ON l.member_id = ev.member_id AND l.ally_id = er.recipient_id
            WHERE ev.blob_id = $1 AND ev.member_id = $2 AND er.recipient_id = $3
              AND l.activated_at IS NOT NULL AND l.activated_at <= ev.received_at
              AND (l.removed_at IS NULL OR ev.received_at < l.removed_at))
         OR EXISTS (
            SELECT 1 FROM reports rp
            JOIN report_recipients rr ON rr.report_id = rp.id
            JOIN ally_links l ON l.member_id = rp.member_id AND l.ally_id = rr.recipient_id
            WHERE rp.blob_id = $1 AND rp.member_id = $2 AND rr.recipient_id = $3
              AND l.activated_at IS NOT NULL AND l.activated_at <= rp.received_at
              AND (l.removed_at IS NULL OR rp.received_at < l.removed_at))",
    )
    .bind(blob_id)
    .bind(owner.as_str())
    .bind(ally.as_str())
    .fetch_optional(e)
    .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_roundtrip_and_strictness() {
        let c = Cursor {
            ts_ms: 1_700_000_000_000,
            rank: 0,
            key1: "dev_abc".into(),
            key2: 42,
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        for bad in [
            "",
            "1.2",
            "x.0.a.0",
            "1.3.a.0",
            "1.0.a'b.0",
            "1.0.a.b",
            "1.0.a.0.extra",
            &format!("1.0.{}.0", "a".repeat(65)),
        ] {
            assert_eq!(Cursor::decode(bad), None, "{bad:?}");
        }
    }

    /// Every placeholder `$1..$n` a query uses appears, with no gaps (Postgres
    /// cannot infer the type of a skipped parameter), and the limit is the
    /// highest one.
    #[test]
    fn feed_queries_number_parameters_densely() {
        fn max_param(sql: &str) -> usize {
            let mut seen = Vec::new();
            let b = sql.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'$' {
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    seen.push(sql[i + 1..j].parse::<usize>().unwrap());
                    i = j;
                } else {
                    i += 1;
                }
            }
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen, (1..=seen.len()).collect::<Vec<_>>(), "{sql}");
            seen.len()
        }
        for a in [After::Later, After::SameOrLater, After::Keyed] {
            for (sql, keys) in [
                (events_query(a), 2),
                (reports_query(a), 1),
                (alerts_query(a), 1),
            ] {
                let n = max_param(sql);
                let expected = if a == After::Keyed { 3 + keys } else { 3 };
                assert_eq!(n, expected, "{sql}");
                assert!(sql.trim_end().ends_with(&format!("LIMIT ${n}")), "{sql}");
            }
        }
    }

    #[test]
    fn cursor_order_breaks_ties() {
        let a = Cursor {
            ts_ms: 5,
            rank: 0,
            key1: "dev_a".into(),
            key2: 9,
        };
        let b = Cursor {
            key2: 10,
            ..a.clone()
        };
        let c = Cursor {
            rank: 1,
            key1: "0".into(),
            key2: 0,
            ..a.clone()
        };
        assert_eq!(a.cmp_key(&b), Ordering::Less);
        assert_eq!(b.cmp_key(&c), Ordering::Less);
        assert_eq!(Cursor::after_time(5).cmp_key(&c), Ordering::Greater);
    }
}
