-- Faro instance schema v2: allies, notifier, liveness, retention, admin
-- settings (ARCHITECTURE.md §3.7, §4.3, §5.2, §5.4, §8).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).
-- Partial indexes (CREATE ... INDEX ... WHERE) are supported by both SQLite
-- and Postgres.

-- At most one live (pending or active) link per (member, ally). A removed
-- link stays for the audit trail and does not block a later re-invite.
CREATE UNIQUE INDEX ally_links_live ON ally_links(member_id, ally_id) WHERE state <> 'removed';

-- Invites are looked up by email when deciding whether an address may sign
-- in under invite-only registration, and swept by expiry.
CREATE INDEX invites_email ON invites(email, expires_at);
CREATE INDEX invites_expires ON invites(expires_at);
CREATE INDEX enroll_codes_expires ON enroll_codes(expires_at);
CREATE INDEX setup_tokens_expires ON setup_tokens(expires_at);

-- An alert may have one recipient outside the member's current allies: the
-- ally who was just removed must still be told (§3.7).
ALTER TABLE alerts ADD COLUMN extra_recipient_id TEXT REFERENCES users(id) ON DELETE SET NULL;

-- Reports are fanned out to notifications like alerts.
ALTER TABLE reports ADD COLUMN dispatched_at BIGINT;
CREATE INDEX reports_undispatched ON reports(dispatched_at, received_at);

-- Notification delivery state. `mode` is immediate or digest (an 'off'
-- preference is recorded as status = 'suppressed'); `due_at` is when it may
-- be sent (quiet hours push it later); `next_attempt_at` drives retries with
-- exponential backoff.
ALTER TABLE notifications ADD COLUMN mode TEXT NOT NULL DEFAULT 'immediate';
ALTER TABLE notifications ADD COLUMN due_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE notifications ADD COLUMN next_attempt_at BIGINT NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX notifications_alert_recipient ON notifications(alert_id, recipient_id, channel);
CREATE UNIQUE INDEX notifications_report_recipient ON notifications(report_id, recipient_id, channel);
CREATE INDEX notifications_due ON notifications(status, mode, due_at);
CREATE INDEX notifications_created ON notifications(created_at);

-- Quiet hours are evaluated with a fixed UTC offset chosen by the browser
-- (minutes east of UTC). The IANA `timezone` column from 0001 is unused: the
-- server deliberately carries no time-zone database.
ALTER TABLE notification_prefs ADD COLUMN tz_offset_min BIGINT;

-- Missed-check-in episodes (§3.7). One open episode per device at most, so
-- a device that stays silent is alerted about once, not every minute.
CREATE TABLE liveness_episodes (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    member_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    silence_start_ms BIGINT NOT NULL,
    opened_at        BIGINT NOT NULL,
    closed_at        BIGINT
);
CREATE UNIQUE INDEX liveness_episodes_open ON liveness_episodes(device_id) WHERE closed_at IS NULL;
CREATE INDEX liveness_episodes_closed ON liveness_episodes(closed_at);

-- Per-member retention, only ever shorter than the instance's (§8).
CREATE TABLE retention_overrides (
    member_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    event_header_days BIGINT,
    blob_days         BIGINT,
    alert_days        BIGINT,
    updated_at        BIGINT NOT NULL
);

CREATE INDEX alerts_created ON alerts(created_at);
CREATE INDEX reports_received ON reports(received_at);
CREATE INDEX instance_uptime_open ON instance_uptime(stopped_at);
