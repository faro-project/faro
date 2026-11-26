-- Faro instance schema v10: groups (docs/GROUPS.md §15).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps,
-- partial indexes that work on SQLite and Postgres). The table is
-- `accountability_groups`, not `groups`: GROUPS is a keyword in both
-- databases' window-function syntax.
--
-- Every column that references `users` must be in
-- `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).

CREATE TABLE accountability_groups (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    created_by       TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at       BIGINT NOT NULL,
    -- {cadence, weekday, minute_of_day, tz_offset_min, place}; written by
    -- the meetings work, NULL until then.
    meeting_json     TEXT,
    -- {who_can_invite}
    settings_json    TEXT NOT NULL DEFAULT '{}',
    -- Directory listing (0/1) and what a listing shows
    -- ({show_meeting_time, show_place}); written by the listing work.
    listed           BIGINT NOT NULL DEFAULT 0,
    listing_json     TEXT,
    -- Optional, set by facilitators.
    max_participants BIGINT,
    -- Archived groups are read-only until `delete_after`, then deleted.
    archived_at      BIGINT,
    archived_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    delete_after     BIGINT,
    -- When the last facilitator's account was purged: the participant who
    -- joined first is offered the role until `facilitator_offer_until`.
    facilitator_offer_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    facilitator_offer_until   BIGINT
);
CREATE INDEX accountability_groups_listed ON accountability_groups(listed)
    WHERE archived_at IS NULL;
CREATE INDEX accountability_groups_delete_after ON accountability_groups(delete_after)
    WHERE archived_at IS NOT NULL;

-- One row per stay in a group: leaving and joining again adds a row.
-- `share_status` / `share_allies` are opt-in sharing with the group (0/1,
-- off by default); nothing reads them yet.
CREATE TABLE group_participants (
    id           TEXT PRIMARY KEY,
    group_id     TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('facilitator', 'participant')),
    state        TEXT NOT NULL CHECK (state IN ('active', 'left', 'removed')),
    invited_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    joined_via   TEXT NOT NULL CHECK (joined_via IN ('invite', 'request', 'created')),
    joined_at    BIGINT NOT NULL,
    ended_at     BIGINT,
    share_status BIGINT NOT NULL DEFAULT 0,
    share_allies BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX group_participants_active ON group_participants(group_id, user_id)
    WHERE state = 'active';
CREATE INDEX group_participants_group ON group_participants(group_id, state);
CREATE INDEX group_participants_user ON group_participants(user_id, state);

-- Visible to every participant, so nobody can be added unseen. The purge
-- sets `subject_id` and `actor_id` to NULL ("Someone left").
CREATE TABLE group_history (
    id         TEXT PRIMARY KEY,
    group_id   TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    at         BIGINT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('joined', 'left', 'removed', 'facilitator_added',
                    'facilitator_removed', 'renamed', 'listed', 'unlisted', 'archived')),
    subject_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_id   TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX group_history_group ON group_history(group_id, at);

-- Single-use, hashed, 7 days, bound to one address or one user.
-- `outcome` is NULL while open, then `accepted` or `declined`.
CREATE TABLE group_invites (
    token_hash TEXT PRIMARY KEY,
    group_id   TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    inviter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    used_by    TEXT REFERENCES users(id) ON DELETE SET NULL,
    outcome    TEXT CHECK (outcome IN ('accepted', 'declined')),
    CHECK ((email IS NULL AND user_id IS NOT NULL) OR (email IS NOT NULL AND user_id IS NULL))
);
CREATE INDEX group_invites_group ON group_invites(group_id);
CREATE INDEX group_invites_email ON group_invites(email);
CREATE INDEX group_invites_user ON group_invites(user_id);

-- Content-free notices about groups (`group_joined`, `group_left`,
-- `group_removed`, `group_archived`), emailed by the notifier like any other
-- notification. They never hold or lead to a group's name or description
-- (GROUPS.md principle 7). `summary` is 1 for the daily summary facilitators
-- of a group with more than 32 participants get instead of one notice per
-- change; `dedupe_key` keeps it to one per day.
CREATE TABLE group_notices (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    summary      BIGINT NOT NULL DEFAULT 0,
    dedupe_key   TEXT UNIQUE,
    created_at   BIGINT NOT NULL
);

ALTER TABLE notifications ADD COLUMN group_notice_id TEXT REFERENCES group_notices(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX notifications_group_notice_recipient
    ON notifications(group_notice_id, recipient_id, channel);

-- The group an ally link was proposed in: a label, never used to authorize
-- anything. Deleting a group leaves its alliances intact.
ALTER TABLE ally_links ADD COLUMN origin_group_id TEXT REFERENCES accountability_groups(id) ON DELETE SET NULL;

-- Which group an admin log entry is about (no foreign key: the entry
-- outlives the group, and holds no name).
ALTER TABLE admin_log ADD COLUMN group_id TEXT;
