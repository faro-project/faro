-- Faro instance schema v12: listed groups, join requests and meeting
-- reminders (docs/GROUPS.md §8.4, §8.8, §15).
--
-- Same portability rules as 0001. Every column that references `users`
-- must be in `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).

-- A person's request to join a listed group. `open` until a facilitator
-- accepts or declines, 14 days pass (`expires_at`), the person withdraws, or
-- the group is unlisted or archived (`void`). The person is shown
-- "Not accepted" for a decline, an expiry and a void alike, and `cooldown_until`
-- is the same moment for the first two (`expires_at` + 30 days), so nothing
-- tells them apart (§8.8). `note_blob_ref` is for join-request notes, which
-- come later.
CREATE TABLE group_join_requests (
    id             TEXT PRIMARY KEY,
    group_id       TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note_blob_ref  TEXT,
    state          TEXT NOT NULL CHECK (state IN ('open', 'accepted', 'not_accepted',
                       'withdrawn', 'void')),
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    decided_at     BIGINT,
    decided_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    cooldown_until BIGINT
);
CREATE UNIQUE INDEX group_join_requests_open ON group_join_requests(group_id, user_id)
    WHERE state = 'open';
CREATE INDEX group_join_requests_user ON group_join_requests(user_id, state);
CREATE INDEX group_join_requests_group ON group_join_requests(group_id, state);

-- A person's own meeting-reminder choices for one group. No row means the
-- defaults: reminders on, and email on only in a group of 32 participants or
-- fewer (`email` NULL follows that default; 0 and 1 are the person's choice).
CREATE TABLE group_meeting_prefs (
    group_id  TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reminders BIGINT NOT NULL DEFAULT 1,
    email     BIGINT,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_meeting_prefs_user ON group_meeting_prefs(user_id);

-- A notice's one detail that is not about the group: for a meeting reminder,
-- "<minute of day>:<0 today | 1 tomorrow>" at the meeting's own UTC offset.
ALTER TABLE group_notices ADD COLUMN detail TEXT;
