-- Faro instance schema v16: check-ins and replies, and whole-group reach
-- outs (docs/GROUPS.md §8.3, §8.6, §10.5, §15 "Phase C"; docs/PROTOCOL.md
-- §11).
--
-- Same portability rules as 0001. Every column that references `users`
-- must be in `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).

-- A check-in or a private reply to one: a signed group message
-- (PROTOCOL.md §11) filed in a group's feed. `id` is the signed `item_id`.
-- `message_json` is the author's `Signed<GroupMessage>` verbatim and
-- `body_json` its encrypted body, so the instance can neither read nor
-- forge a post; every reader's browser checks both. `epoch` is set for a
-- check-in to the whole group (sealed with that epoch's key, one envelope);
-- otherwise `group_post_recipients` lists who may read it. A check-in
-- never notifies anyone, so nothing here references the alert pipeline.
-- Posts follow blob retention (GROUPS.md §18); a reply goes with its
-- check-in.
CREATE TABLE group_posts (
    id           TEXT PRIMARY KEY,
    group_id     TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    author_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('check_in', 'reply')),
    parent_id    TEXT REFERENCES group_posts(id) ON DELETE CASCADE,
    epoch        BIGINT,
    created_at   BIGINT NOT NULL,
    sig          TEXT NOT NULL,
    message_json TEXT NOT NULL,
    body_json    TEXT
);
CREATE INDEX group_posts_feed ON group_posts(group_id, created_at);
CREATE INDEX group_posts_author ON group_posts(author_id, created_at);
CREATE INDEX group_posts_parent ON group_posts(parent_id);

CREATE TABLE group_post_recipients (
    post_id      TEXT NOT NULL REFERENCES group_posts(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id       TEXT NOT NULL,
    PRIMARY KEY (post_id, recipient_id)
);
CREATE INDEX group_post_recipients_recipient ON group_post_recipients(recipient_id);

-- A reach out to the whole group (groups of 32 or fewer) is a message
-- sealed with an epoch key: the epoch is kept so the key is pruned only
-- when nothing stored uses it.
ALTER TABLE group_messages ADD COLUMN epoch BIGINT;

-- `reach_outs.audience` gains `group`. SQLite can't ALTER a CHECK, so the
-- table is rebuilt (this works the same on Postgres): its one child,
-- `reach_out_recipients`, is saved and dropped first, so that dropping
-- the parent can't cascade over its rows (SQLite enforces foreign keys),
-- and is recreated and refilled afterwards.
CREATE TABLE reach_outs_new (
    id         TEXT PRIMARY KEY,
    sender_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   TEXT REFERENCES accountability_groups(id) ON DELETE SET NULL,
    audience   TEXT NOT NULL CHECK (audience IN ('allies', 'facilitators', 'people', 'group')),
    created_at BIGINT NOT NULL,
    sig        TEXT,
    blob_ref   TEXT REFERENCES group_messages(id) ON DELETE SET NULL
);
INSERT INTO reach_outs_new (id, sender_id, group_id, audience, created_at, sig, blob_ref)
    SELECT id, sender_id, group_id, audience, created_at, sig, blob_ref FROM reach_outs;

CREATE TABLE reach_out_recipients_save (
    reach_out_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    answered_at  BIGINT,
    answer       TEXT
);
INSERT INTO reach_out_recipients_save (reach_out_id, recipient_id, answered_at, answer)
    SELECT reach_out_id, recipient_id, answered_at, answer FROM reach_out_recipients;

DROP TABLE reach_out_recipients;
DROP TABLE reach_outs;
ALTER TABLE reach_outs_new RENAME TO reach_outs;
CREATE INDEX reach_outs_sender ON reach_outs(sender_id, created_at);
CREATE INDEX reach_outs_created ON reach_outs(created_at);

CREATE TABLE reach_out_recipients (
    reach_out_id TEXT NOT NULL REFERENCES reach_outs(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    answered_at  BIGINT,
    answer       TEXT CHECK (answer IN ('call', 'here')),
    PRIMARY KEY (reach_out_id, recipient_id)
);
INSERT INTO reach_out_recipients (reach_out_id, recipient_id, answered_at, answer)
    SELECT reach_out_id, recipient_id, answered_at, answer FROM reach_out_recipients_save;
CREATE INDEX reach_out_recipients_recipient ON reach_out_recipients(recipient_id);
DROP TABLE reach_out_recipients_save;
