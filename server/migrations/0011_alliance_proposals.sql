-- Faro instance schema v11: alliance proposals (docs/GROUPS.md §7, §15).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps,
-- partial indexes that work on SQLite and Postgres).
--
-- Every column that references `users` must be in
-- `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).
--
-- A proposal only ever *starts* ally links: accepting one creates `pending`
-- links, and the member's own signed approval
-- (`POST /v1/me/allies/{ally_id}/approve`) is still the only thing that
-- makes a link active (GROUPS.md principle 2).

CREATE TABLE alliance_proposals (
    id                TEXT PRIMARY KEY,
    group_id          TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    from_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('request', 'offer', 'partnership')),
    -- Offers and partnerships: the fingerprint (`key_id`) of the sender's
    -- ally key when they sent it. A label only: accepting uses the sender's
    -- *current* key, which is what the member then endorses.
    offer_ally_key_id TEXT,
    -- The encrypted, signed note (GROUPS.md §10.2); written by the notes
    -- work, NULL until then.
    note_blob_ref     TEXT,
    state             TEXT NOT NULL
                      CHECK (state IN ('open', 'accepted', 'not_accepted', 'withdrawn', 'void')),
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    -- When the recipient accepted or declined, or the sender withdrew.
    -- NULL for an expiry and for a void.
    decided_at        BIGINT,
    -- The end of the cool-down on asking this person for this kind again:
    -- always `expires_at` + 30 days, so the sender can't tell a decline from
    -- an expiry (principle 5). Applies unless accepted or withdrawn.
    cooldown_until    BIGINT NOT NULL,
    -- When the sender withdrew it. Set even when the recipient had already
    -- declined (the sender still saw it as open), so the sender's own view
    -- follows their own action and nothing else.
    withdrawn_at      BIGINT,
    -- 1: the recipient never sees it and is never told (the recipient
    -- blocked the sender, can't receive proposals, or is in a cool-down the
    -- sender can't see). Stored as `not_accepted` from the start; the
    -- sender's view is the same as for any proposal that wasn't accepted.
    hidden            BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX alliance_proposals_open ON alliance_proposals(from_id, to_id, kind)
    WHERE state = 'open';
CREATE INDEX alliance_proposals_from ON alliance_proposals(from_id, created_at);
CREATE INDEX alliance_proposals_to ON alliance_proposals(to_id, created_at);
CREATE INDEX alliance_proposals_group ON alliance_proposals(group_id, state);
CREATE INDEX alliance_proposals_expires ON alliance_proposals(expires_at);

-- "Don't propose to me": `user_id` won't receive proposals from
-- `blocked_id`, in any group. Private to `user_id`.
CREATE TABLE proposal_blocks (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
);
CREATE INDEX proposal_blocks_blocked ON proposal_blocks(blocked_id);
