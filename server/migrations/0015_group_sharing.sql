-- Faro instance schema v15: pairing suggestions (docs/GROUPS.md §8.5, §15).
--
-- `group_participants.share_status` / `share_allies` (opt-in sharing,
-- §8.2) already exist from 0010.
--
-- A suggestion is not a proposal: it only puts a card on two people's
-- group pages. The pair is stored with `user_a < user_b` so the same pair
-- is never posted twice. `dismissed_a` / `dismissed_b` are private to each
-- person: no route shows a facilitator whether anyone acted.
--
-- Every column that references `users` is in
-- `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).

CREATE TABLE pairing_suggestions (
    id             TEXT PRIMARY KEY,
    group_id       TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    facilitator_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    user_a         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     BIGINT NOT NULL,
    dismissed_a    BIGINT NOT NULL DEFAULT 0,
    dismissed_b    BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX pairing_suggestions_pair ON pairing_suggestions(group_id, user_a, user_b);
CREATE INDEX pairing_suggestions_a ON pairing_suggestions(user_a, group_id);
CREATE INDEX pairing_suggestions_b ON pairing_suggestions(user_b, group_id);
