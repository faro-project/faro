-- Faro instance schema v13: the group roster log, snapshots and epoch keys
-- (docs/GROUPS.md §10.3, §10.5, §15 "Phase C"; docs/PROTOCOL.md §10).
--
-- The instance stores and pages what facilitators' browsers sign. It checks
-- structure (seq, prev_hash, signer, that entries match who is in the group)
-- but clients verify everything themselves against their own checkpoint, so
-- nothing here is a trust anchor.
--
-- User ids inside signed entries (`signer_id`, `group_roster_members`) are
-- opaque copies of signed data, without foreign keys: they stay after an
-- account is purged, like other members' signed headers (GROUPS.md §18),
-- until a facilitator signs the person's removal. Columns that reference
-- `users` are in `db::repo::deletion::USER_COLUMNS`.

-- A signing key for someone without member keys (an ally-only facilitator,
-- GROUPS.md decision 6). The Ed25519 seed is sealed (`crypto_box_seal`) to
-- their own encryption key (`enc_pubkey`, their ally key), which their
-- passphrase and recovery code protect.
CREATE TABLE participant_sign_keys (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sign_pubkey TEXT NOT NULL UNIQUE,
    enc_pubkey  TEXT NOT NULL,
    sealed_seed TEXT NOT NULL,
    created_at  BIGINT NOT NULL
);

-- The log: one row per signed entry. `entry_json` is the signed entry with
-- its `sig`, exactly as uploaded.
CREATE TABLE group_roster_log (
    group_id   TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    seq        BIGINT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL,
    signer_id  TEXT NOT NULL,
    epoch      BIGINT,
    entry_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, seq)
);

-- The roster as of the log's head, kept in step with it so uploads can be
-- checked without replaying the log.
CREATE TABLE group_roster_members (
    group_id    TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('facilitator', 'participant')),
    enc_pubkey  TEXT NOT NULL,
    sign_pubkey TEXT,
    PRIMARY KEY (group_id, user_id)
);

-- Signed snapshots of the full roster, at most one per seq. Inline rather
-- than in the blob store: a snapshot is public-key data, at most 8 MiB.
CREATE TABLE group_roster_snapshots (
    group_id      TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    seq           BIGINT NOT NULL,
    hash          TEXT NOT NULL,
    signer_id     TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    PRIMARY KEY (group_id, seq)
);

-- One row per epoch: which entry started it and its key commitment.
CREATE TABLE group_epochs (
    group_id   TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    epoch      BIGINT NOT NULL,
    seq        BIGINT NOT NULL,
    key_check  TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, epoch)
);

-- Each participant's copy of an epoch key, sealed to their encryption key.
-- Deleted with the account (GROUPS.md §18).
CREATE TABLE group_epoch_keys (
    group_id   TEXT NOT NULL REFERENCES accountability_groups(id) ON DELETE CASCADE,
    epoch      BIGINT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_key TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, epoch, user_id)
);
CREATE INDEX group_epoch_keys_user ON group_epoch_keys(user_id);
