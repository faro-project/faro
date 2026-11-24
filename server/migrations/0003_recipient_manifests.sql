-- Faro instance schema v3: member-signed recipient manifests (PROTOCOL.md
-- §5.1).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- Every version a member ever uploaded, kept as history. The latest is the
-- row with the highest version; versions start at 1 and go up by exactly 1
-- (enforced by the API inside a write transaction, and by the primary key
-- against two concurrent uploads of the same version).
CREATE TABLE member_manifests (
    member_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version       BIGINT NOT NULL CHECK (version >= 1),
    hash          TEXT NOT NULL,                      -- BLAKE3(signing_bytes), b3:hex
    manifest_json TEXT NOT NULL,                      -- SignedRecipientManifest
    received_at   BIGINT NOT NULL,
    PRIMARY KEY (member_id, version)
);

-- An alert may name one ally who is *not* told through the alert pipeline:
-- the ally who was just added gets a dedicated notice instead of an
-- "ally added" alert about themself.
ALTER TABLE alerts ADD COLUMN skip_recipient_id TEXT REFERENCES users(id) ON DELETE SET NULL;
