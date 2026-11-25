-- Faro instance schema v6: account deletion (ARCHITECTURE.md §12).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- A person may ask for their account to be deleted. Nothing is removed for
-- a hold of 7 days: they can still sign in and cancel, and their computers
-- keep reporting. `deletion_requested_at` is NULL unless a deletion is
-- pending; `deletion_purge_after` is the end of the hold. The purge starts
-- once the hold has passed and every deletion notice has been delivered,
-- and `deletion_started_at` records that, so a cancel can never race it.
ALTER TABLE users ADD COLUMN deletion_requested_at BIGINT;
ALTER TABLE users ADD COLUMN deletion_purge_after BIGINT;
ALTER TABLE users ADD COLUMN deletion_started_at BIGINT;
CREATE INDEX users_deleting ON users(deletion_purge_after) WHERE deletion_requested_at IS NOT NULL;

-- The keyed token hashes of a deleted account's computers, so they get a
-- clear refusal (`403 account_deleted`) instead of a bare 401 after the
-- purge. Nothing else about the device or its owner is kept. Retention
-- removes rows after 365 days.
CREATE TABLE deleted_device_tokens (
    token_hash TEXT PRIMARY KEY,
    deleted_at BIGINT NOT NULL
);
CREATE INDEX deleted_device_tokens_at ON deleted_device_tokens(deleted_at);
