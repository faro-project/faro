-- Faro instance schema v9: account deletion asked for by an admin
-- (ARCHITECTURE.md §12).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- 1 while a pending deletion was asked for by an admin rather than by the
-- person (an erasure request from someone who can no longer sign in, or a
-- disabled account). Then the person or any admin may cancel it during the
-- hold; a deletion the person asked for themself only they can cancel.
-- Which admin asked is in `admin_log`. Meaningless while
-- `deletion_requested_at` is NULL.
ALTER TABLE users ADD COLUMN deletion_by_admin BIGINT NOT NULL DEFAULT 0;
