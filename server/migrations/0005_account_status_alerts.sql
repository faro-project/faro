-- Faro instance schema v5: alerts about another account (ARCHITECTURE.md §4.3).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- The account an alert is about when that is not the member it is raised
-- on: the ally whose account an admin disabled or re-enabled
-- (`ally_disabled` / `ally_enabled`). Notifications name them. NULL for
-- every other alert.
ALTER TABLE alerts ADD COLUMN about_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;
