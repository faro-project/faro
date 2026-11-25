-- Faro instance schema v8: granting and revoking the admin role
-- (ARCHITECTURE.md §4.3).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- What admins did to accounts, for the admin console. For now only
-- `admin_granted` and `admin_revoked`; `action` has no CHECK so later
-- actions can be added without rebuilding the table.
--
-- `user_id` is the account the action was about, `actor_id` the admin who
-- did it. `via` says where: `console` (an admin in the web app) or
-- `command_line` (`faro-server admin grant` on the server, where
-- `actor_id` is NULL). Both ids become NULL when that account is deleted,
-- so the log never names a deleted person.
CREATE TABLE admin_log (
    id         TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    via        TEXT NOT NULL CHECK (via IN ('console', 'command_line')),
    created_at BIGINT NOT NULL
);
CREATE INDEX admin_log_created ON admin_log(created_at);

-- Each entry is emailed to the person and to every other admin: one
-- notification row per recipient, sent by the notifier like any other.
ALTER TABLE notifications ADD COLUMN admin_log_id TEXT REFERENCES admin_log(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX notifications_admin_log_recipient
    ON notifications(admin_log_id, recipient_id, channel);
