-- Faro instance schema v17: settings changes in the admin log (#195).
--
-- `PATCH /admin/api/settings` now writes a `settings_changed` entry,
-- emailed to the other admins. `detail` says what changed: setting names
-- with their old and new values, e.g. `retention.blob_days:30>7`. Settings
-- are operational configuration, never anyone's content. NULL for every
-- other action. `user_id` of such an entry is the admin who changed them.
ALTER TABLE admin_log ADD COLUMN detail TEXT;
