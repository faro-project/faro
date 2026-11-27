-- Faro instance schema v18: coalesced alerts (#194).
--
-- Repeats of an alert (the same rejected upload again, or alerts beyond a
-- device's rate limit) are counted on the one existing alert instead of
-- being dropped or becoming new rows; allies see "and N more".
ALTER TABLE alerts ADD COLUMN repeat_count BIGINT NOT NULL DEFAULT 0;

-- Round-robin dispatch and per-(recipient, member) email coalescing look up
-- a recipient's last sent notification.
CREATE INDEX notifications_recipient_sent ON notifications(recipient_id, sent_at);
