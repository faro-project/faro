-- Faro instance schema v4: upload-stall detection, retired devices and
-- non-retroactive member retention (ARCHITECTURE.md §3.7, §4.3, §8).
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- Since when the device's signed heartbeats have claimed a chain position
-- (`reported_last_seq`) ahead of the verified head (`last_seq`): the device
-- holds events it has not uploaded. NULL while the head keeps up. Set by a
-- heartbeat, cleared by a heartbeat or an upload that catches up.
ALTER TABLE devices ADD COLUMN upload_behind_since BIGINT;

-- When the device's verified chain ended in an accepted `goodbye`
-- (uninstall / move). The goodbye itself is the urgent alert; the liveness
-- monitor does not also report the device missing. Cleared when the device
-- is heard from again.
ALTER TABLE devices ADD COLUMN goodbye_at BIGINT;

-- When each of a member's windows took its current value. A shorter window
-- applies only to data received from then on; older data keeps the
-- instance window, so shortening retention can't delete sent items early
-- (§4.3). Existing overrides count from their last update.
ALTER TABLE retention_overrides ADD COLUMN event_header_since BIGINT;
ALTER TABLE retention_overrides ADD COLUMN blob_since BIGINT;
ALTER TABLE retention_overrides ADD COLUMN alert_since BIGINT;
UPDATE retention_overrides
   SET event_header_since = updated_at, blob_since = updated_at, alert_since = updated_at;
