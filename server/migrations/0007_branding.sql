-- Faro instance schema v7: instance branding (docs/SELF-HOSTING.md
-- "Branding your instance").
--
-- Same portability rules as 0001 (BIGINT/TEXT only, Unix-ms timestamps).

-- One row, written the first time an admin changes the branding. No row
-- means the defaults: no logo, the instance name in the header, no welcome
-- line and no support contact.
--
-- `settings_json` holds the toggles and the operator's plain text
-- (`crate::branding::BrandingSettings`). The logo is the PNG the server
-- re-encoded from the admin's upload, base64 in `logo_png`, so backups of
-- the database include it. `logo_id` is a hash of those bytes and part of
-- the logo's URL, so the URL changes when the logo does. The four logo
-- columns are all NULL when there is no logo.
CREATE TABLE branding (
    singleton     BIGINT NOT NULL DEFAULT 1 UNIQUE CHECK (singleton = 1),
    settings_json TEXT NOT NULL DEFAULT '{}',
    logo_id       TEXT,
    logo_png      TEXT,
    logo_width    BIGINT,
    logo_height   BIGINT,
    updated_at    BIGINT NOT NULL
);
