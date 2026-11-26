-- Faro instance schema v14: reach outs, and signed, encrypted notes on
-- proposals and join requests (docs/GROUPS.md §8.3, §10.2, §15;
-- PROTOCOL.md §9).
--
-- Same portability rules as 0001. Every column that references `users`
-- must be in `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6).

-- A message one person wrote for specific people: a reach out's text, or a
-- note on a proposal or a join request. The instance can't read it or
-- forge it: `message_json` is the author's `Signed<GroupMessage>`, verbatim,
-- and `body_json` its encrypted body (an `EncryptedItem`, NULL for a signed,
-- content-free reach out). The receiving browser checks both. `id` is the
-- signed `item_id`, chosen by the author's browser.
--
-- Messages are small (500 characters and at most 33 sealed keys), so they
-- stay in the database rather than the blob store. A message lives as long
-- as what uses it (`alliance_proposals.note_blob_ref`,
-- `group_join_requests.note_blob_ref`, `reach_outs.blob_ref`): the
-- retention pass deletes messages nothing uses any more. `group_id` is the
-- signed group, a label only (no foreign key: the group may be deleted
-- before the proposal or reach out is).
CREATE TABLE group_messages (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('reach_out', 'proposal_note', 'join_request_note')),
    author_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id     TEXT,
    message_json TEXT NOT NULL,
    body_json    TEXT,
    created_at   BIGINT NOT NULL
);
CREATE INDEX group_messages_author ON group_messages(author_id, created_at);

-- Who a message may be served to besides its author: the signed
-- recipients, checked against the signature on upload.
CREATE TABLE group_message_recipients (
    message_id   TEXT NOT NULL REFERENCES group_messages(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id       TEXT NOT NULL,
    PRIMARY KEY (message_id, recipient_id)
);
CREATE INDEX group_message_recipients_recipient ON group_message_recipients(recipient_id);

-- "I'm struggling" (§8.3). `audience` is how the sender chose the people
-- (their allies, a group's facilitators, or named people). `sig` is the
-- signature of the message in `blob_ref`, NULL when the sender has no
-- member signing key or didn't sign (a content-free reach out the app
-- marks "Sent through the server. Can't be verified."). Kept for the
-- instance's alert retention.
CREATE TABLE reach_outs (
    id         TEXT PRIMARY KEY,
    sender_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   TEXT REFERENCES accountability_groups(id) ON DELETE SET NULL,
    audience   TEXT NOT NULL CHECK (audience IN ('allies', 'facilitators', 'people')),
    created_at BIGINT NOT NULL,
    sig        TEXT,
    blob_ref   TEXT REFERENCES group_messages(id) ON DELETE SET NULL
);
CREATE INDEX reach_outs_sender ON reach_outs(sender_id, created_at);
CREATE INDEX reach_outs_created ON reach_outs(created_at);

-- Who a reach out went to, and their answer ("I'll call", "I'm here").
CREATE TABLE reach_out_recipients (
    reach_out_id TEXT NOT NULL REFERENCES reach_outs(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    answered_at  BIGINT,
    answer       TEXT CHECK (answer IN ('call', 'here')),
    PRIMARY KEY (reach_out_id, recipient_id)
);
CREATE INDEX reach_out_recipients_recipient ON reach_out_recipients(recipient_id);

-- "Let Sam's reach outs through quiet hours": `user_id` is told about
-- `sender_id`'s reach outs at once, even inside their quiet hours.
CREATE TABLE quiet_hours_bypass (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, sender_id)
);
CREATE INDEX quiet_hours_bypass_sender ON quiet_hours_bypass(sender_id);

-- How `user_id` wants to hear about `sender_id`'s reach outs, when not the
-- default (`immediate`): moved to the digest, or off. Reach outs are not
-- tamper-class, so `off` is honoured (they still appear in Faro).
CREATE TABLE reach_out_prefs (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode      TEXT NOT NULL CHECK (mode IN ('immediate', 'digest', 'off')),
    PRIMARY KEY (user_id, sender_id)
);
CREATE INDEX reach_out_prefs_sender ON reach_out_prefs(sender_id);
