-- See equivalent .sql file for documentation

CREATE TABLE IF NOT EXISTS payments (
    id                                SERIAL  PRIMARY KEY,
    master_pkey                       BYTEA   CHECK   (octet_length(master_pkey) = 32),
    status                            INTEGER NOT     NULL,
    plan                              INTEGER NOT     NULL,
    payment_provider                  INTEGER NOT     NULL,
    auto_renewing                     BOOLEAN NOT     NULL DEFAULT FALSE,
    unredeemed_unix_ts_ms             BIGINT  NOT     NULL,

    redeemed_unix_ts_ms               BIGINT,
    expiry_unix_ts_ms                 BIGINT  NOT     NULL,
    grace_period_duration_ms          BIGINT,
    platform_refund_expiry_unix_ts_ms BIGINT  NOT     NULL,
    revoked_unix_ts_ms                BIGINT,

    apple_original_tx_id              TEXT,
    apple_tx_id                       TEXT,
    apple_web_line_order_tx_id        TEXT,
    google_payment_token              TEXT,
    google_order_id                   TEXT,
    rangeproof_order_id               TEXT,

    refund_requested_unix_ts_ms       BIGINT  NOT     NULL DEFAULT 0,
    google_obfuscated_account_id      BYTEA           NULL CHECK (octet_length(google_obfuscated_account_id) = 32),
    apple_app_account_token           TEXT    NOT     NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
    master_pkey                  BYTEA   PRIMARY KEY  CHECK (octet_length(master_pkey) = 32),
    gen_index                    INTEGER NOT     NULL,
    expiry_unix_ts_ms            BIGINT  NOT     NULL,
    grace_period_duration_ms     BIGINT  NOT     NULL,
    auto_renewing                BOOLEAN NOT     NULL DEFAULT FALSE,
    refund_requested_unix_ts_ms  BIGINT  NOT     NULL DEFAULT 0,
    google_obfuscated_account_id BYTEA           NULL CHECK (octet_length(google_obfuscated_account_id) = 32),
    apple_app_account_token      TEXT    NOT     NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS revocations (
    gen_index            INTEGER PRIMARY KEY NOT NULL,
    creation_unix_ts_ms  BIGINT NOT NULL,  -- When the revocation was created (used to calculate effective time)
    expiry_unix_ts_ms    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime (
    gen_index                                INTEGER NOT NULL DEFAULT 0,
    gen_index_salt                           BYTEA   NOT NULL CHECK   (octet_length(gen_index_salt) = 16),
    backend_key                              BYTEA   NOT NULL CHECK   (octet_length(backend_key)    = 32),
    last_expire_unix_ts_ms                   BIGINT  NOT NULL DEFAULT 0,
    apple_notification_checkpoint_unix_ts_ms BIGINT  NOT NULL DEFAULT 0,
    revocation_ticket                        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS apple_notification_uuid_history (
    uuid              TEXT NOT NULL,
    expiry_unix_ts_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS google_notification_history (
    message_id        BIGINT NOT NULL,
    handled           BOOLEAN NOT NULL DEFAULT FALSE,
    payload           TEXT,
    expiry_unix_ts_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_errors (
    payment_id         TEXT NOT NULL,
    payment_provider   INTEGER NOT NULL,
    unix_ts_ms         BIGINT NOT NULL,
    UNIQUE(payment_id, payment_provider)
);

-- Trigger function for revocation_ticket
CREATE OR REPLACE FUNCTION increment_revocation_ticket()
RETURNS TRIGGER AS '
BEGIN
    UPDATE runtime SET revocation_ticket = revocation_ticket + 1;
    RETURN NEW;
END;
' LANGUAGE plpgsql;

-- Triggers for revocation_ticket
DROP TRIGGER IF EXISTS increment_revocation_ticket_after_insert ON revocations;
CREATE TRIGGER increment_revocation_ticket_after_insert
    AFTER INSERT ON revocations
    FOR EACH ROW
    EXECUTE FUNCTION increment_revocation_ticket();

DROP TRIGGER IF EXISTS increment_revocation_ticket_after_delete ON revocations;
CREATE TRIGGER increment_revocation_ticket_after_delete
    AFTER DELETE ON revocations
    FOR EACH ROW
    EXECUTE FUNCTION increment_revocation_ticket();

-- Schema version tracking (used instead of SQLite PRAGMA user_version)
CREATE TABLE IF NOT EXISTS schema_version (
    id SERIAL PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0
);

-- Initialize version if not exists (only one row allowed due to PK)
INSERT INTO schema_version (version) VALUES (0) ON CONFLICT DO NOTHING;
