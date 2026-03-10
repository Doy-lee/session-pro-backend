-- Session Pro Backend Database Schema

CREATE TABLE IF NOT EXISTS payments (
    id                                INTEGER PRIMARY KEY NOT NULL,
    master_pkey                       BLOB,
    status                            INTEGER NOT NULL,
    plan                              INTEGER NOT NULL,
    payment_provider                  INTEGER NOT NULL,
    auto_renewing                     INTEGER NOT NULL,
    unredeemed_unix_ts_ms             INTEGER NOT NULL,

    -- Timestamp of when the payment was redeemed rounded to the end of the day.
    redeemed_unix_ts_ms               INTEGER,
    expiry_unix_ts_ms                 INTEGER NOT NULL,

    -- Duration of the user's grace period which covers the brief period given to a user in between
    -- the execution of the billing for the renewal of Session Pro for the subsequent billing cycle.
    -- A user is entitled to `expiry_unix_ts_ms + grace_period_duration_ms` if and only if
    -- `auto_renewing` is true. Clients can request a proof for users in a grace period that will
    -- expire at the end of this configured grace period.
    --
    -- The value of the grace period is preserved even if `auto_renewing` is turned off to ensure
    -- that if the user restores renewal of the subscription, the correct grace period is restored
    -- and entitled to the user.
    grace_period_duration_ms          INTEGER,

    -- Time at which the payment is no longer eligible for a refund through its payment platform. If
    -- the payment is always eligible for refund through its payment platform this value will be set
    -- to 0
    platform_refund_expiry_unix_ts_ms INTEGER NOT NULL,
    revoked_unix_ts_ms                INTEGER,

    apple_original_tx_id              TEXT,
    apple_tx_id                       TEXT,
    apple_web_line_order_tx_id        TEXT,

    -- Purchase token associated with a user that is shared across all payments for a given
    -- subscription. Google recommends this be the primary key for the user's subscription
    -- entitlement. So we cannot dedupe payments by this token because in subsequent billing cycles,
    -- the same token is returned.
    --
    -- In order to support subsequent payments we also take the google order ID milliseconds that
    -- the event was associated with. Before adding this payment to the DB it's the caller's
    -- responsibility to have independently re-verified the token using Google APIs provided to
    -- assert the token was valid.
    google_payment_token              TEXT,
    google_order_id                   TEXT,

    rangeproof_order_id               TEXT,

    -- On some platforms the initiation of a refund can be recorded manually by the originating
    -- device by calling the backend with the payment details to mark as having initiated a refund.
    -- This is currently only utilised by iOS.
    --
    -- This field is _opt_ in, clients must call the _set refund request_ endpoint on the backend in
    -- order to set this value. This is because it's possible for a user to initiate a refund
    -- request out-of-band from the application meaning cannot observe this event occurring. As
    -- prior mentioned the only platform that takes advantage of this is iOS.
    --
    -- Our convention is if the request has not been set, this value should be set to 0. If a refund
    -- is declined on iOS we _do_ get notified of this and the backend will try to set this value
    -- back to 0
    refund_requested_unix_ts_ms       INTEGER NOT NULL,

    -- Obfuscated account ID for Google Play subscriptions. Calculated as sha256(master_pkey)
    google_obfuscated_account_id      BLOB,

    -- App account token for Apple subscriptions
    apple_app_account_token           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
    master_pkey      BLOB PRIMARY KEY NOT NULL,

    -- Current generation index allocated for the user. A new index is allocated every time
    -- a payment is added/removed for the associated master key which will change the duration of
    -- entitlement for the user. This means that the generation index which is globally unique,
    -- snapshots the duration entitlement of a user at a particular time.
    --
    -- Pro subscription proofs are signed with this generation index. This means that we can revoke
    -- all prior proofs generated for this user and consequently their entitlement to Session Pro
    -- features by publishing a revoked proof with the index that was allocated to the user.
    --
    -- For example if the user refunded their subscription and there are proofs still circulating
    -- the network with some time remaining on the subscription then clients can know to ignore
    -- proofs for this user.
    --
    -- Another example for revocations is if the user stacks subscriptions to increase the duration
    -- of their entitlement. We can revoke the old proofs identified by the previous index
    -- associated with the user, allocate a new index and sign a new proof with said index.
    --
    -- This will force clients to drop the old proof and adopt the new proof which now correctly
    -- indicates the updated and correct duration that the user is entitled to Session Pro features.
    gen_index INTEGER NOT NULL,

    -- Timestamp that the latest subscriptions for the user expires. This might be in the past for
    -- elapsed payments. This timestamp is inclusive of the grace period and is consequently updated
    -- every time the user toggles their subscription auto-renewing preferences.
    --
    -- This timestamp is used to determine the deadline for which a Session Pro proof can be
    -- generated for a user, after the time has elapsed the user is no longer eligible for a proof
    -- signed by the backend.
    expiry_unix_ts_ms           INTEGER NOT NULL,

    -- Duration that a user is entitled to for their grace period. This value is to be ignored if
    -- `auto_renewing` is false. It can be used to calculate the subscription expiry timestamp by
    -- subtracting `expiry_unix_ts_ms` from this value.
    grace_period_duration_ms    INTEGER NOT NULL,

    auto_renewing               INTEGER NOT NULL,

    -- See the comment on this field in the payments table
    refund_requested_unix_ts_ms INTEGER NOT NULL,

    -- Per platform masked account identifiers to distinguish between different Session
    -- accounts that purchase a subscription using the same platform account.

    -- Obfuscated account ID for Google Play subscriptions. Calculated as sha256(master_pkey)
    google_obfuscated_account_id BLOB NOT NULL,

    -- Apple's per account user token
    apple_app_account_token      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    gen_index         INTEGER PRIMARY KEY NOT NULL,
    expiry_unix_ts_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime (
    gen_index                                INTEGER NOT NULL, -- Next generation index to allocate to an updated user
    gen_index_salt                           BLOB NOT NULL,    -- BLAKE2B salt for hashing the gen_index in proofs
    backend_key                              BLOB NOT NULL,    -- Ed25519 skey for signing proofs
    last_expire_unix_ts_ms                   INTEGER NOT NULL, -- Last time expire payments/revocs/users was called on the table

    -- Last time the DB has successfully handled notifications up to. This is to be used to
    -- determine the start date to retrieve notifications from when starting up the DB to catch out
    -- on missed notifications (e.g. downtime due to maintenance or outages)
    apple_notification_checkpoint_unix_ts_ms INTEGER NOT NULL,
    revocation_ticket                        INTEGER NOT NULL  -- Monotonic index incremented when a revocation is added or removed
);

-- Track notifications that we have processed from Apple by their UUID. We need this for robustness.
-- One, we can miss notifications from Apple due to downtime e.g. planned maintenance in which case,
-- Apple will retry the notification with an exponential backoff:
--
-- > For version 2 notifications, it retries five times, at 1, 12, 24, 48, and 72 hours after the
-- > previous attempt.
--
-- Alternatively, the backend on startup will query for missed notifications and try to catch up on
-- its own. It will store the UUIDs of the notifications it has processed so that if the
-- notification is re-attempted, it will be a no-op if we've already processed it ourselves.
--
-- The other scenario is that the backend may experience network connectivity issue and our
-- acknowledgement of the notification may fail whilst having already processed the notification. In
-- that case, Apple will similarly retry the notification and we need to no-op in that situation as
-- well. This is all managed in this table.
CREATE TABLE IF NOT EXISTS apple_notification_uuid_history (
    uuid              TEXT NOT NULL,
    expiry_unix_ts_ms INTEGER NOT NULL
);

-- Track notifications that we have successfully and failed to process from Google by its message
-- ID. Similar to Apple, if we have network failure we may receive repeated notifications that we
-- should ignore. Google tries to maintain a consistent delivery order but there is no guarantee.
-- Unlike Apple, there's no API to query missed notifications in which case we have to store these
-- notifications we saw ourselves.
--
-- The notification payload is wiped once the notification has been handled and we hold onto the
-- notifications until it has been handled AND the expiry timestamp has elapsed.
--
-- For Google the expiry is configured on the Google Cloud Pub/Sub interface and is currently set to
-- 7 days with an exponential backoff. On startup the unhandled notifications are loaded into the
-- runtime queue and re-attemped.
--
-- Typically if a notification fails, it might be because the notifications came out of order and
-- there's an earlier one that needs to be processed before proceeding. This table persists those
-- failed notifications across restarts as well as ensuring that with exponential backoff, there's
-- time inbetween to allow late notifications to arrive, be sorted into emit order and executed in
-- order.
CREATE TABLE IF NOT EXISTS google_notification_history (
    message_id        INTEGER NOT NULL,
    handled           INTEGER NOT NULL,
    payload           TEXT,
    expiry_unix_ts_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_errors (
    payment_id       TEXT    NOT NULL,
    payment_provider INTEGER NOT NULL,
    unix_ts_ms       INTEGER NOT NULL,
    UNIQUE(payment_id, payment_provider)
);

CREATE TRIGGER IF NOT EXISTS increment_revocation_ticket_after_insert
AFTER INSERT ON revocations
BEGIN
    UPDATE runtime SET revocation_ticket = revocation_ticket + 1;
END;

CREATE TRIGGER IF NOT EXISTS increment_revocation_ticket_after_delete
AFTER DELETE ON revocations
BEGIN
    UPDATE runtime SET revocation_ticket = revocation_ticket + 1;
END;
