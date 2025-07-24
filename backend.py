import nacl.signing
import sqlite3
import hashlib
import os
import enum
import time

import base

BACKEND_SALT: bytes = os.urandom(hashlib.blake2b.SALT_SIZE)
ZERO_BYTES32        = bytes(32)
BLAKE2B_DIGEST_SIZE = 32

class SubscriptionDuration(enum.Enum):
    Days30  = 0
    Days90  = 1
    Days365 = 2

class ProSubscriptionProof:
    success:          bool                   = False
    version:          int                    = 0
    gen_index_hash:   bytes                  = b''
    rotating_pkey:    nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expiry_unix_ts_s: int                    = 0
    sig:              bytes                  = b''

    def to_dict(self) -> dict[str, str | int]:
        result = {
            "version":          self.version,
            "gen_index_hash":   self.gen_index_hash.hex(),
            "rotating_pkey":    bytes(self.rotating_pkey).hex(),
            "expiry_unix_ts_s": self.expiry_unix_ts_s,
            "sig":              self.sig.hex(),
        }
        return result

class UnredeemedPaymentRow:
    payment_token_hash:      bytes = ZERO_BYTES32
    subscription_duration_s: int   = 0

class PaymentRow:
    id:                      int        = 0
    master_pkey:             bytes      = ZERO_BYTES32
    subscription_duration_s: int        = 0
    creation_unix_ts_s:      int        = 0
    activation_unix_ts_s:    int | None = None
    payment_token_hash:      bytes      = ZERO_BYTES32

class UserRow:
    master_pkey:      bytes = ZERO_BYTES32
    gen_index:        int   = 0
    expiry_unix_ts_s: int   = 0

class RevocationRow:
    gen_index:        int   = 0
    expiry_unix_ts_s: int   = 0

class RuntimeRow:
    gen_index:      int                     = 0
    gen_index_salt: bytes                   = b''
    backend_key:    nacl.signing.SigningKey = nacl.signing.SigningKey(ZERO_BYTES32)

class UpdateAfterPaymentsModified:
    latest_expiry_unix_ts_s: int = 0
    gen_index:               int = 0

class SetupDBResult:
    path:     str                       = ''
    success:  bool                      = False
    runtime:  RuntimeRow                = RuntimeRow()
    sql_conn: sqlite3.Connection | None = None

class OpenDBAtPath:
    sql_conn: sqlite3.Connection
    runtime:  RuntimeRow
    def __init__(self, db_path: str, db_path_is_uri: bool = False):
        self.sql_conn = sqlite3.connect(db_path, uri=db_path_is_uri)
        self.runtime  = get_runtime(self.sql_conn)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.sql_conn.close()
        return False

def make_payment_hash(version:            int,
                      master_pkey:        nacl.signing.VerifyKey,
                      rotating_pkey:      nacl.signing.VerifyKey,
                      payment_token_hash: bytes) -> bytes:
    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    hasher.update(bytes(version))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))
    hasher.update(payment_token_hash)
    result: bytes = hasher.digest()
    return result

def sql_table_unredeemed_payments_fields(schema: bool) -> str:
    result: str = (
        "payment_token_hash      {},\n".format("BLOB PRIMARY KEY" if schema else "") +
        "subscription_duration_s {}\n".format("INTEGER NOT NULL"  if schema else "")
    )
    return result

def sql_table_payments_fields(schema: bool) -> str:
    result: str = (
        "id                      {},\n".format("INTEGER PRIMARY KEY" if schema else "") +
        "master_pkey             {},\n".format("BLOB    NOT NULL"    if schema else "") +
        "subscription_duration_s {},\n".format("INTEGER NOT NULL"    if schema else "") +
        "creation_unix_ts_s      {},\n".format("INTEGER NOT NULL"    if schema else "") +
        "activation_unix_ts_s    {},\n".format("INTEGER"             if schema else "") +
        "payment_token_hash      {}".format(  "BLOB    NOT NULL"    if schema else "")
    )
    return result

def sql_table_users_fields(schema: bool) -> str:
    result: str = (
        "master_pkey      {},\n".format("BLOB PRIMARY KEY" if schema else "") +
        "gen_index        {},\n".format("INTEGER NOT NULL" if schema else "") +
        "expiry_unix_ts_s {}\n".format("INTEGER NOT NULL"  if schema else "")
    )
    return result

def sql_table_revocations_fields(schema: bool) -> str:
    result: str = (
        "gen_index        {},\n".format("INTEGER PRIMARY KEY" if schema else "") +
        "expiry_unix_ts_s {}\n".format("INTEGER NOT NULL"     if schema else "")
    )
    return result

def sql_table_runtime_fields(schema: bool) -> str:
    result: str = (
        "gen_index {},\n".format("INTEGER NOT NULL" if schema else "") +
        "gen_index_salt {},\n".format("BLOB NOT NULL " if schema else "") +
        "backend_key {}\n".format("BLOB NOT NULL " if schema else "")
    )
    return result

def get_unredeemed_payments_list(sql_conn: sqlite3.Connection) -> list[UnredeemedPaymentRow]:
    result: list[UnredeemedPaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM unredeemed_payments')
        for row in tx.cursor.fetchall():
            item                         = UnredeemedPaymentRow()
            item.payment_token_hash      = row[0]
            item.subscription_duration_s = row[1]
            result.append(item)
    return result;

def get_payments_list(sql_conn: sqlite3.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('SELECT * FROM payments')
        for row in tx.cursor.fetchall():
            item                         = PaymentRow()
            item.id                      = row[0]
            item.master_pkey             = row[1]
            item.subscription_duration_s = row[2]
            item.creation_unix_ts_s      = row[3]
            item.activation_unix_ts_s    = row[4]
            item.payment_token_hash      = row[5]
            result.append(item)
    return result;

def get_users_list(sql_conn: sqlite3.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('SELECT * FROM users')
        for row in tx.cursor.fetchall():
            item                  = UserRow()
            item.master_pkey      = row[0]
            item.gen_index        = row[1]
            item.expiry_unix_ts_s = row[2]
            result.append(item)
    return result;

def get_user(sql_conn: sqlite3.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _                       = tx.cursor.execute('SELECT * FROM users WHERE master_pkey = ?', (bytes(master_pkey),))
        row                     = tx.cursor.fetchone()
        result.master_pkey      = row[0]
        result.gen_index        = row[1]
        result.expiry_unix_ts_s = row[2]
    return result;

def get_revocations_list(sql_conn: sqlite3.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('SELECT * FROM revocations')
        for row in tx.cursor.fetchall():
            item                  = RevocationRow()
            item.gen_index        = row[0]
            item.expiry_unix_ts_s = row[1]
            result.append(item)
    return result;

def get_runtime(sql_conn: sqlite3.Connection) -> RuntimeRow:
    result: RuntimeRow = RuntimeRow()
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _                     = tx.cursor.execute('SELECT * FROM runtime')
        row                   = tx.cursor.fetchone()
        result.gen_index      = row[0]
        result.gen_index_salt = row[1]

        backend_key: bytes    = row[2]
        assert len(backend_key) == BLAKE2B_DIGEST_SIZE
        result.backend_key    = nacl.signing.SigningKey(backend_key)
    return result;

def db_info_string(sql_conn: sqlite3.Connection, db_path: str, err: base.ErrorSink) -> str:
    unredeemed_payments = 0
    payments            = 0
    users               = 0
    revocations         = 0
    db_size             = 0
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        try:
            _                   = tx.cursor.execute('SELECT COUNT(*) FROM unredeemed_payments')
            unredeemed_payments = tx.cursor.fetchone()[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM payments')
            payments            = tx.cursor.fetchone()[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM users')
            users               = tx.cursor.fetchone()[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM revocations')
            revocations         = tx.cursor.fetchone()[0];
        except Exception as e:
            err.msg_list.append(f"Failed to retrieve DB metadata: {e}")

    result = ''
    if len(err.msg_list) == 0:
        if os.path.exists(db_path):
            db_size = os.stat(db_path).st_size
        runtime: RuntimeRow = get_runtime(sql_conn)
        result = (
            '  DB:                               {} ({})\n'.format(db_path, base.format_bytes(db_size)) +
            '  Users/Revocs/Payments/Unredeemed: {}/{}/{}/{}\n'.format(users, revocations, payments, unredeemed_payments) +
            '  Gen Index:                        {}\n'.format(runtime.gen_index) +
            '  Backend Key:                      {}'.format(bytes(runtime.backend_key.verify_key).hex())
        )

    return result

def setup_db(path: str, uri: bool, err: base.ErrorSink) -> SetupDBResult:
    result: SetupDBResult = SetupDBResult()
    result.path           = path
    try:
        result.sql_conn = sqlite3.connect(path, uri=uri)
    except Exception as e:
        err.msg_list.append(f'Failed to open/connect to DB at {path}: {e}')
        return result

    with base.SQLTransaction(result.sql_conn) as tx:
        sql_stmt: str = f'''
            CREATE TABLE IF NOT EXISTS unredeemed_payments (
                {sql_table_unredeemed_payments_fields(schema=True)}
            );

            CREATE TABLE IF NOT EXISTS payments (
                {sql_table_payments_fields(schema=True)}
            );

            CREATE TABLE IF NOT EXISTS users (
                {sql_table_users_fields(schema=True)}
            );

            CREATE TABLE IF NOT EXISTS revocations (
                {sql_table_revocations_fields(schema=True)}
            );

            CREATE TABLE IF NOT EXISTS runtime (
                {sql_table_runtime_fields(schema=True)}
            );
        '''

        assert tx.cursor is not None

        try:
            _ = tx.cursor.executescript(sql_stmt)
            _ = tx.cursor.execute('''
                INSERT INTO runtime
                SELECT 0, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM runtime)
            ''', (os.urandom(hashlib.blake2b.SALT_SIZE),
                  bytes(nacl.signing.SigningKey.generate())))
            result.success = True
        except Exception as e:
            err.msg_list.append(f"Failed to bootstrap DB tables: {e}")

    if result.success:
        result.runtime = get_runtime(result.sql_conn)
    else:
        result.sql_conn.close()

    return result

def verify_payment_token_hash(hash: bytes, err: base.ErrorSink):
    if len(hash) != BLAKE2B_DIGEST_SIZE:
        err.msg_list.append(f'Payment token hash must be {BLAKE2B_DIGEST_SIZE} bytes, received {len(hash)}')

def add_unredeemed_payment(sql_conn:                sqlite3.Connection,
                           payment_token_hash:      bytes,
                           subscription_duration_s: int,
                           err:                     base.ErrorSink):
    verify_payment_token_hash(payment_token_hash, err)
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('''
            INSERT INTO unredeemed_payments (payment_token_hash, subscription_duration_s)
            VALUES (?, ?)
        ''', (payment_token_hash, subscription_duration_s));

def update_db_after_payments_changed(tx:                   base.SQLTransaction,
                                     master_pkey:          nacl.signing.VerifyKey,
                                     activation_unix_ts_s: int) -> UpdateAfterPaymentsModified:

    result:            UpdateAfterPaymentsModified = UpdateAfterPaymentsModified()
    master_pkey_bytes: bytes = bytes(master_pkey)
    assert tx.cursor is not None

    # Check if the user has any activated subscriptions yet in the payments table
    _ = tx.cursor.execute('''
        SELECT   activation_unix_ts_s
        FROM     payments
        WHERE    activation_unix_ts_s IS NOT NULL AND master_pkey = ?
        ORDER BY activation_unix_ts_s ASC
        LIMIT 1
    ''', (master_pkey_bytes,))

    earliest_activation_unix_ts_s_record = tx.cursor.fetchone()
    earliest_activation_unix_ts_s: int   = 0
    if earliest_activation_unix_ts_s_record:
        # User already has exactly, 1 activated payment row, go and look it up
        earliest_activation_unix_ts_s = earliest_activation_unix_ts_s_record[0]
    else:
        # Get the row with the earliest creation time, then activate it by
        # setting the current unix time (rounded to the next day to mask the
        # registration time to on-the-day boundaries) as the activation time.
        _ = tx.cursor.execute('''
            WITH lookup AS (
                SELECT   id
                FROM     payments
                WHERE    master_pkey = ?
                ORDER BY creation_unix_ts_s ASC
                LIMIT    1
            )
            UPDATE payments
            SET    activation_unix_ts_s = ?
            WHERE  id                   = (SELECT id FROM lookup)
        ''', (master_pkey_bytes,
              activation_unix_ts_s))
        earliest_activation_unix_ts_s = activation_unix_ts_s

    # Calculate the latest expiry date by summing up the total duration of
    # subscriptions this user has.
    _ = tx.cursor.execute('''
        SELECT SUM(subscription_duration_s)
        FROM   payments
        WHERE  master_pkey = ?
    ''', (master_pkey_bytes,))

    sum_of_subscription_duration_s: int                          = tx.cursor.fetchone()[0]
    result.latest_expiry_unix_ts_s: int                          = earliest_activation_unix_ts_s + sum_of_subscription_duration_s + base.SECONDS_IN_DAY
    assert result.latest_expiry_unix_ts_s % base.SECONDS_IN_DAY == 0, "Subscription duration must be on a day boundaring, 30 days, 365 days ...e.t.c"

    # Grab the previous user if it existed, if it did, then add a revocation
    # entry thereby disabling all the previous proofs generated previously. This
    # means that when a new payment is registered, the old proofs are
    # invalidated and the client is forced to retrieve a new proof which now has
    # the most up-to-date expiry time associated with it (and so they can
    # retrieve it and update their UI and give the user instant confirmation
    # that their payment has been processed).
    _ = tx.cursor.execute('''
        WITH prev_user AS (
            SELECT gen_index, expiry_unix_ts_s
            FROM   users
            WHERE  master_pkey = ?
        )
        INSERT INTO revocations (gen_index, expiry_unix_ts_s)
        SELECT      gen_index, expiry_unix_ts_s
        FROM        prev_user
    ''', (master_pkey_bytes,))

    # Increment the global gen index and return the next one to allocate to the user
    _ = tx.cursor.execute('''
        UPDATE    runtime
        SET       gen_index = gen_index + 1
        RETURNING gen_index - 1
    ''')
    result.gen_index = tx.cursor.fetchone()[0]

    # Update the user metadata, grab the next generation index, increment it and then
    # assign/update the user table
    _ = tx.cursor.execute('''
        INSERT INTO users (master_pkey, gen_index, expiry_unix_ts_s)
        VALUES            (?, ?, ?)
        ON CONFLICT (master_pkey) DO UPDATE SET
            gen_index        = excluded.gen_index,
            expiry_unix_ts_s = excluded.expiry_unix_ts_s
    ''', (master_pkey_bytes,
          result.gen_index,
          result.latest_expiry_unix_ts_s))

    return result

def make_pro_subscription_proof_hash(version:          int,
                                     gen_index_hash:   bytes,
                                     rotating_pkey:    nacl.signing.VerifyKey,
                                     expiry_unix_ts_s: int) -> bytes:
    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    hasher.update(bytes(version))
    hasher.update(gen_index_hash)
    hasher.update(bytes(rotating_pkey))
    hasher.update(bytes(expiry_unix_ts_s))
    result: bytes = hasher.digest()
    return result

def make_get_pro_subscription_proof_hash(version:       int,
                                         master_pkey:   nacl.signing.VerifyKey,
                                         rotating_pkey: nacl.signing.VerifyKey,
                                         unix_ts_s:     int) -> bytes:
    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    hasher.update(bytes(version))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))
    hasher.update(bytes(unix_ts_s))
    result: bytes = hasher.digest()
    return result

def build_proof(gen_index:        int,
                rotating_pkey:    nacl.signing.VerifyKey,
                expiry_unix_ts_s: int,
                signing_key:      nacl.signing.SigningKey) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.version               = 0
    result.success               = True
    result.gen_index_hash        = hashlib.blake2b(bytes(gen_index), digest_size=BLAKE2B_DIGEST_SIZE, salt=BACKEND_SALT).digest()
    result.rotating_pkey         = rotating_pkey
    result.expiry_unix_ts_s      = expiry_unix_ts_s

    hash_to_sign: bytes = make_pro_subscription_proof_hash(version=result.version,
                                                           gen_index_hash=result.gen_index_hash,
                                                           rotating_pkey=result.rotating_pkey,
                                                           expiry_unix_ts_s=result.expiry_unix_ts_s)
    result.sig = signing_key.sign(hash_to_sign).signature
    return result

def internal_verify_add_payment_and_get_proof_common_arguments(signing_key:   nacl.signing.SigningKey,
                                                               master_pkey:   nacl.signing.VerifyKey,
                                                               rotating_pkey: nacl.signing.VerifyKey,
                                                               hash_to_sign:  bytes,
                                                               master_sig:    bytes,
                                                               rotating_sig:  bytes,
                                                               err:           base.ErrorSink) -> bool:
    # Verify the signatures first (authenticate that the message was not
    # tampered with first) if these fail, early exit as the contents of the rest
    # of the payload is indeterminate.
    try:
        _ = master_pkey.verify(smessage=hash_to_sign, signature=master_sig)
    except Exception as e:
        err.msg_list.append(f'Failed to verify signature from master key {bytes(master_pkey).hex()}: {e}');
        return False

    try:
        _ = rotating_pkey.verify(smessage=hash_to_sign, signature=rotating_sig)
    except Exception as e:
        err.msg_list.append(f'Failed to verify signature from rotating key {bytes(rotating_pkey).hex()}: {e}');
        return False

    # The hash to sign is only passed by internal code, the user never passes
    # the hash so this assert guards for a development error. Similar with the
    # signing key check.
    assert len(hash_to_sign) == BLAKE2B_DIGEST_SIZE and hash_to_sign != ZERO_BYTES32
    assert bytes(signing_key) != ZERO_BYTES32 and bytes(signing_key.verify_key) != ZERO_BYTES32

    # Sanity check the signing key
    if signing_key.verify_key == master_pkey or signing_key.verify_key == rotating_pkey:
        err.msg_list.append(f'Internal key error during adding payment: please notify the devs')

    # Sanity check the user key's and their signatures
    if master_pkey == rotating_pkey:
        err.msg_list.append(f'Master and rotating key cannot be the same was: {bytes(master_pkey).hex()}')

    if bytes(master_pkey) == ZERO_BYTES32:
        err.msg_list.append(f'Master key cannot be the zero key')

    if bytes(rotating_pkey) == ZERO_BYTES32:
        err.msg_list.append(f'Rotating key cannot be the zero key')

    if master_sig == rotating_sig:
        err.msg_list.append(f'Master and rotating signature cannot be the same')

    result = len(err.msg_list) == 0
    return result

def add_payment(sql_conn:           sqlite3.Connection,
                version:            int,
                signing_key:        nacl.signing.SigningKey,
                creation_unix_ts_s: int,
                master_pkey:        nacl.signing.VerifyKey,
                rotating_pkey:      nacl.signing.VerifyKey,
                payment_token_hash: bytes,
                master_sig:         bytes,
                rotating_sig:       bytes,
                err:                base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()

    # Verify some of the request parameters
    hash_to_sign: bytes = make_payment_hash(version=version,
                                            master_pkey=master_pkey,
                                            rotating_pkey=rotating_pkey,
                                            payment_token_hash=payment_token_hash)
    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key=signing_key,
                                                                   master_pkey=master_pkey,
                                                                   rotating_pkey=rotating_pkey,
                                                                   hash_to_sign=hash_to_sign,
                                                                   master_sig=master_sig,
                                                                   rotating_sig=rotating_sig,
                                                                   err=err)
    if len(err.msg_list) > 0:
        return result

    # Then verify version, token and time
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')

    verify_payment_token_hash(payment_token_hash, err)
    if len(err.msg_list) > 0:
        return result

    # Note being able to pass in the creation unix timestamp is mainly for
    # testing purposes to allow time-travel. User space shold never be
    # specifying this argument, so clients should not be specifying this time,
    # ever, it should be generated by the server hence the assert.
    assert creation_unix_ts_s % base.SECONDS_IN_DAY == 0, \
            "The passed in creation (and or activation) timestamp must lie on a day boundary: {}".format(creation_unix_ts_s)

    # All verified, then try and add the payment to the DB
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None

        # Redeem the payment token: first, delete the entry from the unredeemed table
        _ = tx.cursor.execute('''
            DELETE FROM unredeemed_payments
            WHERE       payment_token_hash = ?
            RETURNING   subscription_duration_s
        ''', (payment_token_hash,))

        delete_operation_row = tx.cursor.fetchone()
        if delete_operation_row:
            assert tx.cursor.rowcount <= 1
            master_pkey_bytes:       bytes = bytes(master_pkey)
            subscription_duration_s: int   = delete_operation_row[0]

            # Redeem the payment token: second, register the payment
            _ = tx.cursor.execute('''
                INSERT INTO payments (master_pkey, subscription_duration_s, creation_unix_ts_s, payment_token_hash)
                VALUES(?, ?, ?, ?)
            ''', (master_pkey_bytes,
                  subscription_duration_s,
                  creation_unix_ts_s,
                  payment_token_hash))

            update: UpdateAfterPaymentsModified = update_db_after_payments_changed(tx=tx,
                                                                                   master_pkey=master_pkey,
                                                                                   activation_unix_ts_s=creation_unix_ts_s)
            result = build_proof(gen_index=update.gen_index,
                                 rotating_pkey=rotating_pkey,
                                 expiry_unix_ts_s=update.latest_expiry_unix_ts_s,
                                 signing_key=signing_key)
        else:
            err.msg_list.append(f"Server has not received the payment for this token ({payment_token_hash.hex()}) and cannot be used")

    return result

def add_revocation(sql_conn: sqlite3.Connection, payment_token_hash: bytes, activation_unix_ts_s: int):
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('''
            DELETE FROM payments
            WHERE       payment_token_hash = ?
            RETURNING   master_pkey
        ''', (payment_token_hash,))

        if tx.cursor.rowcount > 0:
            assert tx.cursor.rowcount == 1
            master_pkey_bytes: bytes = tx.cursor.fetchone()[0]
            _ = update_db_after_payments_changed(tx=tx,
                                                 master_pkey = nacl.signing.VerifyKey(master_pkey_bytes),
                                                 activation_unix_ts_s=activation_unix_ts_s)

def get_pro_subscription_proof(sql_conn:      sqlite3.Connection,
                               version:       int,
                               signing_key:   nacl.signing.SigningKey,
                               master_pkey:   nacl.signing.VerifyKey,
                               rotating_pkey: nacl.signing.VerifyKey,
                               unix_ts_s:     int,
                               master_sig:    bytes,
                               rotating_sig:  bytes,
                               err:           base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()

    # Verify some of the request parameters
    hash_to_sign: bytes = make_get_pro_subscription_proof_hash(version=version,
                                                               master_pkey=master_pkey,
                                                               rotating_pkey=rotating_pkey,
                                                               unix_ts_s=unix_ts_s)

    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key=signing_key,
                                                                   master_pkey=master_pkey,
                                                                   rotating_pkey=rotating_pkey,
                                                                   hash_to_sign=hash_to_sign,
                                                                   master_sig=master_sig,
                                                                   rotating_sig=rotating_sig,
                                                                   err=err)
    if len(err.msg_list) > 0:
        return result

    # Then verify version and time
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')

    # Validate the timestamp is within 5 minutes of the current time (mitigate replay attacks)
    UNIX_TS_S_THRESHOLD: int = 60 * 5;
    now:                 int = int(time.time())
    max_unix_ts_s:       int = now + UNIX_TS_S_THRESHOLD
    min_unix_ts_s:       int = now - UNIX_TS_S_THRESHOLD

    if unix_ts_s < min_unix_ts_s:
        err.msg_list.append(f'Nonce timestamp is too far in the past: {unix_ts_s} (min {min_unix_ts_s})')

    if unix_ts_s > max_unix_ts_s:
        err.msg_list.append(f'Nonce timestamp is too far in the future: {unix_ts_s} (max {max_unix_ts_s})')

    if len(err.msg_list) > 0:
        return result

    # All verified, now generate proof
    user: UserRow = get_user(sql_conn, master_pkey)
    if user.master_pkey == bytes(master_pkey):
        result = build_proof(gen_index=user.gen_index,
                             rotating_pkey=rotating_pkey,
                             expiry_unix_ts_s=user.expiry_unix_ts_s,
                             signing_key=signing_key);
        assert result.success
    else:
        err.msg_list.append(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it, {bytes(user.master_pkey).hex()} {user.gen_index} {user.expiry_unix_ts_s}')

    return result
