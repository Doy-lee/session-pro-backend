import traceback
import nacl.signing
import sqlite3
import hashlib
import os
import typing
import collections.abc
import datetime
import enum
import dataclasses

import base

ZERO_BYTES32                 = bytes(32)
BLAKE2B_DIGEST_SIZE          = 32
ALL_PAYMENTS_PAGINATION_SIZE = 1000

class PaymentStatus(enum.Enum):
    Nil        = 0
    Unredeemed = 1
    Redeemed   = 2
    Activated  = 3
    Expired    = 4
    Refunded   = 5

@dataclasses.dataclass
class ExpireResult:
    already_done_by_someone_else: bool = False
    success:                      bool = False
    payments:                     int  = 0
    revocations:                  int  = 0
    users:                        int  = 0

@dataclasses.dataclass
class ProSubscriptionProof:
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

@dataclasses.dataclass
class SQLField:
    name: str = ''
    type: str = ''

SQL_TABLE_PAYMENTS_FIELD: list[SQLField] = [
  SQLField('master_pkey',                'BLOB NOT NULL'),     # Session Pro master public key associated with the payment
  SQLField('status',                     'INTEGER NOT NULL'),  # Enum cooresponding to `PaymentStatus`
  SQLField('subscription_duration_s',    'INTEGER NOT NULL'),
  SQLField('payment_provider',           'INTEGER NOT NULL'),

  # Timestamp of when the payment was redeemed rounded to the end of the day.
  SQLField('redeemed_unix_ts_s',         'INTEGER'),

  # Timestamp of when a payment is activated. The payment transitions from
  # activated to expired when the subscription duration has elapsed relative to
  # activation time. There is only one activated record per master key at a
  # time.
  #
  # Activating payments one at a time allows correct calculation of the total
  # duration a user is entitled to Pro features. For example if a payment is refunded
  # that may abruptly end a user's entitlement mid-way through their subscription.
  # By activating the next record from the current timestamp and summing the
  # remaining subscription durations forward, this correctly accounts for that user's
  # remaining entitlement by knowing the starting timestamp to sum the subscription
  # durations to.
  SQLField('activated_unix_ts_s',        'INTEGER'),
  SQLField('expired_unix_ts_s',          'INTEGER'),
  SQLField('refunded_unix_ts_s',         'INTEGER'),
  SQLField('apple_original_tx_id',       'BLOB'),
  SQLField('apple_tx_id',                'BLOB'),
  SQLField('apple_web_line_order_tx_id', 'BLOB'),
  SQLField('google_payment_token',       'BLOB'),
]

SQLTablePaymentRowTuple:           typing.TypeAlias = tuple[bytes,      # master_pkey
                                                            int,        # status
                                                            int,        # subscription_duration_s
                                                            int,        # payment_provider
                                                            int,        # redeemed_unix_ts_s
                                                            int | None, # activated_unix_ts_s
                                                            int | None, # expired_unix_ts_s
                                                            int | None, # refunded_unix_ts_s
                                                            str | None, # apple_original_tx_id
                                                            str | None, # apple_tx_id
                                                            str | None, # apple_web_line_order_tx_id
                                                            str | None] # google_payment_token

SQLTableUnredeemedPaymentRowTuple: typing.TypeAlias = tuple[int,        # id
                                                            int,        # subscription_duration_s
                                                            int,        # payment_provider
                                                            str | None, # apple original_tx_id
                                                            str | None, # apple tx_id
                                                            str | None, # apple web_line_order_tx_id
                                                            str | None] # google_payment_token

@dataclasses.dataclass
class PaymentProviderTransaction:
    provider:                   base.PaymentProvider = base.PaymentProvider.Nil
    apple_original_tx_id:       str = ''
    apple_tx_id:                str = ''
    apple_web_line_order_tx_id: str = ''
    google_payment_token:       str = ''

@dataclasses.dataclass
class AddProPaymentUserTransaction:
    provider:             base.PaymentProvider = base.PaymentProvider.Nil
    apple_tx_id:          str                  = ''
    google_payment_token: str                  = ''

@dataclasses.dataclass
class AppleTransaction:
    original_tx_id:       str = ''
    tx_id:                str = ''
    web_line_order_tx_id: str = ''

@dataclasses.dataclass
class UnredeemedPaymentRow:
    id:                         int                  = 0
    subscription_duration_s:    int                  = 0
    payment_provider:           base.PaymentProvider = base.PaymentProvider.Nil
    apple:                      AppleTransaction     = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token:       str                  = ''

@dataclasses.dataclass
class PaymentRow:
    id:                      int                  = 0
    master_pkey:             bytes                = ZERO_BYTES32
    status:                  PaymentStatus        = PaymentStatus.Nil
    subscription_duration_s: int                  = 0
    payment_provider:        base.PaymentProvider = base.PaymentProvider.Nil
    redeemed_unix_ts_s:      int | None           = None
    activated_unix_ts_s:     int | None           = None
    expired_unix_ts_s:       int | None           = None
    refunded_unix_ts_s:      int | None           = None
    apple:                   AppleTransaction     = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token:    str                  = ''

@dataclasses.dataclass
class UserRow:
    master_pkey:      bytes = ZERO_BYTES32
    gen_index:        int   = 0
    expiry_unix_ts_s: int   = 0

@dataclasses.dataclass
class RevocationRow:
    gen_index:        int   = 0
    expiry_unix_ts_s: int   = 0

@dataclasses.dataclass
class RevocationItem:
    '''A revocation object that has only the fields necessary for clients to block Session Pro
    subscription proofs.'''
    gen_index_hash:   bytes = b''
    expiry_unix_ts_s: int   = 0

@dataclasses.dataclass
class RuntimeRow:
    '''The runtime table stores some metadata used for book-keeping and operations of the DB tables

    gen_index - Generation index, an index that is allocated to a user everytime a payment is added
    or removed from that user. It's monotonically increasing and shared across all users and their
    allocated index is what gets signed when Session Pro subscription proofs are generated for
    a particular user.

    Multiple proofs can be generated for a given index until a new payment is added or revoked for
    that user. A generation index can hence be revoked, thereby revoking all the proofs attributable
    to the associated user that were previously signed with the generation index to be revoked.

    gen_index_salt - The generation index gets signed after it has been hashed with this particular
    salt. This prevents leakage of metadata from the generation index which starts from 0 and counts
    upwards. The raw generation index leaks the timeframe relative to the lifetime of the protocol
    that a Session Pro subscription was activated.

    The salt gets bootstrapped on creation of the DB and is stored to persist across sessions.

    backend_key - Ed25519 key used to sign proofs.

    The key gets bootstrapped on creation of the DB and is stored to persist across sessions.

    revocation_ticket - A monotonically increasing index that gets incremented everytime the
    revocation table has a row added or deleted (i.e. a new ticket is allocated when the table
    changes). This ticket's purpose is to be handed out to clients when they request the revocation
    list. The client can then use this ticket to short-circuit the retrieval of the revocation list
    by comparing the current revocation list ticket with their cached ticket.

    If the tickets are the same, clients can conclude that there are no revocation entries to sync
    from the database.
    '''
    gen_index:         int                     = 0
    gen_index_salt:    bytes                   = b''
    backend_key:       nacl.signing.SigningKey = nacl.signing.SigningKey(ZERO_BYTES32)
    revocation_ticket: int                     = 0

@dataclasses.dataclass
class UpdateAfterPaymentsModified:
    latest_expiry_unix_ts_s: int   = 0
    gen_index:               int   = 0
    gen_index_salt:          bytes = b''

@dataclasses.dataclass
class SetupDBResult:
    path:     str                       = ''
    success:  bool                      = False
    runtime:  RuntimeRow                = dataclasses.field(default_factory=RuntimeRow)
    sql_conn: sqlite3.Connection | None = None

@dataclasses.dataclass
class OpenDBAtPath:
    sql_conn: sqlite3.Connection
    runtime:  RuntimeRow
    def __init__(self, db_path: str, db_path_is_uri: bool = False):
        self.sql_conn = sqlite3.connect(db_path, uri=db_path_is_uri)
        self.runtime  = get_runtime(self.sql_conn)

    def __enter__(self):
        return self

    def __exit__(self,
                 exc_type: object | None,
                 exc_value: object | None,
                 traceback: traceback.TracebackException | None):
        self.sql_conn.close()
        return False

def string_from_sql_fields(fields: list[SQLField], schema: bool) -> str:
    result = ''
    if schema:
        result = ',\n'.join([it.name for it in fields]) # Create '<field0> <type0>,\n<field1> <type1>, ...'
    else:
        result = ', '.join([it.name for it in fields])  # Create '<field0>, <field1>, ...'
    return result

def make_blake2b_hasher(salt: bytes | None = None) -> hashlib.blake2b:
    personalization = b'SeshProBackend__'
    final_salt      = salt  if salt else b''
    result          = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE, person=personalization, salt=final_salt)
    return result

def make_gen_index_hash(gen_index: int, gen_index_salt: bytes) -> bytes:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    hasher = make_blake2b_hasher(salt=gen_index_salt)
    hasher.update(gen_index.to_bytes(length=8, byteorder='little'))
    result = hasher.digest()
    return result

def make_add_pro_payment_hash(version:       int,
                              master_pkey:   nacl.signing.VerifyKey,
                              rotating_pkey: nacl.signing.VerifyKey,
                              payment_tx:    AddProPaymentUserTransaction) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))

    hasher.update(int(payment_tx.provider.value).to_bytes(length=1, byteorder='little'))
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        hasher.update(payment_tx.google_payment_token.encode('utf-8'))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        hasher.update(payment_tx.apple_tx_id.encode('utf-8'))
    else:
        assert payment_tx.provider != base.PaymentProvider.Nil, "Nil not supported"

    result: bytes = hasher.digest()
    return result

def get_unredeemed_payments_list(sql_conn: sqlite3.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM payments WHERE status = ?', (int(PaymentStatus.Unredeemed.value),))

        rows = typing.cast(collections.abc.Iterator[tuple[int, *SQLTablePaymentRowTuple]], tx.cursor)
        for row in rows:
            item                            = PaymentRow()
            item.id                         = row[0]
            item.master_pkey                = row[1]
            item.status                     = PaymentStatus(row[2])
            item.subscription_duration_s    = row[3]
            item.payment_provider           = base.PaymentProvider(row[4])
            item.redeemed_unix_ts_s         = row[5]
            item.activated_unix_ts_s        = row[6]
            item.expired_unix_ts_s          = row[7]
            item.refunded_unix_ts_s         = row[8]
            item.apple.original_tx_id       = row[9]  if row[9]  else ''
            item.apple.tx_id                = row[10] if row[10] else ''
            item.apple.web_line_order_tx_id = row[11] if row[11] else ''
            item.google_payment_token       = row[12] if row[12] else ''
            result.append(item)
    return result;

def get_payments_list(sql_conn: sqlite3.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM payments')
        rows = typing.cast(collections.abc.Iterator[tuple[int, *SQLTablePaymentRowTuple]], tx.cursor)
        for row in rows:
            item                            = PaymentRow()
            item.id                         = row[0]
            item.master_pkey                = row[1]
            item.status                     = PaymentStatus(row[2])
            item.subscription_duration_s    = row[3]
            item.payment_provider           = base.PaymentProvider(row[4])
            item.redeemed_unix_ts_s         = row[5]
            item.activated_unix_ts_s        = row[6]
            item.expired_unix_ts_s          = row[7]
            item.refunded_unix_ts_s         = row[8]
            item.apple.original_tx_id       = row[9]  if row[9]  else ''
            item.apple.tx_id                = row[10] if row[10] else ''
            item.apple.web_line_order_tx_id = row[11] if row[11] else ''
            item.google_payment_token       = row[12] if row[12] else ''
            result.append(item)
    return result;

def get_payments_count(sql_conn: sqlite3.Connection, master_pkey: nacl.signing.VerifyKey) -> int:
    result: int = 0
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('''
            SELECT COUNT(*) FROM (SELECT id FROM payments WHERE master_pkey = ?)
        ''', (bytes(master_pkey),))
        result = typing.cast(tuple[int], tx.cursor.fetchone())[0]
    return result;

def get_payments_iterator(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey, offset: int) -> collections.abc.Iterator[SQLTablePaymentRowTuple]:
    assert tx.cursor is not None
    select_fields = string_from_sql_fields(fields=SQL_TABLE_PAYMENTS_FIELD, schema=False)
    _ = tx.cursor.execute(f'''
        SELECT {select_fields}
        FROM   payments
        WHERE  master_pkey = ?
        LIMIT  {ALL_PAYMENTS_PAGINATION_SIZE} OFFSET ?
    ''', (bytes(master_pkey), offset))
    result = typing.cast(collections.abc.Iterator[SQLTablePaymentRowTuple], tx.cursor)
    return result;

def get_users_list(sql_conn: sqlite3.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM users')
        rows = typing.cast(collections.abc.Iterator[tuple[bytes, int, int]], tx.cursor)
        for row in rows:
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
        row                     = typing.cast(tuple[bytes, int, int], tx.cursor.fetchone())
        result.master_pkey      = row[0]
        result.gen_index        = row[1]
        result.expiry_unix_ts_s = row[2]
    return result;

def get_revocations_list(sql_conn: sqlite3.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM revocations')
        rows = typing.cast(collections.abc.Iterator[tuple[int, int]], tx.cursor)
        for row in rows:
            item                  = RevocationRow()
            item.gen_index        = row[0]
            item.expiry_unix_ts_s = row[1]
            result.append(item)
    return result;

def get_revocation_ticket(sql_conn: sqlite3.Connection) -> int:
    result: int = 0
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _      = tx.cursor.execute('SELECT revocation_ticket FROM runtime')
        result = typing.cast(tuple[int], tx.cursor.fetchone())[0]
    return result;


def get_pro_revocations_iterator(tx: base.SQLTransaction) -> collections.abc.Iterator[tuple[int, int]]:
    assert tx.cursor is not None
    _      = tx.cursor.execute('SELECT gen_index, expiry_unix_ts_s FROM revocations')
    result = typing.cast(collections.abc.Iterator[tuple[int, int]], tx.cursor)
    return result;

def get_runtime(sql_conn: sqlite3.Connection) -> RuntimeRow:
    result: RuntimeRow = RuntimeRow()
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _                        = tx.cursor.execute('SELECT * FROM runtime')
        row                      = typing.cast(tuple[int, bytes, bytes, int], tx.cursor.fetchone())
        result.gen_index         = row[0]
        result.gen_index_salt    = row[1]
        backend_key: bytes       = row[2]
        assert len(backend_key) == len(ZERO_BYTES32)
        result.backend_key       = nacl.signing.SigningKey(backend_key)
        result.revocation_ticket = row[3]
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
            _                   = tx.cursor.execute('SELECT COUNT(*) FROM payments WHERE status = ?', (int(PaymentStatus.Unredeemed.value),))
            unredeemed_payments = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM payments')
            payments            = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM users')
            users               = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                   = tx.cursor.execute('SELECT COUNT(*) FROM revocations')
            revocations         = typing.cast(tuple[int], tx.cursor.fetchone())[0];
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

def setup_db(path: str, uri: bool, err: base.ErrorSink, backend_key: nacl.signing.SigningKey | None = None) -> SetupDBResult:
    result: SetupDBResult = SetupDBResult()
    result.path           = path
    try:
        result.sql_conn = sqlite3.connect(path, uri=uri)
    except Exception as e:
        err.msg_list.append(f'Failed to open/connect to DB at {path}: {e}')
        return result

    with base.SQLTransaction(result.sql_conn) as tx:
        sql_stmt: str = f'''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY NOT NULL,
                {string_from_sql_fields(fields=SQL_TABLE_PAYMENTS_FIELD, schema=True)}
            );

            CREATE TABLE IF NOT EXISTS users (
                master_pkey      BLOB PRIMARY KEY NOT NULL,

                -- Current generation index allocated for the user. A new index is allocated
                -- everytime a payment is added/removed for the associated master key which will
                -- change the duration of entitlement for the user. This means that the generation
                -- index which is globally unique, snapshots the duration entitlement of a user at a
                -- particular time.
                --
                -- Pro subscription proofs are signed with this generation index. This means that we
                -- can revoke all prior proofs generated for this user and consequently their
                -- entitlement to Session Pro features by publishing a revoked proof with the index
                -- that was allocated to the user.
                --
                -- For example if the user refunded their subscription and there are proofs still
                -- circulating the network with some time remaining on the subscription then clients
                -- can know to ignore proofs for this user.
                --
                -- Another example for revocations is if the user stacks subscriptions to increase
                -- the duration of their entitlement. We can revoke the old proofs identified by the
                -- previous index associated with the user, allocate a new index and sign a new
                -- proof with said index.
                --
                -- This will force clients to drop the old proof and adopt the new proof which now
                -- correctly indicates the updated and correct duration that the user is entitled to
                -- Session Pro features.
                gen_index        INTEGER NOT NULL,
                expiry_unix_ts_s INTEGER NOT NULL            -- Timestamp at which the sum of all current subscriptions for the user expires
            );

            CREATE TABLE IF NOT EXISTS revocations (
                gen_index        INTEGER PRIMARY KEY NOT NULL,
                expiry_unix_ts_s INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime (
                gen_index             INTEGER NOT NULL, -- Next generation index to allocate to an updated user
                gen_index_salt        BLOB NOT NULL,    -- BLAKE2B salt for hashing the gen_index in proofs
                backend_key           BLOB NOT NULL,    -- Ed25519 skey for signing proofs
                last_expire_unix_ts_s INTEGER NOT NULL, -- Last time expire payments/revocs/users was called on the table
                revocation_ticket     INTEGER NOT NULL  -- Monotonic index incremented when a revocation is added or removed
            );

            CREATE TRIGGER IF NOT EXISTS increment_revocation_ticket_after_insert
            AFTER INSERT ON revocations
            BEGIN
                UPDATE runtime
                SET    revocation_ticket = revocation_ticket + 1;
            END;

            CREATE TRIGGER IF NOT EXISTS increment_revocation_ticket_after_delete
            AFTER DELETE ON revocations
            BEGIN
                UPDATE runtime
                SET    revocation_ticket = revocation_ticket + 1;
            END;
        '''

        assert tx.cursor is not None

        try:
            _                  = tx.cursor.executescript(sql_stmt)
            _                  = tx.cursor.execute('SELECT EXISTS (SELECT 1 FROM runtime) as row_exists')
            runtime_row_exists = bool(typing.cast(tuple[int], tx.cursor.fetchone())[0])
            if not runtime_row_exists:
                if backend_key == None:
                    backend_key = nacl.signing.SigningKey.generate()

                _ = tx.cursor.execute('''
                    INSERT INTO runtime
                    SELECT 0, ?, ?, 0, 0
                ''', (os.urandom(hashlib.blake2b.SALT_SIZE), bytes(backend_key)))
            result.success = True
        except Exception as e:
            err.msg_list.append(f"Failed to bootstrap DB tables: {e}")

    if result.success:
        result.runtime = get_runtime(result.sql_conn)
    else:
        result.sql_conn.close()

    return result


def verify_google_payment_token_hash(hash: str, err: base.ErrorSink):
    # TODO: We might not hash the token anymore, just take the string directly from google?
    # With apple we now take platform specific data (original tx, tx, and web line order tx id) seems
    # painful to abstract those into a singular representation and error prone
    pass

def verify_db(sql_conn: sqlite3.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(sql_conn)
    for index, it in enumerate(unredeemed_payments):
        base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}')
        if it.subscription_duration_s != base.SECONDS_IN_DAY * 30 and \
           it.subscription_duration_s != base.SECONDS_IN_DAY * 90 and \
           it.subscription_duration_s != base.SECONDS_IN_DAY * 365:
               err.msg_list.append(f'Unredeemed payment #{index} had an invalid subscription duration, expected 30, 90 or 365 day duration in seconds, received ({it.subscription_duration_s})')

    # NOTE: Wednesday, 27 August 2025 00:00:00, arbitrary date in the past that PRO cannot
    # possibly be before. We should update this to to the PRO release date.
    PRO_ENABLED_UNIX_TS: int = 1756252800

    payments: list[PaymentRow] = get_payments_list(sql_conn)
    for index, it in enumerate(payments):
        # NOTE: Check mandatory fields
        if it.subscription_duration_s == 0:
            err.msg_list.append(f'{it.status.name} payment #{index} subscription duration is set to 0 but it should not be. It should have been derived from the platform payment provider (e.g. by converting the purchased product ID to a specified duration)')
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(f'{it.status.name} payment #{index} payment provider is set to {it.payment_provider.name} but it should not be. It should have been set by the platform before added to the DB')

        # NOTE: Check mandatory fields or invariants given a particular TX status
        if it.status == PaymentStatus.Nil:
            err.msg_list.append(f'Payment #{index} specified a "nil" status which is invalid and should not be in the DB')
        elif it.status == PaymentStatus.Unredeemed:
            # NOTE: Check that most fields of the payment should not be set yet when it has not been
            # redeemed yet
            if it.master_pkey != ZERO_BYTES32:
                err.msg_list.append(f'{it.status.name} payment #{index} has a master pkey set but this pkey should not be set until it is redeemed (e.g. the user registers it)')
            if it.redeemed_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was {it.redeemed_unix_ts_s}. The payment is not redeemed yet so it should be 0')
            if it.activated_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} activated ts was {it.activated_unix_ts_s}. The payment is not activated yet so it should be 0')
            if it.expired_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was {it.expired_unix_ts_s}. The payment is not expired yet so it should be 0')
            if it.refunded_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} refunded ts was {it.refunded_unix_ts_s}. The payment is not refunded yet so it should be 0')

        elif it.status == PaymentStatus.Redeemed:
            # NOTE: Check that the redeemed ts is set
            if not it.redeemed_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was not set. The payment is redeemed so it should be non-zero')

            # NOTE: Check that expired ts was not set. Note refunded could be set as we can cancel a
            # refund back into a redeemed state
            if it.activated_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} activated ts was set. The payment is redeemed so it should not be set')
            if it.expired_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was set. The payment is redeemed so it should not be set')

        elif it.status == PaymentStatus.Activated:
            # NOTE: Check that redeemed and activated ts is set
            if not it.redeemed_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was not set. The payment is activated so it should be set')
            if not it.activated_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} activated ts was not set. The payment is activated so it should be set')

            # NOTE: Check that expired ts was not set. Note refunded could be set as we can cancel a
            # refund back into an activated state.
            if it.expired_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was set. The payment is activated so it should not be set')

            # NOTE: Check that payment was activated AFTER it was redeemed
            if it.redeemed_unix_ts_s and it.activated_unix_ts_s:
                if it.activated_unix_ts_s < it.redeemed_unix_ts_s:
                    redeemed_date = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_s).strftime('%Y-%m-%d')
                    activated_date = datetime.datetime.fromtimestamp(it.activated_unix_ts_s).strftime('%Y-%m-%d')
                    err.msg_list.append(f'{it.status.name} payment #{index} was activated ({activated_date}) before it was redeemed ({redeemed_date})')

        elif it.status == PaymentStatus.Expired:
            # NOTE: Expired, redeemed and activated ts must be set
            if not it.expired_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was not set. The payment is expired so it should be non-zero')
            if not it.redeemed_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was not set. The payment is expired so it should be set')
            if not it.activated_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} activated ts was not set. The payment is expired so it should be set')

            # NOTE: Check that payment was expired AFTER it was activated and activated AFTER it was redeemed
            if it.redeemed_unix_ts_s and it.activated_unix_ts_s and it.expired_unix_ts_s:
              redeemed_date = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_s).strftime('%Y-%m-%d')
              activated_date = datetime.datetime.fromtimestamp(it.activated_unix_ts_s).strftime('%Y-%m-%d')
              expired_date = datetime.datetime.fromtimestamp(it.expired_unix_ts_s).strftime('%Y-%m-%d')
              if it.expired_unix_ts_s < it.activated_unix_ts_s:
                  err.msg_list.append(f'{it.status.name} payment #{index} was expired ({expired_date}) before it was activated ({activated_date})')
              if it.activated_unix_ts_s < it.redeemed_unix_ts_s:
                  err.msg_list.append(f'{it.status.name} payment #{index} was activated ({activated_date}) before it was redeemed ({redeemed_date})')

        elif it.status == PaymentStatus.Refunded:
            # NOTE: Any payment can transition into the refunded state given any status (except for
            # nil, which is the invalid state). This means that all fields could be set so only a
            # few checks are needed here.
            if not it.refunded_unix_ts_s:
                err.msg_list.append(f'{it.status.name} payment #{index} refunded ts was not set. The payment is refunded so it should be non-zero')

        # NOTE: Verify the subscription duration, it should always be set once
        # it enters the DB and it should have a duration of a specific amount.
        if it.subscription_duration_s != base.SECONDS_IN_DAY * 30 and \
           it.subscription_duration_s != base.SECONDS_IN_DAY * 90 and \
           it.subscription_duration_s != base.SECONDS_IN_DAY * 365:
               err.msg_list.append(f'Payment #{index} had an invalid subscription duration, expected 30, 90 or 365 day duration in seconds, received ({it.subscription_duration_s})')
        base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the payment's redeemed ts is a reasonable value
        if it.redeemed_unix_ts_s and it.redeemed_unix_ts_s < PRO_ENABLED_UNIX_TS:
          date_str = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_s).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a creation date before PRO was enabled: {it.redeemed_unix_ts_s} ({date_str})')

        # NOTE: Check that the token is set correctly
        if it.payment_provider == base.PaymentProvider.GooglePlayStore:
            verify_google_payment_token_hash(it.google_payment_token, err)
        elif len(it.google_payment_token) != 0:
            err.msg_list.append(f'Payment #{index} speceified a google payment token: {it.google_payment_token} for a non-google platform')

    # NOTE: Verify the users
    users: list[UserRow] = get_users_list(sql_conn)
    for index, it in enumerate(users):
        if it.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')
        if it.expiry_unix_ts_s < PRO_ENABLED_UNIX_TS:
          expiry_date_str = datetime.datetime.fromtimestamp(it.expiry_unix_ts_s).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a expiry date before PRO was enabled: {it.expiry_unix_ts_s} ({expiry_date_str})')

    result = len(err.msg_list) == 0
    return result

def refund_apple_payment(sql_conn:                   sqlite3.Connection,
                         apple_web_line_order_tx_id: str | None,
                         apple_original_tx_id:       str,
                         refund_unix_ts_s:           int):
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None

        payments_table_fields: str = string_from_sql_fields(SQL_TABLE_PAYMENTS_FIELD, schema=False)
        if apple_web_line_order_tx_id:
            _ = tx.cursor.execute(f'''
                UPDATE    payments
                SET       status = ?, refunded_unix_ts_s = ?
                WHERE     apple_original_tx_id = ? AND apple_web_line_order_tx_id = ? AND payment_provider = ?
                ORDER BY  redeemed_unix_ts_s DESC
                LIMIT     1
                RETURNING {payments_table_fields}
            ''', (# SET values
                  int(PaymentStatus.Refunded.value),
                  refund_unix_ts_s,
                  # WHERE values
                  apple_original_tx_id,
                  apple_web_line_order_tx_id,
                  int(base.PaymentProvider.iOSAppStore.value)));
        else:
            _ = tx.cursor.execute(f'''
                UPDATE    payments
                SET       status = ?, refunded_unix_ts_s = ?
                WHERE     apple_original_tx_id = ? AND payment_provider = ?
                ORDER BY  redeemed_unix_ts_s DESC
                LIMIT     1
                RETURNING {payments_table_fields}
            ''', (# SET values
                  int(PaymentStatus.Refunded.value),
                  refund_unix_ts_s,
                  # WHERE values
                  apple_original_tx_id,
                  int(base.PaymentProvider.iOSAppStore.value)));

def redeem_payment(sql_conn:           sqlite3.Connection,
                   master_pkey:        nacl.signing.VerifyKey,
                   redeemed_unix_ts_s: int,
                   payment_tx:         AddProPaymentUserTransaction,
                   err:                base.ErrorSink) -> bool:
    result                   = False;
    master_pkey_bytes: bytes = bytes(master_pkey)
    fields                   = ['master_pkey = ?', 'status = ?', 'redeemed_unix_ts_s = ?']
    set_expr                 = ', '.join(fields) # Create '<field0> = ?, <field1> = ?, ...'

    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            _ = tx.cursor.execute(f'''
                UPDATE payments
                SET    {set_expr}
                WHERE  payment_provider = ? AND google_payment_token = ? AND status = ?
            ''', (# SET values
                  master_pkey_bytes,
                  int(PaymentStatus.Redeemed.value),
                  redeemed_unix_ts_s,
                  # WHERE values
                  int(payment_tx.provider.value),
                  payment_tx.google_payment_token,
                  int(PaymentStatus.Unredeemed.value)))
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            _ = tx.cursor.execute(f'''
                UPDATE payments
                SET    {set_expr}
                WHERE  payment_provider = ? AND apple_tx_id = ? AND status = ?
            ''', (# SET fields
                  master_pkey_bytes,
                  int(PaymentStatus.Redeemed.value),
                  redeemed_unix_ts_s,
                  # WHERE fields
                  int(payment_tx.provider.value),
                  payment_tx.apple_tx_id,
                  int(PaymentStatus.Unredeemed.value)))
        else:
            err.msg_list.append('Payment to register specifies an unknown payment provider')

        if tx.cursor.rowcount >= 1:
            result = True
            if tx.cursor.rowcount > 1:
                # TODO: Be more robust here, abort the update if there was more than 1 row, DB is in
                # an unexpected state
                err.msg_list.append(f'Payment was redeemed but more than 1 row was updated, updated {tx.cursor.rowcount}')
                result = False
        else:
            # NOTE: We dump the payment TX to the error list. This does not leak
            # any information because this is all data populated by the user who
            # is sending the redeeming request.
            err.msg_list.append(f'Payment was not redeemed, no payments were found matching the request tx: {payment_tx}')

    return result

def add_unredeemed_payment(sql_conn:                sqlite3.Connection,
                           payment_tx:              PaymentProviderTransaction,
                           subscription_duration_s: int,
                           err:                     base.ErrorSink):
    base.verify_payment_provider(payment_tx.provider, err)
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        verify_google_payment_token_hash(payment_tx.google_payment_token, err)

    if len(err.msg_list) > 0:
        return

    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            # NOTE: Insert into the table, IFF, the payment token hash doesn't already exist somewhere
            # else.
            _ = tx.cursor.execute(f'''
                SELECT 1
                FROM payments
                WHERE payment_provider = ? AND google_payment_token = ?
            ''', (int(payment_tx.provider.value), payment_tx.google_payment_token))

            record = tx.cursor.fetchone()
            if record:
                fields      = ['subscription_duration_s', 'payment_provider', 'google_payment_token', 'status']
                stmt_fields = ', '.join(fields)                 # Create '<field0>, <field1>, ...'
                stmt_values = ', '.join(['?' for _ in fields])  # Create '?,        ?,        ...'

                _ = tx.cursor.execute(f'''
                    INSERT INTO payments ({stmt_fields})
                    VALUES ({stmt_values})
                ''', (subscription_duration_s,
                      payment_tx.provider.value,
                      payment_tx.google_payment_token,
                      int(PaymentStatus.Unredeemed.value)))

        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            # NOTE: Insert into the table, IFF, the apple payment doesn't already exist somewhere else.
            #
            # For Apple each apple_tx_id is always unique.
            # apple_web_line_order_tx_id is unique for the payment of the billing
            # cycle for that subscription and the apple_original_tx_id is reused
            # across all subscriptions of the same type.
            _ = tx.cursor.execute(f'''
                    SELECT 1
                    FROM payments
                    WHERE AND payment_provider = ? AND apple_original_tx_id = ? AND apple_web_line_order_tx_id = ?
            ''', (int(payment_tx.provider.value), payment_tx.apple_original_tx_id, payment_tx.apple_tx_id, payment_tx.apple_web_line_order_tx_id))

            record = tx.cursor.fetchone()
            if record:
                fields:      list[str] = ['subscription_duration_s', 'payment_provider', 'apple_original_tx_id', 'apple_tx_id', 'apple_web_line_order_tx_id']
                stmt_fields: str       = ', '.join(fields)                 # Create '<field0>, <field1>, ...'
                stmt_values: str       = ', '.join(['?' for _ in fields])  # Create '?,        ?,        ...'

                _ = tx.cursor.execute(f'''
                    INSERT INTO payments ({stmt_fields})
                    VALUES ({stmt_values})
                ''', (subscription_duration_s,
                      int(payment_tx.provider.value),
                      payment_tx.apple_original_tx_id,
                      payment_tx.apple_tx_id,
                      payment_tx.apple_web_line_order_tx_id,
                      int(PaymentStatus.Unredeemed.value)))

def update_db_after_payments_changed(tx:                  base.SQLTransaction,
                                     master_pkey:         nacl.signing.VerifyKey,
                                     activated_unix_ts_s: int) -> UpdateAfterPaymentsModified:
    result:            UpdateAfterPaymentsModified = UpdateAfterPaymentsModified()
    master_pkey_bytes: bytes                       = bytes(master_pkey)
    assert tx.cursor is not None

    # Check if the user has any activated subscriptions yet in the payments table
    _ = tx.cursor.execute('''
        SELECT    activated_unix_ts_s
        FROM      payments
        WHERE     activated_unix_ts_s IS NOT NULL AND master_pkey = ? AND status = ?
        ORDER BY  activated_unix_ts_s ASC
        LIMIT 1
    ''', (master_pkey_bytes, int(PaymentStatus.Activated.value),))

    earliest_activated_unix_ts_s_record = typing.cast(tuple[int], tx.cursor.fetchone())
    earliest_activated_unix_ts_s: int   = 0
    if earliest_activated_unix_ts_s_record:
        # User already has exactly, 1 activated payment row, go and look it up
        earliest_activated_unix_ts_s = earliest_activated_unix_ts_s_record[0]
    else:
        # Get the row with the earliest creation time, then activate it by
        # setting the current unix time (rounded to the next day to mask the
        # registration time to on-the-day boundaries) as the activated time.
        _ = tx.cursor.execute('''
            WITH lookup AS (
                SELECT   id
                FROM     payments
                WHERE    master_pkey = ? AND status = ?
                ORDER BY redeemed_unix_ts_s ASC
                LIMIT    1
            )
            UPDATE payments
            SET    activated_unix_ts_s = ?, status = ?
            WHERE  id                  = (SELECT id FROM lookup)
        ''', (# WHERE values
              master_pkey_bytes,
              int(PaymentStatus.Redeemed.value),
              # SET values
              activated_unix_ts_s,
              int(PaymentStatus.Activated.value)))
        earliest_activated_unix_ts_s = activated_unix_ts_s

    # Calculate the latest expiry date by summing up the total duration of
    # subscriptions this user has.
    _ = tx.cursor.execute('''
        SELECT SUM(subscription_duration_s)
        FROM   payments
        WHERE  master_pkey = ? AND status = ? OR status = ?
    ''', (master_pkey_bytes,
          int(PaymentStatus.Redeemed.value),
          int(PaymentStatus.Activated.value)))

    sum_of_subscription_duration_s: int = typing.cast(tuple[int], tx.cursor.fetchone())[0]
    result.latest_expiry_unix_ts_s      = earliest_activated_unix_ts_s + sum_of_subscription_duration_s + base.SECONDS_IN_DAY
    assert result.latest_expiry_unix_ts_s % base.SECONDS_IN_DAY == 0, f"Subscription duration must be on a day boundaring, 30 days, 365 days ...e.t.c, was {base.format_seconds(result.latest_expiry_unix_ts_s)}"

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
        RETURNING gen_index - 1, gen_index_salt
    ''')
    runtime_row           = typing.cast(tuple[int, bytes], tx.cursor.fetchone())
    result.gen_index      = runtime_row[0]
    result.gen_index_salt = runtime_row[1]

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

def make_get_pro_proof_hash(version:       int,
                            master_pkey:   nacl.signing.VerifyKey,
                            rotating_pkey: nacl.signing.VerifyKey,
                            unix_ts_s:     int) -> bytes:
    '''Make the hash to sign for a pre-existing subscription by authorising
    a new rotating_pkey to be used for the Session Pro subscription associated
    with master_pkey'''
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))
    hasher.update(unix_ts_s.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def build_proof_hash(version:          int,
                     gen_index_hash:   bytes,
                     rotating_pkey:    nacl.signing.VerifyKey,
                     expiry_unix_ts_s: int) -> bytes:
    '''Make the hash to the backend signs for to certify the proof'''
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(gen_index_hash)
    hasher.update(bytes(rotating_pkey))
    hasher.update(expiry_unix_ts_s.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def build_proof(gen_index:        int,
                rotating_pkey:    nacl.signing.VerifyKey,
                expiry_unix_ts_s: int,
                signing_key:      nacl.signing.SigningKey,
                gen_index_salt:   bytes) -> ProSubscriptionProof:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.version               = 0
    result.gen_index_hash        = make_gen_index_hash(gen_index=gen_index, gen_index_salt=gen_index_salt)
    result.rotating_pkey         = rotating_pkey
    result.expiry_unix_ts_s      = expiry_unix_ts_s

    hash_to_sign: bytes = build_proof_hash(version          = result.version,
                                           gen_index_hash   = result.gen_index_hash,
                                           rotating_pkey    = result.rotating_pkey,
                                           expiry_unix_ts_s = result.expiry_unix_ts_s)
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

def add_pro_payment(sql_conn:           sqlite3.Connection,
                    version:            int,
                    signing_key:        nacl.signing.SigningKey,
                    redeemed_unix_ts_s: int,
                    master_pkey:        nacl.signing.VerifyKey,
                    rotating_pkey:      nacl.signing.VerifyKey,
                    payment_tx:         AddProPaymentUserTransaction,
                    master_sig:         bytes,
                    rotating_sig:       bytes,
                    err:                base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()

    # In developer mode, the server is intended to be launched locally and we
    # typically run libsession tests against it (to get accurate request and
    # response payloads) from the server. In these tests we try and register
    # a payment, but the design of the pro backend is that it pulls payment
    # tokens from the 3rd party storefronts.
    #
    # It must have pulled the token first before permitting the payment token to
    # be registered. Here we skipping the pulling step by implicitly registering
    # the token into our unredeemed queue, then process the payment from the
    # unredeemed queue immediately.
    #
    # There is a sanity check to _only_ allow this in developer mode. In
    # any other context having this turn on would be a critical failure and
    # would allow someone to register arbitrary Session Pro subscriptions
    # without a valid payment.
    if base.DEV_BACKEND_MODE:
        runtime_row: RuntimeRow = get_runtime(sql_conn)
        assert bytes(runtime_row.backend_key) == base.DEV_BACKEND_DETERMINISTIC_SKEY, \
                "Sanity check failed, developer mode was enabled but the key in the DB was not a development key. This is a special guard to prevent the user from activating developer mode in the wrong environment"
        # Convert the user payment transaction into the backend native representation. Note that
        # this is testing code for the unit tests so for example for Apple we just provide stub data
        # for transaction data.
        internal_payment_tx          = PaymentProviderTransaction()
        internal_payment_tx.provider = payment_tx.provider

        if internal_payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            internal_payment_tx.google_payment_token = payment_tx.google_payment_token
        elif internal_payment_tx.provider == base.PaymentProvider.iOSAppStore:
            internal_payment_tx.apple_tx_id                = payment_tx.apple_tx_id
            internal_payment_tx.apple_web_line_order_tx_id = ''
            internal_payment_tx.apple_original_tx_id       = ''

        print(f'Registering payment in DEV mode: {internal_payment_tx}')
        add_unredeemed_payment(sql_conn=sql_conn,
                               payment_tx=internal_payment_tx,
                               subscription_duration_s=base.SECONDS_IN_DAY * 30,
                               err=err)

    # Verify some of the request parameters
    hash_to_sign: bytes = make_add_pro_payment_hash(version=version,
                                                    master_pkey=master_pkey,
                                                    rotating_pkey=rotating_pkey,
                                                    payment_tx=payment_tx)

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

    if len(err.msg_list) > 0:
        return result

    # Note being able to pass in the creation unix timestamp is mainly for
    # testing purposes to allow time-travel. User space shold never be
    # specifying this argument, so clients should not be specifying this time,
    # ever, it should be generated by the server hence the assert.
    assert redeemed_unix_ts_s % base.SECONDS_IN_DAY == 0, \
            "The passed in creation (and or activated) timestamp must lie on a day boundary: {}".format(redeemed_unix_ts_s)

    # All verified. Redeem the payment by updating the TX to 'redeemed' and setting the unix ts
    _ = redeem_payment(sql_conn=sql_conn,
                       master_pkey=master_pkey,
                       redeemed_unix_ts_s=redeemed_unix_ts_s,
                       payment_tx=payment_tx,
                       err=err)
    if len(err.msg_list) > 0:
        return result

    # Payment has been redeemed. Activate the payment with the earliest start time and generate
    # a Session Pro Proof
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        update: UpdateAfterPaymentsModified = update_db_after_payments_changed(tx=tx,
                                                                               master_pkey=master_pkey,
                                                                               activated_unix_ts_s=redeemed_unix_ts_s)
        result = build_proof(gen_index=update.gen_index,
                             rotating_pkey=rotating_pkey,
                             expiry_unix_ts_s=update.latest_expiry_unix_ts_s,
                             signing_key=signing_key,
                             gen_index_salt=update.gen_index_salt)
    return result

def expire_payments_internal(tx: base.SQLTransaction, payment_token_hash_or_unix_ts: bytes | int, expired_unix_ts_s: int) -> list[nacl.signing.VerifyKey]:
    result: list[nacl.signing.VerifyKey] = []
    assert tx.cursor is not None
    if isinstance(payment_token_hash_or_unix_ts, int):
        unix_ts_s = payment_token_hash_or_unix_ts
        _ = tx.cursor.execute(f'''
            UPDATE    payments
            SET       status = ?, expired_unix_ts_s = ?
            WHERE     activated_unix_ts_s IS NOT NULL AND ? >= (activated_unix_ts_s + subscription_duration_s)
            RETURNING master_pkey
        ''', (# SET values
              int(PaymentStatus.Expired.value),
              expired_unix_ts_s,
              # WHERE values
              unix_ts_s,))
    else:
        assert isinstance(payment_token_hash_or_unix_ts, bytes)
        payment_token_hash = payment_token_hash_or_unix_ts
        _ = tx.cursor.execute(f'''
            UPDATE    payments
            SET       status = ?, expired_unix_ts_s = ?
            WHERE     payment_token_hash = ?
            RETURNING master_pkey
        ''', (# SET values
              int(PaymentStatus.Expired.value),
              expired_unix_ts_s,
              # WHERE values
              payment_token_hash,))

    rows = typing.cast(collections.abc.Iterator[tuple[bytes]], tx.cursor)
    for row in rows:
        master_pkey: bytes = row[0]
        result.append(nacl.signing.VerifyKey(master_pkey))
    return result

def add_revocation(sql_conn: sqlite3.Connection, payment_token_hash: bytes, expired_unix_ts_s: int):
    with base.SQLTransaction(sql_conn) as tx:
        master_pkeys: list[nacl.signing.VerifyKey] = expire_payments_internal(tx=tx,
                                                                              payment_token_hash_or_unix_ts=payment_token_hash,
                                                                              expired_unix_ts_s=expired_unix_ts_s)
        for pkey in master_pkeys:
            _ = update_db_after_payments_changed(tx=tx,
                                                 master_pkey=pkey,
                                                 activated_unix_ts_s=expired_unix_ts_s)

def get_pro_proof(sql_conn:       sqlite3.Connection,
                  version:        int,
                  signing_key:    nacl.signing.SigningKey,
                  gen_index_salt: bytes,
                  master_pkey:    nacl.signing.VerifyKey,
                  rotating_pkey:  nacl.signing.VerifyKey,
                  unix_ts_s:      int,
                  master_sig:     bytes,
                  rotating_sig:   bytes,
                  err:            base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()

    # Verify some of the request parameters
    hash_to_sign: bytes = make_get_pro_proof_hash(version=version,
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

    # Then verify version
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')
    if len(err.msg_list) > 0:
        return result

    # All verified, now generate proof
    user: UserRow = get_user(sql_conn, master_pkey)
    if user.master_pkey == bytes(master_pkey):
        result = build_proof(gen_index=user.gen_index,
                             rotating_pkey=rotating_pkey,
                             expiry_unix_ts_s=user.expiry_unix_ts_s,
                             signing_key=signing_key,
                             gen_index_salt=gen_index_salt);
    else:
        err.msg_list.append(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it, {bytes(user.master_pkey).hex()} {user.gen_index} {user.expiry_unix_ts_s}')

    return result

def expire_payments_revocations_and_users(sql_conn: sqlite3.Connection, unix_ts_s: int) -> ExpireResult:
    result = ExpireResult()
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        # Retrieve the last expiry time that was executed
        _ = tx.cursor.execute('''SELECT last_expire_unix_ts_s FROM runtime''')
        last_expire_unix_ts_s:        int  = typing.cast(tuple[int], tx.cursor.fetchone())[0]
        already_done_by_someone_else: bool = last_expire_unix_ts_s >= unix_ts_s
        if not already_done_by_someone_else:
            # Update the timestamp that we executed DB expiry
            _ = tx.cursor.execute('''UPDATE runtime SET last_expire_unix_ts_s = ?''', (unix_ts_s,))

            # Delete expired payments
            master_pkeys: list[nacl.signing.VerifyKey] = expire_payments_internal(tx=tx,
                                                                                  payment_token_hash_or_unix_ts=unix_ts_s,
                                                                                  expired_unix_ts_s=unix_ts_s)
            result.payments = len(master_pkeys)

            # For each master public key that had a payment deleted, activate their next record if
            # they have one to activate
            for pkey in master_pkeys:
                _ = update_db_after_payments_changed(tx=tx,
                                                     master_pkey=pkey,
                                                     activated_unix_ts_s=unix_ts_s)

            # Delete expired revocations
            _ = tx.cursor.execute('''
                DELETE FROM revocations
                WHERE ? >= expiry_unix_ts_s;
            ''', (unix_ts_s,))
            result.revocations = tx.cursor.rowcount

            # Delete expired users
            _ = tx.cursor.execute('''
                DELETE FROM users
                WHERE ? >= expiry_unix_ts_s;
            ''', (unix_ts_s,))
            result.users = tx.cursor.rowcount

        result.already_done_by_someone_else = already_done_by_someone_else
        result.success                      = True
    return result
