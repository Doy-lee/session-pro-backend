import traceback
import nacl.signing
import sqlite3
import hashlib
import os
import typing
import collections.abc
import datetime
import dataclasses
import random
import logging
import enum

import platform_google_api
import platform_google_types
import base

ZERO_BYTES32        = bytes(32)
BLAKE2B_DIGEST_SIZE = 32
log                 = logging.Logger("BACKEND")

@dataclasses.dataclass
class GoogleNotificationMessageIDInDB:
    present: bool = False
    handled: bool = False

@dataclasses.dataclass
class ExpireResult:
    already_done_by_someone_else:    bool = False
    success:                         bool = False
    payments:                        int  = 0
    revocations:                     int  = 0
    users:                           int  = 0
    apple_notification_uuid_history: int  = 0
    google_notification_history:     int  = 0

@dataclasses.dataclass
class ProSubscriptionProof:
    version:           int                    = 0
    gen_index_hash:    bytes                  = b''
    rotating_pkey:     nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expiry_unix_ts_ms: int                    = 0
    sig:               bytes                  = b''

    def to_dict(self) -> dict[str, str | int]:
        result = {
            "version":           self.version,
            "gen_index_hash":    self.gen_index_hash.hex(),
            "rotating_pkey":     bytes(self.rotating_pkey).hex(),
            "expiry_unix_ts_ms": self.expiry_unix_ts_ms,
            "sig":               self.sig.hex(),
        }
        return result

@dataclasses.dataclass
class LookupUserExpiryUnixTsMs:
    expiry_unix_ts_ms_from_redeemed:                   int  = 0
    grace_duration_ms_from_redeemed:                   int  = 0
    refund_request_unix_ts_ms_from_redeemed:           int  = 0
    auto_renewing_from_redeemed:                       bool = False

    expiry_unix_ts_ms_from_expired_or_revoked:         int  = 0
    grace_duration_ms_from_expired_or_revoked:         int  = 0
    refund_request_unix_ts_ms_from_expired_or_revoked: int  = 0
    auto_renewing_from_expired_or_revoked:             bool = False

    best_expiry_unix_ts_ms:                            int  = 0
    best_grace_duration_ms:                            int  = 0
    best_refund_request_unix_ts_ms:                    int  = 0
    best_auto_renewing:                                bool = False

class RedeemPaymentStatus(enum.Enum):
    Nil             = 0
    Error           = 1
    Success         = 2
    AlreadyRedeemed = 3
    UnknownPayment  = 4

@dataclasses.dataclass
class RedeemPayment:
    proof:  ProSubscriptionProof = dataclasses.field(default_factory=ProSubscriptionProof)
    status: RedeemPaymentStatus  = RedeemPaymentStatus.Nil

@dataclasses.dataclass
class SQLField:
    name: str = ''
    type: str = ''

SQL_TABLE_PAYMENTS_FIELD: list[SQLField] = [
  SQLField('master_pkey',                       'BLOB'),             # Session Pro master public key associated with the payment
  SQLField('status',                            'INTEGER NOT NULL'), # Enum cooresponding to `base.PaymentStatus`
  SQLField('plan',                              'INTEGER NOT NULL'), # Enum cooresponding to `base.ProPlanType`
  SQLField('payment_provider',                  'INTEGER NOT NULL'),
  SQLField('auto_renewing',                     'INTEGER NOT NULL'), # Boolean flag indicating if the subscription payment is known to be auto-renewing
  SQLField('unredeemed_unix_ts_ms',             'INTEGER NOT NULL'),

  # Timestamp of when the payment was redeemed rounded to the end of the day.
  SQLField('redeemed_unix_ts_ms',               'INTEGER'),
  SQLField('expiry_unix_ts_ms',                 'INTEGER NOT NULL'),

  # Duration of the user's grace period which covers the brief period given to a user in between the
  # execution of the billing for the renewal of Session Pro for the subsequent billing cycle. A user
  # is entitled to `expiry_unix_ts_ms + grace_period_duration_ms` if and only if `auto_renewing` is
  # true. Clients can request a proof for users in a grace period that will expire at the end of
  # this configured grace period.
  #
  # The value of the grace period is preserved even if `auto_renewing` is turned off to ensure that
  # if the user restores renewal of the subscription, the correct grace period is restored and
  # entitled to the user.
  SQLField('grace_period_duration_ms',          'INTEGER'),

  # Time at which the payment is no longer eligible for a refund through its payment platform. If
  # the payment is always eligible for refund through its payment platform this value will be set
  # to 0
  SQLField('platform_refund_expiry_unix_ts_ms', 'INTEGER NOT NULL'),
  SQLField('revoked_unix_ts_ms',                'INTEGER'),

  SQLField('apple_original_tx_id',              'BLOB'),
  SQLField('apple_tx_id',                       'BLOB'),
  SQLField('apple_web_line_order_tx_id',        'BLOB'),

  # Purchase token associated with a user that is shared across all payments for a given
  # subscription. Google recommends this be the primary key for the user's subscription entitlement.
  # So we cannot dedupe payments by this token because in subsequent billing cycles, the same token
  # is returned.
  #
  # In order to support subsequent payments we also take in the timestamp in milliseconds that the
  # event was associated with. Before adding this payment to the DB it's the caller's responsibility
  # to have independently re-verified the token using Google APIs provided to assert the token was
  # valid.
  SQLField('google_payment_token',              'BLOB'),
  SQLField('google_order_id',                   'BLOB'),

  # On some platforms the initiation of a refund can be recorded manually by the originating device
  # by calling the backend with the payment details to mark as having initiated a refund. This is
  # currently only utilised by iOS.
  #
  # This field is _opt_ in, clients must call the _set refund request_ endpoint on the backend in
  # order to set this value. This is because it's possible for a user to initiate a refund request
  # out-of-band from the application meaning cannot observe this event occurring. As prior mentioned
  # the only platform that takes advantage of this is iOS.
  #
  # Our convention is if the request has not been set, this value should be set to 0. If a refund is
  # declined on iOS we _do_ get notified of this and the backend will try to set this value back to
  # 0
  SQLField('refund_request_unix_ts_ms',         'INTEGER NOT NULL'),
]

SQLTablePaymentRowTuple:           typing.TypeAlias = tuple[bytes | None, # master_pkey
                                                            int,          # status
                                                            int,          # plan
                                                            int,          # payment_provider
                                                            int,          # auto_renewing
                                                            int,          # unredeemed_unix_ts_ms
                                                            int | None,   # redeemed_unix_ts_ms
                                                            int,          # expiry_unix_ts_ms
                                                            int,          # grace_period_duration_ms
                                                            int,          # platform_refund_expiry_unix_ts_ms
                                                            int | None,   # revoked_unix_ts_ms
                                                            str | None,   # apple_original_tx_id
                                                            str | None,   # apple_tx_id
                                                            str | None,   # apple_web_line_order_tx_id
                                                            str | None,   # google_payment_token
                                                            str | None,   # google_order_id
                                                            int,          # refund_request_unix_ts_ms
                                                            ]

AddRevocationIterator:               typing.TypeAlias = tuple[int,          # (row) id
                                                              bytes | None, # master_pkey
                                                              int]          # expiry_unix_ts_ms

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[int,        # message_id
                                                              str | None, # payload
                                                              int]        # expiry_unix_ts_ms

UserRowIterator:                     typing.TypeAlias = tuple[bytes, # master_pkey
                                                              int,   # gen_index
                                                              int,   # expiry_unix_ts_ms
                                                              int,   # grace_period_duration_ms
                                                              int,   # auto_renewing
                                                              int,   # refund_request_unix_ts_ms
                                                             ]

@dataclasses.dataclass
class UserError:
    provider:                   base.PaymentProvider = base.PaymentProvider.Nil
    apple_original_tx_id:       str = ''
    google_payment_token:       str = ''

@dataclasses.dataclass
class UserPaymentTransaction:
    provider:             base.PaymentProvider = base.PaymentProvider.Nil
    apple_tx_id:          str                  = ''
    google_payment_token: str                  = ''
    google_order_id:      str                  = ''

@dataclasses.dataclass
class AppleTransaction:
    original_tx_id:       str = ''
    tx_id:                str = ''
    web_line_order_tx_id: str = ''

@dataclasses.dataclass
class PaymentRow:
    id:                                 int                  = 0
    master_pkey:                        bytes | None         = None
    status:                             base.PaymentStatus   = base.PaymentStatus.Nil
    plan:                               base.ProPlan         = base.ProPlan.Nil
    payment_provider:                   base.PaymentProvider = base.PaymentProvider.Nil
    auto_renewing:                      bool                 = False
    unredeemed_unix_ts_ms:              int                  = 0
    redeemed_unix_ts_ms:                int | None           = None
    expiry_unix_ts_ms:                  int                  = 0
    grace_period_duration_ms:           int                  = 0
    platform_refund_expiry_unix_ts_ms:  int                  = 0
    revoked_unix_ts_ms:                 int | None           = None
    apple:                              AppleTransaction     = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token:               str                  = ''
    google_order_id:                    str                  = ''
    refund_request_unix_ts_ms:          int                  = 0

@dataclasses.dataclass
class UserRow:
    found:                     bool  = False
    master_pkey:               bytes = ZERO_BYTES32
    gen_index:                 int   = 0
    expiry_unix_ts_ms:         int   = 0
    grace_period_duration_ms:  int   = 0
    auto_renewing:             bool  = False
    refund_request_unix_ts_ms: int   = 0

@dataclasses.dataclass
class GetUserAndPayments:
    user:           UserRow                                           = dataclasses.field(default_factory=UserRow)
    payments_it:    collections.abc.Iterator[SQLTablePaymentRowTuple] = dataclasses.field(default_factory=lambda: iter([SQLTablePaymentRowTuple()]))
    payments_count: int                                               = 0

@dataclasses.dataclass
class RevocationRow:
    gen_index:         int   = 0
    expiry_unix_ts_ms: int   = 0

@dataclasses.dataclass
class RevocationItem:
    '''A revocation object that has only the fields necessary for clients to block Session Pro
    subscription proofs.'''
    gen_index_hash:    bytes = b''
    expiry_unix_ts_ms: int   = 0

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
    that a Session Pro subscription unredeemedd.

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
    gen_index:                                int                     = 0
    gen_index_salt:                           bytes                   = b''
    backend_key:                              nacl.signing.SigningKey = nacl.signing.SigningKey(ZERO_BYTES32)
    last_expire_unix_ts_ms:                   int                     = 0
    apple_notification_checkpoint_unix_ts_ms: int                     = 0
    revocation_ticket:                        int                     = 0

@dataclasses.dataclass
class AllocatedGenID:
    found:             bool  = False
    expiry_unix_ts_ms: int   = 0
    grace_unix_ts_ms:  int   = 0
    gen_index:         int   = 0
    gen_index_salt:    bytes = b''

@dataclasses.dataclass
class SetupDBResult:
    """
    Class is returned by backend.setup_db() which opens the DB and maintains a connection to the DB
    via `sql_conn`. Caller must close `sql_conn` if they wish to release the connection from the DB.
    The setup function creates the tables required to operate the Session Pro Backend.

    Normally you would not return the DB connection as it's easy to accidentally leak the DB
    connection in this object however we also use this in tests which use an in-memory transient DB
    If we were to close connection before returning to the user, the DB will be wiped from memory
    making it useless for tests.

    For the most part the callers of this API (tests and main entry point) explicitly close the DB
    when they are done with it.
    """
    path:     str                       = ''
    success:  bool                      = False
    runtime:  RuntimeRow                = dataclasses.field(default_factory=RuntimeRow)
    sql_conn: sqlite3.Connection | None = None

@dataclasses.dataclass
class OpenDBAtPath:
    """
    Open a pre-existing DB at the specified path. This class should be used in a `with` context to
    ensure that the connection established to the database is closed on scope exit, e.g.:

    with OpenDBAtPath(...) as db:
        # Use db.sql_conn =
        pass
    """

    sql_conn: sqlite3.Connection
    runtime:  RuntimeRow
    def __init__(self, db_path: str, uri: bool = False):
        self.sql_conn = sqlite3.connect(db_path, uri=uri)
        self.runtime  = get_runtime(self.sql_conn)

    def __enter__(self):
        return self

    def __exit__(self,
                 exc_type:  object | None,
                 exc_value: object | None,
                 traceback: traceback.TracebackException | None):
        self.sql_conn.close()
        return False

def payment_provider_tx_log_label(tx: base.PaymentProviderTransaction):
    result = f'{tx.provider.name}, apple (orig/tx/web)=({tx.apple_original_tx_id}/{tx.apple_tx_id}/{tx.apple_web_line_order_tx_id}), google=({tx.google_payment_token}/{tx.google_order_id})'
    return result

def _add_pro_payment_user_tx_log_label(tx: UserPaymentTransaction):
    result = f'{tx.provider.name}, apple={tx.apple_tx_id}, google=({tx.google_payment_token}, {tx.google_order_id})'
    return result

def convert_unix_ts_ms_to_redeemed_unix_ts_ms(unix_ts_ms: int):
    result: int = 0
    if base.DEV_BACKEND_MODE:
        result = unix_ts_ms
    else:
        result = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    return result

def string_from_sql_fields(fields: list[SQLField], schema: bool) -> str:
    result = ''
    if schema:
        result = ',\n'.join([f'{it.name} {it.type}' for it in fields]) # Create '<field0> <type0>,\n<field1> <type1>, ...'
    else:
        result = ', '.join([it.name for it in fields])  # Create '<field0>, <field1>, ...'
    return result

def make_blake2b_personalised_hasher(personalisation: bytes, salt: bytes | None = None) -> hashlib.blake2b:
    final_salt      = salt  if salt else b''
    result          = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE, person=personalisation, salt=final_salt)
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
                              payment_tx:    UserPaymentTransaction) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))

    hasher.update(int(payment_tx.provider.value).to_bytes(length=1, byteorder='little'))
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        hasher.update(payment_tx.google_payment_token.encode('utf-8'))
        hasher.update(payment_tx.google_order_id.encode('utf-8'))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        hasher.update(payment_tx.apple_tx_id.encode('utf-8'))
    else:
        assert payment_tx.provider != base.PaymentProvider.Nil, "Nil not supported"

    result: bytes = hasher.digest()
    return result

def payment_row_from_tuple(row: tuple[int, *SQLTablePaymentRowTuple]) -> PaymentRow:
    result                                    = PaymentRow()
    result.id                                 = row[0]
    result.master_pkey                        = row[1]
    result.status                             = base.PaymentStatus(row[2])
    result.plan                               = base.ProPlan(row[3])
    result.payment_provider                   = base.PaymentProvider(row[4])
    result.auto_renewing                      = bool(row[5])
    result.unredeemed_unix_ts_ms              = row[6]
    result.redeemed_unix_ts_ms                = row[7] if row[7] else None
    result.expiry_unix_ts_ms                  = row[8]
    result.grace_period_duration_ms           = row[9]
    result.platform_refund_expiry_unix_ts_ms  = row[10]
    result.revoked_unix_ts_ms                 = row[11] if row[11] else None
    result.apple.original_tx_id               = row[12] if row[12] else ''
    result.apple.tx_id                        = row[13] if row[13] else ''
    result.apple.web_line_order_tx_id         = row[14] if row[14] else ''
    result.google_payment_token               = row[15] if row[15] else ''
    result.google_order_id                    = row[16] if row[16] else ''
    result.refund_request_unix_ts_ms   = row[17]
    return result

def get_unredeemed_payments_list(sql_conn: sqlite3.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM payments WHERE status = ?', (int(base.PaymentStatus.Unredeemed.value),))

        rows = typing.cast(collections.abc.Iterator[tuple[int, *SQLTablePaymentRowTuple]], tx.cursor)
        for row in rows:
            item = payment_row_from_tuple(row)
            result.append(item)
    return result;

def get_payments_list(sql_conn: sqlite3.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM payments')
        rows = typing.cast(collections.abc.Iterator[tuple[int, *SQLTablePaymentRowTuple]], tx.cursor)
        for row in rows:
            item = payment_row_from_tuple(row)
            result.append(item)
    return result;

def get_user_and_payments(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> GetUserAndPayments:
    assert tx.cursor is not None
    select_fields = string_from_sql_fields(fields=SQL_TABLE_PAYMENTS_FIELD, schema=False)

    result      = GetUserAndPayments()
    result.user = get_user_from_sql_tx(tx, master_pkey)

    _ = tx.cursor.execute(f'''
        SELECT   COUNT(*)
        FROM     payments
        WHERE    master_pkey = ?
    ''', (bytes(master_pkey),))
    result.payments_count = tx.cursor.fetchone()[0]

    _ = tx.cursor.execute(f'''
        SELECT   {select_fields}
        FROM     payments
        WHERE    master_pkey = ?
        ORDER BY unredeemed_unix_ts_ms DESC, id DESC
    ''', (bytes(master_pkey),))

    result.payments_it    = typing.cast(collections.abc.Iterator[SQLTablePaymentRowTuple], tx.cursor)
    return result;

def _user_from_row_iterator(row: UserRowIterator) -> UserRow:
    result                           = UserRow()
    result.found                     = True
    result.master_pkey               = row[0]
    result.gen_index                 = row[1]
    result.expiry_unix_ts_ms         = row[2]
    result.grace_period_duration_ms  = row[3]
    result.auto_renewing             = bool(row[4])
    result.refund_request_unix_ts_ms = row[5]
    return result

def get_users_list(sql_conn: sqlite3.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('SELECT master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, refund_request_unix_ts_ms FROM users')
        rows = typing.cast(collections.abc.Iterator[UserRowIterator], tx.cursor)
        for row in rows:
            result.append(_user_from_row_iterator(row))
    return result;

def get_user_from_sql_tx(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    assert tx.cursor is not None
    _               = tx.cursor.execute('SELECT master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, refund_request_unix_ts_ms FROM users WHERE master_pkey = ?', (bytes(master_pkey),))
    result: UserRow = UserRow()
    row             = typing.cast(UserRowIterator | None, tx.cursor.fetchone())
    if row:
        result = _user_from_row_iterator(row)
    return result;

def get_user(sql_conn: sqlite3.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    with base.SQLTransaction(sql_conn) as tx:
        result = get_user_from_sql_tx(tx, master_pkey)
    return result;

def get_revocations_list(sql_conn: sqlite3.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _    = tx.cursor.execute('SELECT * FROM revocations')
        rows = typing.cast(collections.abc.Iterator[tuple[int, int]], tx.cursor)
        for row in rows:
            item                   = RevocationRow()
            item.gen_index         = row[0]
            item.expiry_unix_ts_ms = row[1]
            result.append(item)
    return result;

def is_gen_index_revoked_tx(sql_conn: sqlite3.Connection, gen_index : int) -> bool:
    result = False
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _  = tx.cursor.execute('SELECT 1 FROM revocations WHERE gen_index = ?', (gen_index,))
        row: tuple[int] | None = typing.cast(tuple[int] | None, tx.cursor.fetchone())
        result                 = row is not None
    return result

def get_revocation_ticket(sql_conn: sqlite3.Connection) -> int:
    result: int = 0
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _      = tx.cursor.execute('SELECT revocation_ticket FROM runtime')
        result = typing.cast(tuple[int], tx.cursor.fetchone())[0]
    return result;


def get_pro_revocations_iterator(tx: base.SQLTransaction) -> collections.abc.Iterator[tuple[int, int]]:
    assert tx.cursor is not None
    _      = tx.cursor.execute('SELECT gen_index, expiry_unix_ts_ms FROM revocations')
    result = typing.cast(collections.abc.Iterator[tuple[int, int]], tx.cursor)
    return result;

def get_runtime_tx(tx: base.SQLTransaction) -> RuntimeRow:
    assert tx.cursor is not None
    _                                                = tx.cursor.execute('SELECT gen_index, gen_index_salt, backend_key, last_expire_unix_ts_ms, apple_notification_checkpoint_unix_ts_ms, revocation_ticket FROM runtime')
    row                                              = typing.cast(tuple[int, bytes, bytes, int, int, int], tx.cursor.fetchone())
    result: RuntimeRow                               = RuntimeRow()
    result.gen_index                                 = row[0]
    result.gen_index_salt                            = row[1]
    backend_key: bytes                               = row[2]
    assert len(backend_key)                         == len(ZERO_BYTES32)
    result.backend_key                               = nacl.signing.SigningKey(backend_key)
    result.apple_notification_checkpoint_unix_ts_ms  = row[3]
    result.apple_notification_checkpoint_unix_ts_ms  = row[4]
    result.revocation_ticket                         = row[5]
    return result;


def get_runtime(sql_conn: sqlite3.Connection) -> RuntimeRow:
    result: RuntimeRow = RuntimeRow()
    with base.SQLTransaction(sql_conn) as tx:
        result = get_runtime_tx(tx)
    return result;

def db_info_string(sql_conn: sqlite3.Connection, db_path: str, err: base.ErrorSink) -> str:
    unredeemed_payments             = 0
    payments                        = 0
    users                           = 0
    revocations                     = 0
    db_size                         = 0
    user_errors                     = 0
    apple_notification_uuid_history = 0
    google_notification_history     = 0
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        try:
            _                               = tx.cursor.execute('SELECT COUNT(*) FROM payments WHERE status = ?', (int(base.PaymentStatus.Unredeemed.value),))
            unredeemed_payments             = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM payments')
            payments                        = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM users')
            users                           = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM revocations')
            revocations                     = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM user_errors')
            user_errors                     = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM apple_notification_uuid_history')
            apple_notification_uuid_history = typing.cast(tuple[int], tx.cursor.fetchone())[0];

            _                               = tx.cursor.execute('SELECT COUNT(*) FROM google_notification_history')
            google_notification_history     = typing.cast(tuple[int], tx.cursor.fetchone())[0];
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
            '  U.Errors/Google/Apple Notifs.:    {}/{}/{}\n'.format(user_errors, google_notification_history, apple_notification_uuid_history) +
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
                gen_index INTEGER NOT NULL,

                -- Timestamp that the latest subscriptions for the user expires. This might be in the
                -- past for elapsed payments. This timestamp is inclusive of the grace period and
                -- is consequently updated every time the user toggles their subscription
                -- auto-renewing preferences.
                --
                -- This timestamp is used to determine the deadline for which a Session Pro proof
                -- can be generated for a user, after the time has elapsed the user is no longer
                -- eligible for a proof signed by the backend and the user will naturally be
                -- vacuumed by the DB once the expiry job executes.
                expiry_unix_ts_ms        INTEGER NOT NULL,

                -- Duration that a user is entitled to for their grace period. This value is to be
                -- ignored if `auto_renewing` is false. It can be used to calculate the subscription
                -- expiry timestamp by subtracting `expiry_unix_ts_ms` from this value.
                grace_period_duration_ms INTEGER NOT NULL,

                auto_renewing            INTEGER NOT NULL,

                -- See the comment on this field in the payments table
                refund_request_unix_ts_ms INTEGER NOT NULL
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
                -- Last time the DB has successfully handled notifications up to. This is to be used
                -- to determine the start date to retrieve notifications from when starting up the
                -- DB to catch out on missed notifications (e.g. downtime due to maintenance or
                -- outages)
                apple_notification_checkpoint_unix_ts_ms INTEGER NOT NULL,
                revocation_ticket                        INTEGER NOT NULL  -- Monotonic index incremented when a revocation is added or removed
            );

            -- Track notifications that we have processed from Apple by their UUID. We need this for
            -- robustness. One, we can miss notifications from Apple due to downtime e.g. planned
            -- maintenance in which case, Apple will retry the notification with an exponential
            -- backoff:
            --
            -- > For version 2 notifications, it retries five times, at 1, 12, 24, 48, and 72 hours after the previous attempt.
            --
            -- Alternatively, the backend on startup will query for missed notifications and try to
            -- catch up on its own. It will store the UUIDs of the notifications it has processed
            -- so that if the notification is re-attempted, it will be a no-op if we've already
            -- processed it ourselves.
            --
            -- The other scenario is that the backend may experience network connectivity issue and
            -- our acknowledgement of the notification may fail whilst having already processed the
            -- notification. In that case, Apple will similarly retry the notification and we need
            -- to no-op in that situation as well. This is all managed in this table.
            CREATE TABLE IF NOT EXISTS apple_notification_uuid_history (
                uuid              STRING NOT NULL,
                expiry_unix_ts_ms INTEGER NOT NULL
            );

            -- Track notifications that we have successfully and failed to process from Google by
            -- its message ID. Similar to Apple, if we have network failure we may receive repeated
            -- notifications that we should ignore. Google tries to maintain a consistent delivery
            -- order but there is no guarantee. Unlike Apple, there's no API to query missed
            -- notifications in which case we have to store these notifications we saw ourselves.
            --
            -- The notification payload is wiped once the notification has been handled and we hold
            -- onto the notifications until it has been handled AND the expiry timestamp has
            -- elapsed.
            --
            -- For Google the expiry is configured on the Google Cloud Pub/Sub interface and is
            -- currently set to 7 days with an exponential backoff. On startup the unhandled
            -- notifications are loaded into the runtime queue and re-attemped.
            --
            -- Typically if a notification fails, it might be because the notifications came out of
            -- order and there's an earlier one that needs to be processed before proceeding. This
            -- table persists those failed notifications across restarts as well as ensuring that
            -- with exponential backoff, there's time inbetween to allow late notifications to
            -- arrive, be sorted into emit order and executed in order.
            CREATE TABLE IF NOT EXISTS google_notification_history (
                message_id        INTEGER NOT NULL,
                handled           INTEGER NOT NULL,
                payload           TEXT,
                expiry_unix_ts_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_errors (
                payment_id       STRING  NOT NULL,
                payment_provider INTEGER NOT NULL,
                unix_ts_ms       INTEGER NOT NULL,
                UNIQUE(payment_id, payment_provider)
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
            # NOTE: Bootstrap tables
            _ = tx.cursor.executescript(sql_stmt)
            _ = tx.cursor.execute('''PRAGMA journal_mode=WAL''')

            # NOTE: Version migration
            target_db_version = 4
            if 1:
                db_version: int = tx.cursor.execute('PRAGMA user_version').fetchone()[0]  # pyright: ignore[reportAny]

                # NOTE: v0 is the nil state, it means the DB has never been bootstrapped. All the
                # tables will have been created with the latest schema so we teleport to the target
                # version
                if db_version == 0:
                    db_version = target_db_version
                    _          = tx.cursor.execute(f'PRAGMA user_version = {db_version}')

                if db_version == 1:
                    log.info(f'Migrating DB version from {db_version} => {db_version + 1}')
                    _ = tx.cursor.executescript('''
                        DROP TABLE user_errors;
                        CREATE TABLE IF NOT EXISTS user_errors (
                            payment_id       STRING  NOT NULL,
                            payment_provider INTEGER NOT NULL,
                            unix_ts_ms       INTEGER NOT NULL,
                            UNIQUE(payment_id, payment_provider)
                        );
                    ''')
                    db_version += 1 # NOTE: Bump the version
                    _           = tx.cursor.execute(f'PRAGMA user_version = {db_version}')

                if db_version == 2:
                    log.info(f'Migrating DB version from {db_version} => {db_version + 1}')
                    _ = tx.cursor.executescript('''
                        DROP TABLE google_notification_history;
                        CREATE TABLE IF NOT EXISTS google_notification_history (
                            message_id        INTEGER NOT NULL,
                            handled           INTEGER NOT NULL,
                            payload           TEXT,
                            expiry_unix_ts_ms INTEGER NOT NULL
                        );
                    ''')
                    db_version += 1 # NOTE: Bump the version
                    _           = tx.cursor.execute(f'PRAGMA user_version = {db_version}')

                if db_version == 3:
                    log.info(f'Migrating DB version from {db_version} => {db_version + 1}')
                    _ = tx.cursor.executescript('''
                        ALTER TABLE payments
                        ADD COLUMN refund_request_unix_ts_ms INTEGER NOT NULL DEFAULT 0;

                        ALTER TABLE users
                        ADD COLUMN refund_request_unix_ts_ms INTEGER NOT NULL DEFAULT 0
                    ''')
                    db_version += 1 # NOTE: Bump the version
                    _           = tx.cursor.execute(f'PRAGMA user_version = {db_version}')

                # NOTE: Verify that the DB was migrated to the target version
                assert db_version == target_db_version

            # NOTE: Initialise the runtime row (app global settings) with the default values
            if 1:
                _                  = tx.cursor.execute('SELECT EXISTS (SELECT 1 FROM runtime) as row_exists')
                runtime_row_exists = bool(typing.cast(tuple[int], tx.cursor.fetchone())[0])
                if not runtime_row_exists:
                    if backend_key == None:
                        backend_key = nacl.signing.SigningKey.generate()

                    _ = tx.cursor.execute('''
                        INSERT INTO runtime
                        SELECT 0, ?, ?, 0, 0, 0
                    ''', (os.urandom(hashlib.blake2b.SALT_SIZE), bytes(backend_key)))

            result.success = True
        except Exception:
            err.msg_list.append(f"Failed to bootstrap DB tables: {traceback.format_exc()}")

    if result.success:
        result.runtime = get_runtime(result.sql_conn)
    else:
        result.sql_conn.close()

    return result

def verify_db(sql_conn: sqlite3.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(sql_conn)
    for index, it in enumerate(unredeemed_payments):
        base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}')
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Unredeemed payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')

    # NOTE: Wednesday, 27 August 2025 00:00:00, arbitrary date in the past that PRO cannot
    # possibly be before. We should update this to to the PRO release date.
    PRO_ENABLED_UNIX_TS: int = 1756252800

    payments: list[PaymentRow] = get_payments_list(sql_conn)
    for index, it in enumerate(payments):
        # NOTE: Check mandatory fields
        if it.plan == base.ProPlan.Nil: 
            err.msg_list.append(f'{it.status.name} payment #{index} plan is invalid. It should have been derived from the platform payment provider (e.g. by converting the unredeemedd product ID to a plan)')
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(f'{it.status.name} payment #{index} payment provider is set to {it.payment_provider.name} but it should not be. It should have been set by the platform before added to the DB')

        # NOTE: Check mandatory fields or invariants given a particular TX status
        if it.status == base.PaymentStatus.Nil:
            err.msg_list.append(f'Payment #{index} specified a "nil" status which is invalid and should not be in the DB')
        elif it.status == base.PaymentStatus.Unredeemed:
            # NOTE: Check that most fields of the payment should not be set yet when it has not been
            # redeemed yet
            if it.master_pkey != ZERO_BYTES32:
                err.msg_list.append(f'{it.status.name} payment #{index} has a master pkey set but this pkey should not be set until it is redeemed (e.g. the user registers it)')
            if it.expiry_unix_ts_ms == 0:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was 0. Expiry should be set when payment was unredeemed')
            if it.redeemed_unix_ts_ms:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was {it.redeemed_unix_ts_ms}. The payment is not redeemed yet so it should be 0')
            if it.revoked_unix_ts_ms:
                err.msg_list.append(f'{it.status.name} payment #{index} revoked ts was {it.revoked_unix_ts_ms}. The payment is not refunded yet so it should be 0')

        elif it.status == base.PaymentStatus.Redeemed:
            # NOTE: Check that the redeemed ts is set
            if not it.redeemed_unix_ts_ms:
                err.msg_list.append(f'{it.status.name} payment #{index} redeemed ts was not set. The payment is redeemed so it should be non-zero')

            # NOTE: Check that expired ts was not set. Note revoked could be set as we can cancel a
            # revoked back into a redeemed state
            if it.expiry_unix_ts_ms == 0:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was 0. Expiry should be set when payment was unredeemed')

        elif it.status == base.PaymentStatus.Expired:
            # NOTE: Expired must be set
            if it.expiry_unix_ts_ms == 0:
                err.msg_list.append(f'{it.status.name} payment #{index} expired ts was 0. Expiry should be set when payment was unredeemed')

            # NOTE: Check that payment was expired AFTER it was redeemed
            if it.expiry_unix_ts_ms > 0:
              if it.redeemed_unix_ts_ms and it.expiry_unix_ts_ms < it.redeemed_unix_ts_ms:
                  redeemed_date = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_ms/1000).strftime('%Y-%m-%d')
                  expiry_date   = datetime.datetime.fromtimestamp(it.expiry_unix_ts_ms/1000).strftime('%Y-%m-%d')
                  err.msg_list.append(f'{it.status.name} payment #{index} was expired ({expiry_date}) before it was activated ({redeemed_date})')

        elif it.status == base.PaymentStatus.Revoked:
            # NOTE: Any payment can transition into the revoked state given any status (except for
            # nil, which is the invalid state). This means that all fields could be set so only a
            # few checks are needed here.
            if not it.revoked_unix_ts_ms:
                err.msg_list.append(f'{it.status.name} payment #{index} revoked ts was not set. The payment is refunded so it should be non-zero')

        # NOTE: Verify the plan, it should always be set once it enters the DB..
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')
        base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the payment's redeemed ts is a reasonable value
        if it.redeemed_unix_ts_ms and it.redeemed_unix_ts_ms < PRO_ENABLED_UNIX_TS:
          date_str = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_ms/1000).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a creation date before PRO was enabled: {it.redeemed_unix_ts_ms} ({date_str})')

        # NOTE: Check that the token is set correctly
        if it.payment_provider == base.PaymentProvider.GooglePlayStore:
            pass
        elif len(it.google_payment_token) != 0:
            err.msg_list.append(f'Payment #{index} speceified a google payment token: {it.google_payment_token} for a non-google platform')

    # NOTE: Verify the users
    users: list[UserRow] = get_users_list(sql_conn)
    for index, it in enumerate(users):
        if it.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')
        if it.expiry_unix_ts_ms < PRO_ENABLED_UNIX_TS:
          expiry_date_str = datetime.datetime.fromtimestamp(it.expiry_unix_ts_ms/1000).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a expiry date before PRO was enabled: {it.expiry_unix_ts_ms} ({expiry_date_str})')

    result = len(err.msg_list) == 0
    return result

def _update_user_expiry_grace_and_renew_flag_from_payment_list(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    assert tx.cursor
    master_pkey_bytes: bytes = bytes(master_pkey)
    lookup: LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table(tx,
                                                                                                     nacl.signing.VerifyKey(master_pkey_bytes))
    # NOTE: We have the latest expiry value, now update the user
    _ = tx.cursor.execute('''
        UPDATE users
        SET    expiry_unix_ts_ms = ?, grace_period_duration_ms = ?, auto_renewing = ?
        WHERE  master_pkey = ?
    ''', (lookup.best_expiry_unix_ts_ms, lookup.best_grace_duration_ms, lookup.best_auto_renewing, master_pkey_bytes))

def revoke_payments_by_id_internal(tx: base.SQLTransaction, rows: list[AddRevocationIterator], revoke_unix_ts_ms: int) -> bool:
    assert tx.cursor
    result                             = False
    master_pkey_dict: dict[bytes, int] = {}
    for row in  rows:
        result                          = True
        id:                int          = row[0]
        master_pkey_bytes: bytes | None = row[1]
        expiry_unix_ts_ms: int          = row[2]

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expiry_unix_ts_ms

        # NOTE: Mark all the payments as revoked
        _ = tx.cursor.execute(f'''
        UPDATE payments
        SET    status = ?, revoked_unix_ts_ms = ?, auto_renewing = 0
        WHERE  id = ? AND (status == ? OR status = ?)
        ''', (# SET values
              int(base.PaymentStatus.Revoked.value),
              revoke_unix_ts_ms,
              # WHERE values
              id,
              int(base.PaymentStatus.Unredeemed.value),
              int(base.PaymentStatus.Redeemed.value)))

    revoke_unix_ts_ms_next_day = round_unix_ts_ms_to_next_day_with_platform_testing_support(base.PaymentProvider.iOSAppStore, revoke_unix_ts_ms)
    for it in master_pkey_dict:
        # NOTE: For each user we revoked a payment for, we have modified their 'auto_renewing' value
        # on the payment, we need to go and update their user row to track the, new, next best
        # expiry time so that the backend knows the new time-frame in which the user is allowed to
        # generate a Session Pro proof (now that one or more of their payments get revoked)
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, nacl.signing.VerifyKey(it))

        # NOTE: expiry_unix_ts_ms in the db is not rounded, but the proof's themselves have an
        # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
        # proofs that aren't going to self-expire by the end of the day.
        #
        # For different platforms in their testing environments, they have different timespans
        # for a day, for example in Google 1 day is 10s. We handle that explicitly here.

        expiry_unix_ts_ms = master_pkey_dict[it]
        if expiry_unix_ts_ms > revoke_unix_ts_ms_next_day:
            master_pkey = nacl.signing.VerifyKey(it)
            _ = revoke_master_pkey_proofs_and_allocate_new_gen_id(tx, master_pkey)

    return result

def add_apple_revocation_tx(tx: base.SQLTransaction, apple_original_tx_id: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""
    assert tx.cursor
    # TODO: Can be cleaned up more, a lot of repeated code between apple and google here, but it
    # works fine. Also, this code is very platform specific, potentially the grabbing of IDs should
    # happen in the platform layers and then the backend only deals with IDs. Potentially separating
    # such platform specific implementation concerns to the requisite platforms.

    # NOTE: Select the newest apple transaction that has been redeemed or not. apple only gives us
    # the original TX ID token in the scenarios that we call this function.
    #
    # From there we need to find the previous plan using this ID which is shared across all payments
    # by the user which we can do by finding the newest most payment that is still valid to be used.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    _ = tx.cursor.execute(f'''
    SELECT id, master_pkey, expiry_unix_ts_ms
    FROM   payments
    WHERE  apple_original_tx_id  = ? AND
           payment_provider      = ? AND
           (status               = ? OR status = ? OR status = ? OR status = ?);
    ''', (# WHERE values
          apple_original_tx_id,
          int(base.PaymentProvider.iOSAppStore.value),
          # OR status == ?
          int(base.PaymentStatus.Unredeemed.value),
          int(base.PaymentStatus.Redeemed.value),
          int(base.PaymentStatus.Expired.value),
          int(base.PaymentStatus.Revoked.value),))

    log.info(f'Revoking Apple payment (orig. TX ID={apple_original_tx_id}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows         = typing.cast(list[AddRevocationIterator], tx.cursor.fetchall())
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Apple orig. TX ID {apple_original_tx_id} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def add_google_revocation_tx(tx: base.SQLTransaction, google_payment_token: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""
    assert tx.cursor

    # NOTE: Select the newest google transaction that has been redeemed or not. Google only gives us
    # the purchase token in the scenarios that we call this function.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    _ = tx.cursor.execute(f'''
    SELECT id, master_pkey, expiry_unix_ts_ms
    FROM   payments
    WHERE  google_payment_token = ? AND
           payment_provider     = ? AND
           (status              = ? OR status = ? OR status = ? OR status = ?)
    ''', (# WHERE values
          google_payment_token,
          int(base.PaymentProvider.GooglePlayStore.value),
          # OR status == ?
          int(base.PaymentStatus.Unredeemed.value),
          int(base.PaymentStatus.Redeemed.value),
          int(base.PaymentStatus.Expired.value),
          int(base.PaymentStatus.Revoked.value),))

    log.info(f'Revoking Google payment (token={google_payment_token}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows = typing.cast(list[AddRevocationIterator], tx.cursor.fetchall())
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Google payment {google_payment_token} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def redeem_payment_tx(tx:                  base.SQLTransaction,
                      master_pkey:         nacl.signing.VerifyKey,
                      rotating_pkey:       nacl.signing.VerifyKey | None,
                      signing_key:         nacl.signing.SigningKey | None,
                      unix_ts_ms:          int,
                      redeemed_unix_ts_ms: int,
                      payment_tx:          UserPaymentTransaction,
                      err:                 base.ErrorSink) -> RedeemPayment:
    """
    unix_ts_ms: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_unix_ts_ms: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'convert_unix_ts_ms_to_redeemed_unix_ts_ms' to
    #mask metadata about the time the user redeemed the payment.
    """

    assert tx.cursor is not None
    result                   = RedeemPayment()
    result.status            = RedeemPaymentStatus.Error

    master_pkey_bytes: bytes = bytes(master_pkey)
    fields                   = ['master_pkey = ?', 'status = ?', 'redeemed_unix_ts_ms = ?']
    set_expr                 = ', '.join(fields) # Create '<field0> = ?, <field1> = ?, ...'

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label    = _add_pro_payment_user_tx_log_label(payment_tx)
        rotating_pkey_label = bytes(rotating_pkey).hex() if rotating_pkey else '(none)'
        log.info(f'Redeeming payment (master={bytes(master_pkey).hex()}, rotating={rotating_pkey_label}, redeemed={base.readable_unix_ts_ms(redeemed_unix_ts_ms)}, payment={payment_tx_label})')

    # NOTE: We technically always allow a redeem of an unredeemed payment as long as the user
    # knows the transaction ID (payment token/tx ID). If for example the user sits on the
    # payment and doesn't redeem it and it expires but the expiry task hasn't been run yet, the
    # user can still redeem the payment, they won't be allowed to use the proof because it has
    # expired, but, they can register their public key for the payment and associate it with
    # their account.
    #
    # The payment will now show up in their cross-platform payment history and visible across
    # all the Session devices they have.
    #
    # TODO: What if the payment was expired and it has no master public key? Following the same
    # train of thought it would be nice to let the user claim that payment so that they have
    # the ability to maintain proper-book-keeping, but it's not clear to me if its even possible
    # for that to happen. Maybe more realistically a payment could get revoked before it was
    # redeemed and it'd be nice to allow the user to claim it and get it attributed to their
    # account.
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        _ = tx.cursor.execute(f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  payment_provider = ? AND google_payment_token = ? AND google_order_id = ? AND status = ?
        ''', (# SET values
              master_pkey_bytes,
              int(base.PaymentStatus.Redeemed.value),
              redeemed_unix_ts_ms,
              # WHERE values
              int(payment_tx.provider.value),
              payment_tx.google_payment_token,
              payment_tx.google_order_id,
              int(base.PaymentStatus.Unredeemed.value)))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        _ = tx.cursor.execute(f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  payment_provider = ? AND apple_tx_id = ? AND status = ?
        ''', (# SET fields
              master_pkey_bytes,
              int(base.PaymentStatus.Redeemed.value),
              redeemed_unix_ts_ms,
              # WHERE fields
              int(payment_tx.provider.value),
              payment_tx.apple_tx_id,
              int(base.PaymentStatus.Unredeemed.value)))
    else:
        err.msg_list.append('Payment to register specifies an unknown payment provider')

    if tx.cursor.rowcount >= 1:
        assert tx.cursor.rowcount == 1
        if tx.cursor.rowcount > 1:
            err.msg_list.append(f'Payment was redeemed for {master_pkey} at {redeemed_unix_ts_ms/1000} but more than 1 row was updated, updated {tx.cursor.rowcount}')

        # NOTE: Payment has been registered, give the user a new generation index. Subsequent
        # proofs will be given a new gen index hash. We used to revoke the old gen index hash
        # but there's no need for that and creates churn in the revoke list. The user will hold
        # onto their proof until it expires and simply request a new one.
        #
        # The key change leading to not requiring a revoke is that we separated the idea that a
        # proof is related to, but not representative of a user's pro payment information (e.g.
        #the proof expiry may or may not co-incide with the pro-plan they are entitled to).
        allocated: AllocatedGenID = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey)
        if allocated.found:
            # NOTE: Only generate the proof if a rotating public key otherwise skip it (i.e.
            # its possible to redeem a payment without automatically creating the corresponding proof)
            if rotating_pkey:
                assert signing_key, "Rotating public key and signing key have to be given in tandem, either both set or both set to nil"
                proposed_proof_expiry_unix_ts_ms: int = base.round_unix_ts_ms_to_next_day(allocated.expiry_unix_ts_ms)
                if base.DEV_BACKEND_MODE:
                    proposed_proof_expiry_unix_ts_ms = allocated.expiry_unix_ts_ms

                result.proof = build_proof(gen_index         = allocated.gen_index,
                                           rotating_pkey     = rotating_pkey,
                                           expiry_unix_ts_ms = _build_proof_clamped_expiry_time(unix_ts_ms=unix_ts_ms, proposed_expiry_unix_ts_ms=proposed_proof_expiry_unix_ts_ms),
                                           signing_key       = signing_key,
                                           gen_index_salt    = allocated.gen_index_salt)

                if not base.DEV_BACKEND_MODE:
                    assert result.proof.expiry_unix_ts_ms % base.SECONDS_IN_DAY == 0, f"Proof expiry must be on a day boundary, 30 days, 365 days ...e.t.c, was {result.proof.expiry_unix_ts_ms}"
        else:
            err.msg_list.append(f'Failed to update DB after new payment was redeemed for {master_pkey}')

        assert allocated.found, "We just added the user's payment we expect to find the latest expiry date for the pkey"

    else:
        # NOTE: We dump the payment TX to the error list. This does not leak
        # any information because this is all data populated by the user who
        # is sending the redeeming request.
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            _ = tx.cursor.execute(f'''
                SELECT COUNT(*) FROM payments WHERE payment_provider = ? AND google_payment_token = ? AND google_order_id = ? AND status > ? AND master_pkey = ?
            ''', (int(payment_tx.provider.value), payment_tx.google_payment_token, payment_tx.google_order_id, int(base.PaymentStatus.Unredeemed.value), master_pkey_bytes))
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            _ = tx.cursor.execute(f'''
                SELECT COUNT(*) FROM payments WHERE payment_provider = ? AND apple_tx_id = ? AND status > ? AND master_pkey = ?
            ''', (int(payment_tx.provider.value), payment_tx.apple_tx_id, int(base.PaymentStatus.Unredeemed.value), master_pkey_bytes))

        if tx.cursor.fetchone()[0] > 0:
            err.msg_list.append(f'Payment was not redeemed, already redeemed TX: {payment_tx}')
            result.status = RedeemPaymentStatus.AlreadyRedeemed
        else:
            err.msg_list.append(f'Payment was not redeemed, no payments were found matching the request tx: {payment_tx}')
            result.status = RedeemPaymentStatus.UnknownPayment

    if not err.has():
        assert result.status == RedeemPaymentStatus.Error
        result.status = RedeemPaymentStatus.Success

    return result

def verify_payment_provider_tx(payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink):
    base.verify_payment_provider(payment_tx.provider, err)
    match payment_tx.provider:
        case base.PaymentProvider.GooglePlayStore:
            if len(payment_tx.google_order_id) == 0:
                err.msg_list.append(f'Google order id was not set')
            if len(payment_tx.google_payment_token) == 0:
                err.msg_list.append(f'Google payment token was not set')
        case base.PaymentProvider.iOSAppStore:
            if len(payment_tx.apple_tx_id) == 0:
                err.msg_list.append(f'Apple TX ID was not set')
            if len(payment_tx.apple_original_tx_id) == 0:
                err.msg_list.append(f'Apple original TX ID was not set')
        case base.PaymentProvider.Nil:
            err.msg_list.append(f'Payment provider was set invalidly to nil')

def _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiryUnixTsMs:
    assert tx.cursor

    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    _ = tx.cursor.execute(f'''
        SELECT    expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, status, payment_provider, refund_request_unix_ts_ms
        FROM      payments
        WHERE     master_pkey = ? AND (status = ? OR status = ? OR status = ?)
    ''', (bytes(master_pkey),
          int(base.PaymentStatus.Redeemed.value),
          int(base.PaymentStatus.Revoked.value),
          int(base.PaymentStatus.Expired.value),))

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result = LookupUserExpiryUnixTsMs()
    rows = typing.cast(list[tuple[int, int, int, int, int, int]], tx.cursor.fetchall())
    for row in rows:
        expiry_unix_ts_ms:         int                  = row[0]
        grace_period_duration_ms:  int                  = row[1]
        auto_renewing:             int                  = row[2]
        status:                    int                  = row[3]
        payment_provider:          base.PaymentProvider = base.PaymentProvider(row[4])
        refund_request_unix_ts_ms: int                  = row[5]

        # NOTE: A revoke does not round the timestamp to EOD, it's effective immediately so we use
        # the expiry time verbatim
        payment_expiry_unix_ts_ms: int = 0
        if status == base.PaymentStatus.Revoked.value:
            assert auto_renewing == False
            payment_expiry_unix_ts_ms = expiry_unix_ts_ms
        else:
            payment_expiry_unix_ts_ms = round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider, expiry_unix_ts_ms)

        if auto_renewing:
            payment_expiry_unix_ts_ms += grace_period_duration_ms

        if status == base.PaymentStatus.Redeemed:
            if payment_expiry_unix_ts_ms > result.expiry_unix_ts_ms_from_redeemed:
                result.expiry_unix_ts_ms_from_redeemed         = payment_expiry_unix_ts_ms
                result.grace_duration_ms_from_redeemed         = grace_period_duration_ms
                result.refund_request_unix_ts_ms_from_redeemed = refund_request_unix_ts_ms
                result.auto_renewing_from_redeemed             = bool(auto_renewing)

        elif status == base.PaymentStatus.Expired or status == base.PaymentStatus.Revoked:
            if payment_expiry_unix_ts_ms > result.expiry_unix_ts_ms_from_expired_or_revoked:
                result.expiry_unix_ts_ms_from_expired_or_revoked         = payment_expiry_unix_ts_ms
                result.grace_duration_ms_from_expired_or_revoked         = grace_period_duration_ms
                result.refund_request_unix_ts_ms_from_expired_or_revoked = refund_request_unix_ts_ms
                result.auto_renewing_from_expired_or_revoked             = bool(auto_renewing)
        else:
            assert False, f"Invalid code path, unhandled PaymentStatus value ({status})"

    if result.expiry_unix_ts_ms_from_redeemed > result.grace_duration_ms_from_expired_or_revoked:
        result.best_expiry_unix_ts_ms         = result.expiry_unix_ts_ms_from_redeemed
        result.best_grace_duration_ms         = result.grace_duration_ms_from_redeemed
        result.best_auto_renewing             = result.auto_renewing_from_redeemed
        result.best_refund_request_unix_ts_ms = result.refund_request_unix_ts_ms_from_redeemed
    else:
        result.best_expiry_unix_ts_ms         = result.expiry_unix_ts_ms_from_expired_or_revoked
        result.best_grace_duration_ms         = result.grace_duration_ms_from_expired_or_revoked
        result.best_auto_renewing             = result.auto_renewing_from_expired_or_revoked
        result.best_refund_request_unix_ts_ms = result.refund_request_unix_ts_ms_from_expired_or_revoked
    return result

def update_payment_renewal_info_tx(tx:                       base.SQLTransaction,
                                   payment_tx:               base.PaymentProviderTransaction,
                                   grace_period_duration_ms: int  | None,
                                   auto_renewing:            bool | None,
                                   err:                      base.ErrorSink) -> bool:
    """
    Update a payment's grace period and/or auto renewing flag. Pass in `None` for the arguments
    you want to opt out of updating.
    """

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Update renewal info (payment={payment_tx_label}, grace period ms={grace_period_duration_ms}, auto_renewing={auto_renewing})')

    result = False
    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return result

    if grace_period_duration_ms is None and auto_renewing is None:
        result = True
        return result

    # NOTE: Generate the fields to write to matching payment in the DB
    sql_execute_args: list[typing.Any] = []
    sql_set_fields:   str              = ''
    if auto_renewing is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'auto_renewing = ?'
        sql_execute_args.append(int(auto_renewing))

    if grace_period_duration_ms is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'grace_period_duration_ms = ?'
        sql_execute_args.append(grace_period_duration_ms)

    # NOTE: Execute the statement
    assert tx.cursor is not None
    match payment_tx.provider:
        case base.PaymentProvider.Nil:
            pass

        case base.PaymentProvider.GooglePlayStore:
            _ = tx.cursor.execute(f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     google_payment_token = ? AND google_order_id = ?
                RETURNING master_pkey
            ''', (*tuple(sql_execute_args), payment_tx.google_payment_token, payment_tx.google_order_id))

        case base.PaymentProvider.iOSAppStore:
            _ = tx.cursor.execute(f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     apple_original_tx_id = ? AND apple_tx_id = ? AND apple_web_line_order_tx_id = ?
                RETURNING master_pkey
            ''', (*tuple(sql_execute_args), payment_tx.apple_original_tx_id, payment_tx.apple_tx_id, payment_tx.apple_web_line_order_tx_id))

    # NOTE: Having `RETURNING master_pkey` seems to break tx.cursor.rowcount and returns 0 even on
    # row modification. We use fetchone instead
    row    = typing.cast(tuple[bytes] | None, tx.cursor.fetchone())
    result = row is not None

    # NOTE: Update the user's expiry to the latest known expiry
    if row and row[0]:
        master_pkey_bytes: bytes = row[0]
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    if result == False:
        payment_id = payment_tx.google_order_id if payment_tx.provider == base.PaymentProvider.GooglePlayStore else payment_tx.apple_tx_id
        err.msg_list.append(f'Updating payment TX failed, no matching payment found for {payment_tx.provider.name} {payment_id}')
    return result

def update_payment_renewal_info(sql_conn:                 sqlite3.Connection,
                                payment_tx:               base.PaymentProviderTransaction,
                                grace_period_duration_ms: int  | None,
                                auto_renewing:            bool | None,
                                err:                      base.ErrorSink) -> bool:

    result = False
    with base.SQLTransaction(sql_conn) as sql_tx:
        result = update_payment_renewal_info_tx(sql_tx, payment_tx, grace_period_duration_ms, auto_renewing, err)
    return result

def add_unredeemed_payment_tx(tx:                                base.SQLTransaction,
                              payment_tx:                        base.PaymentProviderTransaction,
                              plan:                              base.ProPlan,
                              expiry_unix_ts_ms:                 int,
                              unredeemed_unix_ts_ms:             int,
                              platform_refund_expiry_unix_ts_ms: int,
                              err:                               base.ErrorSink):

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Unredeemed payment (payment={payment_tx_label}, plan={plan.name}, expiry={base.readable_unix_ts_ms(expiry_unix_ts_ms)}, unredeemed={base.readable_unix_ts_ms(unredeemed_unix_ts_ms)}, refund={base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)})')

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    assert tx.cursor is not None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        # NOTE: Insert into the table, IFF, the payment token hash doesn't already exist in the
        # payments table
        _ = tx.cursor.execute(f'''
            SELECT 1
            FROM payments
            WHERE payment_provider = ? AND google_payment_token = ? AND google_order_id = ?
        ''', (int(payment_tx.provider.value), payment_tx.google_payment_token, payment_tx.google_order_id))

        record = tx.cursor.fetchone()
        if not record:
            fields      = ['plan',
                           'payment_provider',
                           'google_payment_token',
                           'google_order_id',
                           'status',
                           'expiry_unix_ts_ms',
                           'platform_refund_expiry_unix_ts_ms',
                           'grace_period_duration_ms',
                           'unredeemed_unix_ts_ms',
                           'auto_renewing',
                           'refund_request_unix_ts_ms']
            stmt_fields = ', '.join(fields)                 # Create '<field0>, <field1>, ...'
            stmt_values = ', '.join(['?' for _ in fields])  # Create '?,        ?,        ...'

            _ = tx.cursor.execute(f'''
                INSERT INTO payments ({stmt_fields})
                VALUES ({stmt_values})
            ''', (int(plan.value),
                  payment_tx.provider.value,
                  payment_tx.google_payment_token,
                  payment_tx.google_order_id,
                  int(base.PaymentStatus.Unredeemed.value),
                  expiry_unix_ts_ms,
                  platform_refund_expiry_unix_ts_ms,
                  0, # grace period (updated authoritatively by a Google notification when the user enters grace)
                  unredeemed_unix_ts_ms,
                  1, # auto_renewing is enabled by default until notified otherwise by Google
                  0, # refund request unix ts ms
                  ))

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
                WHERE payment_provider = ? AND apple_original_tx_id = ? AND apple_tx_id = ? AND apple_web_line_order_tx_id = ?
        ''', (int(payment_tx.provider.value),
              payment_tx.apple_original_tx_id,
              payment_tx.apple_tx_id,
              payment_tx.apple_web_line_order_tx_id))

        record = tx.cursor.fetchone()
        if not record:
            fields:      list[str] = ['plan',
                                      'payment_provider',
                                      'apple_original_tx_id',
                                      'apple_tx_id',
                                      'apple_web_line_order_tx_id',
                                      'status',
                                      'expiry_unix_ts_ms',
                                      'platform_refund_expiry_unix_ts_ms',
                                      'grace_period_duration_ms',
                                      'unredeemed_unix_ts_ms',
                                      'auto_renewing',
                                      'refund_request_unix_ts_ms']
            stmt_fields: str       = ', '.join(fields)                 # Create '<field0>, <field1>, ...'
            stmt_values: str       = ', '.join(['?' for _ in fields])  # Create '?,        ?,        ...'

            _ = tx.cursor.execute(f'''
                INSERT INTO payments ({stmt_fields})
                VALUES ({stmt_values})
            ''', (int(plan.value),
                  int(payment_tx.provider.value),
                  payment_tx.apple_original_tx_id,
                  payment_tx.apple_tx_id,
                  payment_tx.apple_web_line_order_tx_id,
                  int(base.PaymentStatus.Unredeemed.value),
                  expiry_unix_ts_ms,
                  platform_refund_expiry_unix_ts_ms,
                  0, # non-null grace_period_duration_ms
                  unredeemed_unix_ts_ms,
                  1, # auto_renewing is enabled by default until notified otherwise by Apple
                  0, # refund request unix ts ms
                  ))

    # NOTE: Find the latest master pkey associated with the common payment identifier (google payment
    # token or apple original tx id). Then find the user if it exists, if the user is still entitled
    # to Session Pro or is in grace, or in account hold, then, we've noticed a new payment for their
    # account.
    #
    # For UX we will automatically redeem the payment in this window and assign it to that public
    # key so that they automatically continue their Pro entitlement across the billing cycle without
    # needing their originating device to be on to "claim" the payment (because only the originating
    # device and the backend knows the confidential payment data it needs to provide to redeem).
    #
    # If the user is no outside of the account hold windows or cancelled their subscription then,
    # the next time they purchase a pro membership the Session account that the purchase was made
    # under will be the one that claims the initial payment. The auto-redeeming will be disabled
    # because the user is not in the auto-redeeming window.
    #
    # So the backend tries automatically redeem the payment on behalf of the user (if it seems
    # reasonable to do so according to that heuristic) for UX.
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        _ = tx.cursor.execute(f'''
            SELECT   master_pkey
            FROM     payments
            WHERE    payment_provider = ? AND google_payment_token = ? AND master_pkey IS NOT NULL
            ORDER BY id DESC
            LIMIT    1
        ''', (int(payment_tx.provider.value), payment_tx.google_payment_token))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        _ = tx.cursor.execute(f'''
            SELECT   master_pkey
            FROM     payments
            WHERE    payment_provider = ? AND apple_original_tx_id = ? AND master_pkey IS NOT NULL
            ORDER BY id DESC
            LIMIT    1
        ''', (int(payment_tx.provider.value), payment_tx.apple_original_tx_id))

    master_pkey_record = typing.cast(tuple[bytes] | None, tx.cursor.fetchone())
    if master_pkey_record and master_pkey_record[0]:
        master_pkey   = nacl.signing.VerifyKey(master_pkey_record[0])
        user: UserRow = get_user_from_sql_tx(tx, master_pkey)
        if user.found:
            auto_redeem_deadline_unix_ts_ms: int = 0

            # TODO: Handle the situation when a user cancels
            if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                # NOTE: Account hold as described by google
                #
                #   > [...] we’re increasing the default account hold duration on December 1, 2025.
                #   > Starting on this date, by default account hold durations will be automatically
                #   > calculated. Initially, the calculation will be 60 days minus any grace period
                #   > duration, but we may change these calculations in the future to further
                #   > improve recovery performance
                #
                # Source: https://support.google.com/googleplay/android-developer/answer/16631229
                auto_redeem_deadline_unix_ts_ms = user.expiry_unix_ts_ms
                if user.auto_renewing:
                    auto_redeem_deadline_unix_ts_ms += 60 * base.MILLISECONDS_IN_DAY - user.grace_period_duration_ms
            else:
                assert payment_tx.provider == base.PaymentProvider.iOSAppStore
                # NOTE: We don't currently configure a grace period/account hold period for Apple
                # hnote the grace and account hold concept is merged together in Apple).
                auto_redeem_deadline_unix_ts_ms = user.expiry_unix_ts_ms
                if user.auto_renewing:
                    auto_redeem_deadline_unix_ts_ms += user.grace_period_duration_ms

            # NOTE: Unredeemed unix timestamp represents now (as this is the timestamp we are marking
            # the payment as having been registered), so we compare (now) to the deadline. If we are
            # before the deadline we are eligible to auto-redeem this payment and assign it to the
            # previous known master public key.
            if unredeemed_unix_ts_ms <= auto_redeem_deadline_unix_ts_ms:
                add_pro_payment_user_tx                      = UserPaymentTransaction()
                add_pro_payment_user_tx.provider             = payment_tx.provider
                add_pro_payment_user_tx.apple_tx_id          = payment_tx.apple_tx_id
                add_pro_payment_user_tx.google_payment_token = payment_tx.google_payment_token
                add_pro_payment_user_tx.google_order_id      = payment_tx.google_order_id

                # NOTE: We use a temp error sink as we don't mind if auto-redeeming failed the user
                # can always try manually by claiming the payment themselves. If this errors
                # returning that to the platform layers (google and apple) can stall them
                # unnecessarily.
                #
                # For internal logging though however, we can report this
                tmp_err = base.ErrorSink()
                _ = redeem_payment_tx(tx                  = tx,
                                      master_pkey         = master_pkey,
                                      rotating_pkey       = None,
                                      signing_key         = None,
                                      unix_ts_ms          = unredeemed_unix_ts_ms,
                                      redeemed_unix_ts_ms = convert_unix_ts_ms_to_redeemed_unix_ts_ms(unredeemed_unix_ts_ms),
                                      payment_tx          = add_pro_payment_user_tx,
                                      err                 = tmp_err)

                if tmp_err.has():
                    err_str = '\n'.join(tmp_err.msg_list)
                    log.error(f'Failed to auto-redeem a payment we witnessed from. (auto_redeem_deadline={base.readable_unix_ts_ms(auto_redeem_deadline_unix_ts_ms)}) {err_str}')

def add_unredeemed_payment(sql_conn:                          sqlite3.Connection,
                           payment_tx:                        base.PaymentProviderTransaction,
                           plan:                              base.ProPlan,
                           expiry_unix_ts_ms:                 int,
                           unredeemed_unix_ts_ms:             int,
                           platform_refund_expiry_unix_ts_ms: int,
                           err:                               base.ErrorSink):
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        add_unredeemed_payment_tx(tx=tx,
                                  payment_tx=payment_tx,
                                  plan=plan,
                                  expiry_unix_ts_ms=expiry_unix_ts_ms,
                                  unredeemed_unix_ts_ms=unredeemed_unix_ts_ms,
                                  platform_refund_expiry_unix_ts_ms=platform_refund_expiry_unix_ts_ms,
                                  err=err)

def _allocate_new_gen_id_if_master_pkey_has_payments(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> AllocatedGenID:
    result:            AllocatedGenID = AllocatedGenID()
    master_pkey_bytes: bytes          = bytes(master_pkey)
    assert tx.cursor is not None

    lookup: LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table(tx, master_pkey)
    result.expiry_unix_ts_ms         = lookup.expiry_unix_ts_ms_from_redeemed
    if lookup.expiry_unix_ts_ms_from_redeemed > 0:
        # NOTE: Master pkey has a payment we can use. Allocate a new generation ID in the runtime table
        result.found = True
        _ = tx.cursor.execute('''
            UPDATE    runtime
            SET       gen_index = gen_index + 1
            RETURNING gen_index - 1, gen_index_salt
        ''')
        runtime_row           = typing.cast(tuple[int, bytes], tx.cursor.fetchone())
        result.gen_index      = runtime_row[0]
        result.gen_index_salt = runtime_row[1]

        # NOTE: Also update the user table with this payment we found that is currently the "best"
        # payment (e.g. the latest and most up to date payment and hence has the best expiry time)
        # for the user into their user record.
        #
        # This means that for the most part, consumers can just rely on the top level object to
        # determine the current state of the user subscription payment.
        _ = tx.cursor.execute('''
            INSERT INTO users (master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, refund_request_unix_ts_ms)
            VALUES            (?, ?, ?, ?, ?, ?)
            ON CONFLICT (master_pkey) DO UPDATE SET
                gen_index                 = excluded.gen_index,
                expiry_unix_ts_ms         = excluded.expiry_unix_ts_ms,
                grace_period_duration_ms  = excluded.grace_period_duration_ms,
                auto_renewing             = excluded.auto_renewing,
                refund_request_unix_ts_ms = excluded.refund_request_unix_ts_ms
        ''', (master_pkey_bytes,
              result.gen_index,
              lookup.best_expiry_unix_ts_ms,
              lookup.best_grace_duration_ms,
              lookup.best_auto_renewing,
              lookup.best_refund_request_unix_ts_ms))

    return result

def make_generate_pro_proof_hash(version:       int,
                            master_pkey:   nacl.signing.VerifyKey,
                            rotating_pkey: nacl.signing.VerifyKey,
                            unix_ts_ms:    int) -> bytes:
    '''Make the hash to sign for a pre-existing subscription by authorising
    a new rotating_pkey to be used for the Session Pro subscription associated
    with master_pkey'''
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def build_proof_hash(version:           int,
                     gen_index_hash:    bytes,
                     rotating_pkey:     nacl.signing.VerifyKey,
                     expiry_unix_ts_ms: int) -> bytes:
    '''Make the hash to the backend signs for to certify the proof'''
    hasher: hashlib.blake2b = make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(gen_index_hash)
    hasher.update(bytes(rotating_pkey))
    hasher.update(expiry_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def _build_proof_clamped_expiry_time(unix_ts_ms: int, proposed_expiry_unix_ts_ms: int):
    # NOTE: Clamp the expiry time of the proof to 1 month and also make it land on the day boundary
    # to reduce metadata leakage.
    clamped_expiry_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms + base.MILLISECONDS_IN_MONTH)
    result: int               = min(clamped_expiry_unix_ts_ms, proposed_expiry_unix_ts_ms)
    return result

def build_proof(gen_index:         int,
                rotating_pkey:     nacl.signing.VerifyKey,
                expiry_unix_ts_ms: int,
                signing_key:       nacl.signing.SigningKey,
                gen_index_salt:    bytes) -> ProSubscriptionProof:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.version               = 0
    result.gen_index_hash        = make_gen_index_hash(gen_index=gen_index, gen_index_salt=gen_index_salt)
    result.rotating_pkey         = rotating_pkey
    result.expiry_unix_ts_ms     = expiry_unix_ts_ms

    hash_to_sign: bytes = build_proof_hash(version           = result.version,
                                           gen_index_hash    = result.gen_index_hash,
                                           rotating_pkey     = result.rotating_pkey,
                                           expiry_unix_ts_ms = result.expiry_unix_ts_ms)
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

def add_pro_payment(sql_conn:            sqlite3.Connection,
                    version:             int,
                    signing_key:         nacl.signing.SigningKey,
                    unix_ts_ms:          int,
                    redeemed_unix_ts_ms: int,
                    master_pkey:         nacl.signing.VerifyKey,
                    rotating_pkey:       nacl.signing.VerifyKey,
                    payment_tx:          UserPaymentTransaction,
                    master_sig:          bytes,
                    rotating_sig:        bytes,
                    err:                 base.ErrorSink) -> RedeemPayment:
    """
    unix_ts_ms: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_unix_ts_ms: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'convert_unix_ts_ms_to_redeemed_unix_ts_ms' to
    #mask metadata about the time the user redeemed the payment.
    """

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = _add_pro_payment_user_tx_log_label(payment_tx)
        log.info(f'Add payment (dev={base.DEV_BACKEND_MODE}, version={version}, redeemed={base.readable_unix_ts_ms(redeemed_unix_ts_ms)}, master={bytes(master_pkey).hex()}, payment={payment_tx_label})')

    result        = RedeemPayment()
    result.status = RedeemPaymentStatus.Error

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
    THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION: bool = False
    if base.DEV_BACKEND_MODE and (payment_tx.google_order_id.startswith('DEV.') or payment_tx.apple_tx_id.startswith('DEV.')):
        runtime_row: RuntimeRow = get_runtime(sql_conn)
        assert bytes(runtime_row.backend_key) == base.DEV_BACKEND_DETERMINISTIC_SKEY, \
                "Sanity check failed, developer mode was enabled but the key in the DB was not a development key. This is a special guard to prevent the user from activating developer mode in the wrong environment"

        # Convert the user payment transaction into the backend native representation. Note that
        # this is testing code for the unit tests so for example for Apple we just provide stub data
        # for transaction data.
        #
        # For the order id, we duplicate the unredeemed token to mock that
        internal_payment_tx          = base.PaymentProviderTransaction()
        internal_payment_tx.provider = payment_tx.provider

        if internal_payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            internal_payment_tx.google_payment_token        = payment_tx.google_payment_token
            internal_payment_tx.google_order_id             = payment_tx.google_order_id
        elif internal_payment_tx.provider == base.PaymentProvider.iOSAppStore:
            internal_payment_tx.apple_tx_id                 = payment_tx.apple_tx_id
            internal_payment_tx.apple_web_line_order_tx_id  = ''
            internal_payment_tx.apple_original_tx_id        = payment_tx.apple_tx_id

        already_exists = False
        for it in get_unredeemed_payments_list(sql_conn):
            if internal_payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                if it.google_payment_token == payment_tx.google_payment_token and it.google_order_id == payment_tx.google_order_id:
                    already_exists = True
            else:
                if it.apple.tx_id == payment_tx.apple_tx_id:
                    already_exists = True

            if already_exists:
                break

        if not already_exists:
            THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION = True
            expiry_unix_ts_ms = redeemed_unix_ts_ms + (60 * 1000)
            add_unredeemed_payment(sql_conn                          = sql_conn,
                                   payment_tx                        = internal_payment_tx,
                                   plan                              = base.ProPlan.OneMonth,
                                   unredeemed_unix_ts_ms             = expiry_unix_ts_ms - 1,
                                   platform_refund_expiry_unix_ts_ms = 0,
                                   expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                   err                               = err)

            # Randomly toggle auto-renewal
            _ = update_payment_renewal_info(sql_conn=sql_conn,
                                            payment_tx=internal_payment_tx,
                                            grace_period_duration_ms=(60 * 1000),
                                            auto_renewing=bool(random.getrandbits(1)),
                                            err=err)

    # Verify some of the request parameters
    hash_to_sign: bytes = make_add_pro_payment_hash(version       = version,
                                                    master_pkey   = master_pkey,
                                                    rotating_pkey = rotating_pkey,
                                                    payment_tx    = payment_tx)

    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                                   master_pkey   = master_pkey,
                                                                   rotating_pkey = rotating_pkey,
                                                                   hash_to_sign  = hash_to_sign,
                                                                   master_sig    = master_sig,
                                                                   rotating_sig  = rotating_sig,
                                                                   err           = err)
    # Then verify version and time
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')

    if len(err.msg_list) > 0:
        return result

    # Note being able to pass in the creation unix timestamp is mainly for
    # testing purposes to allow time-travel. User space should never be
    # specifying this argument, so clients should not be specifying this time,
    # ever, it should be generated and rounded up by the server hence the
    # assert.
    if not base.DEV_BACKEND_MODE:
        assert redeemed_unix_ts_ms % (base.SECONDS_IN_DAY * 1000) == 0, \
                "The passed in creation (and or activated) timestamp must lie on a day boundary: {}".format(redeemed_unix_ts_ms)

    # All verified. Redeem the payment
    with base.SQLTransaction(sql_conn) as tx:
        result = redeem_payment_tx(tx                  = tx,
                                   master_pkey         = master_pkey,
                                   rotating_pkey       = rotating_pkey,
                                   signing_key         = signing_key,
                                   unix_ts_ms          = unix_ts_ms,
                                   redeemed_unix_ts_ms = redeemed_unix_ts_ms,
                                   payment_tx          = payment_tx,
                                   err                 = err)

    if result.status == RedeemPaymentStatus.Success:
        # NOTE: For Google, we acknowledge the payment here on demand when the user claims the payment
        # Unfortunately this leaks in platform details into the DB layer but acknowledgement on claim is
        # the most sensible option and binds the Session client's knowledge of their own payment and
        # that the backend acknowledges the payment in the same step which simplifies implementation
        # greatly. It avoids race conditions such as the client acknowledging but the server hasn't
        # acknowledged yet so it needs to poll the server e.t.c.
        #
        # Yes generating proofs for Google then blocks on the subscription acknowledge, that is
        # unfortunate but intentional, if Google can't be contacted, we can't approve and so the payment
        # cannot be claimed and should be re-attempted.
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore and \
           THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION == False:
            sub_data: platform_google_types.SubscriptionV2Data | None = platform_google_api.fetch_subscription_v2_details(package_name=platform_google_api.package_name,
                                                                                                                          purchase_token=payment_tx.google_payment_token,
                                                                                                                          err=err)
            if not sub_data:
                return result

            if sub_data.acknowledgement_state != platform_google_types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED:
                platform_google_api.subscription_v1_acknowledge(purchase_token=payment_tx.google_payment_token, err=err)
                if len(err.msg_list) > 0:
                    return result

    return result

def revoke_master_pkey_proofs_and_allocate_new_gen_id(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> AllocatedGenID:
    # Revoke the generation index allocated to the master pkey. This blocks all of the proofs
    # generated by the client that were using that payment.
    assert tx.cursor
    _ = tx.cursor.execute('''
        WITH prev_user AS (
            SELECT gen_index, expiry_unix_ts_ms
            FROM   users
            WHERE  master_pkey = ?
        )
        INSERT INTO revocations (gen_index, expiry_unix_ts_ms)
        SELECT      gen_index, expiry_unix_ts_ms
        FROM        prev_user
    ''', (bytes(master_pkey),))

    # If the use had any left over payments that are valid to use, we can allocate them a new
    # generation ID for subsequent proofs to be generated under. Clients will notice that their
    # current proofs on the old generation ID are revoked (via the previous function here) and
    # re-query the backend to generate a new one.
    result = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey)
    return result

def expire_by_unix_ts_ms(tx: base.SQLTransaction, unix_ts_ms: int) -> set[nacl.signing.VerifyKey]:
    log.info(f'Expire by ts (ts={base.readable_unix_ts_ms(unix_ts_ms)})')

    assert tx.cursor
    _ = tx.cursor.execute(f'''
        UPDATE    payments
        SET       status = ?
        WHERE     ? >= expiry_unix_ts_ms AND (status = ? OR status = ?)
        RETURNING master_pkey
    ''', (# SET values
          int(base.PaymentStatus.Expired.value),
          # WHERE values
          unix_ts_ms,
          int(base.PaymentStatus.Unredeemed.value),
          int(base.PaymentStatus.Redeemed.value),
          ))

    result: set[nacl.signing.VerifyKey] = set()
    rows = typing.cast(collections.abc.Iterator[tuple[bytes | None]], tx.cursor)
    for row in rows:
        if row[0]:
            master_pkey = nacl.signing.VerifyKey(row[0])
            result.add(master_pkey)
    return result

def round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider: base.PaymentProvider, unix_ts_ms: int):
    result_unix_ts_ms = unix_ts_ms
    """For different platforms in their testing environments, they have different timespans
    for a day, for example in Google 1 day is 10s. We handle that explicitly here."""
    if base.PLATFORM_TESTING_ENV:
        match payment_provider:
            case base.PaymentProvider.Nil:
                result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
            case base.PaymentProvider.GooglePlayStore:
                ms_in_google_day: int = 10 * 1000 # NOTE: In google 1 day is 10s
                result_unix_ts_ms = ((unix_ts_ms + (ms_in_google_day - 1)) // ms_in_google_day) * ms_in_google_day
            case base.PaymentProvider.iOSAppStore:
                result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    else:
        result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    return result_unix_ts_ms

def generate_pro_proof(sql_conn:       sqlite3.Connection,
                       version:        int,
                       signing_key:    nacl.signing.SigningKey,
                       gen_index_salt: bytes,
                       master_pkey:    nacl.signing.VerifyKey,
                       rotating_pkey:  nacl.signing.VerifyKey,
                       unix_ts_ms:     int,
                       master_sig:     bytes,
                       rotating_sig:   bytes,
                       err:            base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()
    log.info(f'Get pro proof (version={version}, master={bytes(master_pkey).hex()}, ts={base.readable_unix_ts_ms(unix_ts_ms)})')

    # Verify some of the request parameters
    hash_to_sign: bytes = make_generate_pro_proof_hash(version       = version,
                                                  master_pkey   = master_pkey,
                                                  rotating_pkey = rotating_pkey,
                                                  unix_ts_ms    = unix_ts_ms)

    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                                   master_pkey   = master_pkey,
                                                                   rotating_pkey = rotating_pkey,
                                                                   hash_to_sign  = hash_to_sign,
                                                                   master_sig    = master_sig,
                                                                   rotating_sig  = rotating_sig,
                                                                   err           = err)
    if len(err.msg_list) > 0:
        return result

    # Then verify version
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')
    if len(err.msg_list) > 0:
        return result

    # All verified, now generate proof
    get_user = GetUserAndPayments()
    with base.SQLTransaction(sql_conn) as tx:
        get_user = get_user_and_payments(tx, master_pkey)

    if get_user.user.master_pkey == bytes(master_pkey):
        # Check that the gen index hash is not revoked
        if is_gen_index_revoked_tx(sql_conn, get_user.user.gen_index):
            err.msg_list.append(f'User {bytes(master_pkey).hex()} payment has been revoked')
        else:
            proof_deadline_unix_ts_ms: int = get_user.user.expiry_unix_ts_ms + get_user.user.grace_period_duration_ms
            proof_expiry_unix_ts_ms:   int = _build_proof_clamped_expiry_time(unix_ts_ms=unix_ts_ms, proposed_expiry_unix_ts_ms=proof_deadline_unix_ts_ms)
            if unix_ts_ms <= proof_expiry_unix_ts_ms:
                result = build_proof(gen_index         = get_user.user.gen_index,
                                     rotating_pkey     = rotating_pkey,
                                     expiry_unix_ts_ms = proof_expiry_unix_ts_ms,
                                     signing_key       = signing_key,
                                     gen_index_salt    = gen_index_salt);
            else:
                err.msg_list.append(f'User {bytes(master_pkey).hex()} entitlement expired at {base.readable_unix_ts_ms(proof_deadline_unix_ts_ms)} ({base.readable_unix_ts_ms(get_user.user.expiry_unix_ts_ms)} + {get_user.user.grace_period_duration_ms})')
    else:
        err.msg_list.append(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it, {bytes(get_user.user.master_pkey).hex()} {get_user.user.gen_index} {get_user.user.expiry_unix_ts_ms}')

    return result

def expire_payments_revocations_and_users(sql_conn: sqlite3.Connection, unix_ts_ms: int) -> ExpireResult:
    result = ExpireResult()
    with base.SQLTransaction(sql_conn, mode=base.SQLTransactionMode.Exclusive) as tx:
        assert tx.cursor is not None
        # Retrieve the last expiry time that was executed
        _ = tx.cursor.execute('''SELECT last_expire_unix_ts_ms FROM runtime''')
        last_expire_unix_ts_ms:       int  = typing.cast(tuple[int], tx.cursor.fetchone())[0]
        already_done_by_someone_else: bool = last_expire_unix_ts_ms >= unix_ts_ms
        log.info(f'Expire payments/revocs/users (pid={os.getpid()}, ts={base.readable_unix_ts_ms(unix_ts_ms)}, last_expire={last_expire_unix_ts_ms}, already_done_by_someone_else={already_done_by_someone_else})')
        if not already_done_by_someone_else:
            # Update the timestamp that we executed DB expiry
            _ = tx.cursor.execute('''UPDATE runtime SET last_expire_unix_ts_ms = ?''', (unix_ts_ms,))

            # Delete expired payments
            master_pkeys: set[nacl.signing.VerifyKey] = expire_by_unix_ts_ms(tx=tx, unix_ts_ms=unix_ts_ms)
            result.payments = len(master_pkeys)

            # Delete expired revocations
            _ = tx.cursor.execute(''' DELETE FROM revocations WHERE ? >= expiry_unix_ts_ms; ''', (unix_ts_ms,))
            result.revocations = tx.cursor.rowcount

            # Delete expired users
            _ = tx.cursor.execute('''DELETE FROM users WHERE master_pkey NOT IN (SELECT master_pkey FROM payments)''')
            result.users = tx.cursor.rowcount

            # Delete expired apple notification UUIDs
            _ = tx.cursor.execute('''DELETE FROM apple_notification_uuid_history WHERE ? >= expiry_unix_ts_ms''', (unix_ts_ms,))
            result.apple_notification_uuid_history = tx.cursor.rowcount

            # Delete expired google notifications (but only if they have been handled)
            _ = tx.cursor.execute('''DELETE FROM google_notification_history WHERE ? >= expiry_unix_ts_ms AND handled = 1''', (unix_ts_ms,))
            result.google_notification_history = tx.cursor.rowcount

        result.already_done_by_someone_else = already_done_by_someone_else
        result.success                      = True
    return result

def add_user_error(sql_conn: sqlite3.Connection, error: UserError, unix_ts_ms: int):
    assert error.provider != base.PaymentProvider.Nil
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        match error.provider:
            case base.PaymentProvider.GooglePlayStore:
                assert len(error.google_payment_token) > 0
                _ = tx.cursor.execute('''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (?, ?, ?) ON CONFLICT DO NOTHING''',
                     (int(error.provider.value),
                      error.google_payment_token,
                      unix_ts_ms))

            case base.PaymentProvider.iOSAppStore:
                assert len(error.apple_original_tx_id) > 0
                _ = tx.cursor.execute('''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (?, ?, ?) ON CONFLICT DO NOTHING''',
                     (int(error.provider.value),
                      error.apple_original_tx_id,
                      unix_ts_ms))

def has_user_error_tx(tx: base.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    assert tx.cursor is not None
    _                      = tx.cursor.execute('SELECT 1 FROM user_errors WHERE payment_id = ? AND payment_provider = ?', (payment_id, int(payment_provider.value),))
    row: tuple[int] | None = typing.cast(tuple[int] | None, tx.cursor.fetchone())
    result                 = row is not None
    return result;

def has_user_error_from_master_pkey_tx(tx: base.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> bool:
    assert tx.cursor is not None
    _ = tx.cursor.execute(f'''
SELECT EXISTS (
    SELECT 1
    FROM payments p
    LEFT JOIN user_errors ue
        ON (p.payment_provider = {int(base.PaymentProvider.iOSAppStore.value)}     AND p.apple_original_tx_id = ue.payment_id)
        OR (p.payment_provider = {int(base.PaymentProvider.GooglePlayStore.value)} AND p.google_payment_token = ue.payment_id)
    WHERE p.master_pkey = ?
    AND ue.payment_id IS NOT NULL
) AS has_error;
                          ''', (bytes(master_pkey),))
    result = bool(tx.cursor.fetchone()[0] == 1)
    return result;

def has_user_error(sql_conn: sqlite3.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with base.SQLTransaction(sql_conn) as tx:
        result = has_user_error_tx(tx, payment_provider, payment_id)
    return result;

def delete_user_errors(sql_conn: sqlite3.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        _ = tx.cursor.execute('''DELETE FROM user_errors WHERE payment_provider = ? AND payment_id = ?''', (int(payment_provider.value), payment_id))
    result = tx.cursor.rowcount > 0
    return result

def get_payment_tx(tx:          base.SQLTransaction,
                   payment_tx:  base.PaymentProviderTransaction,
                   err:         base.ErrorSink) -> PaymentRow | None:
    result = None
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return result

    assert tx.cursor is not None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        _ = tx.cursor.execute(f'''
            SELECT *
            FROM payments
            WHERE payment_provider = ? AND google_payment_token = ? AND google_order_id = ?
        ''', (int(payment_tx.provider.value),
              payment_tx.google_payment_token,
              payment_tx.google_order_id))

        record = tx.cursor.fetchone()
        if record:
            row = typing.cast(tuple[int, *SQLTablePaymentRowTuple], record)
            result = payment_row_from_tuple(row)

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        _ = tx.cursor.execute(f'''
                SELECT *
                FROM payments
                WHERE payment_provider = ? AND apple_original_tx_id = ? AND apple_tx_id = ? AND apple_web_line_order_tx_id = ?
        ''', (int(payment_tx.provider.value),
              payment_tx.apple_original_tx_id,
              payment_tx.apple_tx_id,
              payment_tx.apple_web_line_order_tx_id))

        record = tx.cursor.fetchone()
        if record:
            row = typing.cast(tuple[int, *SQLTablePaymentRowTuple], record)
            result = payment_row_from_tuple(row)
 
    return result

def get_payment(sql_conn:   sqlite3.Connection,
                payment_tx: base.PaymentProviderTransaction,
                err:        base.ErrorSink) -> PaymentRow | None:
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor is not None
        return get_payment_tx(tx=tx,
                              payment_tx=payment_tx,
                              err=err)

def set_refund_requested_unix_ts_ms(sql_conn:   sqlite3.Connection,
                                    payment_tx: UserPaymentTransaction,
                                    unix_ts_ms: int) -> bool:
    with base.SQLTransaction(sql_conn) as tx:
        assert tx.cursor
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            _ = tx.cursor.execute(f'''
                UPDATE payments
                SET    refund_request_unix_ts_ms = ?
                WHERE  payment_provider = ? AND google_payment_token = ? AND google_order_id = ?
            ''', (unix_ts_ms, int(payment_tx.provider.value), payment_tx.google_payment_token, payment_tx.google_order_id))
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            _ = tx.cursor.execute(f'''
                UPDATE payments
                SET    refund_request_unix_ts_ms = ?
                WHERE  payment_provider = ? AND apple_tx_id = ?
            ''', (unix_ts_ms, int(payment_tx.provider.value), payment_tx.apple_tx_id))

        assert tx.cursor.rowcount == 0 or tx.cursor.rowcount == 1
        result = tx.cursor.rowcount > 0
    return result

def apple_add_notification_uuid_tx(tx: base.SQLTransaction, uuid: str, expiry_unix_ts_ms: int):
    assert tx.cursor
    _ = tx.cursor.execute(f'''
            INSERT INTO apple_notification_uuid_history (uuid, expiry_unix_ts_ms)
            VALUES      (?, ?)
    ''', (uuid, expiry_unix_ts_ms))

def apple_notification_uuid_is_in_db_tx(tx: base.SQLTransaction, uuid: str) -> bool:
    assert tx.cursor
    _ = tx.cursor.execute(f'''
            SELECT 1
            FROM   apple_notification_uuid_history
            WHERE  uuid = ?
    ''', (uuid,))
    row    = typing.cast(tuple[int] | None, tx.cursor.fetchone())
    result = row is not None
    return result

def apple_set_notification_checkpoint_unix_ts_ms(tx: base.SQLTransaction, checkpoint_unix_ts_ms: int):
    assert tx.cursor
    _ = tx.cursor.execute(f'''
            UPDATE runtime
            SET    apple_notification_checkpoint_unix_ts_ms = ?
    ''', (checkpoint_unix_ts_ms,))

def google_add_notification_id_tx(tx: base.SQLTransaction, message_id: int, expiry_unix_ts_ms: int, payload: str):
    assert tx.cursor

    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    _ = tx.cursor.execute(f'''
            INSERT INTO google_notification_history (message_id, handled, payload, expiry_unix_ts_ms)
            VALUES      (?, 0, ?, ?)
    ''', (message_id, maybe_payload, expiry_unix_ts_ms))

def google_set_notification_handled(tx: base.SQLTransaction, message_id: int, delete: bool) -> bool:
    assert tx.cursor
    if delete:
        _ = tx.cursor.execute(f'''DELETE FROM google_notification_history WHERE message_id = ?''', (message_id,))
    else:
        _ = tx.cursor.execute(f'''UPDATE google_notification_history SET handled = 1, payload = NULL WHERE message_id = ?''', (message_id,))
    result = tx.cursor.rowcount >= 1
    return result

def google_get_unhandled_notification_iterator(tx: base.SQLTransaction) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    assert tx.cursor is not None
    _    = tx.cursor.execute('SELECT message_id, payload, expiry_unix_ts_ms FROM google_notification_history WHERE handled = 0')
    result = typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], tx.cursor)
    return result

def google_notification_message_id_is_in_db_tx(tx: base.SQLTransaction, message_id: int) -> GoogleNotificationMessageIDInDB:
    assert tx.cursor
    _      = tx.cursor.execute(f'''SELECT handled FROM google_notification_history WHERE message_id = ?''', (message_id,))
    row    = typing.cast(tuple[int] | None, tx.cursor.fetchone())
    result = row is not None
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0 # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result
