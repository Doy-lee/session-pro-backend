import traceback
import nacl.signing
import hashlib
import os
import typing
import collections.abc
import datetime
import dataclasses
import random
import logging
import enum
import csv
import io

import platform_google_api
import platform_google_types
import base
import db
import sqlalchemy
import sqlalchemy.engine

ZERO_BYTES32               = bytes(32)
BLAKE2B_DIGEST_SIZE        = 32
log                        = logging.Logger("BACKEND")
GENERATE_PROOF_HASH_PERSONALISATION  = b'ProGenerateProof'
BUILD_PROOF_HASH_PERSONALISATION     = b'ProProof________'
ADD_PRO_PAYMENT_HASH_PERSONALISATION = b'ProAddPayment___'
assert len(GENERATE_PROOF_HASH_PERSONALISATION)  == hashlib.blake2b.PERSON_SIZE
assert len(BUILD_PROOF_HASH_PERSONALISATION)     == hashlib.blake2b.PERSON_SIZE
assert len(ADD_PRO_PAYMENT_HASH_PERSONALISATION) == hashlib.blake2b.PERSON_SIZE

class SetRevocationResult(enum.StrEnum):
    UserDoesNotExist = 'User does not exist'
    Skipped          = 'Skipped'
    Updated          = 'Updated'
    Created          = 'Created'
    Deleted          = 'Deleted'

class ReportPeriod(enum.Enum):
    Daily   = 0
    Weekly  = 1
    Monthly = 2

class ReportType(enum.Enum):
    Human = 0
    CSV   = 1

@dataclasses.dataclass(frozen=True)
class ReportRow:
    period:            str
    active_users:      int
    unredeemed:        int
    new_subs:          int
    google:            int
    apple:             int
    plan_1m:           int
    plan_3m:           int
    plan_12m:          int
    refunds_initiated: int
    revoked:           int
    cancelled:         int

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
    expiry_unix_ts_ms_from_redeemed:                     int  = 0
    grace_duration_ms_from_redeemed:                     int  = 0
    refund_requested_unix_ts_ms_from_redeemed:           int  = 0
    auto_renewing_from_redeemed:                         bool = False

    best_expiry_unix_ts_ms:                              int  = 0
    best_grace_duration_ms:                              int  = 0
    best_refund_requested_unix_ts_ms:                    int  = 0
    best_auto_renewing:                                  bool = False

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
                                                            int,          # refund_requested_unix_ts_ms
                                                            bytes,        # google_obfuscated_account_id
                                                            str,          # apple_app_account_token
                                                            ]

AddRevocationIterator:               typing.TypeAlias = tuple[int,          # (row) id
                                                              bytes | None, # master_pkey
                                                              int]          # expiry_unix_ts_ms

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[int,        # message_id
                                                              str | None, # payload
                                                              int]        # expiry_unix_ts_ms

UserRowTuple:                        typing.TypeAlias = tuple[bytes, # master_pkey
                                                              int,   # gen_index
                                                              int,   # expiry_unix_ts_ms
                                                              int,   # grace_period_duration_ms
                                                              int,   # auto_renewing
                                                              int,   # refund_requested_unix_ts_ms
                                                              bytes, # google_obfuscated_account_id
                                                              str,   # apple_app_account_token
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
    refund_requested_unix_ts_ms:        int                  = 0
    google_obfuscated_account_id:       bytes                = b''
    apple_app_account_token:            str                  = ''

@dataclasses.dataclass
class UserRow:
    found:                        bool  = False
    master_pkey:                  bytes = ZERO_BYTES32
    gen_index:                    int   = 0
    expiry_unix_ts_ms:            int   = 0
    grace_period_duration_ms:     int   = 0
    auto_renewing:                bool  = False
    refund_requested_unix_ts_ms:  int   = 0
    google_obfuscated_account_id: bytes = b''
    apple_app_account_token:      str   = ''

@dataclasses.dataclass
class GetUserAndPayments:
    payments_it:    sqlalchemy.engine.Result[SQLTablePaymentRowTuple]
    user:           UserRow                                           = dataclasses.field(default_factory=UserRow)
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

def google_obfuscated_account_id_from_master_pkey(pkey: nacl.signing.VerifyKey) -> bytes:
    result: bytes = hashlib.sha256(bytes(pkey)).digest()
    return result

def apple_obfuscated_account_id_from_master_pkey(pkey: nacl.signing.VerifyKey) -> str:
    result = '' # TODO: Figure out how we derive Apple's app token account id from the master pkey
    return result

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

def make_blake2b_hasher(personalisation: bytes, salt: bytes | None = None) -> hashlib.blake2b:
    final_salt      = salt  if salt else b''
    result          = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE, person=personalisation, salt=final_salt)
    return result

def make_gen_index_hash(gen_index: int, gen_index_salt: bytes) -> bytes:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    hasher = make_blake2b_hasher(personalisation=b'', salt=gen_index_salt)
    hasher.update(gen_index.to_bytes(length=8, byteorder='little'))
    result = hasher.digest()
    return result

def make_add_pro_payment_hash(version:       int,
                              master_pkey:   nacl.signing.VerifyKey,
                              rotating_pkey: nacl.signing.VerifyKey,
                              payment_tx:    UserPaymentTransaction) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=ADD_PRO_PAYMENT_HASH_PERSONALISATION)
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
    result.refund_requested_unix_ts_ms        = row[17]
    result.google_obfuscated_account_id       = row[18] if row[18] else b''
    result.apple_app_account_token            = row[19] if row[19] else ''
    return result

def get_unredeemed_payments_list(conn: sqlalchemy.engine.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, 'SELECT * FROM payments WHERE status = :status', status=int(base.PaymentStatus.Unredeemed.value))
        for row in rows:
            item = payment_row_from_tuple(tuple(row))
            result.append(item)
    return result

def get_payments_list(conn: sqlalchemy.engine.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, 'SELECT * FROM payments')
        for row in rows:
            item = payment_row_from_tuple(tuple(row))
            result.append(item)
    return result

def get_user_and_payments(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> GetUserAndPayments:
    select_fields = ("master_pkey, status, plan, payment_provider, auto_renewing, "
                     "unredeemed_unix_ts_ms, redeemed_unix_ts_ms, expiry_unix_ts_ms, "
                     "grace_period_duration_ms, platform_refund_expiry_unix_ts_ms, "
                     "revoked_unix_ts_ms, apple_original_tx_id, apple_tx_id, "
                     "apple_web_line_order_tx_id, google_payment_token, google_order_id, "
                     "refund_requested_unix_ts_ms, google_obfuscated_account_id, "
                     "apple_app_account_token")

    payments_it = db.query(tx.conn, f'''
        SELECT   {select_fields}
        FROM     payments
        WHERE    master_pkey = :pkey
        ORDER BY unredeemed_unix_ts_ms DESC, id DESC
    ''', pkey=bytes(master_pkey))

    result      = GetUserAndPayments(payments_it=payments_it)
    result.user = get_user_from_sql_tx(tx, master_pkey)

    row = db.query_one(tx.conn, '''
        SELECT COUNT(*)
        FROM   payments
        WHERE  master_pkey = :pkey
    ''', pkey=bytes(master_pkey))
    result.payments_count = row[0] if row else 0
    return result

def _user_from_row_iterator(row: UserRowTuple) -> UserRow:
    result                              = UserRow()
    result.found                        = True
    result.master_pkey                  = row[0]
    result.gen_index                    = row[1]
    result.expiry_unix_ts_ms            = row[2]
    result.grace_period_duration_ms     = row[3]
    result.auto_renewing                = bool(row[4])
    result.refund_requested_unix_ts_ms  = row[5]
    result.google_obfuscated_account_id = row[6]
    result.apple_app_account_token      = row[7]
    return result

def get_users_list(conn: sqlalchemy.engine.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with db.transaction(conn):
        for row in db.query(conn,
                            ("SELECT master_pkey,"
                             "gen_index,"
                             "expiry_unix_ts_ms,"
                             "grace_period_duration_ms,"
                             "auto_renewing,"
                             "refund_requested_unix_ts_ms,"
                             "google_obfuscated_account_id,"
                             "apple_app_account_token FROM users")):
            result.append(_user_from_row_iterator(tuple(row)))
    return result

def get_user_from_sql_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    row = db.query_one(tx.conn, ("SELECT master_pkey,"
                                 "gen_index,"
                                 "expiry_unix_ts_ms,"
                                 "grace_period_duration_ms,"
                                 "auto_renewing,"
                                 "refund_requested_unix_ts_ms,"
                                 "google_obfuscated_account_id,"
                                 "apple_app_account_token FROM users WHERE master_pkey = :pkey"),
                       pkey=bytes(master_pkey))
    if row:
        result = _user_from_row_iterator(tuple(row))
    return result

def get_user(conn: sqlalchemy.engine.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    with db.transaction(conn) as tx:
        result = get_user_from_sql_tx(tx, master_pkey)
    return result

def get_revocations_list(conn: sqlalchemy.engine.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with db.transaction(conn) as tx:
        for row in db.query(tx.conn, "SELECT gen_index, expiry_unix_ts_ms FROM revocations"):
            item                   = RevocationRow()
            item.gen_index         = row[0]
            item.expiry_unix_ts_ms = row[1]
            result.append(item)
    return result

def is_gen_index_revoked_tx(tx: db.SQLTransaction, gen_index: int) -> bool:
    row = db.query_one(tx.conn, "SELECT 1 FROM revocations WHERE gen_index = :index", index=gen_index)
    return row is not None

def is_gen_index_revoked(conn: sqlalchemy.engine.Connection, gen_index: int) -> bool:
    result: bool = False
    with db.transaction(conn) as tx:
        result = is_gen_index_revoked_tx(tx, gen_index)
    return result

def get_revocation_ticket(conn: sqlalchemy.engine.Connection) -> int:
    row = db.query_one(conn, "SELECT revocation_ticket FROM runtime")
    return row[0] if row else 0

def get_pro_revocations_iterator_tx(tx: db.SQLTransaction) -> collections.abc.Iterator[tuple[int, int]]:
    for row in db.query(tx.conn, "SELECT gen_index, expiry_unix_ts_ms FROM revocations"):
        yield (row[0], row[1])

def get_runtime_tx(tx: db.SQLTransaction) -> RuntimeRow:
    row = db.query_one(tx.conn, ("SELECT gen_index,"
                                 "gen_index_salt,"
                                 "backend_key,"
                                 "last_expire_unix_ts_ms,"
                                 "apple_notification_checkpoint_unix_ts_ms,"
                                 "revocation_ticket FROM runtime"))
    result: RuntimeRow = RuntimeRow()
    if row:
        result.gen_index                                 = row[0]
        result.gen_index_salt                            = row[1]
        backend_key: bytes                               = bytes(row[2])
        assert len(backend_key)                         == len(ZERO_BYTES32)
        result.backend_key                               = nacl.signing.SigningKey(backend_key)
        result.last_expire_unix_ts_ms                    = row[3]
        result.apple_notification_checkpoint_unix_ts_ms  = row[4]
        result.revocation_ticket                         = row[5]
    return result

def get_runtime(conn: sqlalchemy.engine.Connection) -> RuntimeRow:
    result: RuntimeRow = RuntimeRow()
    with db.transaction(conn) as tx:
        result = get_runtime_tx(tx)
    return result

def db_info_string(conn: sqlalchemy.engine.Connection, db_url: str, err: base.ErrorSink) -> str:
    unredeemed_payments             = 0
    payments                        = 0
    users                           = 0
    revocations                     = 0
    db_size                         = 0
    user_errors                     = 0
    apple_notification_uuid_history = 0
    google_notification_history     = 0
    with db.transaction(conn) as tx:
        try:
            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM payments WHERE status = :status', status=int(base.PaymentStatus.Unredeemed.value))
            if row:
                unredeemed_payments = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM payments')
            if row:
                payments = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM users')
            if row:
                users = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM revocations')
            if row:
                revocations = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM user_errors')
            if row:
                user_errors = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM apple_notification_uuid_history')
            if row:
                apple_notification_uuid_history = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM google_notification_history')
            if row:
                google_notification_history = row[0]
        except Exception as e:
            err.msg_list.append(f"Failed to retrieve DB metadata: {e}")

    result = ''
    if len(err.msg_list) == 0:
        db_file_path: str | None = db.file_path_from_sqlite_url(db_url)
        if db_file_path and os.path.exists(db_file_path):
            db_size = os.stat(db_file_path).st_size
        with db.transaction(conn) as tx:
            runtime: RuntimeRow = get_runtime_tx(tx)
        lines: list[str] = []
        lines.append('  DB:                               {} ({})'.format(db_url, base.format_bytes(db_size)))
        lines.append('  Users/Revocs/Payments/Unredeemed: {}/{}/{}/{}'.format(users, revocations, payments, unredeemed_payments))
        lines.append('  U.Errors/Google/Apple Notifs.:    {}/{}/{}'.format(user_errors, google_notification_history, apple_notification_uuid_history))
        lines.append('  Gen Index:                        {}'.format(runtime.gen_index))
        lines.append('  Backend Key:                      {}'.format(bytes(runtime.backend_key.verify_key).hex()))
        result = '\n'.join(lines)

    return result

def bootstrap_db(database_url: str, err: base.ErrorSink, backend_key: nacl.signing.SigningKey | None = None) -> sqlalchemy.engine.Engine | None:
    """
    Opens a database and bootstraps/migrates schema if needed.
    Args:
        database_url: Full database URL (e.g., 'sqlite:///path/to/db.db' or 'postgresql://user:pass@host/db')
                     Caller is responsible for providing the correct URL scheme.
        backend_key: Optional backend signing key for initialization
        err: Error sink for collecting error messages
    """
    conn:   sqlalchemy.engine.Connection | None = None
    result: sqlalchemy.engine.Engine     | None = None
    try:
        result = db.create_engine(database_url)
        conn   = result.connect()
    except Exception as e:
        err.msg_list.append(f'Failed to open/connect to DB at {database_url}: {e}')
        return result

    try:
        with db.transaction(conn) as tx:
            # Determine schema file based on database type
            if db.is_postgres(result):
                schema_path = os.path.join(os.path.dirname(__file__), 'backend_schema.pgsql')
            else:
                schema_path = os.path.join(os.path.dirname(__file__), 'backend_schema.sql')

            # Execute schema file
            with open(schema_path, 'r') as f:
                schema_sql = f.read()

            if db.is_postgres(result):
                # PostgreSQL: Execute entire schema as one block to handle functions with semicolons
                _ = db.query(tx.conn, schema_sql)
            else:
                # SQLite: Use executescript for multi-statement execution
                tx.conn.connection.executescript(schema_sql)

            # NOTE: Version migration
            target_db_version = 7
            db_version = db.get_db_version(tx.conn, result)

            # NOTE: v0 is the nil state - DB never bootstrapped, teleport to target
            if db_version == 0:
                db_version = target_db_version
                db.set_db_version(tx.conn, result, db_version)

            if db_version == 5:
                log.info(f'Migrating DB version from {db_version} => {db_version + 1}')
                if not db.is_postgres(result):
                    _ = db.query(tx.conn, ("ALTER TABLE users ADD COLUMN google_obfuscated_account_id BLOB NOT NULL DEFAULT X''"))
                    _ = db.query(tx.conn, ("ALTER TABLE users ADD COLUMN apple_app_account_token STRING NOT NULL DEFAULT ''"))
                    for row in db.query(tx.conn, ('SELECT master_pkey FROM users')).fetchall():
                        master_pkey: bytes                  = bytes(row[0])
                        google_obfuscated_account_id: bytes = google_obfuscated_account_id_from_master_pkey(nacl.signing.VerifyKey(master_pkey))
                        _ = db.query(tx.conn, 'UPDATE users SET google_obfuscated_account_id = :g WHERE master_pkey = :m', g=google_obfuscated_account_id, m=master_pkey)
                db_version += 1
                db.set_db_version(tx.conn, result, db_version)

            if db_version == 6:
                log.info(f'Migrating DB version from {db_version} => {db_version + 1}')
                if not db.is_postgres(result):
                    _ = db.query(tx.conn, ("ALTER TABLE payments ADD COLUMN google_obfuscated_account_id BLOB NOT NULL DEFAULT X''"))
                    _ = db.query(tx.conn, ("ALTER TABLE payments ADD COLUMN apple_app_account_token STRING NOT NULL DEFAULT ''"))
                db_version += 1
                db.set_db_version(tx.conn, result, db_version)

            # NOTE: Verify that the DB was migrated to the target version
            assert db_version == target_db_version

            # NOTE: Initialize the runtime row (app global settings) with the default values
            row = db.query(tx.conn, ('SELECT EXISTS (SELECT 1 FROM runtime)')).fetchone()
            runtime_row_exists = bool(row[0]) if row else False
            if not runtime_row_exists:
                if backend_key is None:
                    backend_key = nacl.signing.SigningKey.generate()

                _ = db.query(tx.conn, ('''
                    INSERT INTO runtime (gen_index, gen_index_salt, backend_key, last_expire_unix_ts_ms, apple_notification_checkpoint_unix_ts_ms, revocation_ticket)
                    VALUES (0, :salt, :backend_key, 0, 0, 0)
                '''), salt=os.urandom(hashlib.blake2b.SALT_SIZE), backend_key=bytes(backend_key))
    except Exception:
        err.msg_list.append(f"Failed to bootstrap DB tables: {traceback.format_exc()}")
    finally:
        if conn:
            conn.close()

    return result

def verify_db(conn: sqlalchemy.engine.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(conn)
    for index, it in enumerate(unredeemed_payments):
        _ = base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}')
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Unredeemed payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')

    # NOTE: Wednesday, 27 August 2025 00:00:00, arbitrary date in the past that PRO cannot
    # possibly be before. We should update this to to the PRO release date.
    PRO_ENABLED_UNIX_TS: int = 1756252800

    payments: list[PaymentRow] = get_payments_list(conn)
    for index, it in enumerate(payments):
        # NOTE: Check mandatory fields
        if it.plan == base.ProPlan.Nil: 
            err.msg_list.append(f'{it.status.name} payment #{index} plan is invalid. It should have been derived from the platform payment provider (e.g. by converting the unredeemedd plan ID to a plan)')
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
        _ = base.verify_payment_provider(it.payment_provider, err)

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
    users: list[UserRow] = get_users_list(conn)
    for index, it in enumerate(users):
        if it.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')
        if it.expiry_unix_ts_ms < PRO_ENABLED_UNIX_TS:
          expiry_date_str = datetime.datetime.fromtimestamp(it.expiry_unix_ts_ms/1000).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a expiry date before PRO was enabled: {it.expiry_unix_ts_ms} ({expiry_date_str})')

    result = len(err.msg_list) == 0
    return result

def _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    master_pkey_bytes: bytes                    = bytes(master_pkey)
    lookup:            LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx, nacl.signing.VerifyKey(master_pkey_bytes))
    # NOTE: We have the latest expiry value, now update the user
    _ = db.query(tx.conn, '''
        UPDATE users
        SET    expiry_unix_ts_ms = :expiry, grace_period_duration_ms = :grace, auto_renewing = :renewing, refund_requested_unix_ts_ms = :refund
        WHERE  master_pkey = :pkey
    ''', expiry   = lookup.best_expiry_unix_ts_ms,
         grace    = lookup.best_grace_duration_ms,
         renewing = lookup.best_auto_renewing,
         refund   = lookup.best_refund_requested_unix_ts_ms,
         pkey     = master_pkey_bytes)

def revoke_payments_by_id_internal_tx(tx: db.SQLTransaction, rows: typing.Any, revoke_unix_ts_ms: int) -> bool:
    result                             = False
    master_pkey_dict: dict[bytes, int] = {}
    for row in  rows:
        result                          = True
        id:                int          = row[0]
        master_pkey_bytes: bytes | None = bytes(row[1]) if row[1] is not None else None
        expiry_unix_ts_ms: int          = row[2]

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expiry_unix_ts_ms

        # NOTE: Mark all the payments as revoked
        _ = db.query(tx.conn, '''
        UPDATE payments
        SET    status = :status, revoked_unix_ts_ms = :revoked_ts, auto_renewing = 0
        WHERE  id = :id AND (status = :unredeemed OR status = :redeemed)
        ''',
            status=int(base.PaymentStatus.Revoked.value),
            revoked_ts=revoke_unix_ts_ms,
            id=id,
            unredeemed=int(base.PaymentStatus.Unredeemed.value),
            redeemed=int(base.PaymentStatus.Redeemed.value))

    revoke_unix_ts_ms_next_day = round_unix_ts_ms_to_next_day_with_platform_testing_support(base.PaymentProvider.iOSAppStore, revoke_unix_ts_ms)
    for it in master_pkey_dict:
        # NOTE: For each user we revoked a payment for, we have modified their 'auto_renewing' value
        # on the payment, we need to go and update their user row to track the, new, next best
        # expiry time so that the backend knows the new time-frame in which the user is allowed to
        # generate a Session Pro proof (now that one or more of their payments get revoked)
        _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, nacl.signing.VerifyKey(it))

        # NOTE: expiry_unix_ts_ms in the db is not rounded, but the proof's themselves have an
        # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
        # proofs that aren't going to self-expire by the end of the day.
        #
        # For different platforms in their testing environments, they have different timespans
        # for a day, for example in Google 1 day is 10s. We handle that explicitly here.

        expiry_unix_ts_ms = master_pkey_dict[it]
        if expiry_unix_ts_ms > revoke_unix_ts_ms_next_day:
            master_pkey = nacl.signing.VerifyKey(it)
            _ = revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx, master_pkey)

    return result

def set_revocation_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, expiry_unix_ts_ms: int, delete_item: bool) -> SetRevocationResult:
    user:   UserRow = get_user_from_sql_tx(tx, master_pkey)
    result          = SetRevocationResult.UserDoesNotExist
    if user.found:
        assert user.master_pkey == bytes(master_pkey), f"{user.master_pkey.hex()} vs {bytes(master_pkey).hex()}"
        row = db.query_one(tx.conn, "SELECT EXISTS (SELECT 1 FROM revocations WHERE gen_index = :idx)", idx=user.gen_index)
        existed = row[0] if row else False

        if delete_item:
            if existed:
                _      = db.query(tx.conn, 'DELETE FROM revocations WHERE gen_index = :idx', idx=user.gen_index)
                result = SetRevocationResult.Deleted
            else:
                result = SetRevocationResult.Skipped
        else:
            _ = db.query(tx.conn, '''
                INSERT INTO revocations (gen_index, expiry_unix_ts_ms)
                VALUES      (:index, :expiry_ts)
                ON CONFLICT (gen_index) DO UPDATE SET
                    expiry_unix_ts_ms = excluded.expiry_unix_ts_ms
            ''', index=user.gen_index, expiry_ts=expiry_unix_ts_ms)
            result = SetRevocationResult.Updated if existed else SetRevocationResult.Created
    return result

def add_apple_revocation_tx(tx: db.SQLTransaction, apple_original_tx_id: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""
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
    rows_result = db.query(tx.conn, f'''
    SELECT id, master_pkey, expiry_unix_ts_ms
    FROM   payments
    WHERE  apple_original_tx_id  = :orig_tx AND
           payment_provider      = :provider AND
           (status               = :unredeemed OR status = :redeemed OR status = :expired OR status = :revoked);
    ''', 
        orig_tx=apple_original_tx_id,
        provider=int(base.PaymentProvider.iOSAppStore.value),
        unredeemed=int(base.PaymentStatus.Unredeemed.value),
        redeemed=int(base.PaymentStatus.Redeemed.value),
        expired=int(base.PaymentStatus.Expired.value),
        revoked=int(base.PaymentStatus.Revoked.value))

    log.info(f'Revoking Apple payment (orig. TX ID={apple_original_tx_id}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Apple orig. TX ID {apple_original_tx_id} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def add_google_revocation_tx(tx: db.SQLTransaction, google_payment_token: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""

    # NOTE: Select the newest google transaction that has been redeemed or not. Google only gives us
    # the purchase token in the scenarios that we call this function.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    rows_result = db.query(tx.conn, f'''
    SELECT id, master_pkey, expiry_unix_ts_ms
    FROM   payments
    WHERE  google_payment_token = :token AND
           payment_provider     = :provider AND
           (status              = :unredeemed OR status = :redeemed OR status = :expired OR status = :revoked)
    ''',
        token=google_payment_token,
        provider=int(base.PaymentProvider.GooglePlayStore.value),
        unredeemed=int(base.PaymentStatus.Unredeemed.value),
        redeemed=int(base.PaymentStatus.Redeemed.value),
        expired=int(base.PaymentStatus.Expired.value),
        revoked=int(base.PaymentStatus.Revoked.value))

    log.info(f'Revoking Google payment (token={google_payment_token}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Google payment {google_payment_token} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def redeem_payment_tx(tx:                  db.SQLTransaction,
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

    result                   = RedeemPayment(status=RedeemPaymentStatus.Error)
    master_pkey_bytes: bytes = bytes(master_pkey)
    fields                   = ['master_pkey = :master_pkey', 'status = :status', 'redeemed_unix_ts_ms = :redeemed_unix_ts_ms']
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
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  payment_provider             = :provider
              AND  google_payment_token         = :token
              AND  google_order_id              = :order_id
              AND  status                       = :where_status
              AND  google_obfuscated_account_id = :account_id
        ''', # SET values
              master_pkey         = master_pkey_bytes,
              status              = int(base.PaymentStatus.Redeemed.value),
              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
              # WHERE values
              provider            = int(payment_tx.provider.value),
              token               = payment_tx.google_payment_token,
              order_id            = payment_tx.google_order_id,
              where_status        = int(base.PaymentStatus.Unredeemed.value),
              account_id          = google_obfuscated_account_id_from_master_pkey(master_pkey))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  payment_provider       = :provider
              AND apple_tx_id             = :tx_id
              AND status                  = :where_status
              AND apple_app_account_token = :account_token
        ''', # SET fields
              master_pkey         = master_pkey_bytes,
              status              = int(base.PaymentStatus.Redeemed.value),
              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
              # WHERE fields
              provider            = int(payment_tx.provider.value),
              tx_id               = payment_tx.apple_tx_id,
              where_status        = int(base.PaymentStatus.Unredeemed.value),
              account_token       = apple_obfuscated_account_id_from_master_pkey(master_pkey))
    else:
        err.msg_list.append('Payment to register specifies an unknown payment provider')
        return result

    rowcount = row_result.rowcount
    if rowcount >= 1:
        assert rowcount == 1
        if rowcount > 1:
            err.msg_list.append(f'Payment was redeemed for {master_pkey} at {redeemed_unix_ts_ms/1000} but more than 1 row was updated, updated {rowcount}')
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

                # NOTE: In dev mode we don't round up to the next day as we want these proofs to
                # expire quickly for testing.
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
            row_result = db.query(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments
                WHERE  payment_provider     = :provider
                  AND  google_payment_token = :token
                  AND  google_order_id      = :order_id
                  AND  status               > :status
                  AND  master_pkey          = :master_pkey
            ''', provider    = int(payment_tx.provider.value),
                 token       = payment_tx.google_payment_token,
                 order_id    = payment_tx.google_order_id,
                 status      = int(base.PaymentStatus.Unredeemed.value),
                 master_pkey = master_pkey_bytes)
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            row_result = db.query(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments
                WHERE  payment_provider = :provider
                  AND  apple_tx_id      = :tx_id
                  AND  status           > :status
                  AND  master_pkey      = :master_pkey
            ''', provider    = int(payment_tx.provider.value),
                 tx_id       = payment_tx.apple_tx_id,
                 status      = int(base.PaymentStatus.Unredeemed.value),
                 master_pkey = master_pkey_bytes)
        first_row = row_result.fetchone()
        if first_row and first_row[0] > 0:
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
    _ = base.verify_payment_provider(payment_tx.provider, err)
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

def _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiryUnixTsMs:
    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    result_set = db.query(tx.conn, ('''
        SELECT    expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, status, refund_requested_unix_ts_ms, payment_provider, apple_original_tx_id, google_order_id, revoked_unix_ts_ms
        FROM      payments
        WHERE     master_pkey = :master_pkey AND (status = :status1 OR status = :status2 OR status = :status3)
        ORDER BY  id DESC
        LIMIT     20
    '''), master_pkey = bytes(master_pkey),
          status1     = int(base.PaymentStatus.Redeemed.value),
          status2     = int(base.PaymentStatus.Revoked.value),
          status3     = int(base.PaymentStatus.Expired.value),)

    used_google_order_ids:  list[str] = []
    used_apple_orig_tx_ids: set[int]  = set()

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result      = LookupUserExpiryUnixTsMs()
    rows        = typing.cast(list[tuple[int, int, int, int, int, int, int, str, int]], result_set.fetchall())
    for row in rows:
        expiry_unix_ts_ms:           int = row[0]
        grace_period_duration_ms:    int = row[1]
        auto_renewing:               int = row[2]
        status:                      int = row[3]
        refund_requested_unix_ts_ms: int = row[4]
        payment_provider:            int = row[5]
        apple_original_tx_id:        int = row[6]
        google_order_id:             str = row[7]
        revoked_unix_ts_ms:          int = row[8]

        # NOTE: Consecutive subscription payments are added to the DB under _roughly_ the same
        # transaction ID (this differs between platforms). We only want to consider that latest
        # subscription payment as the user's "best" payment that we should show as their entitlement
        #
        # For google they do an <order_id> but then append a suffix to disambiguate such as
        # <order_id>, <order_id>..0, <order_id>..1 and so forth
        #
        # For apple they have a <original_transaction_id> that is shared across all transactions for
        # a given subscription.
        #
        # Our SQL query sorts the rows by insertion order and grabs the top 20 and looks for the
        # _latest_ instance of the transactions associated with the user and selects those.
        seen_before = False
        if payment_provider == base.PaymentProvider.GooglePlayStore.value:
            order_split: list[str] = google_order_id.split('..')
            if len(order_split) <= 0:
                log.warning(f"Failed to split order google order ID by '..' for {bytes(master_pkey).hex()}: {base.obfuscate(google_order_id)}")
                continue

            for used_it in used_google_order_ids:
                if used_it.startswith(order_split[0]):
                    seen_before = True
                    break

            if not seen_before:
                used_google_order_ids.append(google_order_id)
        elif payment_provider == base.PaymentProvider.iOSAppStore.value:
            if apple_original_tx_id in used_apple_orig_tx_ids:
                seen_before = True
            else:
                used_apple_orig_tx_ids.add(apple_original_tx_id)
        else:
            log.warning(f"Unrecognised payment provider in {row} for {bytes(master_pkey).hex()}: {payment_provider}")
            continue

        if seen_before:
            continue

        # NOTE: Calculate the current best timestamp (newest payment that entitles them to Pro)
        best_expiry_wo_grace_unix_ts_ms_from_redeemed: int = result.expiry_unix_ts_ms_from_redeemed
        best_expiry_wo_grace_unix_ts_ms:               int = result.best_expiry_unix_ts_ms
        if result.auto_renewing_from_redeemed:
            best_expiry_wo_grace_unix_ts_ms_from_redeemed -= result.grace_duration_ms_from_redeemed

        if result.best_auto_renewing:
            best_expiry_wo_grace_unix_ts_ms -= result.best_grace_duration_ms

        # NOTE: If we're revoked, the expiry and payment expiry that we store into the result is
        # clamped to the revoke timestamp (e.g. the user entitlement is stopped effective at the
        # revoke time)
        if status == base.PaymentStatus.Revoked.value:
            assert auto_renewing == False
            payment_expiry_unix_ts_ms = revoked_unix_ts_ms
            expiry_unix_ts_ms         = revoked_unix_ts_ms
        else:
            payment_expiry_unix_ts_ms = expiry_unix_ts_ms
            if auto_renewing:
                payment_expiry_unix_ts_ms += grace_period_duration_ms

        # NOTE: Evaluate if we should accept this payment
        if status == base.PaymentStatus.Redeemed:
            if expiry_unix_ts_ms > best_expiry_wo_grace_unix_ts_ms_from_redeemed:
                result.expiry_unix_ts_ms_from_redeemed           = payment_expiry_unix_ts_ms
                result.grace_duration_ms_from_redeemed           = grace_period_duration_ms
                result.refund_requested_unix_ts_ms_from_redeemed = refund_requested_unix_ts_ms
                result.auto_renewing_from_redeemed               = bool(auto_renewing)

        if expiry_unix_ts_ms > best_expiry_wo_grace_unix_ts_ms:
            result.best_expiry_unix_ts_ms           = payment_expiry_unix_ts_ms
            result.best_grace_duration_ms           = grace_period_duration_ms
            result.best_refund_requested_unix_ts_ms = refund_requested_unix_ts_ms
            result.best_auto_renewing               = bool(auto_renewing)
    return result

def update_payment_renewal_info_tx(tx:                       db.SQLTransaction,
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
    sql_set_fields: str = ''
    kwparams: dict[str, typing.Any] = {}
    if auto_renewing is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'auto_renewing = :auto_renewing'
        kwparams['auto_renewing'] = int(auto_renewing)

    if grace_period_duration_ms is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'grace_period_duration_ms = :grace_period_duration_ms'
        kwparams['grace_period_duration_ms'] = grace_period_duration_ms

    # NOTE: Execute the statement
    result_set: sqlalchemy.engine.Result[typing.Any] | None = None
    match payment_tx.provider:
        case base.PaymentProvider.Nil:
            pass

        case base.PaymentProvider.GooglePlayStore:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     google_payment_token = :token AND google_order_id = :order_id
                RETURNING master_pkey
            ''', token=payment_tx.google_payment_token,
                 order_id=payment_tx.google_order_id,
                 **kwparams)

        case base.PaymentProvider.iOSAppStore:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     apple_original_tx_id = :orig_tx_id AND apple_tx_id = :tx_id AND apple_web_line_order_tx_id = :line_order_tx_id
                RETURNING master_pkey
            ''', orig_tx_id=payment_tx.apple_original_tx_id,
                 tx_id=payment_tx.apple_tx_id,
                 line_order_tx_id=payment_tx.apple_web_line_order_tx_id,
                 **kwparams)

    # NOTE: Having `RETURNING master_pkey` seems to break rowcount and returns 0 even on
    # row modification. We use fetchone instead
    assert result_set
    row    = typing.cast(sqlalchemy.Row[tuple[bytes]] | None, result_set.fetchone())
    result = row is not None

    # NOTE: Update the user's expiry to the latest known expiry
    if row and row[0]:
        master_pkey_bytes: bytes = bytes(row[0])
        _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    if result == False:
        payment_id = payment_tx.google_order_id if payment_tx.provider == base.PaymentProvider.GooglePlayStore else payment_tx.apple_tx_id
        err.msg_list.append(f'Updating payment TX failed, no matching payment found for {payment_tx.provider.name} {payment_id}')
    return result

def update_payment_renewal_info(conn:                     sqlalchemy.engine.Connection,
                                payment_tx:               base.PaymentProviderTransaction,
                                grace_period_duration_ms: int  | None,
                                auto_renewing:            bool | None,
                                err:                      base.ErrorSink) -> bool:

    result = False
    with db.transaction(conn) as sql_tx:
        result = update_payment_renewal_info_tx(sql_tx, payment_tx, grace_period_duration_ms, auto_renewing, err)
    return result

def add_unredeemed_payment_tx(tx:                                db.SQLTransaction,
                              payment_tx:                        base.PaymentProviderTransaction,
                              plan:                              base.ProPlan,
                              expiry_unix_ts_ms:                 int,
                              unredeemed_unix_ts_ms:             int,
                              platform_refund_expiry_unix_ts_ms: int,
                              platform_obfuscated_account_id:    bytes | str,
                              err:                               base.ErrorSink):

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Unredeemed payment (payment={payment_tx_label}, plan={plan.name}, expiry={base.readable_unix_ts_ms(expiry_unix_ts_ms)}, unredeemed={base.readable_unix_ts_ms(unredeemed_unix_ts_ms)}, refund={base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)})')

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        assert isinstance(platform_obfuscated_account_id, bytes)
        assert len(platform_obfuscated_account_id) == 32

        # NOTE: Insert into the table, IFF, the payment token hash doesn't already exist in the
        # payments table
        result_set = db.query(tx.conn, '''
            SELECT 1
            FROM payments
            WHERE payment_provider = :provider AND google_payment_token = :token AND google_order_id = :order_id
        ''', provider=int(payment_tx.provider.value), token=payment_tx.google_payment_token, order_id=payment_tx.google_order_id)

        record = result_set.fetchone()
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
                           'refund_requested_unix_ts_ms',
                           'google_obfuscated_account_id',
                           'apple_app_account_token']
            stmt_fields = ', '.join(fields)
            stmt_values = ', '.join([':' + f for f in fields])

            _ = db.query(tx.conn, f'''
                INSERT INTO payments ({stmt_fields})
                VALUES ({stmt_values})
            ''', {f: v for f, v in zip(fields, [
                  int(plan.value),
                  payment_tx.provider.value,
                  payment_tx.google_payment_token,
                  payment_tx.google_order_id,
                  int(base.PaymentStatus.Unredeemed.value),
                  expiry_unix_ts_ms,
                  platform_refund_expiry_unix_ts_ms,
                  0,                              # non-null grace period
                  unredeemed_unix_ts_ms,
                  1,                              # auto_renewing is enabled by default until notified otherwise by Google
                  0,                              # refund request unix ts ms
                  platform_obfuscated_account_id, # google_obfuscated_account_id
                  '',                             # apple_app_account_token - empty for google
            ])})

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        assert isinstance(platform_obfuscated_account_id, str)
        # NOTE: Insert into the table, IFF, the apple payment doesn't already exist somewhere else.
        #
        # For Apple each apple_tx_id is always unique.
        # apple_web_line_order_tx_id is unique for the payment of the billing
        # cycle for that subscription and the apple_original_tx_id is reused
        # across all subscriptions of the same type.
        result_set = db.query(tx.conn, '''
                SELECT 1
                FROM payments
                WHERE payment_provider = :provider AND apple_original_tx_id = :orig_tx_id AND apple_tx_id = :tx_id AND apple_web_line_order_tx_id = :line_order_tx_id
        ''', provider=int(payment_tx.provider.value),
              orig_tx_id=payment_tx.apple_original_tx_id,
              tx_id=payment_tx.apple_tx_id,
              line_order_tx_id=payment_tx.apple_web_line_order_tx_id)

        record = result_set.fetchone()
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
                                      'refund_requested_unix_ts_ms',
                                      'google_obfuscated_account_id',
                                      'apple_app_account_token']
            stmt_fields: str       = ', '.join(fields)
            stmt_values: str       = ', '.join([':' + f for f in fields])

            _ = db.query(tx.conn, f'''
                INSERT INTO payments ({stmt_fields})
                VALUES ({stmt_values})
            ''', {f: v for f, v in zip(fields, [
                  int(plan.value),
                  int(payment_tx.provider.value),
                  payment_tx.apple_original_tx_id,
                  payment_tx.apple_tx_id,
                  payment_tx.apple_web_line_order_tx_id,
                  int(base.PaymentStatus.Unredeemed.value),
                  expiry_unix_ts_ms,
                  platform_refund_expiry_unix_ts_ms,
                  0,                              # non-null grace period
                  unredeemed_unix_ts_ms,
                  1,                              # auto_renewing is enabled by default until notified otherwise by Apple
                  0,                              # refund request unix ts ms
                  b'',                            # google_obfuscated_account_id - empty for apple
                  platform_obfuscated_account_id, # apple_app_account_token
            ])})

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
    result_set: sqlalchemy.engine.Result[typing.Any] | None = None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(tx.conn, ('''
            SELECT   master_pkey
            FROM     payments
            WHERE    payment_provider = :provider AND google_payment_token = :token AND master_pkey IS NOT NULL
            ORDER BY id DESC
            LIMIT    1
        '''), {'provider': int(payment_tx.provider.value), 'token': payment_tx.google_payment_token})
    else:
        assert payment_tx.provider == base.PaymentProvider.iOSAppStore
        result_set = db.query(tx.conn, ('''
            SELECT   master_pkey
            FROM     payments
            WHERE    payment_provider = :provider AND apple_original_tx_id = :orig_tx_id AND master_pkey IS NOT NULL
            ORDER BY id DESC
            LIMIT    1
        '''), {'provider': int(payment_tx.provider.value), 'orig_tx_id': payment_tx.apple_original_tx_id})

    master_pkey_record = typing.cast(sqlalchemy.Row[tuple[bytes]] | None, result_set.fetchone())
    if master_pkey_record and master_pkey_record[0]:
        master_pkey   = nacl.signing.VerifyKey(bytes(master_pkey_record[0]))
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

def add_unredeemed_payment(conn:                              sqlalchemy.engine.Connection,
                           payment_tx:                        base.PaymentProviderTransaction,
                           plan:                              base.ProPlan,
                           expiry_unix_ts_ms:                 int,
                           unredeemed_unix_ts_ms:             int,
                           platform_refund_expiry_unix_ts_ms: int,
                           platform_obfuscated_account_id:    bytes | str,
                           err:                               base.ErrorSink):
    with db.transaction(conn) as tx:
        add_unredeemed_payment_tx(tx                                = tx,
                                  payment_tx                        = payment_tx,
                                  plan                              = plan,
                                  expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                  unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                                  platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                  platform_obfuscated_account_id    = platform_obfuscated_account_id,
                                  err                               = err)

def _allocate_new_gen_id_if_master_pkey_has_payments(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> AllocatedGenID:
    result:            AllocatedGenID = AllocatedGenID()
    master_pkey_bytes: bytes          = bytes(master_pkey)

    lookup: LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx, master_pkey)
    result.expiry_unix_ts_ms         = lookup.expiry_unix_ts_ms_from_redeemed
    if lookup.expiry_unix_ts_ms_from_redeemed > 0:
        # NOTE: Master pkey has a payment we can use. Allocate a new generation ID in the runtime table
        result.found = True
        runtime_result = db.query(tx.conn, '''
            UPDATE    runtime
            SET       gen_index = gen_index + 1
            RETURNING gen_index - 1, gen_index_salt
        ''')
        runtime_row           = typing.cast(sqlalchemy.Row[tuple[int, bytes]], runtime_result.fetchone())
        result.gen_index      = runtime_row[0]
        result.gen_index_salt = runtime_row[1]

        # NOTE: Also update the user table with this payment we found that is currently the "best"
        # payment (e.g. the latest and most up to date payment and hence has the best expiry time)
        # for the user into their user record.
        #
        # This means that for the most part, consumers can just rely on the top level object to
        # determine the current state of the user subscription payment.
        _ = db.query(tx.conn, '''
            INSERT INTO users (master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, refund_requested_unix_ts_ms, google_obfuscated_account_id, apple_app_account_token)
            VALUES            (:master_pkey, :gen_index, :expiry, :grace, :auto_renewing, :refund_ts, :google_id, :apple_id)
            ON CONFLICT (master_pkey) DO UPDATE SET
                gen_index                    = excluded.gen_index,
                expiry_unix_ts_ms            = excluded.expiry_unix_ts_ms,
                grace_period_duration_ms     = excluded.grace_period_duration_ms,
                auto_renewing                = excluded.auto_renewing,
                refund_requested_unix_ts_ms  = excluded.refund_requested_unix_ts_ms,
                google_obfuscated_account_id = excluded.google_obfuscated_account_id,
                apple_app_account_token      = excluded.apple_app_account_token
        ''', master_pkey   = master_pkey_bytes,
             gen_index     = result.gen_index,
             expiry        = lookup.best_expiry_unix_ts_ms,
             grace         = lookup.best_grace_duration_ms,
             auto_renewing = lookup.best_auto_renewing,
             refund_ts     = lookup.best_refund_requested_unix_ts_ms,
             google_id     = google_obfuscated_account_id_from_master_pkey(master_pkey),
             apple_id      = apple_obfuscated_account_id_from_master_pkey(master_pkey),
             )

    return result

def make_generate_pro_proof_hash(version:       int,
                                 master_pkey:   nacl.signing.VerifyKey,
                                 rotating_pkey: nacl.signing.VerifyKey,
                                 unix_ts_ms:    int) -> bytes:
    '''Make the hash to sign for a pre-existing subscription by authorising
    a new rotating_pkey to be used for the Session Pro subscription associated
    with master_pkey'''
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=GENERATE_PROOF_HASH_PERSONALISATION)
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
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=BUILD_PROOF_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(gen_index_hash)
    hasher.update(bytes(rotating_pkey))
    hasher.update(expiry_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def _build_proof_clamped_expiry_time(unix_ts_ms: int, proposed_expiry_unix_ts_ms: int):
    # NOTE: Clamp the expiry time of the proof to 1 month and also make it land on the day boundary
    # to reduce metadata leakage. If it's less than 1 month then just take the value verbatim as
    # their subscription is coming to a close.
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

def add_pro_payment(conn:                sqlalchemy.engine.Connection,
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
        runtime_row: RuntimeRow = get_runtime(conn)
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
        for it in get_unredeemed_payments_list(conn):
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
            expiry_unix_ts_ms = redeemed_unix_ts_ms + (30 * 60 * 1000)

            platform_obfuscated_account_id: bytes | str = b''
            if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                platform_obfuscated_account_id = google_obfuscated_account_id_from_master_pkey(master_pkey)
            elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
                platform_obfuscated_account_id = apple_obfuscated_account_id_from_master_pkey(master_pkey)
            else:
                assert False, "Invalid code path"

            add_unredeemed_payment(conn                              = conn,
                                   payment_tx                        = internal_payment_tx,
                                   plan                              = base.ProPlan.OneMonth,
                                   unredeemed_unix_ts_ms             = redeemed_unix_ts_ms,
                                   platform_refund_expiry_unix_ts_ms = 0,
                                   platform_obfuscated_account_id    = platform_obfuscated_account_id,
                                   expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                   err                               = err)

            # Randomly toggle auto-renewal
            is_fake_auto_renewing = bool(random.getrandbits(1))
            _ = update_payment_renewal_info(conn                     = conn,
                                            payment_tx               = internal_payment_tx,
                                            grace_period_duration_ms = (60 * 1000) if is_fake_auto_renewing else 0,
                                            auto_renewing            = is_fake_auto_renewing,
                                            err                      = err)

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
    with db.transaction(conn) as tx:
        result = redeem_payment_tx(tx                  = tx,
                                   master_pkey         = master_pkey,
                                   rotating_pkey       = rotating_pkey,
                                   signing_key         = signing_key,
                                   unix_ts_ms          = unix_ts_ms,
                                   redeemed_unix_ts_ms = redeemed_unix_ts_ms,
                                   payment_tx          = payment_tx,
                                   err                 = err)

        # NOTE: We put this _inside_ the transaction block, because, for Google Payments we ack
        # the payment against Google's servers. If we have a network failure, this will throw an
        # exception and we want the transaction to be reverted because, redeeming and
        # acknowledgement must be done atomically.
        #
        # Ack-ing should be done after redeeming because we can't undo an ack on Google, so first we
        # make sure we can redeem it safely before lastly notifying Google that the payment is good
        # to go.
        if result.status == RedeemPaymentStatus.Success and payment_tx.provider == base.PaymentProvider.GooglePlayStore:
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
            if THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION == False:
                sub_data: platform_google_types.SubscriptionV2Data | None = platform_google_api.fetch_subscription_v2_details(package_name=platform_google_api.package_name,
                                                                                                                              purchase_token=payment_tx.google_payment_token,
                                                                                                                              err=err)
                if not sub_data:
                    tx.cancel = True
                    return result

                if log.getEffectiveLevel() <= logging.INFO:
                    payment_tx_label = _add_pro_payment_user_tx_log_label(payment_tx)
                    log.info(f'Google ack. payment check (dev={base.DEV_BACKEND_MODE}, version={version}, master={bytes(master_pkey).hex()}, payment={payment_tx_label}, acked={sub_data.acknowledgement_state})')

                if sub_data.acknowledgement_state != platform_google_types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED:
                    platform_google_api.subscription_v1_acknowledge(purchase_token=payment_tx.google_payment_token, err=err)
                    if len(err.msg_list) > 0:
                        tx.cancel = True
                        return result

    return result

def revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> AllocatedGenID:
    # Revoke the generation index allocated to the master pkey. This blocks all of the proofs
    # generated by the client that were using that payment.
    _ = db.query(tx.conn, ('''
        WITH prev_user AS (
            SELECT gen_index, expiry_unix_ts_ms
            FROM   users
            WHERE  master_pkey = :master_pkey
        )
        INSERT INTO revocations (gen_index, expiry_unix_ts_ms)
        SELECT      gen_index, expiry_unix_ts_ms
        FROM        prev_user
    '''), master_pkey = bytes(master_pkey))

    # If the use had any left over payments that are valid to use, we can allocate them a new
    # generation ID for subsequent proofs to be generated under. Clients will notice that their
    # current proofs on the old generation ID are revoked (via the previous function here) and
    # re-query the backend to generate a new one.
    result = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey)
    return result

def expire_by_unix_ts_ms(tx: db.SQLTransaction, unix_ts_ms: int) -> set[nacl.signing.VerifyKey]:
    log.info(f'Expire by ts (ts={base.readable_unix_ts_ms(unix_ts_ms)})')

    result_set = db.query(tx.conn, ('''
        UPDATE    payments
        SET       status = :status
        WHERE     :unix_ts_ms >= expiry_unix_ts_ms AND (status = :status1 OR status = :status2)
        RETURNING master_pkey
    '''), # SET values
          status     = int(base.PaymentStatus.Expired.value),
          # WHERE values
          unix_ts_ms = unix_ts_ms,
          status1    = int(base.PaymentStatus.Unredeemed.value),
          status2    = int(base.PaymentStatus.Redeemed.value),)

    result: set[nacl.signing.VerifyKey] = set()
    for row in result_set:
        if row[0]:
            master_pkey = nacl.signing.VerifyKey(bytes(row[0]))
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

def generate_pro_proof(conn: sqlalchemy.engine.Connection,
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
    get_user: GetUserAndPayments | None = None
    with db.transaction(conn) as tx:
        get_user = get_user_and_payments(tx, master_pkey)
    assert get_user

    if get_user.user.master_pkey == bytes(master_pkey):
        # Check that the gen index hash is not revoked
        if is_gen_index_revoked(conn, get_user.user.gen_index):
            err.msg_list.append(f'User {bytes(master_pkey).hex()} payment has been revoked')
        else:
            proof_expiry_unix_ts_ms: int = _build_proof_clamped_expiry_time(unix_ts_ms=unix_ts_ms, proposed_expiry_unix_ts_ms=get_user.user.expiry_unix_ts_ms)
            if unix_ts_ms <= proof_expiry_unix_ts_ms:
                result = build_proof(gen_index         = get_user.user.gen_index,
                                     rotating_pkey     = rotating_pkey,
                                     expiry_unix_ts_ms = proof_expiry_unix_ts_ms,
                                     signing_key       = signing_key,
                                     gen_index_salt    = gen_index_salt);
            else:
                payment_expiry_unix_ts_ms = get_user.user.expiry_unix_ts_ms - get_user.user.grace_period_duration_ms if get_user.user.auto_renewing else 0
                err.msg_list.append(f'User {bytes(master_pkey).hex()} entitlement expired at {base.readable_unix_ts_ms(get_user.user.expiry_unix_ts_ms)} ({base.readable_unix_ts_ms(payment_expiry_unix_ts_ms)} + {get_user.user.grace_period_duration_ms})')
    else:
        err.msg_list.append(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it, {bytes(get_user.user.master_pkey).hex()} {get_user.user.gen_index} {get_user.user.expiry_unix_ts_ms}')

    return result

def expire_payments_revocations_and_users(conn: sqlalchemy.engine.Connection, unix_ts_ms: int) -> ExpireResult:
    result = ExpireResult()
    with db.transaction(conn) as tx:
        # Retrieve the last expiry time that was executed
        runtime_result                     = db.query_one(tx.conn, '''SELECT last_expire_unix_ts_ms FROM runtime''')
        assert runtime_result

        last_expire_unix_ts_ms:       int  = runtime_result[0]
        already_done_by_someone_else: bool = last_expire_unix_ts_ms >= unix_ts_ms
        log.info(f'Expire payments/revocs/users (pid={os.getpid()}, ts={base.readable_unix_ts_ms(unix_ts_ms)}, last_expire={last_expire_unix_ts_ms}, already_done_by_someone_else={already_done_by_someone_else})')
        if not already_done_by_someone_else:
            # Update the timestamp that we executed DB expiry
            _ = db.query(tx.conn, '''UPDATE runtime SET last_expire_unix_ts_ms = :ts''', ts=unix_ts_ms)

            # Delete expired payments
            master_pkeys: set[nacl.signing.VerifyKey] = expire_by_unix_ts_ms(tx=tx, unix_ts_ms=unix_ts_ms)
            result.payments                           = len(master_pkeys)

            # Delete expired revocations
            rev_result                                = db.query(tx.conn, '''DELETE FROM revocations WHERE :ts >= expiry_unix_ts_ms''', ts=unix_ts_ms)
            result.revocations                        = rev_result.rowcount

            # Delete expired users
            users_result                              = db.query(tx.conn, '''DELETE FROM users WHERE master_pkey NOT IN (SELECT master_pkey FROM payments)''')
            result.users                              = users_result.rowcount

            # Delete expired apple notification UUIDs
            apple_result                              = db.query(tx.conn, '''DELETE FROM apple_notification_uuid_history WHERE :ts >= expiry_unix_ts_ms''', ts=unix_ts_ms)
            result.apple_notification_uuid_history    = apple_result.rowcount

            # Delete expired google notifications (but only if they have been handled)
            google_result                      = db.query(tx.conn, '''DELETE FROM google_notification_history WHERE :ts >= expiry_unix_ts_ms AND handled = 1''', ts=unix_ts_ms)
            result.google_notification_history = google_result.rowcount

        result.already_done_by_someone_else = already_done_by_someone_else
        result.success                      = True
    return result

def add_user_error_tx(tx: db.SQLTransaction, error: UserError, unix_ts_ms: int):
    match error.provider:
        case base.PaymentProvider.Nil:
            pass
        case base.PaymentProvider.GooglePlayStore:
            assert len(error.google_payment_token) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (:provider, :payment_id, :ts) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.google_payment_token,
                 ts=unix_ts_ms)

        case base.PaymentProvider.iOSAppStore:
            assert len(error.apple_original_tx_id) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (:provider, :payment_id, :ts) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.apple_original_tx_id,
                 ts=unix_ts_ms)


def add_user_error(conn: sqlalchemy.engine.Connection, error: UserError, unix_ts_ms: int):
    assert error.provider != base.PaymentProvider.Nil
    with db.transaction(conn) as tx:
        add_user_error_tx(tx, error, unix_ts_ms)

def has_user_error_tx(tx: db.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    row = db.query_one(tx.conn,
                       'SELECT 1 FROM user_errors WHERE payment_id = :pid AND payment_provider = :provider',
                       pid=payment_id,
                       provider=int(payment_provider.value))
    result = row is not None
    return result

def has_user_error_from_master_pkey_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> bool:
    row = db.query_one(tx.conn, (f'''
SELECT EXISTS (
    SELECT 1
    FROM payments p
    LEFT JOIN user_errors ue
        ON (p.payment_provider = {int(base.PaymentProvider.iOSAppStore.value)}     AND p.apple_original_tx_id = ue.payment_id)
        OR (p.payment_provider = {int(base.PaymentProvider.GooglePlayStore.value)} AND p.google_payment_token = ue.payment_id)
    WHERE p.master_pkey = :pkey
    AND ue.payment_id IS NOT NULL
) AS has_error;
'''), pkey=bytes(master_pkey))
    result = bool(row[0] == 1) if row else False
    return result

def has_user_error(conn: sqlalchemy.engine.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = has_user_error_tx(tx, payment_provider, payment_id)
    return result;

def delete_user_errors_tx(tx: db.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    row    = db.query(tx.conn, 'DELETE FROM user_errors WHERE payment_provider = :provider AND payment_id = :pid', provider=int(payment_provider.value), pid=payment_id)
    result = row.rowcount > 0
    return result

def delete_user_errors(conn: sqlalchemy.engine.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = delete_user_errors_tx(tx, payment_provider, payment_id)
    return result

def get_payment_tx(tx:          db.SQLTransaction,
                   payment_tx:  base.PaymentProviderTransaction,
                   err:         base.ErrorSink) -> PaymentRow | None:
    result = None
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return result

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(tx.conn, '''
            SELECT *
            FROM payments
            WHERE payment_provider = :provider AND google_payment_token = :token AND google_order_id = :order_id
        ''', provider  = int(payment_tx.provider.value),
              token    = payment_tx.google_payment_token,
              order_id = payment_tx.google_order_id)

        record = result_set.fetchone()
        if record:
            row = typing.cast(sqlalchemy.Row[tuple[int, *SQLTablePaymentRowTuple]], record)
            result = payment_row_from_tuple(tuple(row))

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(tx.conn, '''
                SELECT *
                FROM payments
                WHERE payment_provider = :provider AND apple_original_tx_id = :orig_tx_id AND apple_tx_id = :tx_id AND apple_web_line_order_tx_id = :line_order_tx_id
        ''', provider          = int(payment_tx.provider.value),
              orig_tx_id       = payment_tx.apple_original_tx_id,
              tx_id            = payment_tx.apple_tx_id,
              line_order_tx_id = payment_tx.apple_web_line_order_tx_id)

        record = result_set.fetchone()
        if record:
            row = typing.cast(sqlalchemy.Row[tuple[int, *SQLTablePaymentRowTuple]], record)
            result = payment_row_from_tuple(tuple(row))
 
    return result

def get_payment(conn: sqlalchemy.engine.Connection,
                payment_tx: base.PaymentProviderTransaction,
                err:        base.ErrorSink) -> PaymentRow | None:
    with db.transaction(conn) as tx:
        return get_payment_tx(tx=tx,
                              payment_tx=payment_tx,
                              err=err)

def set_refund_requested_unix_ts_ms_tx(tx: db.SQLTransaction, payment_tx: UserPaymentTransaction, unix_ts_ms: int) -> bool:
    rows: sqlalchemy.engine.Result[typing.Any] | None = None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_unix_ts_ms = :ts
            WHERE  payment_provider = :provider AND google_payment_token = :token AND google_order_id = :order_id
        ''', ts        = unix_ts_ms,
            provider = int(payment_tx.provider.value),
            token    = payment_tx.google_payment_token,
            order_id = payment_tx.google_order_id)
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_unix_ts_ms = :ts
            WHERE  payment_provider = :provider AND apple_tx_id = :tx_id
        ''', ts        = unix_ts_ms,
              provider = int(payment_tx.provider.value),
              tx_id    = payment_tx.apple_tx_id)

    assert rows and (rows.rowcount == 0 or rows.rowcount == 1)
    success = rows.rowcount > 0

    # If the refund timestamp has been set, immediately refresh the user's row.
    #
    # When a client hits /get_pro_details, that endpoint uses the user's row which caches the
    # "best" payment that should be used to entitle a user to pro. Hence if their refund
    # timestamp changes for that best payment, that metadata that is cached in the user details
    # must be updated.
    if success:
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            row = db.query_one(tx.conn, '''
                SELECT master_pkey
                FROM   payments
                WHERE  payment_provider = :provider AND google_payment_token = :token AND google_order_id = :order_id
            ''', provider = int(payment_tx.provider.value),
                 token    = payment_tx.google_payment_token,
                 order_id = payment_tx.google_order_id)
        else:
            row = db.query_one(tx.conn, '''
                SELECT master_pkey
                FROM   payments
                WHERE  payment_provider = :provider AND apple_tx_id = :tx_id
            ''', provider = int(payment_tx.provider.value),
                 tx_id    = payment_tx.apple_tx_id)

        if row:
            master_pkey = nacl.signing.VerifyKey(typing.cast(bytes, bytes(row[0])))
            _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, master_pkey)

    return success

def set_refund_requested_unix_ts_ms(conn: sqlalchemy.engine.Connection,
                                    payment_tx: UserPaymentTransaction,
                                    unix_ts_ms: int) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = set_refund_requested_unix_ts_ms_tx(tx, payment_tx, unix_ts_ms)
    return result

def apple_add_notification_uuid_tx(tx: db.SQLTransaction, uuid: str, expiry_unix_ts_ms: int):
    _ = db.query(tx.conn, ('''
        INSERT INTO apple_notification_uuid_history (uuid, expiry_unix_ts_ms)
        VALUES      (:uuid, :expiry)
    '''), uuid=uuid, expiry=expiry_unix_ts_ms)

def apple_notification_uuid_is_in_db_tx(tx: db.SQLTransaction, uuid: str) -> bool:
    row = db.query_one(tx.conn, ('''
        SELECT 1
        FROM   apple_notification_uuid_history
        WHERE  uuid = :uuid
    '''), uuid=uuid)
    result = row is not None
    return result

def apple_set_notification_checkpoint_unix_ts_ms(tx: db.SQLTransaction, checkpoint_unix_ts_ms: int):
    _ = db.query(tx.conn, ('''
        UPDATE runtime
        SET    apple_notification_checkpoint_unix_ts_ms = :ts
    '''), ts=checkpoint_unix_ts_ms)

def google_add_notification_id_tx(tx: db.SQLTransaction, message_id: int, expiry_unix_ts_ms: int, payload: str):
    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    _ = db.query(tx.conn, ('''
            INSERT INTO google_notification_history (message_id, handled, payload, expiry_unix_ts_ms)
            VALUES      (:message_id, 0, :payload, :expiry)
    '''), message_id = message_id,
          payload    = maybe_payload,
          expiry     = expiry_unix_ts_ms)

def google_set_notification_handled(tx: db.SQLTransaction, message_id: int, delete: bool) -> bool:
    if delete:
        rows = db.query(tx.conn, ('''DELETE FROM google_notification_history WHERE message_id = :message_id'''), message_id=message_id)
    else:
        rows = db.query(tx.conn, ('''UPDATE google_notification_history SET handled = 1, payload = NULL WHERE message_id = :message_id'''), message_id=message_id)
    result: bool = rows.rowcount >= 1
    return result

def google_get_unhandled_notification_iterator(tx: db.SQLTransaction) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    result_set = db.query(tx.conn, ('SELECT message_id, payload, expiry_unix_ts_ms FROM google_notification_history WHERE handled = 0'))
    return typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], result_set)

def google_notification_message_id_is_in_db_tx(tx: db.SQLTransaction, message_id: int) -> GoogleNotificationMessageIDInDB:
    row    = typing.cast(sqlalchemy.Row[tuple[int]] | None, db.query_one(tx.conn, '''SELECT handled FROM google_notification_history WHERE message_id = :message_id''', message_id=message_id))
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0 # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result

def _get_date_group_expr_sql(column: str, period: ReportPeriod, is_postgres: bool) -> str:
    """Generate dialect-specific date grouping SQL expression."""
    if is_postgres:
        match period:
            case ReportPeriod.Daily:
                return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'YYYY-MM-DD')"
            case ReportPeriod.Weekly:
                return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'IYYY-IW')"
            case ReportPeriod.Monthly:
                return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'YYYY-MM')"
    else:
        match period:
            case ReportPeriod.Daily:
                return f"strftime('%Y-%m-%d', {column}/1000, 'unixepoch')"
            case ReportPeriod.Weekly:
                return f"strftime('%Y-%W', {column}/1000, 'unixepoch')"
            case ReportPeriod.Monthly:
                return f"strftime('%Y-%m', {column}/1000, 'unixepoch')"

def _get_period_end_ts_sql(period_str: str, period: ReportPeriod, is_postgres: bool) -> str:
    """Generate dialect-specific period end timestamp SQL expression."""
    if is_postgres:
        if period == ReportPeriod.Weekly:
            year, week = period_str.split("-")
            return f"(TO_TIMESTAMP('{year}-01-01', 'YYYY-MM-DD') + INTERVAL '{(int(week)+1)*7 - 3} days' - INTERVAL '1 day' + INTERVAL '1 day' - INTERVAL '1 second')::bigint * 1000 + 86399"
        elif period == ReportPeriod.Monthly:
            return f"(DATE_TRUNC('month', '{period_str}-01'::date) + INTERVAL '1 month' - INTERVAL '1 second')::bigint * 1000 + 86399"
        else:
            return f"(DATE_TRUNC('day', '{period_str}'::date) + INTERVAL '1 day' - INTERVAL '1 second')::bigint * 1000 + 86399"
    else:
        if period == ReportPeriod.Weekly:
            year, week = period_str.split("-")
            return f"(strftime('%s', '{year}-01-01', '+{(int(week)+1)*7-3} days', 'weekday 0') * 1000 + 86399999)"
        elif period == ReportPeriod.Monthly:
            return f"(strftime('%s', '{period_str}-01', '+1 month', '-1 day') * 1000 + 86399999)"
        else:
            return f"((julianday('{period_str}') + 0.99999) * 86400000)"

def _format_period_label(period_str: str, period: ReportPeriod) -> str:
    """Format period string for display."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        date = datetime.datetime.fromisocalendar(year=int(year), week=int(week), day=1)
        return date.strftime('%F') + f' (W{week})'
    return period_str

def generate_report_rows(conn: sqlalchemy.engine.Connection, period: ReportPeriod, limit: int | None) -> list[ReportRow]:
    def fetch_counts(tx_conn: sqlalchemy.engine.Connection, period: ReportPeriod, unix_ts_ms_column: str, where_clause: str) -> dict[str, int]:
        is_postgres = db.is_postgres(tx_conn.engine)
        group_by_expr = _get_date_group_expr_sql(unix_ts_ms_column, period, is_postgres)

        result_set = db.query(tx_conn, f"""
            SELECT {group_by_expr} AS period, COUNT(*) AS count
            FROM payments
            WHERE {where_clause}
            GROUP BY period
            ORDER BY period DESC
        """)

        result: dict[str, int] = {}
        for row in result_set:
            period_label = _format_period_label(row[0], period)
            result[period_label] = row[1]
        return result

    def fetch_active_users(tx_conn: sqlalchemy.engine.Connection, period: ReportPeriod) -> dict[str, int]:
        is_postgres = db.is_postgres(tx_conn.engine)
        date_expr = _get_date_group_expr_sql("unredeemed_unix_ts_ms", period, is_postgres)

        result_set = db.query(tx_conn, f"""
            SELECT DISTINCT {date_expr} AS period
            FROM payments
        """)
        periods_list = [row[0] for row in result_set]
        result: dict[str, int] = {}

        for it in periods_list:
            assert isinstance(it, str)
            end_ts = _get_period_end_ts_sql(it, period, is_postgres)

            result_set = db.query(tx_conn, f"""
                SELECT COUNT(DISTINCT master_pkey) AS active
                FROM payments
                WHERE {end_ts} >= unredeemed_unix_ts_ms
                  AND {end_ts} <= expiry_unix_ts_ms
                  AND status != {base.PaymentStatus.Revoked.value}
            """)

            count        = result_set.fetchone()[0] or 0
            period_label = _format_period_label(it, period)
            result[period_label] = count

        return result

    result: list[ReportRow] = []
    with db.transaction(conn) as tx:
        unredeemed: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"status = {base.PaymentStatus.Unredeemed.value}",
        )

        plan_1m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = {base.ProPlan.OneMonth.value}",
        )

        plan_3m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = {base.ProPlan.ThreeMonth.value}",
        )

        plan_12m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = {base.ProPlan.TwelveMonth.value}",
        )

        google: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"payment_provider = {base.PaymentProvider.GooglePlayStore.value}",
        )

        apple: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"payment_provider = {base.PaymentProvider.iOSAppStore.value}",
        )

        new_subs: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = "unredeemed_unix_ts_ms IS NOT NULL AND unredeemed_unix_ts_ms > 0",
        )

        refunds_initiated: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "refund_requested_unix_ts_ms",
            where_clause      = "refund_requested_unix_ts_ms > 0",
        )

        revocations: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "revoked_unix_ts_ms",
            where_clause      = "revoked_unix_ts_ms IS NOT NULL AND revoked_unix_ts_ms > 0",
        )

        cancelled: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "expiry_unix_ts_ms",
            where_clause      = f"auto_renewing = 0 AND status != {base.PaymentStatus.Revoked.value}",
        )

        active_users: dict[str, int] = fetch_active_users(tx.conn, period)

        all_periods: set[str] = set()
        for key_list in [new_subs.keys(), refunds_initiated.keys(), revocations.keys(), cancelled.keys(), active_users.keys()]:
            for it in key_list:
                all_periods.add(it)

        sorted_periods: list[str] = sorted(all_periods, reverse=True)[:limit]
        for it in sorted_periods:
            result.append(ReportRow(
                period            = it,
                active_users      = active_users.get(it, 0),
                unredeemed        = unredeemed.get(it, 0),
                new_subs          = new_subs.get(it, 0),
                google            = google.get(it, 0),
                apple             = apple.get(it, 0),
                plan_1m           = plan_1m.get(it, 0),
                plan_3m           = plan_3m.get(it, 0),
                plan_12m          = plan_12m.get(it, 0),
                refunds_initiated = refunds_initiated.get(it, 0),
                revoked           = revocations.get(it, 0),
                cancelled         = cancelled.get(it, 0),
            ))

    return result

def generate_report_str(period: ReportPeriod, data: list[ReportRow], type: ReportType) -> str:
    @dataclasses.dataclass(frozen=True)
    class Section:
        name:       str
        width:      int
        align_left: bool = False

    sections: list[Section] = [
        Section("Period",            16, align_left=True),
        Section("Active Users",      14),
        Section("Unredeemed",        12),
        Section("New Subs",          10),
        Section("Google",            8),
        Section("Apple",             7),
        Section("Plan 1m",           10),
        Section("Plan 3m",           10),
        Section("Plan 12m",          10),
        Section("Refunds Initiated", 20),
        Section("Revoked",           10),
        Section("Cancelling",        12),
    ]

    result: str = ''
    match type:
        case ReportType.Human:
            header_parts: list[str] = []
            for sec in sections:
                if sec.align_left:
                    header_parts.append(f"{sec.name:<{sec.width}}")
                else:
                    header_parts.append(f"{sec.name:>{sec.width}}")
            header = " ".join(header_parts)

            result = f"{period.name.upper()} REPORT\n"
            result += "-" * len(header) + "\n"
            result += header + "\n"
            result += "-" * len(header) + "\n"

            for i, row in enumerate(data):
                if i > 0:
                    result += "\n"

                human_parts: list[str] = []
                part_section           = sections[len(human_parts)]
                padding                = part_section.width
                align                  = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.period:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.active_users:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.unredeemed:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.new_subs:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.google:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.apple:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_1m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_3m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_12m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.refunds_initiated:20}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.revoked:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.cancelled:{align}{padding}}")

                assert len(human_parts) == len(sections)
                result += " ".join(human_parts)

        case ReportType.CSV:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([sec.name for sec in sections])
            for row in data:
                csv_parts: list[str | int] = [
                    row.period,
                    row.active_users,
                    row.unredeemed,
                    row.new_subs,
                    row.google,
                    row.apple,
                    row.plan_1m,
                    row.plan_3m,
                    row.plan_12m,
                    row.refunds_initiated,
                    row.revoked,
                    row.cancelled,
                ]
                assert len(csv_parts) == len(sections)
                writer.writerow(csv_parts)
            result = output.getvalue().strip()
    return result
