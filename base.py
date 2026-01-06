'''
The base layer contains common utilities that is useful to other files in the project and should
have no dependency on any project files, only, native Python packages. Typically useful to share
functionality from the testing suite and the project but not limited to.
'''
import dataclasses
import datetime
import enum
import glob
import json
import logging
import math
import os
import pathlib
import sqlite3
import sys
import threading
import time
import traceback
import typing
import typing_extensions
import urllib.request

# NOTE: Constants
SECONDS_IN_DAY:        int     = 60 * 60 * 24
MILLISECONDS_IN_DAY:   int     = 60 * 60 * 24 * 1000
MILLISECONDS_IN_MONTH: int     = MILLISECONDS_IN_DAY * 30
SECONDS_IN_MONTH:      int     = SECONDS_IN_DAY * 30
MILLISECONDS_IN_YEAR:  int     = MILLISECONDS_IN_DAY * 365
SECONDS_IN_YEAR:       int     = SECONDS_IN_DAY * 365

# NOTE: Global variables
DB_PATH                        = ''
DB_PATH_IS_URI                 = False
DEV_BACKEND_MODE               = False
DEV_BACKEND_DETERMINISTIC_SKEY = bytes([0xCD] * 32)
UNSAFE_LOGGING                 = False
PLATFORM_TESTING_ENV           = False

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONPrimitive: typing.TypeAlias = str | int | float | bool | None
JSONValue:     typing.TypeAlias = JSONPrimitive | dict[str, 'JSONValue'] | list['JSONValue']
JSONObject:    typing.TypeAlias = dict[str, JSONValue]
JSONArray:     typing.TypeAlias = list[JSONValue]

@dataclasses.dataclass
class BackupRotationDryRun:
    to_keep: list[pathlib.Path]   = dataclasses.field(default_factory=list)
    to_delete: list[pathlib.Path] = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class PaymentProviderData:
    id: int = 0

class PaymentProvider(enum.Enum):
    Nil             = 0
    GooglePlayStore = 1
    iOSAppStore     = 2

@dataclasses.dataclass
class PaymentProviderTransaction:
    provider:                   PaymentProvider = PaymentProvider.Nil
    apple_original_tx_id:       str = ''
    apple_tx_id:                str = ''
    apple_web_line_order_tx_id: str = ''
    google_payment_token:       str = ''
    google_order_id:            str = ''

class PaymentStatus(enum.IntEnum):
    Nil        = 0
    Unredeemed = 1
    Redeemed   = 2
    Expired    = 3
    Revoked    = 4

class ProPlan(enum.Enum):
    """
    Universal Pro Plan Identifier.
    This enum is stored as an int in the database, existing entries must
    not be reordered or changed.
    """
    Nil             = 0
    OneMonth        = 1
    ThreeMonth      = 2
    TwelveMonth     = 3

class LogFormatter(logging.Formatter):
    @typing_extensions.override
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None):
        dt     = datetime.datetime.fromtimestamp(record.created)
        result = dt.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]
        return result

@dataclasses.dataclass
class ErrorSink:
    '''
    Helper class to pass to functions that want to return error messages without unwinding the stack
    by using throwing exceptions.

    The typical pattern in that this construct is used is calling a sequence of functions that can
    error but have no dependency on each other. Errors are accumulated into the sink and checked at
    the end where it reports the error from the sink and returns a failure if there is one.

    See the parsing code in server.py for an example of where this is useful.
    '''
    msg_list: list[str] = dataclasses.field(default_factory=list)

    def has(self) -> bool:
        result = len(self.msg_list) > 0
        return result

    def build(self) -> str:
        result = '\n  '.join(self.msg_list)
        return result

class SQLTransactionMode(enum.IntEnum):
    Default   = 0 # Acquires requisite r/w DB lock on first query
    Immediate = 1 # Acquires write lock and allows concurrent reads
    Exclusive = 2 # Acquires lock and blocks concurrent reads (and by definition, writes)

@dataclasses.dataclass
class SQLTransaction:
    conn:   sqlite3.Connection
    cursor: sqlite3.Cursor | None = None
    cancel: bool                  = False
    mode:   SQLTransactionMode    = SQLTransactionMode.Default
    def __init__(self, conn: sqlite3.Connection, mode: SQLTransactionMode = SQLTransactionMode.Default):
        self.conn = conn
        self.mode = mode

    def __enter__(self):
        mode_label = ''
        match self.mode:
            case SQLTransactionMode.Default:
                mode_label = 'DEFERRED '
            case SQLTransactionMode.Immediate:
                mode_label = 'IMMEDIATE '
            case SQLTransactionMode.Exclusive:
                mode_label = 'EXCLUSIVE '
        self.cursor = self.conn.execute(f'BEGIN {mode_label} TRANSACTION')
        return self

    def __exit__(self,
                 exc_type: object | None,
                 exc_value: object | None,
                 traceback: traceback.TracebackException | None):
        if self.cursor:
            self.cursor.close()
        if exc_type is not None or self.cancel:
            self.conn.rollback()
        else:
            self.conn.commit()
        return False

def is_sql_database_locked_error(e: sqlite3.OperationalError) -> bool:
    result = "database is locked" in str(e)
    return result

def retry_function_on_database_locked_error(callback: typing.Callable[[], typing.Any], log: logging.Logger, error_prefix: str, err: ErrorSink):
    """
    Execute a user-provided callable with retries on SQLite 'database is locked' errors. Pass a
    lambda as the operation callable to be the function that should be retried on failure
    """

    sleep_time_s: int = 1
    max_attempts: int = 8
    for exc_attempt in range(max_attempts):
        reattempt = False
        try:
            callback()
        except sqlite3.OperationalError as e:
            if is_sql_database_locked_error(e):
                log.warning(f'{error_prefix} attempt #{exc_attempt}/{max_attempts}, database was locked. Re-attempting in {sleep_time_s}s. Error was: {traceback.format_exc()}')
                time.sleep(sleep_time_s)
                sleep_time_s *= 2
                reattempt    = True
            else:
                err.msg_list.append(f'{error_prefix}. Error was: {traceback.format_exc()}')
        except Exception as e:
            err.msg_list.append(f'{error_prefix}. Error was: {traceback.format_exc()}')

        if not reattempt:
            break

@dataclasses.dataclass
class TableStrings:
    name:     str = ''
    contents: list[list[str]] = dataclasses.field(default_factory=list)

class AsyncSessionWebhookLogHandler(logging.Handler):
    webhook_url:    str
    display_name:   str
    _submit_thread: threading.Thread
    timeout:        int       = 2

    def __init__(self, url: str, name: str):
        super().__init__()
        self.webhook_url    = url
        self.display_name   = name
        assert len(self.display_name) <= 100, f'Display name must be less than 100 characters: {len(self.display_name)}'
        self._lock          = threading.Lock()
        self._stop_event    = threading.Event()
        self._queue_dirtied = threading.Event()
        self.msg_queue      = []
        self._submit_thread = threading.Thread(target=self._worker, daemon=True)
        self._stop_event    = threading.Event()
        self._submit_thread.start()

    def emit_text(self, text: str, date_prefix: bool = True):
        prefix: str = ''
        if date_prefix:
            date   = datetime.datetime.fromtimestamp(time.time())
            prefix = date.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]

        max_size = 128
        with self._lock:
            if len(self.msg_queue) >= max_size:
                self.msg_queue = self.msg_queue[-(max_size - 2):]
                self.msg_queue.append(f"{prefix} Message queue was full, overwriting old message")
            self.msg_queue.append(f"{prefix} {text}"[:2000])
        self._queue_dirtied.set()

    @typing_extensions.override
    def emit(self, record: logging.LogRecord):
        if record.levelno < logging.WARNING:
            return
        self.emit_text(self.format(record)[:2000], date_prefix=False)

    def _worker(self):
        while True:
            _ = self._queue_dirtied.wait()
            if self._stop_event.is_set():
                break
            self._queue_dirtied.clear()

            # Extract batch of messages to send with lock
            while True:
                batch: list[str] = []
                with self._lock:
                    batch_size     = min(len(self.msg_queue), 8) # Pump at most, 8 at a time then yield
                    batch          = self.msg_queue[:batch_size]
                    self.msg_queue = self.msg_queue[batch_size:]

                for it in batch: # Blocking send
                    payload: dict[str, str] = { "text": "```\n" + it + "\n```", "display_name": self.display_name }
                    request                 = urllib.request.Request(self.webhook_url, data=json.dumps(payload).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
                    try:
                        _ = urllib.request.urlopen(request, timeout=self.timeout)  # pyright: ignore[reportAny]
                    except Exception as e:
                        print(f"Session webhook send failed: {e}", file=sys.stderr)

                with self._lock:
                    if len(self.msg_queue) == 0:
                        break

    @typing_extensions.override
    def close(self):
        self._stop_event.set()
        self._queue_dirtied.set()
        if self._submit_thread.is_alive():
            self._submit_thread.join(timeout=2)
        super().close()

def verify_payment_provider(payment_provider: PaymentProvider | int, err: ErrorSink | None) -> bool:
    result = False
    provider = PaymentProvider.Nil
    if isinstance(payment_provider, PaymentProvider):
        provider = payment_provider
        result = True
    else:
        try:
            provider = PaymentProvider(payment_provider)
            result = True
        except ValueError:
            if err:
                err.msg_list.append('Unrecognised payment provider: {}'.format(payment_provider))

    if err and len(err.msg_list) == 0 and provider == PaymentProvider.Nil:
        err.msg_list.append('Nil payment provider is invalid, must be set to a provider')

    return result

def hex_to_bytes(hex: str, label: str, hex_len: int, err: ErrorSink) -> bytes:
    result = b''
    if len(hex) != hex_len:
        err.msg_list.append(f'{label} was not {hex_len} characters, was {len(hex)} characters')
    else:
        try:
            result = bytes.fromhex(hex)
        except Exception as e:
            err.msg_list.append(f'{label} was not valid hex: {e}')
    return result

def readable_unix_ts_ms(unix_ts_ms: int) -> str:
    date_str = datetime.datetime.fromtimestamp(unix_ts_ms/1000.0).strftime('%y-%m-%d %H:%M:%S.%f')[:-3]
    result   = f'{unix_ts_ms} ({date_str})'
    return result

def print_unicode_table(rows: list[list[str]]) -> None:
    # Calculate maximum width for each column
    col_widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]

    # Print top border
    line = '┌'
    for i, width in enumerate(col_widths):
        line += '─' * (width + 2)  # +2 for padding spaces
        if i < len(col_widths) - 1:
            line += '┬'
    line += '┐'
    print(line)

    # Print header (first row)
    header_row = '│'
    for i, field in enumerate(rows[0]):
        header_row += f' {field:<{col_widths[i]}} │'
    print(header_row)

    # Print separator between header and data
    separator = '├'
    for i, width in enumerate(col_widths):
        separator += '─' * (width + 2)
        if i < len(col_widths) - 1:
            separator += '┼'
    separator += '┤'
    print(separator)

    # Print data rows
    for row in rows[1:]:
        row_str = '│'
        for i, field in enumerate(row):
            row_str += f' {field:<{col_widths[i]}} │'
        print(row_str)

    # Print bottom border
    bottom = '└'
    for i, width in enumerate(col_widths):
        bottom += '─' * (width + 2)
        if i < len(col_widths) - 1:
            bottom += '┴'
    bottom += '┘'
    print(bottom)

def print_db_to_stdout_tx(tx: SQLTransaction) -> None:
    table_strings: list[TableStrings] = []
    assert tx.cursor is not None
    _           = tx.cursor.execute('SELECT name FROM sqlite_master WHERE type="table";')
    tables      = typing.cast(list[tuple[str]], tx.cursor.fetchall())
    table_names = [table[0] for table in tables]
    for table_name in table_names:
        _                       = tx.cursor.execute(f'SELECT * FROM {table_name}')
        rows                    = tx.cursor.fetchall()
        column_names: list[str] = [description[0] for description in tx.cursor.description]

        table_str: TableStrings = TableStrings()
        table_str.name          = table_name
        table_str.contents      = [column_names]

        if rows:
            for row in rows:
                content: list[str] = []
                for index, value in enumerate(row):
                    col = column_names[index]
                    if value is None:
                        content.append(str(value))
                    elif isinstance(value, bytes):
                        try:
                            text = value.decode('utf-8');
                            text = text.replace('\n', '')
                            text = text.replace('\r', '')
                            text = text.replace('\t', '')

                            print_limit = 128
                            if len(text) > print_limit:
                                print("woah nelly")
                                content.append(str(text[:print_limit]) + f'...({len(value)})')
                            else:
                                content.append(str(text))
                        except Exception:
                            content.append(value.hex())
                    elif isinstance(value, str):
                        try:
                            text = value.replace('\n', '')
                            text = text.replace('\r', '')
                            text = text.replace('\t', '')

                            print_limit = 128
                            if len(text) > print_limit:
                                content.append(str(text[:print_limit]) + f'...({len(value)})')
                            else:
                                content.append(str(text))
                        except Exception:
                            content.append(str(value))
                    elif col.endswith('unix_ts_ms'):
                        content.append(readable_unix_ts_ms(int(value)))
                    elif col.endswith('_s'):
                        seconds = int(value)
                        days    = seconds / SECONDS_IN_DAY
                        content.append(f'{seconds} ({days:.2f} days)')
                    elif col == 'payment_provider':
                        value_int = int(value)
                        if value_int == PaymentProvider.Nil.value:
                            content.append(f'Nil ({value_int})')
                        elif value_int == PaymentProvider.GooglePlayStore.value:
                            content.append(f'Google Play Store ({value_int})')
                        elif value_int == PaymentProvider.iOSAppStore.value:
                            content.append(f'iOS App Store ({value_int})')
                        else:
                            content.append(f'Unknown ({value_int})')
                    elif table_name == 'payments' and col == 'status':
                        value_enum = PaymentStatus(value)
                        content.append(f'{value_enum.name} ({value_enum.value})')
                    elif table_name == 'payments' and col == 'plan':
                        value_enum = ProPlan(value)
                        content.append(f'{value_enum.name} ({value_enum.value})')
                    elif table_name == 'payments' and col == 'auto_renewing':
                        content.append('Yes' if value else 'No' + f' ({value})')
                    else:
                        content.append(str(value))
                table_str.contents.append(content)
        table_strings.append(table_str)

    for it in table_strings:
        print(f'Table: {it.name}')
        print_unicode_table(it.contents)

def print_db_to_stdout(sql_conn: sqlite3.Connection) -> None:
    with SQLTransaction(sql_conn) as tx:
        print_db_to_stdout_tx(tx)

def round_unix_ts_ms_to_next_day(unix_ts_ms: int) -> int:
    result: int = (unix_ts_ms + (MILLISECONDS_IN_DAY - 1)) // MILLISECONDS_IN_DAY * MILLISECONDS_IN_DAY
    return result

def round_unix_ts_ms_to_start_of_day(unix_ts_ms: int) -> int:
    result: int = unix_ts_ms // MILLISECONDS_IN_DAY * MILLISECONDS_IN_DAY
    return result

def format_bytes(size: int):
    units = [
        (1 << 40, 'TB'),
        (1 << 30, 'GB'),
        (1 << 20, 'MB'),
        (1 << 10, 'kB'),
        (1,       'B')
    ]
    for base, prefix in units:
        if size >= base:
            formatted_size = size / base
            return f'{formatted_size:.2f} {prefix}'
    return '0.00 B'

def format_seconds(duration_s: float) -> str:
    hours = int(duration_s // 3600)
    minutes = int((duration_s % 3600) // 60)
    seconds = duration_s % 60
    result = ''
    if hours > 0:
        result += f"{hours}h"
    if minutes > 0:
        result += f"{' ' if result else ''}{minutes}m"
    # For seconds: show decimals only if there's a fractional part
    if seconds >= 1 or result == '':  # Always show seconds if no higher units
        if seconds == int(seconds):
            sec_str = str(int(seconds))
        else:
            # Show up to 3 decimal places, strip trailing zeros
            sec_str = f"{seconds:.3f}".rstrip('0').rstrip('.')
        result += f"{' ' if result else ''}{sec_str}s"
    return result if result else '0s'

def obfuscate(val: str) -> str:
    """
    Obfuscate a string by masking the contents preserving the prefix and suffix. If the string is
    less than 3 characters, the original string is retuned.
    """
    if len(val) < 3:
        return val
    n_ends = max(math.floor(len(val) * 0.3), 1)
    return f"{val[:n_ends]}…{val[-n_ends:]}"

def reflect_enum(enum_value: enum.Enum) -> str:
    name = enum_value.name
    value = None
    if isinstance(enum_value, enum.IntEnum):
        value = enum_value.value
    return f'{name} ({value})' if value is not None else name

def _extract_keys_format_value(value):
    """
    Internal helper function to format dictionary values,
    it's better to define this outside the function.
    """
    if isinstance(value, dict):
        # Get all keys from the dictionary
        keys = []
        for k, v in value.items():
            if isinstance(v, dict):
                # If the value is a dict, recursively format it
                keys.append(f"{k}: {_extract_keys_format_value(v)}")
            else:
                keys.append(k)
        return "{" + ', '.join(keys) + "}"
    else:
        return str(value)

def extract_keys_recursive(d: dict[str, typing.Any]) -> str:
    """
    Recursively extract keys from a nested dictionary and format them.
    
    Args:
        d: Dictionary to extract keys from
    
    Returns:
        String representation of keys in the format:
        "{key1, key2: {subkey1, subkey2}, key3: {subkey: {subsubkey}}}"
    """
    try:
        result = []
        for key, value in d.items():
            if isinstance(value, dict):
                result.append(f"{key}: {_extract_keys_format_value(value)}")
            else:
                result.append(key)
        
        return ', '.join(result)
    except Exception as e:
        return "FAILED TO EXTRACT KEYS"

def safe_dump_dict_keys_or_data(d: dict[str, typing.Any] | None) -> str:
    """Dump the dict or just the keys if UNSAFE_LOGGING is set"""
    if d is None:
        return "None"
    if UNSAFE_LOGGING:
        return json.dumps(d)
    return "dictionary w/ keys: {" + extract_keys_recursive(d) + "}"

def safe_dump_arbitrary_value_or_type(v: typing.Any) -> str:  # pyright: ignore[reportAny]
    """Dump the value or just its type if UNSAFE_LOGGING is set"""
    result = f'({type(v)}) {v}' if UNSAFE_LOGGING else f'{type(v)}'
    return result

def safe_get_dict_value_type(d: dict[str, typing.Any], key: str) -> str:
    v = d.get(key)
    return safe_dump_arbitrary_value_or_type(v)

def json_dict_require_str(d: JSONObject, key: str, err: ErrorSink) -> str:
    result = ''
    if key in d:
        if isinstance(d[key], str):
            result = typing.cast(str, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a string: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_int(d: JSONObject, key: str, err: ErrorSink) -> int:
    result = 0
    if key in d:
        if isinstance(d[key], int):
            result = typing.cast(int, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an integer: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_bool(d: JSONObject, key: str, err: ErrorSink) -> bool:
    result = False
    if key in d:
        if isinstance(d[key], bool):
            result = typing.cast(bool, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a bool: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_array(d: JSONObject, key: str, err: ErrorSink) -> JSONArray:
    result: list[JSONValue] = []
    if key in d:
        if isinstance(d[key], list):
            result = typing.cast(list[JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an array: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_obj(d: dict[str, JSONValue], key: str, err: ErrorSink) -> JSONObject:
    result: dict[str, JSONValue] = {}
    if key in d:
        if isinstance(d[key], dict):
            result = typing.cast(dict[str, JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an object: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_str_coerce_to_int(d: JSONObject, key: str, err: ErrorSink) -> int:
    result_str = json_dict_require_str(d, key, err)
    result = 0
    try:
        result = int(result_str)
    except Exception as e:
        err.msg_list.append(f'Unable to parse {key} type to an int: {e}')
    return result

def json_dict_require_str_coerce_to_enum(d: JSONObject, key: str, my_enum: typing.Type[enum.StrEnum], err: ErrorSink):
    result_str = json_dict_require_str(d, key, err)
    result = my_enum._value2member_map_.get(result_str)
    if result is None:
        err.msg_list.append(f'Unable to parse {key} type to an enum')
    return result

def json_dict_require_int_coerce_to_enum(d: JSONObject, key: str, my_enum: typing.Type[enum.IntEnum], err: ErrorSink):
    result = None
    result_int = None
    if key in d:
        if isinstance(d[key], int):
            result_int = typing.cast(int, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an integer: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}')

    if result_int is not None:
        result = my_enum._value2member_map_.get(result_int)

    if result is None:
        err.msg_list.append(f'Unable to parse {key} type to an enum')

    return result

def json_dict_optional_bool(d: JSONObject, key: str, default: bool, err: ErrorSink) -> bool:
    result = default
    if key in d:
        if isinstance(d[key], bool):
            result = typing.cast(bool, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a bool: "{safe_get_dict_value_type(d, key)}"')
    return result

def json_dict_optional_str(d: JSONObject, key: str, err: ErrorSink) -> str | None:
    result = None
    if key in d:
        if isinstance(d[key], str):
            result = typing.cast(str, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a string: "{safe_get_dict_value_type(d, key)}"')
    return result

def json_dict_optional_obj(d: JSONObject, key: str, err: ErrorSink) -> JSONObject | None:
    result: dict[str, JSONValue] | None = None
    if key in d:
        if isinstance(d[key], dict):
            result = typing.cast(dict[str, JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an object: "{safe_get_dict_value_type(d, key)}"')
    return result

def validate_string_list(items: list[JSONValue]) -> typing.TypeGuard[list[str]]:
    return all(isinstance(item, str) for item in items)

def handle_not_implemented(name: str, err: ErrorSink):
    err.msg_list.append(f"'{name}' is not implemented!")

def os_get_boolean_env(var_name: str, default: bool = False):
    value = os.getenv(var_name, str(int(default)))  # Default to 0 or 1
    if value == '1':
        return True
    elif value == '0':
        return False
    else:
        raise ValueError(f"Invalid value for environment variable '{var_name}': {value}. Allowed values are 0 or 1.")

def backup_file_path(base_file_path: pathlib.Path, now: datetime.datetime) -> str:
    date:      str          = now.strftime("%Y-%m-%d_%H%M%S")
    file_name: str          = base_file_path.name
    parent:    pathlib.Path = base_file_path.parent
    result                  = str(parent / f'{date}_{file_name}.bak')
    return result

def backup_rotation_from_dated_files_dry_run(backup_files_listing: list[str], now: datetime.datetime) -> BackupRotationDryRun:
    """
    Given a list of files in the format "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
    return the list of those files to delete to fulfill the rotating backup criteria:

    - Keep the last 180 days worth of backups
    - AND Keep the earliest backup for each month

    The rotating date filter to all files in the list even if "<rest_of_file_name_and>.<extension>"
    are different from each other.
    """

    @dataclasses.dataclass
    class BackupItem:
        date: datetime.datetime
        path: pathlib.Path
        keep: bool = False

    # NOTE: Parse the list of on-disk backups into (year) -> (month) -> [(date, path)] entries
    year_backups: dict[int, dict[int, list[BackupItem]]] = {}
    for item in backup_files_listing:
        try:
            file_name:        str = pathlib.Path(item).name  # Extract file name
            # Extract timestamp from filename of format
            # "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
            expected_prefix: str = "YYYY-MM-DD_HHMMSS"
            ts_str:          str = file_name[:len(expected_prefix)]
            dt                   = datetime.datetime.strptime(ts_str, "%Y-%m-%d_%H%M%S") # Parse the timestamp
            if not dt.year in year_backups:
                year_backups[dt.year] = {}
            if not dt.month in year_backups[dt.year]:
                year_backups[dt.year][dt.month] = []
            year_backups[dt.year][dt.month].append(BackupItem(date=dt, path=pathlib.Path(item)))
        except:
            continue  # skip malformed

    # NOTE: Sort each list of backups belonging to the (year, month)
    for year in year_backups:
        for month in year_backups[year]:
            year_backups[year][month] = sorted(year_backups[year][month], key=lambda it: it.date)

    # NOTE: Determine which backup to keep
    cutoff_unix_ts_s: int = int(now.timestamp()) - (SECONDS_IN_DAY * 180)
    for year in year_backups:
        for month in year_backups[year]:
            backups: list[BackupItem] = year_backups[year][month]

            # NOTE: If we're within the recent cutoff date, keep the file
            for backup_it in backups:
                if backup_it.date.timestamp() >= cutoff_unix_ts_s:
                    backup_it.keep  = True

            # NOTE: We keep the earliest one we have for that month
            backups[0].keep  = True

    # NOTE: Generate the final result (the 2 lists, keep or delete)
    result = BackupRotationDryRun()
    for year in year_backups:
        for month in year_backups[year]:
            backups = year_backups[year][month]
            for backup_it in backups:
                if backup_it.keep:
                    result.to_keep.append(backup_it.path)
                else:
                    result.to_delete.append(backup_it.path)

    return result

def backup_rotation_dry_run(base_file_path: pathlib.Path, now: datetime.datetime) -> BackupRotationDryRun:
    """
    Given a path to the file denoted by 'base_file_path' enumerate for other files in the directory
    with the format "YYYY-MM-DD_HHMMSS_<base_file_name>" and return the list of those files to
    keep and delete for the rotating backup criteria (see: dry_run_backup_rotation_from_dated_files)
    """

    backup_dir:  pathlib.Path = pathlib.Path(base_file_path).parent
    backup_name: str          = pathlib.Path(base_file_path).name

    # NOTE: Retrieve the list of backups
    backup_files_listing: list[str]            = glob.glob(str(backup_dir / f"*_{backup_name}.bak"))
    result:               BackupRotationDryRun = backup_rotation_from_dated_files_dry_run(backup_files_listing, now)
    return result

