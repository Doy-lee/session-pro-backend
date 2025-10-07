'''
The base layer contains common utilities that is useful to other files in the project and should
have no dependency on any project files, only, native Python packages. Typically useful to share
functionality from the testing suite and the project but not limited to.
'''
import json
import traceback
import sqlite3
import datetime
import typing
import enum
import dataclasses
from math import floor

import env
import os

class PaymentProvider(enum.IntEnum):
    Nil             = 0
    GooglePlayStore = 1
    iOSAppStore     = 2

SECONDS_IN_DAY:      int       = 60 * 60 * 24
MILLISECONDS_IN_DAY: int       = 60 * 60 * 24 * 1000
MILLISECONDS_IN_MONTH: int     = MILLISECONDS_IN_DAY * 30
SECONDS_IN_MONTH: int          = SECONDS_IN_DAY * 30
MILLISECONDS_IN_YEAR: int      = MILLISECONDS_IN_DAY * 365
SECONDS_IN_YEAR: int           = SECONDS_IN_DAY * 365
DEV_BACKEND_MODE:    bool      = False
DEV_BACKEND_DETERMINISTIC_SKEY = bytes([0xCD] * 32)
WITH_PLATFORM_APPLE: bool      = False

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
        return len(self.msg_list) > 0

@dataclasses.dataclass
class SQLTransaction:
    conn:   sqlite3.Connection
    cursor: sqlite3.Cursor | None = None
    cancel: bool                  = False
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self):
        self.cursor = self.conn.execute('BEGIN TRANSACTION')
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

@dataclasses.dataclass
class TableStrings:
    name:     str = ''
    contents: list[list[str]] = dataclasses.field(default_factory=list)

def verify_payment_provider(payment_provider: PaymentProvider | int, err: ErrorSink):
    provider = PaymentProvider.Nil
    if isinstance(payment_provider, int):
        try:
            provider = PaymentProvider(payment_provider)
        except ValueError:
            err.msg_list.append('Unrecognised payment provider: {}'.format(payment_provider))
    else:
        provider = payment_provider

    if len(err.msg_list) == 0 and provider == PaymentProvider.Nil:
        err.msg_list.append('Nil payment provider is invalid, must be set to a provider')

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

def print_db_to_stdout(sql_conn: sqlite3.Connection) -> None:
    table_strings: list[TableStrings] = []
    with SQLTransaction(sql_conn) as tx:
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
                            content.append(value.hex())
                        elif col.endswith('unix_ts_ms'):
                            timestamp = int(value)
                            date_str  = datetime.datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d')
                            content.append(f'{timestamp} ({date_str})')
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
                        else:
                            content.append(str(value))
                    table_str.contents.append(content)
            table_strings.append(table_str)

    for it in table_strings:
        print(f'Table: {it.name}')
        print_unicode_table(it.contents)

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

def format_seconds(duration_s: int):
    hours   = duration_s // 3600
    minutes = (duration_s % 3600) // 60
    seconds = duration_s % 60
    result = ''
    if hours > 0:
        result += f"{hours}h"
    if minutes > 0:
        result += "{}{}m".format(" " if len(result) > 0 else "", minutes)
    result += "{}{}s".format(" " if len(result) > 0 else "", seconds)
    return result

def obfuscate(val: str) -> str:
    """
    Obfuscate a string to contain a partial first and last chunk of the
    original string. If the string is less than 3 characters, the original
    string is retuned, otherwise the first and last 30% are returned.
    
    Args:
        val (str): String to obfuscate
    
    Returns:
        str: The obfuscated string
    """
    if len(val) < 3:
        return val
    n_ends = max(floor(len(val) * 0.3), 1)
    return f"{val[:n_ends]}…{val[-n_ends:]}"

def dump_enum_details(enum_value: enum.Enum) -> str:
    """
    Convert an Enum instance to its string name for logging, including
    its original value for integer enums.
    """
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
    """
    Safely dump a dictionary's information to a string for logging.

    If `env.SESH_PRO_BACKEND_UNSAFE_LOGGING` is True, the entire dict
    data will be dumped.
    Else a list of top-level keys will be dumped.
    """
    if d is None:
        return "None"
    
    if env.SESH_PRO_BACKEND_UNSAFE_LOGGING:
        return json.dumps(d)

    return "dictionary w/ keys: {" + extract_keys_recursive(d) + "}"

def safe_dump_arbitrary_value_or_type(v) -> str:
    """
    Safely dump a value and its type to a string for logging.

    If `env.SESH_PRO_BACKEND_UNSAFE_LOGGING` is True, the value
    and type will be dumped.
    Else just the type will be dumped.

    Args:
        v: Value to dump.

    Returns:
        String of value info in the format if unsafe logging:
        "(type) value"
        Else:
        "type"
    """
    t = type(v)
    if env.SESH_PRO_BACKEND_UNSAFE_LOGGING:
        return f'({t}) {v}'
    else:
        return str(t)


def safe_get_dict_value_type(d: dict[str, typing.Any], key: str) -> str:
    v = d.get(key)
    return safe_dump_arbitrary_value_or_type(v)

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONPrimitive: typing.TypeAlias = str | int | float | bool | None
JSONValue: typing.TypeAlias = JSONPrimitive | dict[str, 'JSONValue'] | list['JSONValue']
JSONObject: typing.TypeAlias = dict[str, JSONValue]
JSONArray: typing.TypeAlias = list[JSONValue]

def json_dict_require_str(d: JSONObject, key: str, err: ErrorSink) -> str:
    result = ''
    if key in d:
        if isinstance(d[key], str):
            result = typing.cast(str, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a string: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_int(d: JSONObject, key: str, err: ErrorSink) -> int:
    result = 0
    if key in d:
        if isinstance(d[key], int):
            result = typing.cast(int, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an integer: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_bool(d: JSONObject, key: str, err: ErrorSink) -> bool:
    result = False
    if key in d:
        if isinstance(d[key], bool):
            result = typing.cast(bool, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a bool: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_array(d: JSONObject, key: str, err: ErrorSink) -> JSONArray:
    result: list[JSONValue] = []
    if key in d:
        if isinstance(d[key], list):
            result = typing.cast(list[JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an array: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')
    return result

def json_dict_require_obj(d: dict[str, JSONValue], key: str, err: ErrorSink) -> JSONObject:
    result: dict[str, JSONValue] = {}
    if key in d:
        if isinstance(d[key], dict):
            result = typing.cast(dict[str, JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an object: "{safe_get_dict_value_type(d, key)}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')
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
        err.msg_list.append(f'Required key "{key}" is missing from: {safe_dump_dict_keys_or_data(d)}')

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
