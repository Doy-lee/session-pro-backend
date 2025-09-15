'''
The base layer contains common utilities that is useful to other files in the
project and should have no dependency on any project files, only, native Python
packages. Typically useful to share functionality from the testing suite and the
project but not limited to.
'''
import json
import traceback
import sqlite3
import datetime
import typing
import enum
import dataclasses

class PaymentProvider(enum.Enum):
    Nil             = 0
    GooglePlayStore = 1
    iOSAppStore     = 2

SECONDS_IN_DAY:                 int  = 60 * 60 * 24
DEV_BACKEND_MODE:               bool = False
DEV_BACKEND_DETERMINISTIC_SKEY       = bytes([0xCD] * 32)

@dataclasses.dataclass
class ErrorSink:
    '''
    Helper class to pass to functions that want to return error messages without
    unwinding the stack by using throwing exceptions.

    The typical pattern in that this construct is used is calling a sequence of
    functions that can error but have no dependency on each other. Errors are
    accumulated into the sink and checked at the end where it reports
    the error from the sink and returns a failure if there is one.

    See the parsing code in server.py for an example of where this is useful.
    '''
    msg_list: list[str] = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class SQLTransaction:
    conn:   sqlite3.Connection
    cursor: sqlite3.Cursor | None = None
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
        self.conn.commit() if exc_type is None else self.conn.rollback()
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

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONValue = typing.TypeVar('JSONValue', int, str, list[dict[str, int | str]])

def json_dict_require(d: dict[str, JSONValue], key: str, default_val: JSONValue, err_msg: str, err: ErrorSink) -> JSONValue:
    if not key in d:
        err.msg_list.append(f'{err_msg}: \'{key}\'')

    # NOTE: Keep isinstance check for untrusted JSON input, as d[key] could be any
    # type (untrusted input potentially)
    if not isinstance(d[key], type(default_val)): # pyright: ignore[reportUnnecessaryIsInstance]
        err.msg_list.append(f'{err_msg}: \'{key}\' is not a valid \'{type(default_val).__name__}\'')
        return default_val

    result: JSONValue = d[key]
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
                        elif col.endswith('unix_ts_s'):
                            timestamp = int(value)
                            date_str  = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
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

def round_unix_ts_to_next_day(unix_ts_s: int) -> int:
    result: int = (unix_ts_s + (SECONDS_IN_DAY - 1)) // SECONDS_IN_DAY * SECONDS_IN_DAY
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

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONValue = int | str | list[dict[str, int | str]] | dict[str, int | str]
def json_dict_require_str(d: dict[str, JSONValue], key: str, err: ErrorSink) -> str:
    result = ''
    if key in d:
        if isinstance(d[key], str):
            result = typing.cast(str, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a string: "{d[key]}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {json.dumps(d)}')
    return result

def json_dict_require_int(d: dict[str, JSONValue], key: str, err: ErrorSink) -> int:
    result = 0
    if key in d:
        if isinstance(d[key], int):
            result = typing.cast(int, d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not a integer: "{d[key]}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {json.dumps(d)}')
    return result

def json_dict_require_array(d: dict[str, JSONValue], key: str, err: ErrorSink) -> list[JSONValue]:
    result: list[JSONValue] = []
    if key in d:
        if isinstance(d[key], list):
            result = typing.cast(list[JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an array: "{d[key]}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {json.dumps(d)}')
    return result

def json_dict_require_obj(d: dict[str, JSONValue], key: str, err: ErrorSink) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    if key in d:
        if isinstance(d[key], dict):
            result = typing.cast(dict[str, JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an object: "{d[key]}"')
    else:
        err.msg_list.append(f'Required key "{key}" is missing from: {json.dumps(d)}')
    return result
