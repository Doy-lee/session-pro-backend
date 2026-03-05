#!/usr/bin/env python3
"""
Command Line Interface for Session Pro Backend.

Provides a clean CLI for database operations that were previously only available
via awkward environment variable invocation through the Flask app.

Usage:
    python cli.py --config config.ini <command> [options] [args...]

Examples:
    python cli.py --config config.ini user-error set "1:token123=true"
    python cli.py --config config.ini google-notification handle "12345,67890"
    python cli.py --config config.ini revoke list 0xabcd...
    python cli.py --config config.ini report daily --count 7
    python cli.py --config config.ini db info
"""

import argparse
import configparser
import dataclasses
import os
import pathlib
import sys
import time

import nacl.signing

import base
import backend
import db


# Epilog definitions
BRIEF_EPILOG = """
GLOBAL OPTIONS:
  --config, -c       Path to config.ini file (required for DB operations)
  --dry-run, -n      Preview what would be done without executing changes
  --help-full        Show detailed help with full documentation

COMMANDS:
  user-error          set       <provider>:<id>=<true|false>[,...]
  user-error          delete    <provider>:<id>[,...]
  google-notification handle    <msgid>[,...]
  google-notification delete    <msgid>[,...]
  google-notification list
  revoke              list      <master_pkey_hex>
  revoke              delete    <master_pkey_hex>
  revoke              timestamp <master_pkey_hex> <unix_ts_s>
  report              generate  <daily|weekly|monthly> [--format <human|csv>] [--count <n>]
  db                  info
  db                  print

DRY RUN EXAMPLES:
  python cli.py --config config.ini --dry-run user-error set "1:token123=true"
  python cli.py --config config.ini --dry-run revoke delete aaaa...aaaa
"""

DETAILED_EPILOG = """
GLOBAL OPTIONS:
  --config, -c       Path to config.ini file (required)
  --dry-run, -n      Preview what would be done without executing changes
  --help-full        Show detailed help with full documentation

COMMAND FORMATS:
  user-error set "<provider>:<payment_id>=<flag>[,...]"
    provider:     Integer (1=Google Play Store, 2=iOS App Store)
    payment_id:   String (google_payment_token or apple_original_tx_id)
    flag:         true to add error, false to delete

    Examples:
      python cli.py --config config.ini user-error set "1:abc123token=true"
      python cli.py --config config.ini user-error set "1:token1=true,1:token2=true,2:apple1=false"

  user-error delete "<provider>:<payment_id>[,...]"
    Same format as 'set' but only deletes (no =true/false)

    Examples:
      python cli.py --config config.ini user-error delete "1:abc123token"
      python cli.py --config config.ini user-error delete "1:token1,1:token2,2:apple1"

  google-notification handle "<message_id>[,...]"
    message_id:   Integer (Google's notification message ID)

    Examples:
      python cli.py --config config.ini google-notification handle "12345"
      python cli.py --config config.ini google-notification handle "12345,67890,11111"

  google-notification delete "<message_id>[,...]"
    Same format as 'handle', but deletes the notification entirely

  google-notification list
    Lists all unhandled notifications with message_id and expiry

  revoke list <master_pkey_hex>
    master_pkey_hex:  64-character hex string (optionally prefixed with 0x)
    Shows all revocable payments for the user

    Examples:
      python cli.py --config config.ini revoke list aaaa...aaaa
      python cli.py --config config.ini revoke list 0xaaaa...aaaa

  revoke delete <master_pkey_hex>
    Removes the revocation entry for the specified master public key

  revoke timestamp <master_pkey_hex> <unix_ts_s>
    master_pkey_hex:  64-character hex string
    unix_ts_s:        Unix timestamp in seconds (not milliseconds!)
    Sets when the revocation expires

    Examples:
      python cli.py --config config.ini revoke timestamp aaaa...aaaa 1741170600

  report generate <period> [--format <format>] [--count <n>]
    period:   daily, weekly, or monthly
    format:   human (default) or csv
    count:    Number of periods to report (default: 7)

    Examples:
      python cli.py --config config.ini report generate daily
      python cli.py --config config.ini report generate weekly --format csv --count 4
      python cli.py --config config.ini report generate monthly --count 3

  db info
    Shows database statistics and info

  db print
    Prints all tables to stdout (for debugging)
"""


def parse_set_user_error_arg(arg: str, err: base.ErrorSink) -> list[tuple[base.PaymentProvider, str, bool]]:
    """Parse a comma-separated string of errors into a list of (payment_provider, payment_id, set_flag) tuples."""
    result: list[tuple[base.PaymentProvider, str, bool]] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        if ':' not in item or '=' not in item:
            err.msg_list.append(f"Invalid format for user error: '{item}'. Expected '<payment_provider>:<payment_id>=[true|false]'.")
            return result
        payment_provider_str, remainder = item.split(':', 1)
        payment_id, set_flag_str = remainder.split('=', 1)
        payment_provider_str = payment_provider_str.strip()
        payment_provider = base.PaymentProvider.Nil

        try:
            payment_provider = base.PaymentProvider(int(payment_provider_str))
        except Exception:
            err.msg_list.append(f'Failed to parse payment provider ({payment_provider_str}) for item {item}')
            return result

        set_flag = False
        if set_flag_str.lower() == 'true':
            set_flag = True
        elif set_flag_str.lower() == 'false':
            set_flag = False
        else:
            err.msg_list.append(f'Failed to parse set flag ({set_flag_str}) for item {item}')
            return result

        result.append((payment_provider, payment_id, set_flag))
    return result


def parse_payment_id_list(arg: str, err: base.ErrorSink) -> list[tuple[base.PaymentProvider, str]]:
    """Parse a comma-separated string of payment IDs for deletion."""
    result: list[tuple[base.PaymentProvider, str]] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        if ':' not in item:
            err.msg_list.append(f"Invalid format for payment ID: '{item}'. Expected '<payment_provider>:<payment_id>'.")
            return result
        payment_provider_str, payment_id = item.split(':', 1)
        payment_provider_str = payment_provider_str.strip()

        try:
            payment_provider = base.PaymentProvider(int(payment_provider_str))
        except Exception:
            err.msg_list.append(f'Failed to parse payment provider ({payment_provider_str}) for item {item}')
            return result

        result.append((payment_provider, payment_id))
    return result


def parse_message_id_list(arg: str, err: base.ErrorSink) -> list[int]:
    """Parse a comma-separated string of message IDs."""
    result: list[int] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        try:
            message_id = int(item)
            result.append(message_id)
        except Exception:
            err.msg_list.append(f'Failed to parse message_id as integer ({item})')
            return result
    return result


def parse_master_pkey(hex_str: str, err: base.ErrorSink) -> nacl.signing.VerifyKey | None:
    """Parse a hex string into a VerifyKey."""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    if len(hex_str) != 64:
        err.msg_list.append(f"Expected 64 hex chars for master public key, received {len(hex_str)}")
        return None

    try:
        hex_bytes = bytes.fromhex(hex_str)
        return nacl.signing.VerifyKey(hex_bytes)
    except Exception as e:
        err.msg_list.append(f"Failed to parse hex as master public key: {e}")
        return None


@dataclasses.dataclass
class CLIConfig:
    db_url:   str = ''
    log_path: str = ''


def load_config(config_path: str, err: base.ErrorSink) -> CLIConfig:
    result = CLIConfig()

    if not pathlib.Path(config_path).exists():
        err.msg_list.append(f'Config file "{config_path}" does not exist or is not readable')
        return result

    try:
        parser = configparser.ConfigParser()
        _ = parser.read(config_path)

        if 'base' not in parser:
            err.msg_list.append(f'Config file "{config_path}" is missing [base] section')
            return result

        base_section = parser['base']
        result.db_url = base_section.get('db_url', '')
        result.log_path = base_section.get('log_path', '')

        # Allow environment variable override
        result.db_url = os.getenv('SESH_PRO_BACKEND_DB_URL', result.db_url)

    except Exception as e:
        err.msg_list.append(f'Failed to parse config file: {e}')

    return result


def cmd_user_error_set(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    items = parse_set_user_error_arg(args.items, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if len(items) == 0:
        print("No items to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, (payment_provider, payment_id, set_flag) in enumerate(items):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {payment_provider.value}:{payment_id} = {set_flag}'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    if set_flag:
                        error = backend.UserError(provider=payment_provider)
                        if payment_provider == base.PaymentProvider.GooglePlayStore:
                            error.google_payment_token = payment_id
                        else:
                            error.apple_original_tx_id = payment_id

                        if backend.has_user_error(conn=conn, payment_provider=payment_provider, payment_id=payment_id):
                            label += ' (skipped - already exists)'
                        else:
                            backend.add_user_error(conn=conn, error=error, unix_ts_ms=int(time.time() * 1000))
                            count += 1
                            label += ' (added)'
                    else:
                        if backend.delete_user_errors(conn=conn, payment_provider=payment_provider, payment_id=payment_id):
                            count += 1
                            label += ' (deleted)'
                        else:
                            label += ' (skipped - not found)'

                print(f"Set {count}/{len(items)} user errors\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_user_error_delete(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    items = parse_payment_id_list(args.items, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if len(items) == 0:
        print("No items to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, (payment_provider, payment_id) in enumerate(items):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {payment_provider.value}:{payment_id}'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    if backend.delete_user_errors(conn=conn, payment_provider=payment_provider, payment_id=payment_id):
                        count += 1
                        label += ' (deleted)'
                    else:
                        label += ' (skipped - not found)'

                print(f"Deleted {count}/{len(items)} user errors\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_handle(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    message_ids = parse_message_id_list(args.items, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if len(message_ids) == 0:
        print("No message IDs to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, message_id in enumerate(message_ids):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {message_id} = Handled'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    with db.transaction(conn) as tx:
                        updated = backend.google_set_notification_handled(tx=tx, message_id=message_id, delete=False)
                        if updated:
                            count += 1
                        else:
                            label += ' (skipped - not found)'

                print(f"Marked {count}/{len(message_ids)} google notifications as handled\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_delete(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    message_ids = parse_message_id_list(args.items, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if len(message_ids) == 0:
        print("No message IDs to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, message_id in enumerate(message_ids):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {message_id} = Delete'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    with db.transaction(conn) as tx:
                        updated = backend.google_set_notification_handled(tx=tx, message_id=message_id, delete=True)
                        if updated:
                            count += 1
                        else:
                            label += ' (skipped - not found)'

                print(f"Deleted {count}/{len(message_ids)} google notifications\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_list(args: argparse.Namespace, config: CLIConfig) -> int:
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    unhandled_it = backend.google_get_unhandled_notification_iterator(tx)

                    items = list(unhandled_it)
                    if len(items) == 0:
                        print("No unhandled google notifications")
                        return 0

                    print(f"Found {len(items)} unhandled google notifications:")
                    for index, item in enumerate(items):
                        message_id, payload, expiry_unix_ts_ms = item
                        expiry_str = base.readable_unix_ts_ms(expiry_unix_ts_ms)
                        print(f"  {index:02d} message_id={message_id}, expiry={expiry_str}")

                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_revoke_list(args: argparse.Namespace, config: CLIConfig) -> int:
    err = base.ErrorSink()
    master_pkey = parse_master_pkey(args.master_pkey, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if master_pkey is None:
        print("ERROR: Master public key is required", file=sys.stderr)
        return 1

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    user_and_payments = backend.get_user_and_payments(tx=tx, master_pkey=master_pkey)

                    eligible_count = 0
                    list_label = ''

                    for row in user_and_payments.payments_it:
                        faux_row_id = 0
                        payment: backend.PaymentRow = backend.payment_row_from_tuple((faux_row_id, *row))

                        plan_label = ''
                        match payment.plan:
                            case base.ProPlan.Nil:         plan_label = '??'
                            case base.ProPlan.OneMonth:    plan_label = '1M'
                            case base.ProPlan.ThreeMonth:  plan_label = '3M'
                            case base.ProPlan.TwelveMonth: plan_label = '12M'

                        payment_id = ''
                        match payment.payment_provider:
                            case base.PaymentProvider.Nil:             pass
                            case base.PaymentProvider.GooglePlayStore: payment_id = f'{payment.google_payment_token}-{payment.google_order_id}'
                            case base.PaymentProvider.iOSAppStore:     payment_id = f'{payment.apple.original_tx_id}'

                        if payment.status == base.PaymentStatus.Expired or int(time.time() * 1000) >= payment.expiry_unix_ts_ms:
                            continue

                        list_label += f'\n    {eligible_count:02d} RevokeID={payment.payment_provider.name}-{payment_id}; Status={payment.status.name}; Plan={plan_label}; Unredeemed={base.readable_unix_ts_ms(payment.unredeemed_unix_ts_ms)}; Expiry={base.readable_unix_ts_ms(payment.expiry_unix_ts_ms)};'
                        eligible_count += 1

                    print(f"User {args.master_pkey} has {eligible_count} revocable payments{list_label}")
                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1

def cmd_revoke_delete(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    master_pkey = parse_master_pkey(args.master_pkey, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if master_pkey is None:
        print("ERROR: Master public key is required", file=sys.stderr)
        return 1

    if dry_run:
        print(f"(DRY RUN) Would delete revocation for {args.master_pkey}")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    set_result = backend.set_revocation_tx(tx=tx, master_pkey=master_pkey, expiry_unix_ts_ms=0, delete_item=True)
                    print(f"Deleted revocation for {args.master_pkey} ({set_result.value.lower()})")
                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_revoke_timestamp(args: argparse.Namespace, config: CLIConfig, dry_run: bool) -> int:
    err = base.ErrorSink()
    master_pkey = parse_master_pkey(args.master_pkey, err)

    if err.has():
        print(f"ERROR: Failed to parse arguments:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if master_pkey is None:
        print("ERROR: Master public key is required", file=sys.stderr)
        return 1

    if dry_run:
        print(f"(DRY RUN) Would set revocation timestamp for {args.master_pkey} to {base.readable_unix_ts_ms(args.unix_ts_s * 1000)}")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    expiry_unix_ts_ms = args.unix_ts_s * 1000
                    set_result = backend.set_revocation_tx(tx=tx, master_pkey=master_pkey, expiry_unix_ts_ms=expiry_unix_ts_ms, delete_item=False)
                    print(f"Set revocation for {args.master_pkey} to {base.readable_unix_ts_ms(expiry_unix_ts_ms)} ({set_result.value.lower()})")
                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_report_generate(args: argparse.Namespace, config: CLIConfig) -> int:
    """Handle report generate command."""
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                report_type = backend.ReportType.Human
                if args.format.lower() == 'csv':
                    report_type = backend.ReportType.CSV

                report_period = backend.ReportPeriod.Daily
                if args.period.lower() == 'weekly':
                    report_period = backend.ReportPeriod.Weekly
                elif args.period.lower() == 'monthly':
                    report_period = backend.ReportPeriod.Monthly

                count = args.count
                report_rows = backend.generate_report_rows(conn, report_period, limit=count)
                report_str = backend.generate_report_str(report_period, report_rows, report_type)

                print(report_str)
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_db_info(args: argparse.Namespace, config: CLIConfig) -> int:
    """Handle db info command."""
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                err = base.ErrorSink()
                info_str = backend.db_info_string(conn=conn, db_url=config.db_url, err=err)

                if err.has():
                    print(f"ERROR: Failed to get DB info: {err.msg_list}", file=sys.stderr)
                    return 1

                print(info_str)
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_db_print(config: CLIConfig) -> int:
    """Handle db print command."""
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                base.print_db_to_stdout(conn)
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    # Check if --help-full was requested
    use_full_help = '--help-full' in sys.argv

    parser = argparse.ArgumentParser(
        description='Session Pro Backend CLI - Database operations tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DETAILED_EPILOG if use_full_help else BRIEF_EPILOG,
        add_help=False  # We'll add help manually to control the position
    )

    # Global options
    _                       = parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                       help='Show brief help message and exit')
    _                       = parser.add_argument('--help-full', action='help', default=argparse.SUPPRESS,
                       help='Show detailed help with full documentation')
    _                       = parser.add_argument('--config', '-c', required=True, help='Path to config.ini file')
    _                       = parser.add_argument('--dry-run', '-n', action='store_true', help='Show what would be done without executing')

    subparsers              = parser.add_subparsers(dest='command', help='Available commands')

    # User error commands
    user_error_parser       = subparsers.add_parser('user-error', help='Manage user errors')
    user_error_subparsers   = user_error_parser.add_subparsers(dest='user_error_command', help='User error subcommands')

    user_error_set          = user_error_subparsers.add_parser('set', help='Set user errors (format: <provider>:<id>=true|false,...)')
    _                       = user_error_set.add_argument('items', help='Comma-separated list of errors')

    user_error_delete       = user_error_subparsers.add_parser('delete', help='Delete user errors (format: <provider>:<id>,...)')
    _                       = user_error_delete.add_argument('items', help='Comma-separated list of payment IDs')

    # Google notification commands
    google_notif_parser     = subparsers.add_parser('google-notification', help='Manage Google notifications')
    google_notif_subparsers = google_notif_parser.add_subparsers(dest='google_notif_command', help='Google notification subcommands')

    google_notif_handle     = google_notif_subparsers.add_parser('handle', help='Mark notifications as handled')
    _                       = google_notif_handle.add_argument('items', help='Comma-separated list of message IDs')

    google_notif_delete     = google_notif_subparsers.add_parser('delete', help='Delete notifications')
    _                       = google_notif_delete.add_argument('items', help='Comma-separated list of message IDs')
    _                       = google_notif_subparsers.add_parser('list', help='List unhandled notifications')

    # Revoke commands
    revoke_parser           = subparsers.add_parser('revoke', help='Manage revocations')
    revoke_subparsers       = revoke_parser.add_subparsers(dest='revoke_command', help='Revocation subcommands')

    revoke_list             = revoke_subparsers.add_parser('list', help='List revocable payments for a user')
    _                       = revoke_list.add_argument('master_pkey', help='Master public key (64 hex chars)')

    revoke_delete           = revoke_subparsers.add_parser('delete', help='Delete revocation entry')
    _                       = revoke_delete.add_argument('master_pkey', help='Master public key (64 hex chars)')

    revoke_timestamp        = revoke_subparsers.add_parser('timestamp', help='Set revocation with timestamp')
    _                       = revoke_timestamp.add_argument('master_pkey', help='Master public key (64 hex chars)')
    _                       = revoke_timestamp.add_argument('unix_ts_s', type=int, help='Unix timestamp in seconds')

    # Report commands
    report_parser           = subparsers.add_parser('report', help='Generate reports')
    report_subparsers       = report_parser.add_subparsers(dest='report_command', help='Report subcommands')

    report_generate         = report_subparsers.add_parser('generate', help='Generate a report')
    _                       = report_generate.add_argument('period', choices=['daily', 'weekly', 'monthly'], help='Report period')
    _                       = report_generate.add_argument('--format', choices=['human', 'csv'], default='human', help='Report format')
    _                       = report_generate.add_argument('--count', type=int, default=7, help='Number of periods to report')

    # DB commands
    db_parser               = subparsers.add_parser('db', help='Database operations')
    db_subparsers           = db_parser.add_subparsers(dest='db_command', help='Database subcommands')
    _                       = db_subparsers.add_parser('info', help='Show database info')
    _                       = db_subparsers.add_parser('print', help='Print all tables')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Load configuration
    err = base.ErrorSink()
    config = load_config(args.config, err)

    if err.has():
        print(f"ERROR: Failed to load config:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
        return 1

    if len(config.db_url) == 0:
        print("ERROR: No database URL configured in config file", file=sys.stderr)
        return 1

    # Dispatch to command handler
    dry_run = args.dry_run

    if args.command == 'user-error':
        if args.user_error_command == 'set':
            return cmd_user_error_set(args, config, dry_run)
        elif args.user_error_command == 'delete':
            return cmd_user_error_delete(args, config, dry_run)
        else:
            user_error_parser.print_help()
            return 1

    elif args.command == 'google-notification':
        if args.google_notif_command == 'handle':
            return cmd_google_notification_handle(args, config, dry_run)
        elif args.google_notif_command == 'delete':
            return cmd_google_notification_delete(args, config, dry_run)
        elif args.google_notif_command == 'list':
            return cmd_google_notification_list(args, config)
        else:
            google_notif_parser.print_help()
            return 1

    elif args.command == 'revoke':
        if args.revoke_command == 'list':
            return cmd_revoke_list(args, config)
        elif args.revoke_command == 'delete':
            return cmd_revoke_delete(args, config, dry_run)
        elif args.revoke_command == 'timestamp':
            return cmd_revoke_timestamp(args, config, dry_run)
        else:
            revoke_parser.print_help()
            return 1

    elif args.command == 'report':
        if args.report_command == 'generate':
            return cmd_report_generate(args, config)
        else:
            report_parser.print_help()
            return 1

    elif args.command == 'db':
        if args.db_command == 'info':
            return cmd_db_info(args, config)
        elif args.db_command == 'print':
            return cmd_db_print(config)
        else:
            db_parser.print_help()
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
