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
  dev-payment         add       --url <url> --provider <google|apple> [--dev-plan <1M|3M|12M>] [--dev-duration-ms ...] [--dev-auto-renewing]
  dev-payment         refund    --url <url> --provider <google|apple> [options]
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
  --config, -c       Path to config.ini file
  --dry-run, -n      Preview what would be done without executing changes
  --help-full        Show detailed help with full documentation

COMMAND FORMATS:
  dev-payment add --url <url> --provider <google|apple> [options]
    Add a development payment to a Session Pro backend server (requires backend to be running in dev mode).

    Required:
      --url <url>               Server URL (e.g., http://localhost:8000)
      --provider <google|apple> Payment provider

    Optional:
      --master-key <hex>        64-char hex master private key (generates new if omitted)
      --rotating-key <hex>      64-char hex rotating private key (generates new if omitted)
      --version <int>           Request version (default: 0)
      --dev-plan <1M|3M|12M>    Subscription plan (1M/3M/12M)
      --dev-duration-ms <ms>    Override duration in milliseconds
      --dev-auto-renewing       Set auto-renewing to true (default: false)

    The command generates DEV.-prefixed order/tx IDs and sends them to the server.
    Generated keys are always printed to stdout for reproducibility.

    Examples:
      python cli.py dev-payment add --url http://localhost:8000 --provider google --dev-plan 1M
      python cli.py dev-payment add --url http://localhost:8000 --provider apple --dev-plan 3M --master-key abcdef...

  dev-payment refund --url <url> --provider <google|apple> [options]
    Mark a development payment as refund requested.

    Required:
      --url <url>               Server URL
      --provider <google|apple> Payment provider
      --master-key <hex>        64-char hex master private key
      --payment-token <token>   Google: payment token (required for Google)
      --order-id <id>           Google: order ID (required for Google)
      --tx-id <id>              Apple: transaction ID (required for Apple)

    Optional:
      --refund-time <ms>        Unix timestamp ms for refund (default: now + 1s)
      --version <int>           Request version (default: 0)

    Examples:
      python cli.py dev-payment refund --url http://localhost:8000 --provider google --master-key abcdef... --payment-token tok123 --order-id DEV.abc123
      python cli.py dev-payment refund --url http://localhost:8000 --provider apple --master-key abcdef... --tx-id DEV.xyz789

  user-error set "<provider>:<payment_id>=<flag>[,...]"
    A ',' delimited string to instruct the DB to delete the specified rows from the user errors table
    in the DB on startup. This value must be of the format

      "<payment_provider integer>:<payment_id>=[true|false], ..."

    For example

      "1:the_google_order_id=true,2:the_apple_order_id=false"

    Which will add the row that has a payment provider of 1 (which corresponds to the Google Play
    Store) and has a payment ID that matches "google_order_id" to have an error. For the next entry
    similarly it will set the Apple row to false (e.g. delete the row from the DB)

    This is intended to be used to flush errors from the DB if they are encountered during the
    handling of payment notifications for a specific user. Platform clients may be using the error
    table to populate UI that indicates that a user should contact support, hence clearing this
    value may clear the error prompt for said user.

    Options:
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
    A ',' delimited string of message IDs to instruct the DB to mark the specified rows as handled
    from the google notification history table in the DB on startup.

      "8392,1234"

    Which will mark the notifications with the ID 8392 and 1234 as to being handled (which stops the
    backend from trying to process the message). Note that when you handle a message, this also
    wipes the notification payload from the table (since the backend does not need to parse and
    process the message anymore).

    Handled notifications will get deleted at the expiry date and persist in the database just incase
    Google redelivers the notification. Duplicated notifications are de-duped by their message ID.

    This is intended to flush out bad notifications that may be invalid or no longer necessary to
    process/impossible to process due to inconsistent DB state, otherwise, do not use unless you
    know the intended consequences! Make a backup of the DB before proceeding!

    Options:
      message_id: Google's notification message ID (an integer)

    Examples:
      python cli.py --config config.ini google-notification handle "12345"
      python cli.py --config config.ini google-notification handle "12345,67890,11111"

  google-notification delete "<message_id>[,...]"
    Same format as 'handle', but deletes the notification entirely

  google-notification list
    Lists all unhandled notifications with message_id and expiry

  revoke list <master_pkey_hex>
    Shows all revocable payments for the user

    Options:
      master_pkey_hex:  64-character hex string (optionally prefixed with 0x)

    Examples:
      python cli.py --config config.ini revoke list aaaa...aaaa
      python cli.py --config config.ini revoke list 0xaaaa...aaaa

  revoke delete <master_pkey_hex>
    Removes the revocation entry for the specified master public key

    The current generation index associated with the pkey will be looked up and the corresponding
    hash will be revoked. If the user is not known by the database (e.g. the user doesn't exist, or,
    the user's master public key mapping has been pruned because the user was inactive for example)
    then no action is taken.

  revoke timestamp <master_pkey_hex> <unix_ts_s>
    Add or update the time (or create a new revocation entry if it doesn't exist) at which the
    revocation item will be effective until.

    Note that executing any revoke action increments the global generation index counter to the next
    value. This is expected behaviour as a side effect of modifying the revocation table.

    Options:
      master_pkey_hex:  64-character hex string
      unix_ts_s:        Unix timestamp in seconds (not milliseconds!)

    Examples:
      python cli.py --config config.ini revoke timestamp aaaa...aaaa 1741170600

  report generate <period> [--format <format>] [--count <n>]
    Generate a report of the payments for the given report type, period and optional count. The
    fields of the report are defined as follows:

      Active Users: Number of Session Pro payments that were still active (i.e. not expired or
      revoked) at the end of the reporting period.

      Cancelling: Number of Session Pro payments that are scheduled to expire and not be renewed in
      that reporting period.

    Options:
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


def require_config(args: argparse.Namespace) -> CLIConfig:
    if not args.config:
        print("ERROR: --config is required for this command", file=sys.stderr)
        sys.exit(1)

    err = base.ErrorSink()
    config = load_config(args.config, err)

    if err.has():
        msg = "ERROR: Failed to load config:\n  " + "\n  ".join(err.msg_list)
        print(msg, file=sys.stderr)
        sys.exit(1)

    if not config.db_url:
        print("ERROR: No database URL configured in config file", file=sys.stderr)
        sys.exit(1)

    return config


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


def cmd_user_error_set(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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


def cmd_user_error_delete(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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


def cmd_google_notification_handle(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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


def cmd_google_notification_delete(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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


def cmd_google_notification_list(args: argparse.Namespace) -> int:
    config = require_config(args)
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


def cmd_revoke_list(args: argparse.Namespace) -> int:
    config = require_config(args)
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

def cmd_revoke_delete(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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


def cmd_revoke_timestamp(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
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

def cmd_report_generate(args: argparse.Namespace) -> int:
    config = require_config(args)
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


def cmd_db_info(args: argparse.Namespace) -> int:
    config = require_config(args)
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


def cmd_db_print(args: argparse.Namespace) -> int:
    config = require_config(args)
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                base.print_db_to_stdout(conn)
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_dev_payment_add(args: argparse.Namespace) -> int:
    import hashlib
    import json
    import os
    import urllib.request
    import urllib.error

    # Parse or generate master key
    if args.master_key:
        try:
            master_key = nacl.signing.SigningKey(bytes.fromhex(args.master_key))
        except Exception as e:
            print(f"ERROR: Failed to parse master key: {e}", file=sys.stderr)
            return 1
    else:
        master_key = nacl.signing.SigningKey.generate()
        print(f'Generated Master SKey: {bytes(master_key).hex()}')
        print(f'Generated Master PKey: {bytes(master_key.verify_key).hex()}')

    # Parse or generate rotating key
    if args.rotating_key:
        try:
            rotating_key = nacl.signing.SigningKey(bytes.fromhex(args.rotating_key))
        except Exception as e:
            print(f"ERROR: Failed to parse rotating key: {e}", file=sys.stderr)
            return 1
    else:
        rotating_key = nacl.signing.SigningKey.generate()
        print(f'Generated Rotating SKey: {bytes(rotating_key).hex()}')
        print(f'Generated Rotating PKey: {bytes(rotating_key.verify_key).hex()}')

    # Determine provider enum and build payment_tx
    if args.provider == 'google':
        provider_enum = 1
        google_payment_token = os.urandom(8).hex()
        google_order_id = 'DEV.' + os.urandom(8).hex()

        # Compute hash
        hasher = hashlib.blake2b(digest_size=32, person=b'ProAddPayment___')
        hasher.update(args.version.to_bytes(length=1, byteorder='little'))
        hasher.update(bytes(master_key.verify_key))
        hasher.update(bytes(rotating_key.verify_key))
        hasher.update(provider_enum.to_bytes(length=1, byteorder='little'))
        hasher.update(google_payment_token.encode('utf-8'))
        hasher.update(google_order_id.encode('utf-8'))

        payment_tx = {'provider': provider_enum, 'google_payment_token': google_payment_token, 'google_order_id': google_order_id}
    else:  # apple
        provider_enum = 2
        apple_tx_id = 'DEV.' + os.urandom(8).hex()

        # Compute hash
        hasher = hashlib.blake2b(digest_size=32, person=b'ProAddPayment___')
        hasher.update(args.version.to_bytes(length=1, byteorder='little'))
        hasher.update(bytes(master_key.verify_key))
        hasher.update(bytes(rotating_key.verify_key))
        hasher.update(provider_enum.to_bytes(length=1, byteorder='little'))
        hasher.update(apple_tx_id.encode('utf-8'))

        payment_tx = {'provider': provider_enum, 'apple_tx_id': apple_tx_id}

    # Build request
    request_body = {
        'version': args.version,
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hasher.digest()).signature).hex(),
        'rotating_sig': bytes(rotating_key.sign(hasher.digest()).signature).hex(),
        'payment_tx': payment_tx
    }

    # Add dev arguments
    plan_map = {'1M': 'OneMonth', '3M': 'ThreeMonth', '12M': 'TwelveMonth'}
    if args.dev_plan:
        request_body['dev_plan'] = plan_map[args.dev_plan]
    if args.dev_duration_ms is not None:
        request_body['dev_duration_ms'] = args.dev_duration_ms
    if args.dev_auto_renewing:
        request_body['dev_auto_renewing'] = True

    print(f'\nAdd Pro Payment via {"Google" if args.provider == "google" else "Apple"}')
    print(f'Request:\n{json.dumps(request_body, indent=1)}')

    # Send request
    try:
        request = urllib.request.Request(
            f'{args.url}/add_pro_payment',
            data=json.dumps(request_body).encode('utf-8'),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(request) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            print(f"Response: {json.dumps(response_data, indent=1)}")
            return 0
    except urllib.error.HTTPError as e:
        print(f"ERROR: Server returned {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to connect to {args.url}: {e}", file=sys.stderr)
        return 1


def cmd_dev_payment_refund(args: argparse.Namespace) -> int:
    import hashlib
    import json
    import time
    import urllib.request
    import urllib.error
    
    # Parse master key
    try:
        master_key = nacl.signing.SigningKey(bytes.fromhex(args.master_key))
    except Exception as e:
        print(f"ERROR: Failed to parse master key: {e}", file=sys.stderr)
        return 1

    # Determine provider enum and payment details
    if args.provider == 'google':
        provider_enum = 1
        if not args.payment_token or not args.order_id:
            print("ERROR: --payment-token and --order-id are required for Google", file=sys.stderr)
            return 1
        payment_tx = {'provider': provider_enum, 'google_payment_token': args.payment_token, 'google_order_id': args.order_id}
    else:  # apple
        provider_enum = 2
        if not args.tx_id:
            print("ERROR: --tx-id is required for Apple", file=sys.stderr)
            return 1
        payment_tx = {'provider': provider_enum, 'apple_tx_id': args.tx_id}

    # Set refund timestamp
    if args.refund_time:
        refund_unix_ts_ms = args.refund_time
    else:
        refund_unix_ts_ms = int((time.time() + 1) * 1000)

    now_unix_ts_ms = int(time.time() * 1000)

    # Compute hash
    hasher = hashlib.blake2b(digest_size=32, person=b'ProSetRefundReq_')
    hasher.update(args.version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_key.verify_key))
    hasher.update(now_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(refund_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(provider_enum.to_bytes(length=1, byteorder='little'))

    if args.provider == 'google':
        hasher.update(args.payment_token.encode('utf-8'))
        hasher.update(args.order_id.encode('utf-8'))
    else:
        hasher.update(args.tx_id.encode('utf-8'))

    # Build request
    request_body = {
        'version': args.version,
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hasher.digest()).signature).hex(),
        'unix_ts_ms': now_unix_ts_ms,
        'refund_requested_unix_ts_ms': refund_unix_ts_ms,
        'payment_tx': payment_tx
    }

    print(f'\nSet payment refund requested via {"Google" if args.provider == "google" else "Apple"}')
    print(f'Request:\n{json.dumps(request_body, indent=1)}')

    # Send request
    try:
        request = urllib.request.Request(
            f'{args.url}/set_payment_refund_requested',
            data=json.dumps(request_body).encode('utf-8'),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(request) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            print(f"Response: {json.dumps(response_data, indent=1)}")
            return 0
    except urllib.error.HTTPError as e:
        print(f"ERROR: Server returned {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to connect to {args.url}: {e}", file=sys.stderr)
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
    _                       = parser.add_argument('--config', '-c', required=False, help='Path to config.ini file (required for DB operations)')
    _                       = parser.add_argument('--dry-run', '-n', action='store_true', help='Show what would be done without executing')

    subparsers              = parser.add_subparsers(dest='command', help='Available commands')

    # Dev payment commands (no config required)
    dev_payment_parser      = subparsers.add_parser('dev-payment', help='Development payment operations (no --config required)')
    dev_payment_subparsers  = dev_payment_parser.add_subparsers(dest='dev_payment_command', help='Dev payment subcommands')

    dev_payment_add         = dev_payment_subparsers.add_parser('add',                                                        help='Add a DEV payment to a development server')
    _                       = dev_payment_add.add_argument('--url',               required=True,                              help='Server URL (e.g., http://localhost:8000)')
    _                       = dev_payment_add.add_argument('--provider',          required=True, choices=['google', 'apple'], help='Payment provider')
    _                       = dev_payment_add.add_argument('--master-key',                                                    help='64-char hex master private key (generates new if omitted)')
    _                       = dev_payment_add.add_argument('--rotating-key',                                                  help='64-char hex rotating private key (generates new if omitted)')
    _                       = dev_payment_add.add_argument('--version',           type=int, default=0,                        help='Request version (default: 0)')
    _                       = dev_payment_add.add_argument('--dev-plan',                         choices=['1M', '3M', '12M'], help='Subscription plan (1M/3M/12M)')
    _                       = dev_payment_add.add_argument('--dev-duration-ms',   type=int,                                   help='Override duration in milliseconds')
    _                       = dev_payment_add.add_argument('--dev-auto-renewing', action='store_true',                        help='Set auto-renewing to true (default: false)')

    dev_payment_refund      = dev_payment_subparsers.add_parser('refund',                                                    help='Mark a DEV payment as refund requested')
    _                       = dev_payment_refund.add_argument('--url',           required=True,                              help='Server URL')
    _                       = dev_payment_refund.add_argument('--provider',      required=True, choices=['google', 'apple'], help='Payment provider')
    _                       = dev_payment_refund.add_argument('--master-key',    required=True,                              help='64-char hex master private key')
    _                       = dev_payment_refund.add_argument('--payment-token',                                             help='Google: payment token (required for Google)')
    _                       = dev_payment_refund.add_argument('--order-id',                                                  help='Google: order ID (required for Google)')
    _                       = dev_payment_refund.add_argument('--tx-id',                                                     help='Apple: transaction ID (required for Apple)')
    _                       = dev_payment_refund.add_argument('--refund-time',   type=int,                                   help='Unix timestamp ms for refund (default: now + 1s)')
    _                       = dev_payment_refund.add_argument('--version',       type=int,      default=0,                   help='Request version (default: 0)')

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

    # Dispatch to command handler - commands that need config will load it themselves
    dry_run = args.dry_run

    if args.command == 'dev-payment':
        if args.dev_payment_command == 'add':
            return cmd_dev_payment_add(args)
        elif args.dev_payment_command == 'refund':
            return cmd_dev_payment_refund(args)
        else:
            dev_payment_parser.print_help()
            return 1

    elif args.command == 'user-error':
        if args.user_error_command == 'set':
            return cmd_user_error_set(args, dry_run)
        elif args.user_error_command == 'delete':
            return cmd_user_error_delete(args, dry_run)
        else:
            user_error_parser.print_help()
            return 1

    elif args.command == 'google-notification':
        if args.google_notif_command == 'handle':
            return cmd_google_notification_handle(args, dry_run)
        elif args.google_notif_command == 'delete':
            return cmd_google_notification_delete(args, dry_run)
        elif args.google_notif_command == 'list':
            return cmd_google_notification_list(args)
        else:
            google_notif_parser.print_help()
            return 1

    elif args.command == 'revoke':
        if args.revoke_command == 'list':
            return cmd_revoke_list(args)
        elif args.revoke_command == 'delete':
            return cmd_revoke_delete(args, dry_run)
        elif args.revoke_command == 'timestamp':
            return cmd_revoke_timestamp(args, dry_run)
        else:
            revoke_parser.print_help()
            return 1

    elif args.command == 'report':
        if args.report_command == 'generate':
            return cmd_report_generate(args)
        else:
            report_parser.print_help()
            return 1

    elif args.command == 'db':
        if args.db_command == 'info':
            return cmd_db_info(args)
        elif args.db_command == 'print':
            return cmd_db_print(args)
        else:
            db_parser.print_help()
            return 1

    else:
        parser.print_help()
        return 1
if __name__ == '__main__':
    sys.exit(main())
