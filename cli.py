#!/usr/bin/env python3
"""
Command Line Interface for manipulating the Session Pro Backend database like adding revocations,
flushing historical notifications received, generating reports e.t.c
"""

import argparse
import configparser
import dataclasses
import os
import pathlib
import sys
import time
import uuid

import nacl.signing

import base
import backend
import db


# Epilog definitions
BRIEF_EPILOG = """
QUICK START EXAMPLES:
  server              add-pro-payment              --url <url> --provider <google|apple|...> [--dev-plan <1M|3M|12M>] [--dev-duration-ms ...] [--dev-auto-renewing]
  server              set-payment-refund-requested --url <url> --provider <google|apple> --payment-token <token> --order-id <id>
  server              get-pro-revocations          --url <url> [--ticket <int>]
  server              get-pro-details              --url <url> --master-skey <hex> [--count <n>]
  server              generate-pro-proof           --url <url> --master-skey <hex> --rotating-skey <hex>

  voucher                                           --master-pkey <hex> --plan <1M|3M|12M> [--rotating-pkey <hex>] [--dev-duration-ms <ms>] (requires --config)

  user-error          set                          <provider>:<payment-id>=<true|false>[,...]                                               (requires --config)
  user-error          delete                       <provider>:<payment-id>[,...]                                                            (requires --config)

  google-notification handle                       <msgid>[,...]                                                                            (requires --config)
  google-notification delete                       <msgid>[,...]                                                                            (requires --config)
  google-notification list                                                                                                                  (requires --config)

  revoke              list                         <master_pkey_hex>                                                                        (requires --config)
  revoke              delete                       <master_pkey_hex>                                                                        (requires --config)
  revoke              timestamp                    [--creation-unix-ts-s <ts>] <master_pkey_hex> <unix_ts_s>                                (requires --config)

  report              generate                     <daily|weekly|monthly> [--format <human|csv>] [--count <n>]                              (requires --config)

  db                  info                                                                                                                  (requires --config)
  db                  print                                                                                                                 (requires --config)
"""

DETAILED_EPILOG = """
COMMAND FORMATS DETAILED:
  server add-pro-payment --url <url> --provider <google|apple|...> [options]
    Add a development payment to a Session Pro backend server (requires backend to be running in dev mode).
    Mirrors the /add_pro_payment endpoint.

    Required:
      --url <url>               Server URL (e.g., http://localhost:8000)
      --provider                Payment provider (one of the following: google, apple, rangeproof)

    Optional:
      --master-skey <hex>       64-char hex master secret key (generates new if omitted)
      --rotating-skey <hex>     64-char hex rotating secret key (generates new if omitted)
      --version <int>           Request version (default: 0)
      --dev-plan <1M|3M|12M>    Subscription plan (1M/3M/12M)
      --dev-duration-ms <ms>    Override duration in milliseconds
      --dev-auto-renewing       Set auto-renewing to true (default: false)

    The command generates DEV.-prefixed order/tx IDs and sends them to the server.
    Generated keys are always printed to stdout for reproducibility.

    Examples:
      python cli.py server add-pro-payment --url http://localhost:8000 --provider google --dev-plan 1M
      python cli.py server add-pro-payment --url http://localhost:8000 --provider apple --dev-plan 3M --master-skey abcdef...

  server set-payment-refund-requested --url <url> --provider <google|apple> --master-skey <hex> [options]
    Mark a development payment as refund requested. Mirrors the /set_payment_refund_requested endpoint.

    Required:
      --url <url>               Server URL
      --provider <google|apple> Payment provider
      --master-skey <hex>       64-char hex master secret key

    Google Required:
      --payment-token <token>   Google: payment token
      --order-id <id>           Google: order ID

    Apple Required:
      --tx-id <id>              Apple: transaction ID

    Optional:
      --refund-requested-unix-ts-ms <ms>  Unix timestamp ms for refund (default: now + 1s)
      --version <int>                     Request version (default: 0)

    Examples:
      python cli.py server set-payment-refund-requested --url http://localhost:8000 --provider google --master-skey abcdef... --payment-token tok123 --order-id DEV.abc123
      python cli.py server set-payment-refund-requested --url http://localhost:8000 --provider apple --master-skey abcdef... --tx-id DEV.xyz789

  server get-pro-revocations --url <url> [--ticket <int>]
    Get pro revocations from the server. Mirrors the /get_pro_revocations endpoint.

    Required:
      --url <url>    Server URL (e.g., http://localhost:8000)

    Optional:
      --ticket <int>  Revocation ticket to query from (default: 0)
      --version <int> Request version (default: 0)

    Examples:
      python cli.py server get-pro-revocations --url http://localhost:8000
      python cli.py server get-pro-revocations --url http://localhost:8000 --ticket 100

  server get-pro-details --url <url> --master-skey <hex> [--count <n>]
    Get pro details for a user. Mirrors the /get_pro_details endpoint.

    Required:
      --url <url>         Server URL (e.g., http://localhost:8000)
      --master-skey <hex> 64-char hex master secret key for signing

    Optional:
      --count <n>     Number of payments to retrieve (default: 10)
      --version <int> Request version (default: 0)

    Examples:
      python cli.py server get-pro-details --url http://localhost:8000 --master-skey abcdef...
      python cli.py server get-pro-details --url http://localhost:8000 --master-skey abcdef... --count 5

  server generate-pro-proof --url <url> --master-skey <hex> --rotating-skey <hex>
    Generate a pro proof for a pre-existing subscription. Mirrors the /generate_pro_proof endpoint.

    Required:
      --url <url>             Server URL (e.g., http://localhost:8000)
      --master-skey <hex>     64-char hex master secret key for signing
      --rotating-skey <hex>   64-char hex rotating secret key

    Optional:
      --version <int>         Request version (default: 0)

    Examples:
      python cli.py server generate-pro-proof --url http://localhost:8000 --master-skey abcdef... --rotating-skey fedcba...

  user-error set "<provider>:<payment_id>=<flag>[,...]" (requires --config)
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

    Examples:
      python cli.py user-error set "1:abc123token=true"
      python cli.py user-error set "1:token1=true,1:token2=true,2:apple1=false"

  user-error set "<provider>:<payment_id>=<flag>[,...]" (requires --config)
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

  user-error delete "<provider>:<payment_id>[,...]" (requires --config)
    Same format as 'set' but only deletes (no =true/false)

    Examples:
      python cli.py --config config.ini user-error delete "1:abc123token"
      python cli.py --config config.ini user-error delete "1:token1,1:token2,2:apple1"

  voucher --config <ini> --master-pkey <hex> --plan <1M|3M|12M> [--rotating-pkey <hex>] [--dev-duration-ms <ms>] (requires --config)
    Create a Rangeproof voucher payment and auto-redeem it. This is an admin command for granting
    promotional or complimentary Session Pro subscriptions directly in the database.

    Required:
      --config <ini>          Path to config.ini file
      --master-pkey <hex>     64-char hex master public key of the recipient
      --plan <1M|3M|12M>      Subscription plan duration

    Optional:
      --rotating-pkey <hex>   64-char hex rotating public key (generates new if omitted)
      --dev-duration-ms <ms>  Override duration in milliseconds

    Examples:
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 1M
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 3M --rotating-pkey fedcba...
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 12M --dev-duration-ms 5000

  google-notification handle "<message_id>[,...]" (requires --config)
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

  google-notification delete "<message_id>[,...]" (requires --config)
    Same format as 'handle', but deletes the notification entirely

  google-notification list (requires --config)
    Lists all unhandled notifications with message_id and expiry

  revoke list <master_pkey_hex> (requires --config)
    Shows all revocable payments for the user

    Options:
      master_pkey_hex:  64-character hex string (optionally prefixed with 0x)

    Examples:
      python cli.py --config config.ini revoke list aaaa...aaaa
      python cli.py --config config.ini revoke list 0xaaaa...aaaa

  revoke delete <master_pkey_hex> (requires --config)
    Removes the revocation entry for the specified master public key

    The current generation index associated with the pkey will be looked up and the corresponding
    hash will be revoked. If the user is not known by the database (e.g. the user doesn't exist, or,
    the user's master public key mapping has been pruned because the user was inactive for example)
    then no action is taken.

  revoke timestamp [--creation-unix-ts-s <ts>] <master_pkey_hex> <unix_ts_s> (requires --config)
    Add or update the time (or create a new revocation entry if it doesn't exist) at which the
    revocation item will be effective until.

    Note that executing any revoke action increments the global generation index counter to the next
    value. This is expected behaviour as a side effect of modifying the revocation table.

    Options:
      master_pkey_hex:  64-character hex string
      unix_ts_s:        Unix timestamp in seconds (not milliseconds!)

    Examples:
      python cli.py --config config.ini revoke timestamp --creation-unix-ts-s 1741170600 aaaa...aaaa 1741170720

  report generate <period> [--format <format>] [--count <n>] (requires --config)
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

  db info (requires --config)
    Shows database statistics and info

  db print (requires --config)
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

        assert payment_provider != base.PaymentProvider.Nil,        "Nil payment provider cannot be used for errors"
        assert payment_provider != base.PaymentProvider.Rangeproof, "Rangeproof payment provider does not support errors"

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

    # NOTE: Parse the config
    err              = base.ErrorSink()
    result           = CLIConfig()
    if 1:
        config_path: str = args.config
        if not pathlib.Path(config_path).exists():
            err.msg_list.append(f'Config file "{config_path}" does not exist or is not readable')
            return result

        try:
            parser = configparser.ConfigParser()
            _ = parser.read(config_path)

            if 'base' not in parser:
                err.msg_list.append(f'Config file "{config_path}" is missing [base] section')
            else:
                base_section          = parser['base']
                result.db_url         = base_section.get('db_url', '')
                result.log_path       = base_section.get('log_path', '')
                base.DEV_BACKEND_MODE = base_section.getboolean('dev', fallback=False)

                # Allow environment variable override
                result.db_url = os.getenv('SESH_PRO_BACKEND_DB_URL', result.db_url)
        except Exception as e:
            err.msg_list.append(f'Failed to parse config file: {e}')

    # NOTE: Log errors
    if err.has():
        msg = "ERROR: Failed to load config:\n  " + "\n  ".join(err.msg_list)
        print(msg, file=sys.stderr)
        sys.exit(1)

    if not result.db_url:
        print("ERROR: No database URL configured in config file", file=sys.stderr)
        sys.exit(1)

    return result


def load_config(config_path: str, err: base.ErrorSink) -> CLIConfig:
    result = CLIConfig()

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
                            assert payment_provider == base.PaymentProvider.iOSAppStore
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
                            case base.PaymentProvider.Rangeproof:      payment_id = f'{payment.rangeproof_order_id}'

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
                    set_result = backend.set_revocation_tx(tx=tx, master_pkey=master_pkey, creation_unix_ts_ms=int(time.time() * 1000), expiry_unix_ts_ms=0, delete_item=True)
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
                    expiry_unix_ts_ms   = args.expiry_unix_ts_s * 1000
                    creation_unix_ts_ms = args.creation_unix_ts_s * 1000
                    set_result          = backend.set_revocation_tx(tx=tx, master_pkey=master_pkey, creation_unix_ts_ms=creation_unix_ts_ms, expiry_unix_ts_ms=expiry_unix_ts_ms, delete_item=False)
                    print(f"Set revocation for {args.master_pkey} to {base.readable_unix_ts_ms(creation_unix_ts_ms)} to {base.readable_unix_ts_ms(expiry_unix_ts_ms)} ({set_result.value.lower()})")
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


def cmd_server_add_pro_payment(args: argparse.Namespace) -> int:
    import json
    import os
    import urllib.request
    import urllib.error

    # Parse or generate master key
    if args.master_skey:
        try:
            master_skey = nacl.signing.SigningKey(bytes.fromhex(args.master_skey))
        except Exception as e:
            print(f"ERROR: Failed to parse master key: {e}", file=sys.stderr)
            return 1
    else:
        master_skey = nacl.signing.SigningKey.generate()
        print(f'Generated Master SKey: {bytes(master_skey).hex()}')
        print(f'Generated Master PKey: {bytes(master_skey.verify_key).hex()}')

    # Parse or generate rotating key
    if args.rotating_skey:
        try:
            rotating_skey = nacl.signing.SigningKey(bytes.fromhex(args.rotating_skey))
        except Exception as e:
            print(f"ERROR: Failed to parse rotating key: {e}", file=sys.stderr)
            return 1
    else:
        rotating_skey = nacl.signing.SigningKey.generate()
        print(f'Generated Rotating SKey: {bytes(rotating_skey).hex()}')
        print(f'Generated Rotating PKey: {bytes(rotating_skey.verify_key).hex()}')

    # Determine provider enum and build payment_tx
    if args.provider == 'google':
        payment_tx_obj = backend.UserPaymentTransaction(
            provider             = base.PaymentProvider.GooglePlayStore,
            google_payment_token = os.urandom(8).hex(),
            google_order_id      = 'DEV.' + os.urandom(8).hex()
        )
    elif args.provider == 'apple':
        payment_tx_obj = backend.UserPaymentTransaction(
            provider    = base.PaymentProvider.iOSAppStore,
            apple_tx_id = 'DEV.' + os.urandom(8).hex()
        )
    elif args.provider == 'rangeproof':
        payment_tx_obj = backend.UserPaymentTransaction(
            provider            = base.PaymentProvider.Rangeproof,
            rangeproof_order_id = 'DEV.' + os.urandom(8).hex()
        )
    else:
        print(f"ERROR: Unsupported payment provider: {args.provider}", file=sys.stderr)
        return 1

    # Compute hash using backend function
    hash_bytes = backend.make_add_pro_payment_hash(
        version       = args.version,
        master_pkey   = master_skey.verify_key,
        rotating_pkey = rotating_skey.verify_key,
        payment_tx    = payment_tx_obj
    )

    # Build request
    request_body = {
        'version':       args.version,
        'master_pkey':   bytes(master_skey.verify_key).hex(),
        'rotating_pkey': bytes(rotating_skey.verify_key).hex(),
        'master_sig':    bytes(master_skey.sign(hash_bytes).signature).hex(),
        'rotating_sig':  bytes(rotating_skey.sign(hash_bytes).signature).hex(),
        'payment_tx':  {
            'provider': payment_tx_obj.provider.value,
        }
    }

    if payment_tx_obj.provider == base.PaymentProvider.GooglePlayStore:
        request_body['payment_tx']['google_payment_token']  = payment_tx_obj.google_payment_token
        request_body['payment_tx']['google_order_id']       = payment_tx_obj.google_order_id
    elif payment_tx_obj.provider == base.PaymentProvider.iOSAppStore:
        request_body['payment_tx']['apple_tx_id']           = payment_tx_obj.apple_tx_id
    elif payment_tx_obj.provider == base.PaymentProvider.Rangeproof:
        request_body['payment_tx']['rangeproof_order_id']   = payment_tx_obj.rangeproof_order_id
    else:
        print(f"ERROR: Unsupported payment provider: {args.provider}", file=sys.stderr)
        return 1

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


def cmd_server_set_payment_refund_requested(args: argparse.Namespace) -> int:
    import json
    import time
    import urllib.request
    import urllib.error

    # Parse master key
    try:
        master_skey = nacl.signing.SigningKey(bytes.fromhex(args.master_skey))
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
    if args.refund_requested_unix_ts_ms:
        refund_unix_ts_ms = args.refund_requested_unix_ts_ms
    else:
        refund_unix_ts_ms = int((time.time() + 1) * 1000)

    now_unix_ts_ms = int(time.time() * 1000)

    # Compute hash
    payment_tx = backend.UserPaymentTransaction()
    if args.provider == 'google':
        payment_tx.provider             = base.PaymentProvider.GooglePlayStore
        payment_tx.google_payment_token = args.payment_token
        payment_tx.google_order_id      = args.order_id
    elif args.provider == 'apple':
        payment_tx.provider    = base.PaymentProvider.iOSAppStore
        payment_tx.apple_tx_id = args.tx_id
    else:
        print(f"ERROR: Unsupported payment provider: {args.provider}", file=sys.stderr)
        return 1

    hash_bytes: bytes = backend.make_set_payment_refund_requested_hash(args.version, master_skey.verify_key, now_unix_ts_ms, refund_unix_ts_ms, payment_tx)

    # Build request
    request_body = {
        'version': args.version,
        'master_pkey': bytes(master_skey.verify_key).hex(),
        'master_sig': bytes(master_skey.sign(hash_bytes).signature).hex(),
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


def cmd_server_get_pro_revocations(args: argparse.Namespace) -> int:
    """Handle query revocations command."""
    import json
    import urllib.request
    import urllib.error

    request_body = {
        'version': args.version,
        'ticket': args.ticket
    }

    print(f'\nQuery Pro Revocations (ticket: {args.ticket})')
    print(f'Request:\n{json.dumps(request_body, indent=1)}')

    # Send request
    try:
        request = urllib.request.Request(
            f'{args.url}/get_pro_revocations',
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


def cmd_server_get_pro_details(args: argparse.Namespace) -> int:
    """Handle query details command."""
    import json
    import time
    import urllib.request
    import urllib.error

    # Parse master key
    try:
        master_skey = nacl.signing.SigningKey(bytes.fromhex(args.master_skey))
    except Exception as e:
        print(f"ERROR: Failed to parse master key: {e}", file=sys.stderr)
        return 1

    unix_ts_ms = int(time.time() * 1000)

    # Compute hash
    hash_bytes = backend.make_get_pro_details_hash(
        version=args.version,
        master_pkey=master_skey.verify_key,
        unix_ts_ms=unix_ts_ms,
        count=args.count
    )

    # Build request
    request_body = {
        'version': args.version,
        'master_pkey': bytes(master_skey.verify_key).hex(),
        'master_sig': bytes(master_skey.sign(hash_bytes).signature).hex(),
        'unix_ts_ms': unix_ts_ms,
        'count': args.count
    }

    print(f'\nQuery Pro Details')
    print(f'Request:\n{json.dumps(request_body, indent=1)}')

    # Send request
    try:
        request = urllib.request.Request(
            f'{args.url}/get_pro_details',
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


def cmd_server_generate_pro_proof(args: argparse.Namespace) -> int:
    """Handle generate pro proof command."""
    import json
    import time
    import urllib.request
    import urllib.error

    # Parse master key
    try:
        master_skey = nacl.signing.SigningKey(bytes.fromhex(args.master_skey))
    except Exception as e:
        print(f"ERROR: Failed to parse master key: {e}", file=sys.stderr)
        return 1

    # Parse rotating key
    try:
        rotating_skey = nacl.signing.SigningKey(bytes.fromhex(args.rotating_skey))
    except Exception as e:
        print(f"ERROR: Failed to parse rotating key: {e}", file=sys.stderr)
        return 1

    unix_ts_ms = int(time.time() * 1000)

    # Compute hash
    hash_bytes = backend.make_generate_pro_proof_hash(
        version=args.version,
        master_pkey=master_skey.verify_key,
        rotating_pkey=rotating_skey.verify_key,
        unix_ts_ms=unix_ts_ms
    )

    # Build request
    request_body = {
        'version': args.version,
        'master_pkey': bytes(master_skey.verify_key).hex(),
        'rotating_pkey': bytes(rotating_skey.verify_key).hex(),
        'master_sig': bytes(master_skey.sign(hash_bytes).signature).hex(),
        'rotating_sig': bytes(rotating_skey.sign(hash_bytes).signature).hex(),
        'unix_ts_ms': unix_ts_ms
    }

    print(f'\nGenerate Pro Proof')
    print(f'Request:\n{json.dumps(request_body, indent=1)}')

    # Send request
    try:
        request = urllib.request.Request(
            f'{args.url}/generate_pro_proof',
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


def cmd_voucher(args: argparse.Namespace) -> int:
    """Handle voucher command - creates Rangeproof voucher and auto-redeems it."""
    config = require_config(args)

    # Parse master public key
    try:
        master_pkey_hex = args.master_pkey
        if master_pkey_hex.startswith("0x"):
            master_pkey_hex = master_pkey_hex[2:]
        master_pkey = nacl.signing.VerifyKey(bytes.fromhex(master_pkey_hex))
    except Exception as e:
        print(f"ERROR: Failed to parse master public key: {e}", file=sys.stderr)
        return 1

    # Handle rotating key
    rotating_skey = None
    rotating_pkey = None
    if args.rotating_pkey:
        try:
            rotating_pkey_hex = args.rotating_pkey
            if rotating_pkey_hex.startswith("0x"):
                rotating_pkey_hex = rotating_pkey_hex[2:]
            rotating_pkey = nacl.signing.VerifyKey(bytes.fromhex(rotating_pkey_hex))
        except Exception as e:
            print(f"ERROR: Failed to parse rotating public key: {e}", file=sys.stderr)
            return 1
    else:
        # Generate a throwaway rotating keypair
        rotating_skey = nacl.signing.SigningKey.generate()
        rotating_pkey = rotating_skey.verify_key
        print(f'Generated Rotating SKey: {bytes(rotating_skey).hex()}')
        print(f'Generated Rotating PKey: {bytes(rotating_pkey).hex()}')

    rangeproof_order_id = str(uuid.uuid4())
    print(f'Generated Rangeproof Order ID: {rangeproof_order_id}')

    # Map plan to enum and calculate duration
    plan_map = {'1M': base.ProPlan.OneMonth, '3M': base.ProPlan.ThreeMonth, '12M': base.ProPlan.TwelveMonth}
    plan     = plan_map[args.plan]

    # Calculate plan duration in milliseconds
    if args.dev_duration_ms:
        duration_ms = args.dev_duration_ms
    else:
        if plan == base.ProPlan.OneMonth:
            duration_ms = 30 * base.SECONDS_IN_DAY * 1000
        elif plan == base.ProPlan.ThreeMonth:
            duration_ms = 90 * base.SECONDS_IN_DAY * 1000
        else:  # TwelveMonth
            duration_ms = 365 * base.SECONDS_IN_DAY * 1000

    # Create payment transaction
    payment_tx = base.PaymentProviderTransaction(
        provider=base.PaymentProvider.Rangeproof,
        rangeproof_order_id=rangeproof_order_id
    )

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    unix_ts_ms            = int(time.time() * 1000)
                    expiry_unix_ts_ms     = unix_ts_ms + duration_ms
                    unredeemed_unix_ts_ms = unix_ts_ms

                    # Step 1: Add unredeemed payment
                    print('\nStep 1: Creating unredeemed Rangeproof payment...')
                    err = base.ErrorSink()
                    backend.add_unredeemed_payment_tx(
                        tx                                = tx,
                        payment_tx                        = payment_tx,
                        plan                              = plan,
                        expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                        unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                        platform_refund_expiry_unix_ts_ms = 0,
                        platform_obfuscated_account_id    = b'',
                        err                               = err
                    )

                    if err.has():
                        print(f"ERROR: Failed to create unredeemed payment:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
                        return 1

                    print("Success: Unredeemed payment created")

                    # Get the backend signing key from runtime
                    runtime_result = db.query(tx.conn, "SELECT backend_key FROM runtime")
                    runtime_row    = runtime_result.fetchone()
                    if not runtime_row:
                        print("ERROR: Could not load runtime from database", file=sys.stderr)
                        return 1

                    backend_key_bytes = bytes(runtime_row[0])
                    backend_key       = nacl.signing.SigningKey(backend_key_bytes)

                    # Step 2: Redeem the payment via add_pro_payment
                    print('\nStep 2: Redeeming payment and generating pro proof...')
                    err = base.ErrorSink()
                    redeem_result = backend.add_pro_payment_tx(
                        tx                  = tx,
                        version             = 0,
                        signing_key         = backend_key,
                        unix_ts_ms          = unix_ts_ms,
                        redeemed_unix_ts_ms = backend.convert_unix_ts_ms_to_redeemed_unix_ts_ms(unix_ts_ms),
                        master_pkey         = master_pkey,
                        rotating_pkey       = rotating_pkey,
                        payment_tx          = backend.UserPaymentTransaction(
                            provider            = base.PaymentProvider.Rangeproof,
                            rangeproof_order_id = rangeproof_order_id
                        ),
                        err                 = err,
                        THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION=False,
                    )

                    if err.has():
                        print(f"ERROR: Failed to redeem payment:\n  " + "\n  ".join(err.msg_list), file=sys.stderr)
                        return 1

                    if redeem_result.status != backend.RedeemPaymentStatus.Success:
                        print(f"ERROR: Payment redemption failed with status: {redeem_result.status}", file=sys.stderr)
                        return 1

                    print("Success: Payment redeemed and pro proof generated")
                    print(f'\nProof Details:')
                    print(f'  Expiry: {base.readable_unix_ts_ms(redeem_result.proof.expiry_unix_ts_ms)}')
                    print(f'  Gen Index Hash: {redeem_result.proof.gen_index_hash.hex()}')

                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description     = 'Session Pro Backend CLI',
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog          = DETAILED_EPILOG if '--help-full' in sys.argv else BRIEF_EPILOG,
        add_help        = False
    )

    # Global options
    _                       = parser.add_argument('--help',      action='help',       default=argparse.SUPPRESS, help='Show brief help message and exit')
    _                       = parser.add_argument('--help-full', action='help',       default=argparse.SUPPRESS, help='Show detailed help with full documentation')
    _                       = parser.add_argument('--config',                         required=False,            help='Path to config.ini file (required for DB operations)')
    _                       = parser.add_argument('--dry-run',   action='store_true',                            help='Show what would be done without executing')

    subparsers              = parser.add_subparsers(dest='command', help='Available commands')

    # Server commands (no config required) - mirror HTTP endpoints
    server_parser           = subparsers.add_parser('server', help='Server endpoint operations (no --config required)')
    server_subparsers       = server_parser.add_subparsers(dest='server_command', help='Server endpoint subcommands')

    # add-pro-payment endpoint
    server_add_pro_payment  = server_subparsers.add_parser('add-pro-payment',                                                                      help='Add a pro payment. Mirrors /add_pro_payment')
    _                       = server_add_pro_payment.add_argument('--url',               required=True,                                            help='Server URL (e.g., http://localhost:8000)')
    _                       = server_add_pro_payment.add_argument('--provider',          required=True, choices=['google', 'apple', 'rangeproof'], help='Payment provider')
    _                       = server_add_pro_payment.add_argument('--master-skey',                                                                 help='64-char hex master secret key (generates new if omitted)')
    _                       = server_add_pro_payment.add_argument('--rotating-skey',                                                               help='64-char hex rotating secret key (generates new if omitted)')
    _                       = server_add_pro_payment.add_argument('--version',           type=int, default=0,                                      help='Request version (default: 0)')
    _                       = server_add_pro_payment.add_argument('--dev-plan',                         choices=['1M', '3M', '12M'],               help='Subscription plan (1M/3M/12M)')
    _                       = server_add_pro_payment.add_argument('--dev-duration-ms',   type=int,                                                 help='Override duration in milliseconds')
    _                       = server_add_pro_payment.add_argument('--dev-auto-renewing', action='store_true',                                      help='Set auto-renewing to true (default: false)')

    # set-payment-refund-requested endpoint
    server_set_refund       = server_subparsers.add_parser('set-payment-refund-requested',                                                help='Mark payment as refund requested. Mirrors /set_payment_refund_requested')
    _                       = server_set_refund.add_argument('--url',                         required=True,                              help='Server URL')
    _                       = server_set_refund.add_argument('--provider',                    required=True, choices=['google', 'apple'], help='Payment provider')
    _                       = server_set_refund.add_argument('--master-skey',                 required=True,                              help='64-char hex master secret key')
    _                       = server_set_refund.add_argument('--payment-token',                                                           help='Google: payment token')
    _                       = server_set_refund.add_argument('--order-id',                                                                help='Google: order ID')
    _                       = server_set_refund.add_argument('--tx-id',                                                                   help='Apple: transaction ID')
    _                       = server_set_refund.add_argument('--refund-requested-unix-ts-ms', type=int,                                   help='Unix timestamp ms for refund (default: now + 1s)')
    _                       = server_set_refund.add_argument('--version',                     type=int,      default=0,                   help='Request version (default: 0)')

    # get-pro-revocations endpoint
    server_get_revocations  = server_subparsers.add_parser('get-pro-revocations',                          help='Get pro revocations. Mirrors /get_pro_revocations')
    _                       = server_get_revocations.add_argument('--url',     required=True,              help='Server URL (e.g., http://localhost:8000)')
    _                       = server_get_revocations.add_argument('--ticket',  type=int, default=0,        help='Revocation ticket to query from (default: 0)')
    _                       = server_get_revocations.add_argument('--version', type=int, default=0,        help='Request version (default: 0)')

    # get-pro-details endpoint
    server_get_details      = server_subparsers.add_parser('get-pro-details',                              help='Get pro details. Mirrors /get_pro_details')
    _                       = server_get_details.add_argument('--url',         required=True,              help='Server URL (e.g., http://localhost:8000)')
    _                       = server_get_details.add_argument('--master-skey', required=True,              help='64-char hex master secret key for signing')
    _                       = server_get_details.add_argument('--count',       type=int, default=10,       help='Number of payments to retrieve (default: 10)')
    _                       = server_get_details.add_argument('--version',     type=int, default=0,        help='Request version (default: 0)')

    # generate-pro-proof endpoint
    server_gen_proof        = server_subparsers.add_parser('generate-pro-proof',                           help='Generate pro proof. Mirrors /generate_pro_proof')
    _                       = server_gen_proof.add_argument('--url',           required=True,              help='Server URL (e.g., http://localhost:8000)')
    _                       = server_gen_proof.add_argument('--master-skey',   required=True,              help='64-char hex master secret key')
    _                       = server_gen_proof.add_argument('--rotating-skey', required=True,              help='64-char hex rotating secret key')
    _                       = server_gen_proof.add_argument('--version',       type=int, default=0,        help='Request version (default: 0)')

    # Voucher command (creates Rangeproof voucher and auto-redeems it)
    voucher_parser          = subparsers.add_parser('voucher',                                                             help='Create a Rangeproof voucher payment (requires --config)')
    _                       = voucher_parser.add_argument('--master-pkey',     required=True,                              help='64-char hex master public key of the recipient')
    _                       = voucher_parser.add_argument('--plan',            required=True, choices=['1M', '3M', '12M'], help='Subscription plan (1M/3M/12M)')
    _                       = voucher_parser.add_argument('--rotating-pkey',                                               help='64-char hex rotating public key (generates new if omitted)')
    _                       = voucher_parser.add_argument('--dev-duration-ms', type=int,                                   help='Override duration in milliseconds')

    # User error commands
    user_error_parser       = subparsers.add_parser('user-error',                         help='Manage user errors')
    user_error_subparsers   = user_error_parser.add_subparsers(dest='user_error_command', help='User error subcommands')

    user_error_set          = user_error_subparsers.add_parser('set',                     help='Set user errors (format: <provider>:<payment-id>=true|false,...)')
    _                       = user_error_set.add_argument('items',                        help='Comma-separated list of errors')

    user_error_delete       = user_error_subparsers.add_parser('delete',                  help='Delete user errors (format: <provider>:<payment-id>,...)')
    _                       = user_error_delete.add_argument('items',                     help='Comma-separated list of payment IDs')

    # Google notification commands
    google_notif_parser     = subparsers.add_parser('google-notification',                    help='Manage the list of Google notifications received in the database')
    google_notif_subparsers = google_notif_parser.add_subparsers(dest='google_notif_command', help='Google notification subcommands')

    google_notif_handle     = google_notif_subparsers.add_parser('handle',                    help='Mark notifications as handled')
    _                       = google_notif_handle.add_argument('items',                       help='Comma-separated list of message IDs')

    google_notif_delete     = google_notif_subparsers.add_parser('delete',                    help='Delete notifications')
    _                       = google_notif_delete.add_argument('items',                       help='Comma-separated list of message IDs')
    _                       = google_notif_subparsers.add_parser('list',                      help='List unhandled notifications')

    # Revoke commands
    revoke_parser           = subparsers.add_parser('revoke',                     help='Manage revocations')
    revoke_subparsers       = revoke_parser.add_subparsers(dest='revoke_command', help='Revocation subcommands')

    revoke_list             = revoke_subparsers.add_parser('list',                help='List revocable payments for a user')
    _                       = revoke_list.add_argument('master_pkey',             help='Master public key (64 hex chars)')

    revoke_delete           = revoke_subparsers.add_parser('delete',              help='Delete revocation entry')
    _                       = revoke_delete.add_argument('master_pkey',           help='Master public key (64 hex chars)')

    revoke_timestamp        = revoke_subparsers.add_parser('timestamp',             help='Set revocation with timestamp')
    _                       = revoke_timestamp.add_argument('master_pkey',          help='Master public key (64 hex chars)')
    _                       = revoke_timestamp.add_argument('--creation-unix-ts-s', type=int, default=int(time.time()), help='Revoke creation timestamp in seconds')
    _                       = revoke_timestamp.add_argument('expiry_unix_ts_s',     type=int,                           help='Expiry unix timestamp in seconds')

    # Report commands
    report_parser           = subparsers.add_parser('report',                     help='Generate reports')
    report_subparsers       = report_parser.add_subparsers(dest='report_command', help='Report subcommands')

    report_generate         = report_subparsers.add_parser('generate',                                                            help='Generate a report')
    _                       = report_generate.add_argument('period',   choices=['daily', 'weekly',  'monthly'],                   help='Report period')
    _                       = report_generate.add_argument('--format', choices=['human', 'csv'],                 default='human', help='Report format')
    _                       = report_generate.add_argument('--count',  type=int,                                 default=7,       help='Number of periods to report')

    # DB commands
    db_parser               = subparsers.add_parser('db',                 help='Database operations')
    db_subparsers           = db_parser.add_subparsers(dest='db_command', help='Database subcommands')
    _                       = db_subparsers.add_parser('info',            help='Show database info')
    _                       = db_subparsers.add_parser('print',           help='Print all tables')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Dispatch to command handler - commands that need config will load it themselves
    dry_run = args.dry_run

    if args.command == 'server':
        if args.server_command == 'add-pro-payment':
            return cmd_server_add_pro_payment(args)
        elif args.server_command == 'set-payment-refund-requested':
            return cmd_server_set_payment_refund_requested(args)
        elif args.server_command == 'get-pro-revocations':
            return cmd_server_get_pro_revocations(args)
        elif args.server_command == 'get-pro-details':
            return cmd_server_get_pro_details(args)
        elif args.server_command == 'generate-pro-proof':
            return cmd_server_generate_pro_proof(args)
        else:
            server_parser.print_help()
            return 1

    elif args.command == 'voucher':
        return cmd_voucher(args)

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
