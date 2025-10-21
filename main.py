'''
Main entry point for the Session Pro Backend. This runs the necessary setup code like initialising
the DB and responding startup arguments before handing over control-flow to Flask.

This application has command line options that must be specified as environment variables because
this application runs directly as a flask app (in a dev environment) and it also can be served over
UWSGI for a production use-case.

We've designed the backend primarily for UWSGI which mounts the flask app with no possibility to
forward command line arguments to the underlying application. Thus we cannot use argparse or flask's
@click.options as there's no way to specify them in the UWSGI manifest hence the design decision to
use environment variables.
'''

import pathlib
import os
import flask
import threading
import time
import datetime
import signal
import types
import nacl.signing
import logging
import logging.handlers
import configparser
import sys
import dataclasses

import base
import backend
import server
import platform_apple
import platform_google

log                   = logging.Logger('PRO')
google_thread_context = platform_google.ThreadContext()

@dataclasses.dataclass
class ParsedArgs:
    ini_path:                            str         = ''
    db_path:                             str         = ''
    db_path_is_uri:                      bool        = False
    print_tables:                        bool        = False
    dev:                                 bool        = False
    unsafe_logging:                      bool        = False
    with_platform_apple:                 bool        = False
    with_platform_google:                bool        = False
    platform_testing_env:                bool        = False

    apple_key_id:                        str         = ''
    apple_issuer_id:                     str         = ''
    apple_bundle_id:                     str         = ''
    apple_key_path:                      str         = ''
    apple_root_cert_path:                str         = ''
    apple_root_cert_ca_g2_path:          str         = ''
    apple_root_cert_ca_g3_path:          str         = ''
    apple_key:                           bytes       = b''
    apple_root_certs:                    list[bytes] = dataclasses.field(default_factory=list)
    apple_sandbox_env:                   bool        = False
    apple_production_app_id:             int | None  = None

    google_package_name:                 str            = ''
    google_application_credentials_path: str            = ''
    google_project_name:                 str            = ''
    google_subscription_name:            str            = ''
    google_subscription_product_id:      str            = ''

def signal_handler(sig: int, _frame: types.FrameType | None):
    global stop_proof_expiry_thread
    global proof_expiry_thread_cv
    global proof_expiry_thread_mutex

    # NOTE: Wake up the thread and set the flag to terminate it
    with proof_expiry_thread_mutex:
        stop_proof_expiry_thread = True
        proof_expiry_thread_cv.notify_all()

    # NOTE: Also kill the google-thread if there's one was initiated. The google thread is sleeping
    # on a Future that has a timeout. We don't have a way to signal the thread to wake up but it
    # is configured with a short timeout.
    google_thread_context.kill_thread = True

    # NOTE: Unregister handler and resume the default handler by re-raising it
    _ = signal.signal(sig, signal.SIG_DFL)
    signal.raise_signal(sig)

def backend_proof_expiry_thread_entry_point(db_path: str):
    global proof_expiry_thread_cv
    global proof_expiry_thread_mutex
    global stop_proof_expiry_thread

    while not stop_proof_expiry_thread:
        start_unix_ts_s:    int = int(time.time())
        next_day_unix_ts_s: int = int(base.round_unix_ts_ms_to_next_day(start_unix_ts_s * 1000) / 1000)
        sleep_time_s:       int = next_day_unix_ts_s - start_unix_ts_s
        next_day_str:       str = datetime.datetime.fromtimestamp(next_day_unix_ts_s).strftime('%Y-%m-%d')

        # Sleep on CV until sleep time has elapsed, or, we get woken up by SIG handler.
        while sleep_time_s > 0 and not stop_proof_expiry_thread:
            assert sleep_time_s <= base.SECONDS_IN_DAY
            log.info(f'Sleeping for {base.format_seconds(sleep_time_s)} to expire DB entries at UTC {next_day_str}')
            with proof_expiry_thread_mutex:
                _ = proof_expiry_thread_cv.wait(timeout=sleep_time_s)
            sleep_time_s = next_day_unix_ts_s - int(time.time())

        # We only reach here if the sleep time has elapsed OR woken up. If sleep time has elapsed,
        # then we can go and expire the records from the DB
        if not stop_proof_expiry_thread:
            expire_result = backend.ExpireResult()
            with backend.OpenDBAtPath(db_path=db_path) as db:
                expire_result = backend.expire_payments_revocations_and_users(sql_conn=db.sql_conn,
                                                                              unix_ts_ms=next_day_unix_ts_s * 1000)

            yesterday_str: str = datetime.datetime.fromtimestamp(next_day_unix_ts_s - base.SECONDS_IN_DAY).strftime('%Y-%m-%d')
            today_str: str     = datetime.datetime.fromtimestamp(next_day_unix_ts_s).strftime('%m-%d')
            if expire_result.success:
                if not expire_result.already_done_by_someone_else:
                    log.info('Daily pruning for {} completed on {}. Expired payments/revocations/users/apple notifs={}/{}/{}/{}'.format(yesterday_str,
                                                                                                                     today_str,
                                                                                                                     expire_result.payments,
                                                                                                                     expire_result.revocations,
                                                                                                                     expire_result.users,
                                                                                                                     expire_result.apple_notification_uuid_history))
            else:
                log.error(f'Daily pruning for {yesterday_str} failed due to an unknown DB error')

def parse_args(err: base.ErrorSink) -> ParsedArgs:
    # NOTE: Parse .INI file if present and get arguments for it
    result          = ParsedArgs()
    result.ini_path = os.getenv('SESH_PRO_BACKEND_INI_PATH', '')
    if len(result.ini_path) > 0:
        if not pathlib.Path(result.ini_path).exists():
            log.error(f'.INI config file "{result.ini_path}", was specified but does not exist/is not readable')
            sys.exit(1)

        ini_parser                                 = configparser.ConfigParser()
        _                                          = ini_parser.read(filenames=result.ini_path)

        base_section: configparser.SectionProxy    = ini_parser['base']
        result.db_path                             = base_section.get(option='db_path',                        fallback='')
        result.db_path_is_uri                      = base_section.getboolean(option='db_path_is_uri',          fallback=False)
        result.print_tables                        = base_section.getboolean(option='print_tables',            fallback=False)
        result.dev                                 = base_section.getboolean(option='dev',                     fallback=False)
        result.unsafe_logging                      = base_section.getboolean(option='unsafe_logging',          fallback=False)
        result.with_platform_apple                 = base_section.getboolean(option='with_platform_apple',     fallback=False)
        result.with_platform_google                = base_section.getboolean(option='with_platform_google',    fallback=False)
        result.platform_testing_env                = base_section.getboolean(option='platform_testing_env',    fallback=False)

        if result.with_platform_apple:
            if 'apple' in ini_parser:
                apple_section: configparser.SectionProxy   = ini_parser['apple']
                result.apple_key_id                        = apple_section.get(option='key_id',                        fallback='')
                result.apple_issuer_id                     = apple_section.get(option='issuer_id',                     fallback='')
                result.apple_bundle_id                     = apple_section.get(option='bundle_id',                     fallback='')
                result.apple_key_path                      = apple_section.get(option='key_path',                      fallback='')
                result.apple_root_cert_path                = apple_section.get(option='root_cert_path',                fallback='')
                result.apple_root_cert_ca_g2_path          = apple_section.get(option='root_cert_ca_g2_path',          fallback='')
                result.apple_root_cert_ca_g3_path          = apple_section.get(option='root_cert_ca_g3_path',          fallback='')
                result.apple_sandbox_env                   = apple_section.getboolean(option='sandbox_env',            fallback=False)
                result.apple_production_app_id             = apple_section.getint(option='production_app_id')
            else:
                err.msg_list.append('Platform Apple was enabled but [apple] section is missing')

        if result.with_platform_google:
            if 'google' in ini_parser:
                google_section: configparser.SectionProxy  = ini_parser['google']
                result.google_package_name                 = google_section.get(option='package_name',                 fallback='')
                result.google_project_name                 = google_section.get(option='project_name',                 fallback='')
                result.google_subscription_name            = google_section.get(option='subscription_name',            fallback='')
                result.google_application_credentials_path = google_section.get(option='application_credentials_path', fallback='')
                result.google_subscription_product_id      = google_section.get(option='subscription_product_id',      fallback='')
            else:
                err.msg_list.append('Platform Google was enabled but [google] section is missing')

    # NOTE: Get arguments from environment, they override .INI values if specified
    result.db_path              = os.getenv('SESH_PRO_BACKEND_DB_PATH',                            result.db_path)
    result.db_path_is_uri       = base.os_get_boolean_env('SESH_PRO_BACKEND_DB_PATH_IS_URI',       result.db_path_is_uri)
    result.print_tables         = base.os_get_boolean_env('SESH_PRO_BACKEND_PRINT_TABLES',         result.print_tables)
    result.dev                  = base.os_get_boolean_env('SESH_PRO_BACKEND_DEV',                  result.dev)
    result.with_platform_apple  = base.os_get_boolean_env('SESH_PRO_BACKEND_WITH_PLATFORM_APPLE',  result.with_platform_apple)
    result.with_platform_google = base.os_get_boolean_env('SESH_PRO_BACKEND_WITH_PLATFORM_GOOGLE', result.with_platform_google)
    result.with_platform_google = base.os_get_boolean_env('SESH_PRO_BACKEND_PLATFORM_TESTING_ENV', result.with_platform_google)

    if result.with_platform_apple:
        if len(result.apple_key_id) == 0:
            err.msg_list.append('Platform Apple was enabled but key_id was not specified')
        if len(result.apple_issuer_id) == 0:
            err.msg_list.append('Platform Apple was enabled but issuer_id was not specified')
        if len(result.apple_bundle_id) == 0:
            err.msg_list.append('Platform Apple was enabled but bundle_id was not specified')
        if len(result.apple_key_path) == 0:
            err.msg_list.append('Platform Apple was enabled but key_path was not specified')
        if len(result.apple_root_cert_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_path was not specified')
        if len(result.apple_root_cert_ca_g2_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_ca_g2_path was not specified')
        if len(result.apple_root_cert_ca_g3_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_ca_g3_path was not specified')

        if not result.apple_sandbox_env:
            if result.apple_production_app_id is None:
                err.msg_list.append('Platform Apple was enabled in production mode (e.g. not sandbox mode) but the production_app_id was not specified')

        if result.apple_sandbox_env:
            if result.platform_testing_env == False:
                log.warning('Platform Apple was enabled in sandbox mode but platform_testing_env was not set to true. You want to set this to true, overriding the flag to true')
                result.platform_testing_env = True

        if not err.has():
            try:
                result.apple_key = pathlib.Path(result.apple_key_path).read_bytes()
                result.apple_root_certs = [
                    pathlib.Path(result.apple_root_cert_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g2_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g3_path).read_bytes(),
                ]
            except Exception as e:
                err.msg_list.append(f'Platform Apple was enabled but we are unable to read the path: {e}');

    if result.with_platform_google:
        if len(result.google_package_name) == 0:
            err.msg_list.append('Platform Google was enabled but package_name was not specified')
        if len(result.google_project_name) == 0:
            err.msg_list.append('Platform Google was enabled but project_name was not specified')
        if len(result.google_subscription_name) == 0:
            err.msg_list.append('Platform Google was enabled but subscription_name was not specified')
        if len(result.google_application_credentials_path) == 0:
            err.msg_list.append('Platform Google was enabled but application_credentials_path was not specified')
        if len(result.google_subscription_product_id) == 0:
            err.msg_list.append('Platform Google was enabled but subscription_product_id was not specified')

    return result

def entry_point() -> flask.Flask:
    if 1: # NOTE: Setup logger
        console_logger = logging.StreamHandler()
        file_logger    = logging.handlers.RotatingFileHandler(filename='session_backend_pro.log', maxBytes=64 * 1024 * 1024, backupCount=2, encoding='utf-8')

        log_formatter = base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
        console_logger.setFormatter(log_formatter)
        file_logger.setFormatter(log_formatter)

        # NOTE: Equip handlers
        log.addHandler(console_logger)
        log.addHandler(file_logger)

        # NOTE: Setup backend logger
        backend.log.addHandler(console_logger)
        backend.log.addHandler(file_logger)

        # NOTE: Setup google logger
        platform_google.log.addHandler(console_logger)
        platform_google.log.addHandler(file_logger)

        # NOTE: Setup apple logger
        platform_apple.log.addHandler(console_logger)
        platform_apple.log.addHandler(file_logger)

    # NOTE: Parse arguments from .INI if present and environment variables, then setup global variables
    err = base.ErrorSink()
    parsed_args: ParsedArgs   = parse_args(err);
    base.UNSAFE_LOGGING       = parsed_args.unsafe_logging
    base.DEV_BACKEND_MODE     = parsed_args.dev
    base.DB_PATH              = parsed_args.db_path
    base.DB_PATH_IS_URI       = parsed_args.db_path_is_uri
    base.PLATFORM_TESTING_ENV = parsed_args.platform_testing_env
    if err.has():
        log.error(f'Failed to startup, invalid configuration options:\n  ' + '\n  '.join(err.msg_list))
        sys.exit(1)

    # NOTE: Ensure the path is setup for writing the database
    try:
        pathlib.Path(parsed_args.db_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.error(f'Failed to create directory for {parsed_args.db_path}: {e}')
        sys.exit(1)

    # NOTE: A developer backend generates a deterministic key for testing purposes
    backend_key: nacl.signing.SigningKey | None = None
    if parsed_args.dev:
        DEV_BACKEND_DETERMINISTIC_SKEY = bytes([0xCD] * 32)
        backend_key                    = nacl.signing.SigningKey(DEV_BACKEND_DETERMINISTIC_SKEY)

    # NOTE: Open the DB (create tables if necessary)
    db: backend.SetupDBResult = backend.setup_db(path=parsed_args.db_path, uri=parsed_args.db_path_is_uri, err=err, backend_key=backend_key)
    if len(err.msg_list) > 0:
        log.error(f"{err.msg_list}")
        sys.exit(1)

    # NOTE: Sanity check dev mode
    if base.DEV_BACKEND_MODE:
        assert db.sql_conn
        runtime_row: backend.RuntimeRow = backend.get_runtime(db.sql_conn)
        assert bytes(runtime_row.backend_key) == base.DEV_BACKEND_DETERMINISTIC_SKEY, \
                "Sanity check failed, developer mode was enabled but the key in the DB was not a development key. This is a special guard to prevent the user from activating developer mode in the wrong environment"

    # NOTE: Dump some startup diagnostics
    assert db.sql_conn is not None
    info_string: str = backend.db_info_string(sql_conn=db.sql_conn, db_path=db.path, err=err)
    if len(err.msg_list) > 0:
        log.error(f"{err.msg_list}")
        sys.exit(1)

    if parsed_args.dev:
        log.info("######################################")
        log.info("###                                ###")
        log.info("###        Dev Mode Enabled        ###")
        log.info("###                                ###")
        log.info("######################################")

    log.info(f'Session Pro Backend\n{info_string}')
    log.info(f'  Features:')
    if len(parsed_args.ini_path) > 0:
        log.info(f'    Config .INI file loaded: {parsed_args.ini_path}')
    if 1:
        label = ' (URI)' if parsed_args.db_path_is_uri else ''
        log.info(f'    DB loaded from: {db.path}{label}')
    if parsed_args.unsafe_logging:
        log.info(f'    Unsafe logging enabled (this must NOT be used in production)')
    if parsed_args.platform_testing_env:
        log.info(f'    Platform testing environment enabled (special behaviour for rounding timestamps to EOD)')
    if parsed_args.with_platform_apple:
        label = 'Sandbox' if parsed_args.apple_sandbox_env else 'Production'
        log.info(f'    Platform: {label} Apple iOS App Store notification handling enabled')
    if parsed_args.with_platform_google:
        log.info(f'    Platform: Google Play Store notification handling enabled')

    if parsed_args.dev:
        log.info("######################################")
        log.info("###                                ###")
        log.info("###        Dev Mode Enabled        ###")
        log.info("###                                ###")
        log.info("######################################")

    # NOTE: Handle printing of the DB to standard out if requested
    if parsed_args.print_tables:
        base.print_db_to_stdout(db.sql_conn)
        sys.exit(1)

    # NOTE: Running the application just in Flask (e.g. local development) we
    # need a way to signal to the long-running payment expiry thread to
    # terminate itself, we do this using a cv+mutex combo otherwise the
    # application hangs on exit, forever as the thread is never terminated.
    #
    # In UWSGI we want to use the same code to catch the signal and terminate,
    # but, by default UWSGI hijacks the signal handler and so our thread
    # termination code doesn't run. However, you can override this on UWSGI by
    # passing the flag `py-call-osafterfork` which makes the UWSGI process
    # respect our custom signal handlers.
    #
    # This option however is not present on older UWSGI version like 2.0.21.
    # But actually UWSGI is able to terminate the thread without our signal
    # handling because they hijack the process and do whatever magic they do as
    # long as you pass `--lazy-apps` which ensures that each spawned process
    # runs our `entry_point`.
    #
    # Since UWSGI can handle terminating the thread we only equip our signal
    # handlers if we know we're not running in UWSGI mode, this means we don't
    # need to use `py-call-osafterfork` which increases the backend's
    # compatibility to a large suite of operating environments.
    _ = signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    _ = signal.signal(signal.SIGTERM, signal_handler) # Terminate
    _ = signal.signal(signal.SIGQUIT, signal_handler) # Quit

    # Dispatch a long-running "thread" that wakes up every 00:00 UTC to expire
    # entries in the DB. This thread has program-lifetime and hence should exit
    # when the Flask app exits.
    #
    # In UWSGI mode, we launch multiple processes, so we actually have multiple
    # of these threads running. I considered separating this into a separate app
    # that you have to run, or, some smart way to detect that only one process
    # out of the set should be running this thread to clean the DB.
    #
    # But this complicates the architecture _alot_ trying to get UWSGI to
    # intelligently handle this, either by defining a custom hook, or
    # _multiple_ UWSGI instances, or running them under UWSGI emperor so that
    # you can then run 2 apps (100% more setup than 1 app!) for the backend.
    #
    # The trade-off in choosing that is unacceptable for managing Session Pro
    # subscriptions which on paper is a very simple CRUD application.
    # Instead, I've embedded the periodic cleaning of the DB into the app
    # itself so that the entire stack is self-contained and hence monolithic.
    #
    # By running the app, either in flask, UWSGI w/ multiple processes or
    # whatever, that is in itself self-sufficient to maintain a valid Session
    # Pro database without any additional configuration. Just launch the app and
    # it "just works". This avoids the need for external frameworks like UWSGI
    # needing to know about internal details (i.e. leaky abstractions) to run
    # the application.
    #
    # The trade-off for this is that all processes running the app will attempt
    # to clean the DB and race at UTC 00:00 to do so. We just make sure to do
    # that operation over an atomic transaction and allow exactly one process
    # out of the N available to actually clean the DB. The rest will no-op.
    thread = threading.Thread(target=backend_proof_expiry_thread_entry_point, args=(parsed_args.db_path,))
    thread.start()

    result: flask.Flask = server.init(testing_mode=False,
                                      db_path=db.path,
                                      db_path_is_uri=parsed_args.db_path_is_uri,
                                      server_x25519_skey=db.runtime.backend_key.to_curve25519_private_key())

    # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled. Apple will
    # contact the endpoint when a notification is generated.
    if parsed_args.with_platform_apple:
        core: platform_apple.Core = platform_apple.init(key_id      = parsed_args.apple_key_id,
                                                        issuer_id   = parsed_args.apple_issuer_id,
                                                        bundle_id   = parsed_args.apple_bundle_id,
                                                        app_id      = None if parsed_args.apple_sandbox_env else parsed_args.apple_production_app_id,
                                                        key_bytes   = parsed_args.apple_key,
                                                        root_certs  = parsed_args.apple_root_certs,
                                                        sandbox_env = parsed_args.apple_sandbox_env)
        platform_apple.equip_flask_routes(core, result)

        # NOTE: Offset by 10s to account for clock drift between backend and the Apple servers
        end_unix_ts_ms = int((time.time() - 10) * 1000)
        platform_apple.catchup_on_missed_notifications(core           = core,
                                                       sql_conn       = db.sql_conn,
                                                       end_unix_ts_ms = end_unix_ts_ms)

    # NOTE: Enable Google Play Store notification handling, this is a blocking call so it's delegated
    # to a thread. We use Google's asynchronous streaming pull client which spawns a thread pool
    # (10 threads by default) to process messages.
    if parsed_args.with_platform_google:
        global google_thread_context
        google_thread_context = platform_google.init(sql_conn                = db.sql_conn,
                                                     project_name            = parsed_args.google_project_name,
                                                     package_name            = parsed_args.google_package_name,
                                                     subscription_name       = parsed_args.google_subscription_name,
                                                     subscription_product_id = parsed_args.google_subscription_product_id,
                                                     app_credentials_path    = parsed_args.google_application_credentials_path)
        assert google_thread_context.thread
        google_thread_context.thread.start()

    # The flask runner/UWSGI takes over from here and runs the application for
    # us across multiple processes if necessary. We'll close our db connection
    # here. Each request we receive will open their own connection the DB.
    db.sql_conn.close()

    return result

# Flask entry point
stop_proof_expiry_thread  = False
proof_expiry_thread_mutex = threading.Lock()
proof_expiry_thread_cv    = threading.Condition(proof_expiry_thread_mutex)
flask_app: flask.Flask    = entry_point()
