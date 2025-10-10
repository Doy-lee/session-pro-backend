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
import env
import logging
import logging.handlers

import base
import backend
import server
import platform_apple

log = logging.Logger('PRO')

def signal_handler(sig: int, _frame: types.FrameType | None):
    global stop_proof_expiry_thread
    global proof_expiry_thread_cv
    global proof_expiry_thread_mutex

    # Wake up the thread and set the flag to terminate it
    with proof_expiry_thread_mutex:
        stop_proof_expiry_thread = True
        proof_expiry_thread_cv.notify_all()

    # Unregister handler and resume the default handler by re-raising it
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
                    log.info('Daily pruning for {} completed on {}. Expired payments/revocations/users={}/{}/{}'.format(yesterday_str,
                                                                                                                     today_str,
                                                                                                                     expire_result.payments,
                                                                                                                     expire_result.revocations,
                                                                                                                     expire_result.users))
            else:
                log.error(f'Daily pruning for {yesterday_str} failed due to an unknown DB error')

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

    # NOTE: Get arguments from environment
    db_path:             str            = os.getenv('SESH_PRO_BACKEND_DB_PATH',                      './backend.db')
    db_path_is_uri:      bool           = base.os_get_boolean_env('SESH_PRO_BACKEND_DB_PATH_IS_URI',      False)
    print_tables:        bool           = base.os_get_boolean_env('SESH_PRO_BACKEND_PRINT_TABLES',        False)
    dev_backend:         bool           = base.os_get_boolean_env('SESH_PRO_BACKEND_DEV',                 False)
    with_platform_apple: bool           = base.os_get_boolean_env('SESH_PRO_BACKEND_WITH_PLATFORM_APPLE', False)

    # TODO: Move into base or move all the other environment variables into env
    env.SESH_PRO_BACKEND_UNSAFE_LOGGING = base.os_get_boolean_env('SESH_PRO_BACKEND_UNSAFE_LOGGING', False)

    # NOTE: Ensure the path is setup for writing the database
    try:
        pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.error(f'Failed to create directory for {db_path}: {e}')
        os._exit(1)

    # NOTE: A developer backend generates a deterministic key for testing purposes
    backend_key: nacl.signing.SigningKey | None = None
    if dev_backend:
        base.DEV_BACKEND_MODE          = True
        DEV_BACKEND_DETERMINISTIC_SKEY = bytes([0xCD] * 32)
        backend_key                    = nacl.signing.SigningKey(DEV_BACKEND_DETERMINISTIC_SKEY)

    # NOTE: Open the DB (create tables if necessary)
    err = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path=str(db_path), uri=db_path_is_uri, err=err, backend_key=backend_key)
    if len(err.msg_list) > 0:
        log.error(f"{err.msg_list}")
        os._exit(1)

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
        os._exit(1)

    if dev_backend:
        log.info("######################################")
        log.info("###                                ###")
        log.info("###        Dev Mode Enabled        ###")
        log.info("###                                ###")
        log.info("######################################")

    log.info(f'Session Pro Backend\n{info_string}')

    if env.SESH_PRO_BACKEND_UNSAFE_LOGGING or with_platform_apple:
        log.info(f'  Features:')
        if env.SESH_PRO_BACKEND_UNSAFE_LOGGING:
            log.info(f'    Unsafe logging enabled (this must NOT be used in production)')
        if with_platform_apple:
            log.info(f'    Platform: Apple iOS App Store notification handling is enabled')

    if dev_backend:
        log.info("######################################")
        log.info("###                                ###")
        log.info("###        Dev Mode Enabled        ###")
        log.info("###                                ###")
        log.info("######################################")

    # Handle printing of the DB to standard out if requested
    if print_tables:
        base.print_db_to_stdout(db.sql_conn)
        os._exit(1)

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
    try:
        import uwsgi  # pyright: ignore[reportMissingModuleSource, reportUnusedImport]
    except ImportError:
        # NOTE: For Flask handlers
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
    thread = threading.Thread(target=backend_proof_expiry_thread_entry_point, args=(db_path,))
    thread.start()

    # The flask runner/UWSGI takes over from here and runs the application for
    # us across multiple processes if necessary. We'll close our db connection
    # here. Each request we receive will open their own connection the DB.
    db.sql_conn.close()

    result: flask.Flask = server.init(testing_mode=False,
                                      db_path=db.path,
                                      db_path_is_uri=db_path_is_uri,
                                      server_x25519_skey=db.runtime.backend_key.to_curve25519_private_key())

    # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled
    if with_platform_apple:
        base.WITH_PLATFORM_APPLE  = True
        core: platform_apple.Core = platform_apple.init()
        platform_apple.equip_flask_routes(core, result)
    return result

# Flask entry point
stop_proof_expiry_thread  = False
proof_expiry_thread_mutex = threading.Lock()
proof_expiry_thread_cv    = threading.Condition(proof_expiry_thread_mutex)
flask_app: flask.Flask    = entry_point()
