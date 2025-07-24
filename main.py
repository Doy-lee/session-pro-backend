'''
Main entry point for the Session Pro Backend.

This application has command line options that must be specified as environment
variables because this application runs directly as a flask app (in a dev
environment) and it also can be served over WSGI for a production usecase.

We've designed the backend primarily for UWSGI which mounts the flask app with
no possibility to forward command line arguments to the underlying application.
Thus we cannot use argparse or flask's @click.options as there's no way to
specify them in the uWSGI manifest.
'''

import pathlib
import os
import flask

import base
import backend

def os_get_boolean_env(var_name: str, default: bool = False):
    value = os.getenv(var_name, str(int(default)))  # Default to 0 or 1
    if value == '1':
        return True
    elif value == '0':
        return False
    else:
        raise ValueError(f"Invalid value for environment variable '{var_name}': {value}. Allowed values are 0 or 1.")

def entry_point():
    # Get arguments from environment
    db_path:      str  = os.getenv('SESH_PRO_BACKEND_DB_PATH',               './backend.db')
    print_tables: bool = os_get_boolean_env('SESH_PRO_BACKEND_PRINT_TABLES', False)

    # Ensure the path is setup for writing the database
    try:
        pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Failed to create directory for {db_path}: {e}')
        os._exit(1)

    # Open the DB (create tables if necessary)
    err = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path=str(db_path), uri=False, err=err)
    if len(err.msg_list) > 0:
        print(f"{err.msg_list}")
        os._exit(1)

    # Dump some startup diagnostics
    assert db.sql_conn is not None
    info_string: str = backend.db_info_string(sql_conn=db.sql_conn, db_path=db.path, err=err)
    if len(err.msg_list) > 0:
        print(f"{err.msg_list}")
        os._exit(1)
    print(f'Session Pro Backend\n{info_string}')

    # Handle printing of the DB to standard out if requested
    if print_tables:
        base.print_db_to_stdout(db.sql_conn)
        os._exit(1)

    # The flask runner/uWSGI takes over from here and runs the application for
    # us across multiple processes if necessary. We'll close our db connection
    # here. Each request we receive will open their own connection the DB.
    db.sql_conn.close()

# Flask entry point
flask_app: flask.Flask = flask.Flask(__name__)
entry_point()
