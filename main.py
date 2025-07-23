'''
Main entrypoint for the codebase and application.
'''

import pathlib
import argparse
import os

import base
import backend

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    _ = parser.add_argument('--db-path',      type=pathlib.Path,   default='backend.db', help='Path to the DB to use to store backend data.')
    _ = parser.add_argument('--print-tables', action='store_true', help='Dump the DB to standard out as ascii tables')
    args = parser.parse_args()

    try:
        args.db_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Failed to create data directory at {args.data_dir}: {e}')
        os._exit(1)

    err                             = base.ErrorSink
    db_setup: backend.SetupDBResult = backend.setup_db(path=str(args.db_path), uri=False, err=err)
    if not db_setup.success:
        print(f"{err}")
        os._exit(1)
    assert db_setup.sql_conn is not None

    print(f'Session Pro Backend\n{backend.db_info_string(db_setup)}')
    if args.print_tables:
        base.print_db_to_stdout(db_setup.sql_conn)
        os._exit(1)
