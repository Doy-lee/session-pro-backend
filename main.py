import pathlib
import argparse
import os

import base
import test
import backend

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    _ = parser.add_argument('--db-path',      type=pathlib.Path,   default='backend.db', help='Path to the DB to use to store backend data.')
    _ = parser.add_argument('--print-tables', action='store_true', help='Dump the DB to standard out as ascii tables')
    _ = parser.add_argument('--do-tests',     action='store_true', help='Execute the testing suite')
    args = parser.parse_args()

    if args.do_tests:
        test.do_test()
        os._exit(0)

    try:
        args.db_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Failed to create data directory at {args.data_dir}: {e}')
        os._exit(1)

    db_setup: backend.SetupDBResult = backend.setup_db(str(args.db_path))
    if not db_setup.success:
        os._exit(1)

    print(f'Session Pro Backend\n{backend.db_header_string(db_setup)}')
    if args.print_tables:
        base.print_db_to_stdout(db_setup.sql_conn)
        os._exit(1)

