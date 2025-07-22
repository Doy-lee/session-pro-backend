import pathlib
import argparse
import os

import base
import test
import backend

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some database options.')
    _ = parser.add_argument('--data-dir', type=pathlib.Path, default='data', help='Path to the directory to store backend data.')
    _ = parser.add_argument('--print-tables', action='store_true', help='Dump the DB to standard out as ascii tables')
    _ = parser.add_argument('--do-tests', action='store_true', help='Execute the testing suite')
    args = parser.parse_args()

    try:
        args.data_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Failed to create data directory at {args.data_dir}: {e}')
        os._exit(1)

    db_path:  pathlib.Path          = pathlib.Path(args.data_dir) / 'backend.db'
    db_setup: backend.SetupDBResult = backend.setup_db(str(db_path))
    if not db_setup.success:
        print(f'Failed to create DB for backend to {db_path}')
        os._exit(1)

    print('Session Pro Backend\n' +
          '  Data Directory:                   {}\n'.format(args.data_dir) +
          '  DB:                               {} ({})\n'.format(db_path, base.format_bytes(db_setup.db_size)) +
          '  Users/Revocs/Payments/Unredeemed: {}/{}/{}/{}\n'.format(db_setup.users, db_setup.revocations, db_setup.payments, db_setup.unredeemed_payments) +
          '  Gen Index:                        {}'.format(db_setup.gen_index));

    if args.print_tables:
        base.print_db_to_stdout(db_setup.sql_conn)
        os._exit(1)

    if args.do_tests:
        test.do_test()
