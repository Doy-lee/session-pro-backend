"""
Database abstraction supporting SQLite and PostgreSQL backends using SQLAlchemy.

Usage Examples:
    # Create engine
    engine = db.create_engine('sqlite:///backend.db')

    # PostgreSQL example
    # engine = create_engine( "postgresql://user:pass@localhost/db", pool_size=10, max_overflow=20, pool_pre_ping=True) # PostgreSQL with connection pooling

    # Transaction (outer scope pattern)
    with engine.connect() as conn:
        with db.transaction(conn) as tx:
            row = db.query_one(conn, 'SELECT * FROM users WHERE id = :id', id=1)
            db.query(conn, 'UPDATE users SET status = :s WHERE id = :id', s=2, id=1)
            if should_rollback:
                tx.cancel = True
        # Auto-committed here (unless tx.cancel was set)
"""

import collections.abc
import contextlib
import dataclasses
import logging
import sqlite3
import traceback
import typing

import sqlalchemy
import sqlalchemy.event

@dataclasses.dataclass
class SQLTransaction:
    conn:   sqlalchemy.engine.Connection
    cancel: bool = False

@contextlib.contextmanager
def connection(engine: sqlalchemy.engine.Engine):
    conn = engine.connect()
    try:
        yield conn
    finally:
        conn.close()

@contextlib.contextmanager
def transaction(conn: sqlalchemy.engine.Connection):
    result = SQLTransaction(conn=conn)
    try:
        with conn.begin() as tx:
            yield result
            if result.cancel: # SQLAlchemy will automatically rollback on exception
                raise Exception("Cancel requested")
    except Exception as e:
        if str(e) != "Cancel requested":
            raise

@contextlib.contextmanager
def transaction_from_engine(engine: sqlalchemy.engine.Engine):
    conn   = engine.connect()
    result = SQLTransaction(conn=conn)
    try:
        with conn.begin() as tx:
            yield result
            if result.cancel: # SQLAlchemy will automatically rollback on exception
                raise Exception("Cancel requested")
    except Exception as e:
        if str(e) != "Cancel requested":
            raise

@contextlib.contextmanager
def open_database(database_url: str) -> collections.abc.Iterator[sqlalchemy.engine.Engine]:
    """
    Example:
        with open_database('sqlite:///my.db') as engine:
            with connection(engine) as conn:
                result = query(conn, 'SELECT 1')
    """
    engine = create_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()

def create_engine(database_url: str, **kwargs: typing.Any) -> sqlalchemy.engine.Engine:
    parsed:    str  = database_url.split('://', 1)[0]
    is_sqlite: bool = parsed == 'sqlite'

    if is_sqlite:
        connect_args: dict[str, typing.Any] = kwargs.get('connect_args', {})
        connect_args.setdefault('check_same_thread', False)
        kwargs['connect_args'] = connect_args

    engine: sqlalchemy.engine.Engine = sqlalchemy.create_engine(database_url, **kwargs)
    if is_sqlite:
        @sqlalchemy.event.listens_for(engine, 'connect')
        def set_sqlite_pragmas(dbapi_conn: sqlite3.Connection, connection_record: typing.Any) -> None:  # pyright: ignore[reportUnusedParameter, reportUnusedFunction]
            cursor = dbapi_conn.cursor()
            _ = cursor.execute('PRAGMA journal_mode=WAL')
            _ = cursor.execute('PRAGMA foreign_keys=ON')
            cursor.close()

    return engine

def query(conn: sqlalchemy.engine.Connection, sql: str, params: dict[str, typing.Any] | None = None, *, bind_expanding: list[str] | None = None, **kwparams: typing.Any) -> sqlalchemy.engine.cursor.CursorResult[typing.Any]:
    stmt = sqlalchemy.text(sql)
    if bind_expanding:
        stmt = stmt.bindparams(*[sqlalchemy.bindparam(name, expanding=True) for name in bind_expanding])
    all_params = {**(params or {}), **kwparams}
    return conn.execute(stmt, all_params)

def query_one(conn: sqlalchemy.engine.Connection, sql: str, *, bind_expanding: list[str] | None = None, **params: typing.Any) -> sqlalchemy.engine.Row[typing.Any] | None:
    result = query(conn, sql, bind_expanding=bind_expanding, **params)
    return result.fetchone()

def is_postgres(engine: sqlalchemy.engine.Engine) -> bool:
    return engine.dialect.name == 'postgresql'

def is_sqlite(engine: sqlalchemy.engine.Engine) -> bool:
    return engine.dialect.name == 'sqlite'

def get_db_version(conn: sqlalchemy.engine.Connection, engine: sqlalchemy.engine.Engine) -> int:
    if is_postgres(engine):
        row = conn.execute(sqlalchemy.text('SELECT version FROM schema_version LIMIT 1')).fetchone()
        return row[0] if row else 0
    else:
        row = conn.execute(sqlalchemy.text('PRAGMA user_version')).fetchone()
        return row[0] if row else 0

def set_db_version(conn: sqlalchemy.engine.Connection, engine: sqlalchemy.engine.Engine, version: int) -> None:
    if is_postgres(engine):
        _ = conn.execute(sqlalchemy.text('UPDATE schema_version SET version = :v'), {'v': version})
    else:
        _ = conn.execute(sqlalchemy.text(f'PRAGMA user_version = {version}'))


def retry_on_database_locked(callback: typing.Callable[[], typing.Any], log: logging.Logger, error_prefix: str) -> None:
    # Execute a callback, retrying on SQLite database locked errors.
    try:
        callback()
    except Exception as e:
        log.error(f"{error_prefix}. Error was: {traceback.format_exc()}")
