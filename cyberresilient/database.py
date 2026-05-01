"""
cyberresilient/database.py

Database engine and session factory.
Uses SQLite by default for local development.
Set DATABASE_URL env var for PostgreSQL in production.
"""

from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///cyberresilient.db",
)


@lru_cache(maxsize=1)
def get_engine():
    connect_args = {}
    if _DATABASE_URL.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(_DATABASE_URL, connect_args=connect_args)


def get_session() -> Session:
    engine = get_engine()
    factory = sessionmaker(bind=engine)
    return factory()


def init_db() -> None:
    """Create all tables and migrate missing columns."""
    from cyberresilient.models.db_models import Base
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _migrate_missing_columns(engine, Base)


def _migrate_missing_columns(engine, Base) -> None:
    """Add any columns defined in models but missing from existing tables (SQLite ALTER TABLE)."""
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    for table_name, table in Base.metadata.tables.items():
        if not insp.has_table(table_name):
            continue
        existing = {c["name"] for c in insp.get_columns(table_name)}
        for col in table.columns:
            if col.name not in existing:
                col_type = col.type.compile(engine.dialect)
                default = "''"
                if hasattr(col.default, 'arg') and col.default is not None:
                    default = repr(col.default.arg)
                elif str(col_type).startswith(('INTEGER', 'FLOAT')):
                    default = '0'
                elif str(col_type).startswith('BOOLEAN'):
                    default = '0'
                stmt = f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {col_type} DEFAULT {default}'
                with engine.begin() as conn:
                    conn.execute(text(stmt))
