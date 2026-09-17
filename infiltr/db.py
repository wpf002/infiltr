"""Database engine + session management.

Defaults to a local SQLite file; set ``DATABASE_URL`` to point at Postgres in prod
(e.g. postgresql+psycopg://user:pass@host/infiltr).
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

DEFAULT_URL = f"sqlite:///{os.path.join(os.getcwd(), 'infiltr.db')}"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_URL)
IS_SQLITE = DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    _kwargs = {"connect_args": {"check_same_thread": False}}
else:
    # server-class pool for Postgres/multi-tenant: recycle stale conns, pre-ping,
    # bounded pool so many workers/replicas don't exhaust the DB.
    _kwargs = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.environ.get("INFILTR_DB_POOL_RECYCLE", "1800")),
        "pool_size": int(os.environ.get("INFILTR_DB_POOL_SIZE", "10")),
        "max_overflow": int(os.environ.get("INFILTR_DB_MAX_OVERFLOW", "20")),
    }

engine = create_engine(DATABASE_URL, echo=False, future=True, **_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        # WAL + a long busy timeout so concurrent writers wait instead of erroring
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=15000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


_init_lock = threading.Lock()
_initialized = False


def init_db(force: bool = False) -> None:
    """Create all tables once per process (guarded so concurrent calls don't race)."""
    global _initialized
    if _initialized and not force:
        return
    with _init_lock:
        if _initialized and not force:
            return
        from .models import Base  # local import to avoid cycles
        Base.metadata.create_all(engine)
        _initialized = True


@contextmanager
def session_scope() -> Session:
    """Transactional session context."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
