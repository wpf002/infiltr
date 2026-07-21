"""Database engine + session management.

Defaults to a local SQLite file; set ``DATABASE_URL`` to point at Postgres in prod
(e.g. postgresql+psycopg://user:pass@host/infiltr).
"""
from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

DEFAULT_URL = f"sqlite:///{os.path.join(os.getcwd(), 'infiltr.db')}"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_URL)

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, future=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db() -> None:
    """Create all tables. Safe to call repeatedly."""
    from .models import Base  # local import to avoid cycles
    Base.metadata.create_all(engine)


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
