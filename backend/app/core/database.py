"""
Database Engine, Session Management, Concurrency & Tenant Isolation for OpenRecon.
- PostgreSQL is the primary production database (with connection pooling).
- SQLite is supported exclusively for isolated development and automated testing,
  with WAL mode, busy_timeout, and foreign key enforcement enabled.
"""

from contextlib import contextmanager
from typing import Any, Generator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import settings

is_sqlite = settings.DATABASE_URL.startswith("sqlite")

engine_kwargs: dict[str, Any] = {
    "pool_pre_ping": True,
}

if is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
else:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    engine_kwargs["pool_recycle"] = 1800

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

if is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_transaction() -> Generator[Session, None, None]:
    """Explicit transactional scope with automatic commit/rollback."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def enforce_org_isolation(query, model, organization_id: Optional[int]):
    """
    Applies mandatory organization_id tenant filtering to SQLAlchemy queries.
    Raises ValueError if organization_id is missing or invalid.
    """
    if organization_id is None or organization_id <= 0:
        raise ValueError("Tenant isolation violation: a valid organization_id (> 0) is required.")
    return query.filter(model.organization_id == organization_id)
