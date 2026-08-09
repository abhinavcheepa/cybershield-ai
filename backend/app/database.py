from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}

#: Endpoints are sync `def`, so FastAPI runs them in its threadpool (40 threads)
#: — that is the real ceiling on concurrent sessions per worker. 5 + 10 keeps a
#: four-worker deployment under 60 connections, which fits every managed
#: Postgres free tier. Recycling matters because cloud providers silently drop
#: connections that idle for a few minutes.
_pool_args = {} if _is_sqlite else {"pool_size": 5, "max_overflow": 10, "pool_recycle": 1800}

engine = create_engine(
    settings.database_url, connect_args=_connect_args, pool_pre_ping=True, **_pool_args
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

#: Arbitrary but fixed: every worker asks for the same Postgres advisory lock,
#: so exactly one of them creates the schema and seeds while the rest wait.
_STARTUP_LOCK_ID = 8_675_309


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def startup_lock() -> Iterator[None]:
    """Serialise schema creation and seeding across uvicorn workers.

    Four workers booting at once would otherwise run `CREATE TABLE` and the
    idempotent-but-racy seed inserts concurrently. On SQLite there is only ever
    one worker, so this is a no-op.
    """
    if _is_sqlite:
        yield
        return

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _STARTUP_LOCK_ID})
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _STARTUP_LOCK_ID})


def init_db() -> None:
    from . import models  # noqa: F401  - registers mappers before create_all
    from .target import models as target_models  # noqa: F401  - vulnerable-site tables

    Base.metadata.create_all(bind=engine)
