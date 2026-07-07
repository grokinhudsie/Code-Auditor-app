import os
import time

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from shared.models import Base

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://vulnscanner:vulnscanner@localhost:5432/vulnscanner",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# create_all only creates missing TABLES; columns added to existing tables ship
# here as idempotent DDL so upgrades are automatic on boot (DEPLOY.md §7).
MIGRATIONS = [
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id VARCHAR(32) "
    "REFERENCES users(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_scans_user_created ON scans (user_id, created_at DESC)",
]

_MIGRATION_LOCK = 421_337  # arbitrary app-wide advisory lock id


def _run_migrations() -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.connect() as conn:
        # api and worker both call init_db on boot; serialize them
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _MIGRATION_LOCK})
        try:
            for stmt in MIGRATIONS:
                conn.execute(text(stmt))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _MIGRATION_LOCK})


def init_db(retries: int = 10, delay: float = 2.0) -> None:
    """Create tables and apply column migrations, retrying while postgres boots."""
    for attempt in range(retries):
        try:
            Base.metadata.create_all(engine)
            _run_migrations()
            return
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
