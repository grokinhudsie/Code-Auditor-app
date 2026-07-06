import os
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.models import Base

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://vulnscanner:vulnscanner@localhost:5432/vulnscanner",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db(retries: int = 10, delay: float = 2.0) -> None:
    """Create tables, retrying while postgres finishes booting."""
    for attempt in range(retries):
        try:
            Base.metadata.create_all(engine)
            return
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
