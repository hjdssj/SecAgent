from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_env, get_path_env

DEFAULT_DB_PATH = get_path_env("SECAGENT_DB_PATH", get_path_env("DB_PATH", get_path_env("DATABASE_PATH", Path(__file__).resolve().parents[3] / "data" / "secagent.db")))
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
DATABASE_URL = get_env("DATABASE_URL", DEFAULT_DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """
    Provide the declarative base class for database ORM models.

    Parameters:
     None

    Returns:
     SQLAlchemy declarative base class

    Raises:
     None
    """


def ensure_sqlite_parent_dir() -> None:
    """
    Ensure the default SQLite database parent directory exists.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    if DATABASE_URL == DEFAULT_DATABASE_URL:
        DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
