from sqlalchemy import inspect, text

from app.db.models import AlertRecord  # noqa: F401
from app.db.session import Base, engine, ensure_sqlite_parent_dir

SQLITE_ALERT_COLUMN_UPGRADES = {
    "session_id": "VARCHAR(64)",
    "event_timestamp": "DATETIME",
    "llm_used": "BOOLEAN NOT NULL DEFAULT 0",
    "llm_skipped_reason": "VARCHAR(128)",
    "llm_summary": "TEXT",
    "llm_model": "VARCHAR(128)",
    "llm_provider": "VARCHAR(128)",
    "llm_latency_ms": "FLOAT NOT NULL DEFAULT 0.0",
    "llm_prompt_tokens": "INTEGER",
    "llm_completion_tokens": "INTEGER",
    "llm_total_tokens": "INTEGER",
    "llm_error": "TEXT",
}


def init_db() -> None:
    """
    Initialize database tables used by the backend.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    ensure_sqlite_parent_dir()
    Base.metadata.create_all(bind=engine)
    upgrade_sqlite_alert_columns()


def upgrade_sqlite_alert_columns() -> None:
    """
    Add newly introduced alert columns to an existing SQLite database.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    if not engine.url.drivername.startswith("sqlite"):
        return

    inspector = inspect(engine)

    if "alerts" not in inspector.get_table_names():
        return

    existing_columns = {
        column["name"]
        for column in inspector.get_columns("alerts")
    }
    missing_columns = {
        name: definition
        for name, definition in SQLITE_ALERT_COLUMN_UPGRADES.items()
        if name not in existing_columns
    }

    if not missing_columns:
        return

    with engine.begin() as connection:
        for name, definition in missing_columns.items():
            connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {name} {definition}"))
