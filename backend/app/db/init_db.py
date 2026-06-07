from app.db.models import AlertRecord
from app.db.session import Base, engine, ensure_sqlite_parent_dir


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
