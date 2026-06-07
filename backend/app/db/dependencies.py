from collections.abc import Generator

from sqlalchemy.orm import Session

from app.db.session import SessionLocal


def get_db_session() -> Generator[Session, None, None]:
    """
    Provide a database session for FastAPI dependencies.

    Parameters:
     None

    Returns:
     Database session generator

    Raises:
     None
    """

    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()
