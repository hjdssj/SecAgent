import sys
from collections.abc import Generator
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.dependencies import get_db_session
from app.db.session import Base
from app.main import app
from app.models.alert import SecurityAlert
from app.repositories.alert_repository import AlertRepository


def build_alert(alert_id: str = "alert-api-status") -> SecurityAlert:
    """
    Build a deterministic alert for status API tests.

    Parameters:
     alert_id - alert identifier used by the sample alert

    Returns:
     Security alert ready to persist in a test database

    Raises:
     None
    """

    return SecurityAlert(
        alert_id=alert_id,
        event_id="event-api-status",
        attack_type="XSS",
        risk_score=78,
        risk_level="high",
        source_ip="8.8.8.8",
        target="/search",
        confidence=0.82,
        evidence=["matched XSS pattern"],
        recommendations=["review output encoding"],
        status="needs_review",
        automation_decision="human_review_required",
        triage_reason="high risk event requires review",
        requires_human_review=True,
    )


def build_client(tmp_path: Path) -> TestClient:
    """
    Build a FastAPI test client backed by an isolated SQLite database.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     Test client with database dependency override installed

    Raises:
     None
    """

    engine = create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as session:
        AlertRepository(session).save(build_alert())

    def override_db_session() -> Generator[Session, None, None]:
        """
        Provide a test database session for FastAPI dependencies.

        Parameters:
         None

        Returns:
         Test database session generator

        Raises:
         None
        """

        session = TestingSessionLocal()

        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db_session] = override_db_session
    return TestClient(app)


def test_update_alert_status_api_updates_workflow_fields(tmp_path: Path) -> None:
    """
    Verify status API updates alert workflow fields.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    client = build_client(tmp_path)

    try:
        response = client.patch(
            "/api/alerts/alert-api-status/status",
            json={
                "status": "resolved",
                "analyst_note": "Confirmed blocked by WAF.",
                "handled_by": "analyst",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "resolved"
    assert data["requires_human_review"] is False
    assert data["analyst_note"] == "Confirmed blocked by WAF."
    assert data["handled_by"] == "analyst"
    assert data["handled_at"] is not None


def test_update_alert_status_api_returns_404_for_missing_alert(tmp_path: Path) -> None:
    """
    Verify status API returns 404 when the alert does not exist.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    client = build_client(tmp_path)

    try:
        response = client.patch(
            "/api/alerts/not-found/status",
            json={
                "status": "resolved",
                "analyst_note": "missing",
                "handled_by": "analyst",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
