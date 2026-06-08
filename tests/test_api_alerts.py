import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.dependencies import get_db_session
from app.db.session import Base
from app.main import app
from app.models.alert import SecurityAlert
from app.repositories.alert_repository import AlertRepository


def build_alert(
    alert_id: str = "alert-test",
    event_id: str | None = None,
    risk_score: int = 95,
    risk_level: str = "critical",
) -> SecurityAlert:
    """
    Build a deterministic alert for API tests.

    Parameters:
     alert_id - alert identifier used by the sample alert
     event_id - event identifier used by the sample alert
     risk_score - risk score assigned to the sample alert
     risk_level - risk level assigned to the sample alert

    Returns:
     Security alert ready to persist in a test database

    Raises:
     None
    """

    return SecurityAlert(
        alert_id=alert_id,
        event_id=event_id or f"event-{alert_id}",
        attack_type="SQL Injection",
        risk_score=risk_score,
        risk_level=risk_level,
        source_ip="45.67.89.10",
        target="/login",
        confidence=0.9,
        evidence=["demo evidence"],
        recommendations=["demo recommendation"],
        report_markdown="## demo",
        status="needs_review",
        automation_decision="human_review_required",
        triage_reason="critical asset requires review",
        requires_human_review=True,
    )


def test_recent_alerts_api_returns_persisted_alerts(tmp_path: Path) -> None:
    """
    Verify recent alerts API returns database-backed alert responses.

    Parameters:
     tmp_path - pytest fixture used to create an isolated SQLite database

    Returns:
     None

    Raises:
     None
    """

    engine = create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as session:
        AlertRepository(session).save(build_alert())

    def override_db_session():
        """
        Provide a test database session for the alerts API.

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

    try:
        client = TestClient(app)
        response = client.get("/api/alerts/recent?count=1&status=needs_review")
    finally:
        app.dependency_overrides.clear()


    assert response.status_code == 200
    data = response.json()
    assert data[0]["attack_type"] == "SQL Injection"
    assert data[0]["risk_level"] == "critical"
    assert data[0]["status"] == "needs_review"
    assert data[0]["requires_human_review"] is True


def test_recent_alerts_api_filters_by_risk_level(tmp_path: Path) -> None:
    """
    Verify recent alerts API can filter persisted alerts by risk level.

    Parameters:
     tmp_path - pytest fixture used to create an isolated SQLite database

    Returns:
     None

    Raises:
     None
    """

    engine = create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as session:
        repository = AlertRepository(session)
        repository.save(build_alert(alert_id="alert-critical"))
        repository.save(
            build_alert(
                alert_id="alert-low",
                risk_score=25,
                risk_level="low",
            )
        )

    def override_db_session():
        """
        Provide a test database session for the alerts API.

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

    try:
        client = TestClient(app)
        response = client.get("/api/alerts/recent?count=10&risk_level=critical")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert [alert["alert_id"] for alert in data] == ["alert-critical"]
    assert data[0]["risk_level"] == "critical"
