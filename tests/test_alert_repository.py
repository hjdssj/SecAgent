import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models import AlertRecord
from app.db.session import Base
from app.models.alert import MitreTechnique, SecurityAlert
from app.models.alert_update import AlertStatusUpdate
from app.repositories.alert_repository import AlertRepository


def build_alert(
    alert_id: str = "alert-repo-test",
    event_id: str | None = None,
    risk_score: int = 95,
    risk_level: str = "critical",
) -> SecurityAlert:
    """
    Build a deterministic alert for repository tests.

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
        event_timestamp="2026-06-08T12:34:56+00:00",
        attack_type="SQL Injection",
        risk_score=risk_score,
        risk_level=risk_level,
        source_ip="45.67.89.10",
        target="/login",
        confidence=0.9,
        evidence=["matched SQL injection pattern"],
        mitre_attack=[
            MitreTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
            )
        ],
        recommendations=["review parameterized query usage"],
        report_markdown="## demo report",
        status="needs_review",
        automation_decision="human_review_required",
        triage_reason="critical asset requires review",
        requires_human_review=True,
        business_owner="account-team",
        asset_name="Account Center Login",
        asset_criticality="critical",
        context_references=["asset_inventory.md: /login"],
    )


def build_repository(tmp_path: Path) -> tuple[AlertRepository, object]:
    """
    Build an alert repository backed by an isolated SQLite database.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     Repository and its active SQLAlchemy session

    Raises:
     None
    """

    engine = create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    return AlertRepository(session), session


def test_alert_repository_saves_and_reads_alert(tmp_path: Path) -> None:
    """
    Verify repository can persist and reconstruct a security alert.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        saved = repository.save(build_alert())
        alerts = repository.list_recent(count=10)
    finally:
        session.close()

    assert saved.alert_id == "alert-repo-test"
    assert alerts[0].attack_type == "SQL Injection"
    assert alerts[0].event_timestamp is not None
    assert alerts[0].event_timestamp.startswith("2026-06-08T12:34:56")
    assert alerts[0].mitre_attack[0].technique_id == "T1190"
    assert alerts[0].context_references == ["asset_inventory.md: /login"]


def test_alert_repository_updates_existing_alert(tmp_path: Path) -> None:
    """
    Verify saving the same alert ID updates one record instead of inserting duplicates.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        repository.save(build_alert(risk_score=90))
        repository.save(build_alert(risk_score=100))
        records = session.scalars(select(AlertRecord)).all()
        alerts = repository.list_recent(count=10)
    finally:
        session.close()

    assert len(records) == 1
    assert alerts[0].risk_score == 100


def test_alert_repository_deduplicates_by_event_id(tmp_path: Path) -> None:
    """
    Verify saving the same event ID updates one record even if alert ID changes.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        repository.save(
            build_alert(
                alert_id="alert-fast",
                event_id="event-duplicate",
                risk_score=82,
                risk_level="high",
            )
        )
        saved = repository.save(
            build_alert(
                alert_id="alert-llm",
                event_id="event-duplicate",
                risk_score=95,
                risk_level="critical",
            )
        )
        records = session.scalars(select(AlertRecord)).all()
    finally:
        session.close()

    assert len(records) == 1
    assert saved.event_id == "event-duplicate"
    assert saved.risk_score == 95
    assert records[0].risk_score == 95


def test_alert_repository_list_recent_deduplicates_historical_event_ids(tmp_path: Path) -> None:
    """
    Verify list views collapse historical duplicate records for the same event ID.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        first = AlertRecord(alert_id="alert-old", event_id="event-duplicate")
        second = AlertRecord(alert_id="alert-new", event_id="event-duplicate")
        repository._apply_alert(
            first,
            build_alert(
                alert_id="alert-old",
                event_id="event-duplicate",
                risk_score=82,
                risk_level="high",
            ),
        )
        repository._apply_alert(
            second,
            build_alert(
                alert_id="alert-new",
                event_id="event-duplicate",
                risk_score=95,
                risk_level="critical",
            ),
        )
        session.add_all([first, second])
        session.commit()
        alerts = repository.list_recent(count=10)
    finally:
        session.close()

    assert len(alerts) == 1
    assert alerts[0].alert_id == "alert-new"
    assert alerts[0].risk_score == 95


def test_alert_repository_filters_and_updates_status(tmp_path: Path) -> None:
    """
    Verify repository supports workflow filters and status updates.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        repository.save(build_alert(alert_id="alert-review"))
        repository.save(
            build_alert(alert_id="alert-auto").model_copy(
                update={
                    "status": "auto_triaged",
                    "requires_human_review": False,
                    "automation_decision": "observe_only",
                }
            )
        )
        review_alerts = repository.list_recent(
            count=10,
            status="needs_review",
            requires_human_review=True,
        )
        updated = repository.update_status(
            "alert-review",
            AlertStatusUpdate(
                status="resolved",
                analyst_note="WAF blocked the request and owner confirmed no impact.",
                handled_by="analyst",
            ),
        )
    finally:
        session.close()

    assert [alert.alert_id for alert in review_alerts] == ["alert-review"]
    assert updated is not None
    assert updated.status == "resolved"
    assert updated.requires_human_review is False
    assert updated.analyst_note == "WAF blocked the request and owner confirmed no impact."
    assert updated.handled_by == "analyst"
    assert updated.handled_at is not None


def test_alert_repository_filters_by_risk_level(tmp_path: Path) -> None:
    """
    Verify repository can filter recent alerts by risk level.

    Parameters:
     tmp_path - pytest temporary directory used to store the database

    Returns:
     None

    Raises:
     None
    """

    repository, session = build_repository(tmp_path)

    try:
        repository.save(build_alert(alert_id="alert-critical", risk_level="critical"))
        repository.save(
            build_alert(
                alert_id="alert-low",
                risk_score=25,
                risk_level="low",
            )
        )
        critical_alerts = repository.list_recent(count=10, risk_level="critical")
        low_alerts = repository.list_recent(count=10, risk_level="low")
    finally:
        session.close()

    assert [alert.alert_id for alert in critical_alerts] == ["alert-critical"]
    assert [alert.alert_id for alert in low_alerts] == ["alert-low"]
