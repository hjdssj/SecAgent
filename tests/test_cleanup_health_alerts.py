import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import scripts.cleanup_health_alerts as cleanup
from app.db.models import AlertRecord
from app.db.session import Base


def build_record(alert_id: str, target: str) -> AlertRecord:
    """
    Build a persisted alert record for cleanup tests.

    Parameters:
     alert_id - alert identifier
     target - alert target path

    Returns:
     Alert record ready to persist

    Raises:
     None
    """

    return AlertRecord(
        alert_id=alert_id,
        event_id=f"event-{alert_id}",
        attack_type="Unknown",
        risk_score=25,
        risk_level="low",
        source_ip="127.0.0.1",
        target=target,
        confidence=0.5,
        evidence_json="[]",
        mitre_attack_json="[]",
        recommendations_json="[]",
        context_references_json="[]",
    )


def install_test_session(tmp_path: Path) -> None:
    """
    Install an isolated database session factory into cleanup module.

    Parameters:
     tmp_path - pytest temporary directory used to store the test database

    Returns:
     None

    Raises:
     None
    """

    engine = create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    cleanup.SessionLocal = TestingSessionLocal
    cleanup.init_db = lambda: None

    with TestingSessionLocal() as session:
        session.add(build_record("health-alert", "/__waf_health"))
        session.add(build_record("login-alert", "/login"))
        session.commit()


def test_cleanup_health_alerts_counts_and_deletes_only_target(tmp_path: Path) -> None:
    """
    Verify cleanup deletes only configured health check target alerts.

    Parameters:
     tmp_path - pytest temporary directory used to store the test database

    Returns:
     None

    Raises:
     None
    """

    install_test_session(tmp_path)

    count_before = cleanup.count_matching_alerts(["/__waf_health"])
    deleted = cleanup.delete_matching_alerts(["/__waf_health"])
    count_after = cleanup.count_matching_alerts(["/__waf_health"])
    remaining_login = cleanup.count_matching_alerts(["/login"])

    assert count_before == 1
    assert deleted == 1
    assert count_after == 0
    assert remaining_login == 1


def test_parse_targets_uses_cli_values() -> None:
    """
    Verify explicit target paths override environment defaults.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    assert cleanup.parse_targets("/__waf_health,/healthz") == [
        "/__waf_health",
        "/healthz",
    ]
