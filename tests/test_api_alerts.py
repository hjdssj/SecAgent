import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from fastapi.testclient import TestClient

from app.main import app
from app.models.alert import SecurityAlert


def test_recent_alerts_api_returns_alerts(monkeypatch) -> None:
    """
    Verify recent alerts API returns structured alert responses.

    Parameters:
     monkeypatch - pytest fixture used to replace Redis-backed alert reader

    Returns:
     None

    Raises:
     None
    """

    alert = SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type="SQL Injection",
        risk_score=95,
        risk_level="critical",
        source_ip="45.67.89.10",
        target="/login",
        confidence=0.9,
        evidence=["demo evidence"],
        recommendations=["demo recommendation"],
        report_markdown="## demo",
    )

    monkeypatch.setattr("app.api.alerts.read_recent_alerts", lambda count=20: [alert])
    client = TestClient(app)

    response = client.get("/api/alerts/recent?count=1")

    assert response.status_code == 200
    data = response.json()
    assert data[0]["attack_type"] == "SQL Injection"
    assert data[0]["risk_level"] == "critical"
