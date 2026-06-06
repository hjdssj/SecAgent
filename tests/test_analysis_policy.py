import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.analysis.policy import AnalysisPolicy
from app.models.alert import SecurityAlert


def make_alert(score: int, level: str) -> SecurityAlert:
    """
    Build a minimal alert for analysis policy tests.

    Parameters:
     score - risk score assigned to the alert
     level - risk level assigned to the alert

    Returns:
     Minimal security alert

    Raises:
     None
    """

    return SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type="Unknown",
        risk_score=score,
        risk_level=level,
        source_ip="127.0.0.1",
        target="/",
        confidence=0.1,
    )


def test_analysis_policy_selects_fast_enriched_and_deep() -> None:
    """
    Verify analysis policy selects cost-control modes by risk.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    policy = AnalysisPolicy()

    assert policy.select_mode(make_alert(25, "low")) == "fast"
    assert policy.select_mode(make_alert(55, "medium")) == "enriched"
    assert policy.select_mode(make_alert(85, "high")) == "deep"
    assert policy.select_mode(make_alert(72, "critical")) == "deep"


def test_analysis_policy_returns_enabled_and_skipped_modules() -> None:
    """
    Verify analysis policy exposes enabled and skipped modules for each mode.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    policy = AnalysisPolicy()

    assert policy.modules_for_mode("fast") == ([], ["RAG", "ThreatIntel", "Memory"])
    assert policy.modules_for_mode("enriched") == (["RAG", "Memory"], ["ThreatIntel"])
    assert policy.modules_for_mode("deep") == (["RAG", "ThreatIntel", "Memory"], [])
