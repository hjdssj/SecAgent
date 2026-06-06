import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.log_parser_agent import LogParserAgent
from app.context.context_agent import ContextAgent
from app.context.context_loader import ContextLoader
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent
from app.triage.auto_triage_policy import AutoTriagePolicy


def test_context_agent_extracts_login_asset_context() -> None:
    """
    Verify context agent extracts owner, asset name, criticality, and WAF action.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="45.67.89.10",
        path="/login",
        url="/login?id=1' OR '1'='1",
        query="id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="942100",
        waf_message="SQL Injection Attack Detected",
        status=403,
    )
    parsed = LogParserAgent().parse(event)
    alert = SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type=parsed.attack_type,
        risk_score=92,
        risk_level="critical",
        source_ip=event.source_ip,
        target=event.path,
        confidence=parsed.confidence,
    )

    context = ContextAgent().analyze(alert, parsed)

    assert context.asset_name == "Account Center Login"
    assert context.asset_criticality == "critical"
    assert context.business_owner == "account-team"
    assert context.waf_action == "block"
    assert not context.is_internal_scanner
    assert context.references


def test_context_agent_detects_internal_scanner() -> None:
    """
    Verify context agent detects whitelisted internal scanner source IP.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="10.10.3.8",
        path="/search",
        url="/search?q=test",
        user_agent="internal-vulnerability-scanner",
        waf_rule_id="941100",
        waf_message="XSS Attack Detected",
    )
    parsed = LogParserAgent().parse(event)
    alert = SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type=parsed.attack_type,
        risk_score=55,
        risk_level="medium",
        source_ip=event.source_ip,
        target=event.path,
        confidence=parsed.confidence,
    )

    context = ContextAgent().analyze(alert, parsed)

    assert context.is_internal_scanner
    assert any(reference.category == "scanner_whitelist" for reference in context.references)


def test_auto_triage_requires_review_for_critical_asset() -> None:
    """
    Verify auto triage requires human review for high-risk critical assets.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="45.67.89.10",
        path="/login",
        url="/login?id=1' OR '1'='1",
        query="id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="942100",
        waf_message="SQL Injection Attack Detected",
        status=403,
    )
    parsed = LogParserAgent().parse(event)
    alert = SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type=parsed.attack_type,
        risk_score=95,
        risk_level="critical",
        source_ip=event.source_ip,
        target=event.path,
        confidence=parsed.confidence,
    )
    context = ContextAgent().analyze(alert, parsed)

    triage = AutoTriagePolicy().decide(alert, context)

    assert triage.status == "needs_review"
    assert triage.automation_decision == "human_review_required"
    assert triage.requires_human_review


def test_auto_triage_auto_closes_low_risk_internal_scanner() -> None:
    """
    Verify auto triage can auto-close low-risk internal scanner alerts.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="10.10.3.8",
        path="/search",
        url="/search?q=test",
        user_agent="internal-vulnerability-scanner",
    )
    parsed = LogParserAgent().parse(event)
    alert = SecurityAlert(
        alert_id="alert-test",
        event_id="event-test",
        attack_type=parsed.attack_type,
        risk_score=35,
        risk_level="low",
        source_ip=event.source_ip,
        target=event.path,
        confidence=parsed.confidence,
    )
    context = ContextAgent().analyze(alert, parsed)

    triage = AutoTriagePolicy().decide(alert, context)

    assert triage.status == "auto_triaged"
    assert triage.automation_decision == "auto_close"
    assert not triage.requires_human_review
