import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.log_parser_agent import LogParserAgent
from app.models.event import SecurityEvent


def test_log_parser_detects_sqli_over_scanner_rule() -> None:
    """
    Verify SQL injection payload is not hidden by scanner evidence.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="45.67.89.10",
        url="/login?id=1' OR '1'='1",
        path="/login",
        query="id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="913100",
        waf_message="Found User-Agent associated with security scanner",
    )

    parsed = LogParserAgent().parse(event)

    assert parsed.attack_type == "SQL Injection"
    assert "Automated Scanner" in parsed.attack_features


def test_log_parser_does_not_match_command_injection_from_raw_audit_text() -> None:
    """
    Verify ModSecurity raw log operator backticks do not cause command injection false positives.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="127.0.0.1",
        url="/",
        path="/",
        raw_log="Matched \"Operator `Rx'\" against Host header",
        waf_rule_id="920350",
        waf_message="Host header is a numeric IP address",
    )

    parsed = LogParserAgent().parse(event)

    assert parsed.attack_type == "Unknown"
