import json
import sys
from datetime import UTC
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.collector.waf_log_collector import WafLogCollector


def build_audit_entry(
    uri: str,
    unique_id: str,
    status: int = 200,
    rule_id: str | None = "100001",
    user_agent: str = "pytest",
    method: str = "GET",
) -> dict:
    """
    Build a minimal ModSecurity audit entry for collector tests.

    Parameters:
     uri - request URI stored in the audit entry
     unique_id - transaction unique ID
     status - HTTP response status stored in the audit entry
     rule_id - optional ModSecurity rule ID stored in the audit entry
     user_agent - request User-Agent stored in the audit entry
     method - request method stored in the audit entry

    Returns:
     Minimal ModSecurity JSON audit entry

    Raises:
     None
    """

    return {
        "transaction": {
            "unique_id": unique_id,
            "client_ip": "127.0.0.1",
            "time_stamp": "Mon Jun  8 01:11:20 2026",
            "request": {
                "method": method,
                "uri": uri,
                "headers": {
                    "User-Agent": user_agent,
                },
            },
            "response": {
                "http_code": status,
            },
            "messages": (
                [
                    {
                        "message": "test message",
                        "details": {
                            "ruleId": rule_id,
                        },
                    }
                ]
                if rule_id
                else []
            ),
        }
    }


def test_waf_collector_ignores_health_check_path() -> None:
    """
    Verify collector skips configured health check paths before publishing events.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    collector = WafLogCollector()
    health_event = collector._entry_to_event(build_audit_entry("/__waf_health", "health"))
    login_event = collector._entry_to_event(build_audit_entry("/login", "login"))

    assert health_event is not None
    assert login_event is not None
    assert collector._should_ignore_event(health_event) is True
    assert collector._should_ignore_event(login_event) is False


def test_waf_collector_extracts_json_entries() -> None:
    """
    Verify collector can extract multiple JSON audit entries from raw content.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    collector = WafLogCollector()
    content = "\n".join(
        [
            json.dumps(build_audit_entry("/__waf_health", "health")),
            json.dumps(build_audit_entry("/login", "login")),
        ]
    )

    entries = collector._extract_entries(content)
    events = [
        event
        for entry in entries
        if (event := collector._entry_to_event(entry)) is not None
    ]
    publishable = [
        event
        for event in events
        if not collector._should_ignore_event(event)
    ]

    assert [event.path for event in events] == ["/__waf_health", "/login"]
    assert [event.path for event in publishable] == ["/login"]


def test_waf_collector_parses_modsecurity_timestamp_as_utc() -> None:
    """
    Verify ModSecurity timestamps without timezone are treated as UTC.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    collector = WafLogCollector()
    parsed = collector._parse_timestamp("Mon Jun  8 01:11:20 2026")

    assert parsed is not None
    assert parsed.tzinfo == UTC
    assert parsed.isoformat() == "2026-06-08T01:11:20+00:00"


def test_waf_collector_drops_benign_static_asset() -> None:
    """
    Verify collector drops obvious benign static asset traffic.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    collector = WafLogCollector()
    event = collector._entry_to_event(
        build_audit_entry("/assets/app.js", "static", rule_id=None)
    )

    assert event is not None
    assert collector._should_ignore_event(event) is True


def test_waf_collector_keeps_suspicious_user_agent_without_rule() -> None:
    """
    Verify collector keeps scanner-looking traffic even without a WAF rule ID.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    collector = WafLogCollector()
    event = collector._entry_to_event(
        build_audit_entry(
            "/index",
            "scanner",
            rule_id=None,
            user_agent="sqlmap/1.7",
        )
    )

    assert event is not None
    assert collector._should_ignore_event(event) is False
