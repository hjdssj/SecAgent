import json
import sys
from datetime import UTC
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.collector.waf_log_collector import WafLogCollector


def build_audit_entry(uri: str, unique_id: str) -> dict:
    """
    Build a minimal ModSecurity audit entry for collector tests.

    Parameters:
     uri - request URI stored in the audit entry
     unique_id - transaction unique ID

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
                "method": "GET",
                "uri": uri,
                "headers": {
                    "User-Agent": "pytest",
                },
            },
            "response": {
                "http_code": 200,
            },
            "messages": [
                {
                    "message": "test message",
                    "details": {
                        "ruleId": "100001",
                    },
                }
            ],
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
