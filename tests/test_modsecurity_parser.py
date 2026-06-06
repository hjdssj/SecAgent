import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.collector.modsecurity_parser import ModSecurityParser


def test_parse_sqli_log_line() -> None:
    """
    Verify simplified ModSecurity log parsing for SQL injection traffic.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    line = (
        "client_ip=45.67.89.10 method=GET "
        "url=\"/login?id=1' OR '1'='1\" status=403 "
        "user_agent=\"sqlmap/1.7\" rule_id=942100 "
        "message=\"SQL Injection Attack Detected\""
    )

    event = ModSecurityParser().parse_line(line)

    assert event.source_ip == "45.67.89.10"
    assert event.path == "/login"
    assert event.query == "id=1' OR '1'='1"
    assert event.waf_rule_id == "942100"


def test_parse_path_traversal_log_line() -> None:
    """
    Verify simplified ModSecurity log parsing for path traversal traffic.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    line = (
        "client_ip=9.9.9.9 method=GET "
        "url=\"/download?file=../../etc/passwd\" status=403 "
        "user_agent=\"Mozilla/5.0\" rule_id=930120 "
        "message=\"Path Traversal Attack Detected\""
    )

    event = ModSecurityParser().parse_line(line)

    assert event.source_ip == "9.9.9.9"
    assert event.path == "/download"
    assert event.query == "file=../../etc/passwd"
    assert event.waf_rule_id == "930120"
