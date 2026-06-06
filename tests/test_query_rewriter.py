import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.log_parser_agent import LogParserAgent
from app.models.event import SecurityEvent
from app.rag.query_rewriter import SecurityQueryRewriter


def test_query_rewriter_expands_attack_and_waf_context() -> None:
    """
    Verify query rewrite expands parsed event fields into security retrieval terms.

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
        waf_rule_id="942100",
        waf_message="SQL Injection Attack Detected",
    )
    parsed = LogParserAgent().parse(event)

    query = SecurityQueryRewriter().rewrite(parsed)

    assert "SQL Injection" in query
    assert "942100" in query
    assert "OWASP CRS 942" in query
    assert "MITRE T1190" in query
    assert "sqlmap" in query
    assert "parameterized query" in query
