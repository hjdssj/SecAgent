import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.log_parser_agent import LogParserAgent
from app.models.event import SecurityEvent
from app.rag.rag_agent import RAGAgent


def test_rag_agent_retrieves_sqli_knowledge() -> None:
    """
    Verify local RAG retrieval returns SQL injection knowledge references.

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

    result = RAGAgent().analyze(parsed)

    titles = {reference.title for reference in result.references}
    assert "SQL Injection" in titles or "OWASP CRS 942 SQL Injection" in titles
    assert result.recommended_actions
