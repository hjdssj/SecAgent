import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.memory.schemas import IpMemorySummary
from app.models.event import SecurityEvent


class InMemoryEventMemory:
    """
    Provide deterministic event memory for orchestrator tests.

    Parameters:
     None

    Returns:
     In-memory replacement for EventMemory

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize the in-memory alert counter.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.count = 0
        self.attack_types: set[str] = set()
        self.targets: set[str] = set()

    def get_ip_summary(self, source_ip: str) -> IpMemorySummary:
        """
        Return current in-memory summary for a source IP.

        Parameters:
         source_ip - source IP address

        Returns:
         In-memory source IP summary

        Raises:
         None
        """

        return IpMemorySummary(
            source_ip=source_ip,
            alert_count=self.count,
            attack_types=sorted(self.attack_types),
            targets=sorted(self.targets),
            storage_available=True,
        )

    def record_alert(self, alert) -> None:
        """
        Record one alert in memory.

        Parameters:
         alert - generated security alert

        Returns:
         None

        Raises:
         None
        """

        self.count += 1
        self.attack_types.add(alert.attack_type)
        self.targets.add(alert.target)

    def enrich_alert(self, alert, summary: IpMemorySummary):
        """
        Delegate memory enrichment to the real EventMemory implementation.

        Parameters:
         alert - generated security alert
         summary - source IP summary

        Returns:
         Security alert enriched with memory context

        Raises:
         None
        """

        from app.memory.event_memory import EventMemory

        return EventMemory().enrich_alert(alert, summary)


def test_orchestrator_adds_rag_intel_memory_and_judgment() -> None:
    """
    Verify orchestrator enriches alerts with RAG, threat intelligence, memory, and judgment.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator = SecurityAnalysisOrchestrator()
    orchestrator.event_memory = InMemoryEventMemory()

    event = SecurityEvent(
        source_ip="45.67.89.10",
        url="/login?id=1' OR '1'='1",
        path="/login",
        query="id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="942100",
        waf_message="SQL Injection Attack Detected",
    )

    alert = orchestrator.analyze(event)
    text = "\n".join(alert.evidence) + "\n" + (alert.report_markdown or "")

    assert alert.attack_type == "SQL Injection"
    assert "attack_patterns.md" in text or "owasp_crs.md" in text
    assert "local_mock" in text
    assert "Memory" in text
    assert "45.67.89.10" in text
