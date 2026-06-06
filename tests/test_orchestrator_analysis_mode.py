import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.intel.schemas import ThreatIntelResult
from app.memory.schemas import IpMemorySummary
from app.models.alert import SecurityAlert
from app.models.event import ParsedSecurityEvent, SecurityEvent


class TrackingRAGAgent:
    """
    Track whether RAG enrichment was executed during orchestrator tests.

    Parameters:
     None

    Returns:
     Test RAG agent replacement

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize tracking state.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.called = False

    def enrich_alert(self, alert: SecurityAlert, parsed: ParsedSecurityEvent) -> SecurityAlert:
        """
        Mark RAG as called and append deterministic evidence.

        Parameters:
         alert - base security alert
         parsed - parsed security event

        Returns:
         Alert enriched with deterministic RAG evidence

        Raises:
         None
        """

        self.called = True
        return alert.model_copy(
            update={
                "evidence": [*alert.evidence, "RAG test reference"],
                "report_markdown": f"{alert.report_markdown or ''}\n\n## RAG test\n",
            }
        )


class TrackingThreatIntelAgent:
    """
    Track whether threat intelligence was executed during orchestrator tests.

    Parameters:
     risk_score - deterministic threat intelligence risk score

    Returns:
     Test threat intelligence agent replacement

    Raises:
     None
    """

    def __init__(self, risk_score: int = 0) -> None:
        """
        Initialize tracking state and deterministic risk score.

        Parameters:
         risk_score - deterministic threat intelligence risk score

        Returns:
         None

        Raises:
         None
        """

        self.risk_score = risk_score
        self.lookup_called = False
        self.enrich_called = False

    def lookup(self, source_ip: str) -> ThreatIntelResult:
        """
        Return deterministic threat intelligence and record lookup usage.

        Parameters:
         source_ip - source IP address

        Returns:
         Deterministic threat intelligence result

        Raises:
         None
        """

        self.lookup_called = True
        return ThreatIntelResult(
            source_ip=source_ip,
            reputation="malicious" if self.risk_score >= 80 else "unknown",
            risk_score=self.risk_score,
            tags=["test"],
        )

    def enrich_alert(self, alert: SecurityAlert, intel: ThreatIntelResult) -> SecurityAlert:
        """
        Mark threat intelligence as called and apply deterministic score delta.

        Parameters:
         alert - base security alert
         intel - deterministic threat intelligence result

        Returns:
         Alert enriched with deterministic score delta

        Raises:
         None
        """

        self.enrich_called = True
        next_score = min(alert.risk_score + 5, 100)
        return alert.model_copy(
            update={
                "risk_score": next_score,
                "risk_level": "critical" if next_score >= 90 else alert.risk_level,
                "evidence": [*alert.evidence, "Threat intel test evidence"],
            }
        )


class TrackingEventMemory:
    """
    Track whether event memory was executed during orchestrator tests.

    Parameters:
     alert_count - deterministic historical alert count

    Returns:
     Test event memory replacement

    Raises:
     None
    """

    def __init__(self, alert_count: int = 0) -> None:
        """
        Initialize tracking state and deterministic memory summary.

        Parameters:
         alert_count - deterministic historical alert count

        Returns:
         None

        Raises:
         None
        """

        self.alert_count = alert_count
        self.summary_called = False
        self.enrich_called = False
        self.record_called = False

    def get_ip_summary(self, source_ip: str) -> IpMemorySummary:
        """
        Return deterministic memory summary and record summary usage.

        Parameters:
         source_ip - source IP address

        Returns:
         Deterministic IP memory summary

        Raises:
         None
        """

        self.summary_called = True
        return IpMemorySummary(
            source_ip=source_ip,
            alert_count=self.alert_count,
            attack_types=["SQL Injection"] if self.alert_count else [],
            targets=["/login"] if self.alert_count else [],
            storage_available=True,
        )

    def enrich_alert(self, alert: SecurityAlert, summary: IpMemorySummary) -> SecurityAlert:
        """
        Mark memory as called and apply deterministic score delta.

        Parameters:
         alert - base security alert
         summary - deterministic memory summary

        Returns:
         Alert enriched with deterministic memory score

        Raises:
         None
        """

        self.enrich_called = True
        delta = 2 if summary.alert_count else 0
        return alert.model_copy(
            update={
                "risk_score": min(alert.risk_score + delta, 100),
                "evidence": [*alert.evidence, "Memory test evidence"],
            }
        )

    def record_alert(self, alert: SecurityAlert) -> None:
        """
        Record that the final alert would be stored.

        Parameters:
         alert - final security alert

        Returns:
         None

        Raises:
         None
        """

        self.record_called = True


def build_orchestrator() -> tuple[
    SecurityAnalysisOrchestrator,
    TrackingRAGAgent,
    TrackingThreatIntelAgent,
    TrackingEventMemory,
]:
    """
    Build an orchestrator with deterministic test doubles.

    Parameters:
     None

    Returns:
     Orchestrator and tracking test doubles

    Raises:
     None
    """

    orchestrator = SecurityAnalysisOrchestrator()
    rag = TrackingRAGAgent()
    intel = TrackingThreatIntelAgent(risk_score=90)
    memory = TrackingEventMemory(alert_count=1)
    orchestrator.rag_agent = rag
    orchestrator.threat_intel_agent = intel
    orchestrator.event_memory = memory
    return orchestrator, rag, intel, memory


def test_orchestrator_fast_mode_skips_costly_modules() -> None:
    """
    Verify low-risk events use fast mode and skip optional enrichment.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory = build_orchestrator()
    event = SecurityEvent(source_ip="127.0.0.1", path="/", url="/")

    alert = orchestrator.analyze(event)

    assert alert.analysis_mode == "fast"
    assert alert.analysis_metadata is not None
    assert alert.analysis_metadata.enabled_modules == ["ContextRAG", "AutoTriage"]
    assert alert.analysis_metadata.skipped_modules == ["RAG", "ThreatIntel", "Memory"]
    assert alert.score_breakdown is not None
    assert not rag.called
    assert not intel.lookup_called
    assert not memory.summary_called
    assert memory.record_called


def test_orchestrator_enriched_mode_uses_rag_and_memory_only() -> None:
    """
    Verify medium-risk events use RAG and memory while skipping threat intelligence.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory = build_orchestrator()
    event = SecurityEvent(
        source_ip="8.8.8.8",
        path="/search",
        query="q=<script>alert(1)</script>",
        url="/search?q=<script>alert(1)</script>",
        waf_rule_id="941100",
        waf_message="XSS Attack Detected",
    )

    alert = orchestrator.analyze(event)

    assert alert.analysis_mode == "enriched"
    assert alert.analysis_metadata is not None
    assert alert.analysis_metadata.enabled_modules == ["RAG", "Memory", "ContextRAG", "AutoTriage"]
    assert alert.analysis_metadata.skipped_modules == ["ThreatIntel"]
    assert rag.called
    assert memory.summary_called
    assert memory.enrich_called
    assert not intel.lookup_called
    assert alert.score_breakdown is not None
    assert any(item.source == "rag" for item in alert.score_breakdown.items)
    assert any(item.source == "memory" for item in alert.score_breakdown.items)


def test_orchestrator_deep_mode_uses_all_enrichment_modules() -> None:
    """
    Verify high-risk events use deep mode and execute all enrichment modules.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory = build_orchestrator()
    event = SecurityEvent(
        source_ip="45.67.89.10",
        path="/login",
        query="id=1' OR '1'='1",
        url="/login?id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="942100",
        waf_message="SQL Injection Attack Detected",
        status=403,
    )

    alert = orchestrator.analyze(event)

    assert alert.analysis_mode == "deep"
    assert alert.analysis_metadata is not None
    assert alert.analysis_metadata.enabled_modules == [
        "RAG",
        "ThreatIntel",
        "Memory",
        "ContextRAG",
        "AutoTriage",
    ]
    assert alert.analysis_metadata.skipped_modules == []
    assert rag.called
    assert memory.summary_called
    assert intel.lookup_called
    assert intel.enrich_called
    assert alert.score_breakdown is not None
    assert any(item.source == "intel" for item in alert.score_breakdown.items)
    assert "分析模式与评分解释" in (alert.report_markdown or "")
