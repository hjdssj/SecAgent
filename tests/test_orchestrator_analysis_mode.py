import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.intel.schemas import ThreatIntelResult
from app.llm.schemas import LLMAttackClassificationResult
from app.memory.long_term_schemas import (
    LongTermMemoryRecord,
    LongTermMemorySearchResult,
    LongTermMemoryWriteResult,
)
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


class TrackingLLMReportEnhancer:
    """
    Track whether LLM report enhancement was executed during orchestrator tests.

    Parameters:
     used - whether the fake enhancer should mark LLM as used

    Returns:
     Test LLM report enhancer replacement

    Raises:
     None
    """

    def __init__(self, used: bool = False) -> None:
        """
        Initialize tracking state.

        Parameters:
         used - whether the fake enhancer should mark LLM as used

        Returns:
         None

        Raises:
         None
        """

        self.used = used
        self.called = False

    def enhance(self, alert: SecurityAlert) -> SecurityAlert:
        """
        Mark LLM enhancement as called and return deterministic metadata.

        Parameters:
         alert - security alert before LLM enhancement

        Returns:
         Alert with deterministic LLM metadata

        Raises:
         None
        """

        self.called = True

        if not self.used:
            return alert.model_copy(
                update={
                    "llm_used": False,
                    "llm_skipped_reason": "LLM_DISABLED",
                    "llm_model": "fake-model",
                    "llm_provider": "fake-provider",
                }
            )

        return alert.model_copy(
            update={
                "llm_used": True,
                "llm_summary": "fake analyst summary",
                "llm_model": "fake-model",
                "llm_provider": "fake-provider",
                "llm_latency_ms": 12.0,
                "llm_total_tokens": 42,
                "report_markdown": f"{alert.report_markdown or ''}\n\n## LLM 分析师报告\n\nfake report",
            }
        )


class TrackingLLMUnknownClassifier:
    """
    Track whether unknown attack classification was executed during orchestrator tests.

    Parameters:
     attack_type - optional attack type used to replace Unknown parsed events

    Returns:
     Test unknown classifier replacement

    Raises:
     None
    """

    def __init__(self, attack_type: str | None = None) -> None:
        """
        Initialize tracking state.

        Parameters:
         attack_type - optional attack type used to replace Unknown parsed events

        Returns:
         None

        Raises:
         None
        """

        self.attack_type = attack_type
        self.called = False

    def enhance(
        self,
        parsed: ParsedSecurityEvent,
    ) -> tuple[ParsedSecurityEvent, LLMAttackClassificationResult]:
        """
        Mark classifier usage and optionally replace Unknown attack type.

        Parameters:
         parsed - parsed security event before LLM fallback

        Returns:
         Possibly updated parsed event and deterministic classification result

        Raises:
         None
        """

        self.called = True

        if parsed.attack_type != "Unknown":
            return parsed, LLMAttackClassificationResult(skipped_reason="RULE_CLASSIFIED")

        if not self.attack_type:
            return parsed, LLMAttackClassificationResult(skipped_reason="LLM_DISABLED")

        updated = parsed.model_copy(
            update={
                "attack_type": self.attack_type,
                "attack_features": [*parsed.attack_features, "LLM Unknown Classification"],
                "evidence": [
                    *parsed.evidence,
                    f"LLM Unknown 补充识别：{self.attack_type}，置信度 0.91。",
                ],
                "confidence": 0.91,
            }
        )
        return updated, LLMAttackClassificationResult(
            used=True,
            attack_suspected=True,
            attack_type=self.attack_type,
            confidence=0.91,
        )


class FakeSessionMemoryStore:
    """
    Track saved analysis state without requiring Redis during tests.

    Parameters:
     None

    Returns:
     Fake session memory store

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize fake session storage.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.saved_state = None

    def save_state(self, state) -> bool:
        """
        Record the state and report a successful save.

        Parameters:
         state - analysis state generated by the orchestrator

        Returns:
         True

        Raises:
         None
        """

        self.saved_state = state
        return True


class FakeLongTermMemoryStore:
    """
    Track long-term memory calls without requiring Milvus during tests.

    Parameters:
     None

    Returns:
     Fake long-term memory store

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize fake long-term memory state.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.called = False

    def save_analysis(self, alert: SecurityAlert, state) -> LongTermMemoryWriteResult:
        """
        Record the write attempt and skip deterministic storage.

        Parameters:
         alert - final security alert
         state - analysis state generated by the orchestrator

        Returns:
         Skipped long-term memory write result

        Raises:
         None
        """

        self.called = True
        return LongTermMemoryWriteResult(skipped_reason="TEST_DISABLED")

    def search_for_alert(self, alert: SecurityAlert, state, top_k: int = 3):
        """
        Return no similar memory during default orchestrator tests.

        Parameters:
         alert - final security alert
         state - analysis state generated by the orchestrator
         top_k - maximum result count

        Returns:
         Empty result list and deterministic skipped reason

        Raises:
         None
        """

        return [], "TEST_DISABLED"


class MatchingLongTermMemoryStore(FakeLongTermMemoryStore):
    """
    Return one deterministic similar memory during orchestrator tests.

    Parameters:
     None

    Returns:
     Fake long-term memory store with one search match

    Raises:
     None
    """

    def search_for_alert(self, alert: SecurityAlert, state, top_k: int = 3):
        """
        Return one deterministic similar long-term memory.

        Parameters:
         alert - final security alert
         state - analysis state generated by the orchestrator
         top_k - maximum result count

        Returns:
         One similar memory result and no skipped reason

        Raises:
         None
        """

        record = LongTermMemoryRecord(
            memory_id="memory-alert-history-001",
            alert_id="alert-history-001",
            session_id="session-history-001",
            source_ip="45.67.89.10",
            target="/login",
            attack_type=alert.attack_type,
            risk_level="high",
            business_owner="account-team",
            asset_criticality="high",
            status="resolved",
            automation_decision="human_review_required",
            summary="Historical SQL Injection against account login.",
            evidence_text="WAF rule 942100",
            recommendation_text="Confirmed parameterized query remediation.",
            analyst_note="Confirmed true positive and patched login query.",
            handled_by="alice",
            handled_at="2026-06-01T00:00:00+00:00",
            created_at="2026-06-01T00:00:00+00:00",
            enabled=True,
        )

        return [
            LongTermMemorySearchResult(
                record=record,
                score=0.93,
            )
        ], None


def build_orchestrator() -> tuple[
    SecurityAnalysisOrchestrator,
    TrackingRAGAgent,
    TrackingThreatIntelAgent,
    TrackingEventMemory,
    TrackingLLMReportEnhancer,
    TrackingLLMUnknownClassifier,
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
    llm = TrackingLLMReportEnhancer()
    unknown_classifier = TrackingLLMUnknownClassifier()
    session_memory = FakeSessionMemoryStore()
    orchestrator.rag_agent = rag
    orchestrator.threat_intel_agent = intel
    orchestrator.event_memory = memory
    orchestrator.llm_report_enhancer = llm
    orchestrator.llm_unknown_classifier = unknown_classifier
    orchestrator.session_memory = session_memory
    orchestrator.long_term_memory = FakeLongTermMemoryStore()
    return orchestrator, rag, intel, memory, llm, unknown_classifier


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

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
    event = SecurityEvent(source_ip="127.0.0.1", path="/", url="/")

    alert = orchestrator.analyze(event)

    assert alert.analysis_mode == "fast"
    assert alert.analysis_metadata is not None
    assert alert.analysis_metadata.enabled_modules == ["ContextRAG", "AutoTriage"]
    assert alert.analysis_metadata.skipped_modules == [
        "RAG",
        "ThreatIntel",
        "Memory",
        "LLMUnknownClassifier:LLM_DISABLED",
        "LLMReport:LLM_DISABLED",
        "LongTermMemorySearch:FAST_MODE",
    ]
    assert alert.score_breakdown is not None
    assert not rag.called
    assert not intel.lookup_called
    assert not memory.summary_called
    assert memory.record_called
    assert llm.called
    assert unknown_classifier.called
    assert alert.llm_used is False
    assert alert.session_id is not None
    assert orchestrator.session_memory.saved_state is not None
    assert orchestrator.session_memory.saved_state.session_id == alert.session_id
    assert any(
        step.name == "long_term_memory"
        for step in orchestrator.session_memory.saved_state.workflow_steps
    )


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

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
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
    assert alert.analysis_metadata.skipped_modules == [
        "ThreatIntel",
        "LLMReport:LLM_DISABLED",
        "LongTermMemorySearch:TEST_DISABLED",
    ]
    assert rag.called
    assert memory.summary_called
    assert memory.enrich_called
    assert not intel.lookup_called
    assert alert.score_breakdown is not None
    assert any(item.source == "rag" for item in alert.score_breakdown.items)
    assert any(item.source == "memory" for item in alert.score_breakdown.items)
    assert llm.called
    assert unknown_classifier.called


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

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
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
    assert alert.analysis_metadata.skipped_modules == [
        "LLMReport:LLM_DISABLED",
        "LongTermMemorySearch:TEST_DISABLED",
    ]
    assert rag.called
    assert memory.summary_called
    assert intel.lookup_called
    assert intel.enrich_called
    assert alert.score_breakdown is not None
    assert any(item.source == "intel" for item in alert.score_breakdown.items)
    assert "分析模式与评分解释" in (alert.report_markdown or "")
    assert llm.called
    assert unknown_classifier.called


def test_orchestrator_records_llm_report_when_enhancer_uses_model() -> None:
    """
    Verify orchestrator records LLM report usage without changing deterministic judgment.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
    llm.used = True
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

    assert alert.attack_type == "SQL Injection"
    assert alert.llm_used is True
    assert alert.llm_summary == "fake analyst summary"
    assert alert.analysis_metadata is not None
    assert "LLMReport" in alert.analysis_metadata.enabled_modules
    assert "LLM 分析师报告" in (alert.report_markdown or "")
    assert unknown_classifier.called


def test_orchestrator_adds_similar_long_term_memory_matches() -> None:
    """
    Verify similar long-term memories are appended to evidence and report.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
    orchestrator.long_term_memory = MatchingLongTermMemoryStore()
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
    report = alert.report_markdown or ""

    assert alert.analysis_metadata is not None
    assert "LongTermMemorySearch" in alert.analysis_metadata.enabled_modules
    assert "LongTermMemorySearch" not in "\n".join(alert.analysis_metadata.skipped_modules)
    assert any("长期记忆相似事件" in item for item in alert.evidence)
    assert "## 长期记忆相似事件" in report
    assert "alert-history-001" in report
    assert "Confirmed true positive and patched login query." in report
    assert "Confirmed parameterized query remediation." in report
    assert llm.called
    assert unknown_classifier.called
    assert rag.called
    assert memory.summary_called
    assert intel.lookup_called


def test_orchestrator_uses_llm_unknown_classifier_before_decision() -> None:
    """
    Verify Unknown events can be classified by LLM fallback before scoring.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    orchestrator, rag, intel, memory, llm, unknown_classifier = build_orchestrator()
    unknown_classifier.attack_type = "SSRF"
    event = SecurityEvent(
        source_ip="6.6.6.6",
        path="/fetch",
        query="url=http://169.254.169.254/latest/meta-data/",
        url="/fetch?url=http://169.254.169.254/latest/meta-data/",
        status=403,
    )

    alert = orchestrator.analyze(event)

    assert unknown_classifier.called
    assert alert.attack_type == "SSRF"
    assert alert.risk_score >= 70
    assert alert.risk_level in {"high", "critical"}
    assert alert.analysis_metadata is not None
    assert "LLMUnknownClassifier" in alert.analysis_metadata.enabled_modules
    assert any("LLM Unknown 补充识别" in item for item in alert.evidence)
    assert rag.called
