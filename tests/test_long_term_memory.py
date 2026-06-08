import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.analysis.state import AnalysisState
from app.memory.long_term_builder import LongTermMemoryBuilder
from app.memory.long_term_policy import LongTermMemoryPolicy
from app.memory.long_term_schemas import LongTermMemorySearchResult
from app.memory.long_term_store import LongTermMemoryStore
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent


def build_alert(risk_level: str = "high", automation_decision: str = "observe_only") -> SecurityAlert:
    """
    Build a deterministic alert for long-term memory tests.

    Parameters:
     risk_level - alert risk level
     automation_decision - alert automation decision

    Returns:
     Security alert fixture

    Raises:
     None
    """

    return SecurityAlert(
        alert_id="alert-test-001",
        session_id="session-test-001",
        event_id="event-test-001",
        attack_type="SQL Injection",
        risk_score=88,
        risk_level=risk_level,
        source_ip="45.67.89.10",
        target="/login",
        confidence=0.9,
        evidence=["SQL payload matched", "WAF rule 942100"],
        recommendations=["Use parameterized queries"],
        status="needs_review",
        automation_decision=automation_decision,
        triage_reason="High-risk request requires review",
        business_owner="account-team",
        asset_criticality="high",
    )


def build_state(alert: SecurityAlert | None = None) -> AnalysisState:
    """
    Build a deterministic analysis state for long-term memory tests.

    Parameters:
     alert - optional final alert attached to the state

    Returns:
     Analysis state fixture

    Raises:
     None
    """

    state = AnalysisState(
        session_id="session-test-001",
        event=SecurityEvent(
            event_id="event-test-001",
            source_ip="45.67.89.10",
            path="/login",
            query="id=1' OR '1'='1",
            waf_rule_id="942100",
        ),
    )
    state.final_alert = alert
    state.add_finding(
        finding_type="attack_detection",
        title="Detected SQL Injection",
        description="Rule and WAF evidence matched",
        evidence=["SQL payload matched"],
        confidence=0.9,
        source="decision_agent",
    )
    state.add_reflection(
        summary="Stable SQL Injection memory candidate",
        suggested_rule_update=False,
    )

    return state


class FakeEmbeddingClient:
    """
    Provide deterministic embedding behavior for long-term memory tests.

    Parameters:
     available - whether the fake client should report availability

    Returns:
     Fake embedding client

    Raises:
     None
    """

    def __init__(self, available: bool = True) -> None:
        """
        Initialize fake embedding state.

        Parameters:
         available - whether the fake client should report availability

        Returns:
         None

        Raises:
         None
        """

        self._available = available
        self.last_text = ""

    def available(self) -> bool:
        """
        Return fake embedding availability.

        Parameters:
         None

        Returns:
         Availability flag

        Raises:
         None
        """

        return self._available

    def embed_text(self, text: str) -> list[float] | None:
        """
        Return a deterministic embedding vector.

        Parameters:
         text - text requested for embedding

        Returns:
         Deterministic embedding vector

        Raises:
         None
        """

        self.last_text = text
        return [0.1, 0.2, 0.3] if self._available else None


class FakeMilvusClient:
    """
    Provide deterministic Milvus behavior for long-term memory tests.

    Parameters:
     available - whether the fake client should report availability

    Returns:
     Fake Milvus client

    Raises:
     None
    """

    def __init__(self, available: bool = True) -> None:
        """
        Initialize fake Milvus state.

        Parameters:
         available - whether the fake client should report availability

        Returns:
         None

        Raises:
         None
        """

        self._available = available
        self.records = []
        self.embeddings = []

    def available(self) -> bool:
        """
        Return fake Milvus availability.

        Parameters:
         None

        Returns:
         Availability flag

        Raises:
         None
        """

        return self._available

    def upsert_memory_records(self, records, embeddings) -> int:
        """
        Record memory rows and report deterministic write count.

        Parameters:
         records - memory records submitted by the store
         embeddings - memory embeddings submitted by the store

        Returns:
         Number of records accepted

        Raises:
         None
        """

        self.records = records
        self.embeddings = embeddings
        return len(records) if self._available else 0

    def search_memory(self, query_embedding, top_k=5, filters=None):
        """
        Return deterministic similar memory results.

        Parameters:
         query_embedding - query embedding vector
         top_k - maximum result count
         filters - optional metadata filters

        Returns:
         Similar memory search results

        Raises:
         None
        """

        record = self.records[0]
        return [
            LongTermMemorySearchResult(
                record=record,
                score=0.91,
            )
        ]


def test_long_term_policy_disabled_by_default(monkeypatch) -> None:
    """
    Verify long-term memory writing is disabled by default.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.delenv("LONG_TERM_MEMORY_ENABLED", raising=False)
    policy = LongTermMemoryPolicy()

    should_write, reason = policy.should_write(build_alert())

    assert should_write is False
    assert reason == "LONG_TERM_MEMORY_DISABLED"


def test_long_term_policy_skips_below_threshold(monkeypatch) -> None:
    """
    Verify low-risk alerts are skipped when minimum risk is high.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    monkeypatch.setenv("LONG_TERM_MEMORY_MIN_RISK_LEVEL", "high")
    policy = LongTermMemoryPolicy()

    should_write, reason = policy.should_write(build_alert(risk_level="medium"))

    assert should_write is False
    assert reason == "RISK_LEVEL_BELOW_THRESHOLD"


def test_long_term_policy_allows_high_risk(monkeypatch) -> None:
    """
    Verify high-risk alerts can be written when policy is enabled.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    monkeypatch.setenv("LONG_TERM_MEMORY_MIN_RISK_LEVEL", "high")
    policy = LongTermMemoryPolicy()

    should_write, reason = policy.should_write(build_alert(risk_level="high"))

    assert should_write is True
    assert reason is None


def test_long_term_policy_skips_auto_closed_by_default(monkeypatch) -> None:
    """
    Verify auto-closed alerts are skipped unless explicitly enabled.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    monkeypatch.setenv("LONG_TERM_MEMORY_MIN_RISK_LEVEL", "low")
    monkeypatch.delenv("LONG_TERM_MEMORY_WRITE_AUTO_CLOSED", raising=False)
    policy = LongTermMemoryPolicy()

    should_write, reason = policy.should_write(
        build_alert(risk_level="high", automation_decision="auto_close")
    )

    assert should_write is False
    assert reason == "AUTO_CLOSED_ALERT_SKIPPED"


def test_long_term_builder_creates_semantic_record() -> None:
    """
    Verify builder creates a searchable semantic memory record.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    alert = build_alert()
    state = build_state(alert)
    record = LongTermMemoryBuilder().build(alert, state)

    assert record.memory_id == "memory-alert-test-001"
    assert record.attack_type == "SQL Injection"
    assert record.business_owner == "account-team"
    assert "Detected SQL Injection" in record.summary
    assert "Stable SQL Injection memory candidate" in record.summary
    assert "SQL payload matched" in record.evidence_text


def test_long_term_store_skips_when_embedding_unavailable(monkeypatch) -> None:
    """
    Verify store skips safely when embedding is unavailable.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    store = LongTermMemoryStore(
        embedding_client=FakeEmbeddingClient(available=False),
        milvus_client=FakeMilvusClient(),
    )

    result = store.save_analysis(build_alert(), build_state())

    assert result.attempted is True
    assert result.written is False
    assert result.skipped_reason == "EMBEDDING_UNAVAILABLE"


def test_long_term_store_writes_when_dependencies_available(monkeypatch) -> None:
    """
    Verify store writes memory when policy, embedding, and Milvus are available.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    embedding = FakeEmbeddingClient()
    milvus = FakeMilvusClient()
    store = LongTermMemoryStore(embedding_client=embedding, milvus_client=milvus)
    alert = build_alert()

    result = store.save_analysis(alert, build_state(alert))

    assert result.attempted is True
    assert result.written is True
    assert result.memory_id == "memory-alert-test-001"
    assert len(milvus.records) == 1
    assert milvus.embeddings == [[0.1, 0.2, 0.3]]
    assert "SQL Injection" in embedding.last_text


def test_long_term_store_searches_similar_memories(monkeypatch) -> None:
    """
    Verify store searches similar memories through embedding and Milvus.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    milvus = FakeMilvusClient()
    store = LongTermMemoryStore(
        embedding_client=FakeEmbeddingClient(),
        milvus_client=milvus,
    )
    alert = build_alert()
    store.save_analysis(alert, build_state(alert))

    results = store.search_similar(
        "same source ip sql injection",
        filters={"attack_type": "SQL Injection"},
    )

    assert len(results) == 1
    assert results[0].record.alert_id == alert.alert_id
    assert results[0].score == 0.91


def test_long_term_store_searches_for_alert_when_enabled(monkeypatch) -> None:
    """
    Verify store can search similar memories for a current alert.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    monkeypatch.setenv("LONG_TERM_MEMORY_SEARCH_ENABLED", "true")
    milvus = FakeMilvusClient()
    embedding = FakeEmbeddingClient()
    store = LongTermMemoryStore(
        embedding_client=embedding,
        milvus_client=milvus,
    )
    alert = build_alert()
    state = build_state(alert)
    store.save_analysis(alert, state)

    results, skipped_reason = store.search_for_alert(alert, state)

    assert skipped_reason is None
    assert len(results) == 1
    assert results[0].record.attack_type == "SQL Injection"
    assert "attack_features" in embedding.last_text


def test_long_term_store_skips_alert_search_when_disabled(monkeypatch) -> None:
    """
    Verify alert-level similar memory search can be disabled independently.

    Parameters:
     monkeypatch - pytest environment patch helper

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("LONG_TERM_MEMORY_ENABLED", "true")
    monkeypatch.setenv("LONG_TERM_MEMORY_SEARCH_ENABLED", "false")
    store = LongTermMemoryStore(
        embedding_client=FakeEmbeddingClient(),
        milvus_client=FakeMilvusClient(),
    )

    results, skipped_reason = store.search_for_alert(build_alert(), build_state())

    assert results == []
    assert skipped_reason == "LONG_TERM_MEMORY_SEARCH_DISABLED"
