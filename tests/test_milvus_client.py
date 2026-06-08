import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.milvus.client import MilvusKnowledgeClient
from app.milvus.config import MilvusConfig
from app.rag.schemas import KnowledgeChunk


def test_milvus_client_disabled_is_unavailable() -> None:
    """
    Verify disabled Milvus config reports unavailable.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = MilvusConfig()
    config.enabled = False
    client = MilvusKnowledgeClient(config=config)

    assert client.available() is False


def test_milvus_filter_expression_uses_allowed_metadata_fields() -> None:
    """
    Verify Milvus filter expression is built from safe metadata fields.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = MilvusConfig()
    client = MilvusKnowledgeClient(config=config)

    expression = client._filter_expression(
        {
            "category": "attack",
            "source": "attack_patterns.md",
            "ignored": "value",
        }
    )

    assert 'source == "attack_patterns.md"' in expression
    assert 'category == "attack"' in expression
    assert "ignored" not in expression


def test_milvus_to_results_reconstructs_local_chunks() -> None:
    """
    Verify raw Milvus rows are converted into retrieval results.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    chunk = KnowledgeChunk(
        chunk_id="attack_patterns:1",
        doc_id="attack_patterns",
        source="attack_patterns.md",
        title="SSRF",
        category="attack",
        content="SSRF metadata access.",
    )
    config = MilvusConfig()
    client = MilvusKnowledgeClient(config=config)

    results = client._to_results(
        [
            [
                {
                    "id": "attack_patterns:1",
                    "distance": 0.82,
                    "entity": {"chunk_id": "attack_patterns:1"},
                }
            ]
        ],
        {"attack_patterns:1": chunk},
    )

    assert len(results) == 1
    assert results[0].chunk.title == "SSRF"
    assert results[0].retrieval_type == "vector"


def test_milvus_memory_filter_expression_uses_allowed_metadata_fields() -> None:
    """
    Verify memory filter expression only uses supported metadata fields.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = MilvusConfig()
    client = MilvusKnowledgeClient(config=config)

    expression = client._memory_filter_expression(
        {
            "attack_type": "SQL Injection",
            "risk_level": "high",
            "ignored": "value",
        }
    )

    assert "enabled == true" in expression
    assert 'attack_type == "SQL Injection"' in expression
    assert 'risk_level == "high"' in expression
    assert "ignored" not in expression


def test_milvus_to_memory_results_reconstructs_records() -> None:
    """
    Verify raw Milvus rows are converted into long-term memory results.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = MilvusConfig()
    client = MilvusKnowledgeClient(config=config)

    results = client._to_memory_results(
        [
            [
                {
                    "id": "memory-alert-1",
                    "distance": 0.87,
                    "entity": {
                        "memory_id": "memory-alert-1",
                        "alert_id": "alert-1",
                        "session_id": "session-1",
                        "source_ip": "45.67.89.10",
                        "target": "/login",
                        "attack_type": "SQL Injection",
                        "risk_level": "high",
                        "business_owner": "account-team",
                        "asset_criticality": "high",
                        "status": "needs_review",
                        "automation_decision": "human_review_required",
                        "summary": "SQL Injection against account login.",
                        "evidence_text": "WAF rule 942100",
                        "recommendation_text": "Use parameterized queries.",
                        "analyst_note": None,
                        "handled_by": None,
                        "handled_at": None,
                        "created_at": "2026-06-07T00:00:00+00:00",
                        "enabled": True,
                    },
                }
            ]
        ]
    )

    assert len(results) == 1
    assert results[0].record.alert_id == "alert-1"
    assert results[0].record.attack_type == "SQL Injection"
    assert results[0].score == 0.87
