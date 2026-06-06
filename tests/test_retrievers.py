import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.bm25_retriever import BM25Retriever
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.knowledge_loader import KnowledgeLoader


def test_bm25_retriever_returns_sqli_knowledge() -> None:
    """
    Verify BM25 retrieval ranks SQL injection knowledge for SQLi queries.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    chunks = KnowledgeLoader().load_chunks()
    results = BM25Retriever(chunks).search(
        "SQL Injection sqlmap OWASP CRS 942 parameterized query",
        top_k=3,
    )

    assert results
    assert results[0].score > 0
    assert any("SQL Injection" in result.chunk.title for result in results)
    assert all(result.reason for result in results)


def test_hybrid_retriever_keeps_source_score_and_reason() -> None:
    """
    Verify hybrid retrieval returns explainable references for XSS queries.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    chunks = KnowledgeLoader().load_chunks()
    results = HybridRetriever(chunks).search(
        "XSS cross site scripting OWASP CRS 941 output encoding",
        top_k=3,
    )

    assert results
    assert any("XSS" in result.chunk.title or "941" in result.chunk.title for result in results)
    assert all(result.retrieval_type == "hybrid" for result in results)
    assert all(result.chunk.source for result in results)
    assert all(result.score > 0 for result in results)
