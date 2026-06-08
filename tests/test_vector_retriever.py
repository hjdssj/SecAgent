import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.hybrid_retriever import HybridRetriever
from app.rag.schemas import KnowledgeChunk, RetrievalResult
from app.rag.vector_retriever import VectorRetriever


class FakeEmbeddingClient:
    """
    Return deterministic embeddings for vector retriever tests.

    Parameters:
     vector - embedding vector returned for every query

    Returns:
     Fake embedding client

    Raises:
     None
    """

    def __init__(self, vector: list[float] | None = None) -> None:
        """
        Initialize fake embedding client.

        Parameters:
         vector - embedding vector returned for every query

        Returns:
         None

        Raises:
         None
        """

        self.vector = vector
        self.called = False

    def embed_text(self, text: str) -> list[float] | None:
        """
        Return deterministic query embedding.

        Parameters:
         text - query text

        Returns:
         Configured embedding vector or None

        Raises:
         None
        """

        self.called = True
        return self.vector


class FakeMilvusClient:
    """
    Return deterministic Milvus search results for vector retriever tests.

    Parameters:
     available - whether vector search should be available
     results - deterministic retrieval results returned from search

    Returns:
     Fake Milvus client

    Raises:
     None
    """

    def __init__(
        self,
        available: bool = True,
        results: list[RetrievalResult] | None = None,
    ) -> None:
        """
        Initialize fake Milvus client.

        Parameters:
         available - whether vector search should be available
         results - deterministic retrieval results returned from search

        Returns:
         None

        Raises:
         None
        """

        self._available = available
        self.results = results or []
        self.called = False

    def available(self) -> bool:
        """
        Return configured availability.

        Parameters:
         None

        Returns:
         True when fake Milvus is available

        Raises:
         None
        """

        return self._available

    def search_knowledge(
        self,
        query_embedding: list[float],
        chunk_by_id: dict[str, KnowledgeChunk],
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[RetrievalResult]:
        """
        Return deterministic vector retrieval results.

        Parameters:
         query_embedding - query embedding vector
         chunk_by_id - local chunk lookup
         top_k - maximum number of results
         filters - optional metadata filters

        Returns:
         Configured retrieval results

        Raises:
         None
        """

        self.called = True
        return self.results[:top_k]


def build_chunks() -> list[KnowledgeChunk]:
    """
    Build deterministic knowledge chunks for retriever tests.

    Parameters:
     None

    Returns:
     Knowledge chunks used by fake retrievers

    Raises:
     None
    """

    return [
        KnowledgeChunk(
            chunk_id="attack_patterns:1",
            doc_id="attack_patterns",
            source="attack_patterns.md",
            title="SSRF",
            category="attack",
            content="SSRF attempts may target cloud metadata endpoint 169.254.169.254.",
            tags=["ssrf"],
            keywords=["ssrf", "metadata"],
        ),
        KnowledgeChunk(
            chunk_id="remediation:1",
            doc_id="remediation",
            source="remediation.md",
            title="SQL Injection Remediation",
            category="remediation",
            content="Use parameterized queries to prevent SQL injection.",
            tags=["sqli"],
            keywords=["sql", "injection"],
        ),
    ]


def test_vector_retriever_returns_empty_when_milvus_unavailable() -> None:
    """
    Verify vector retriever safely returns no results when Milvus is unavailable.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    embedding = FakeEmbeddingClient(vector=[0.1, 0.2])
    milvus = FakeMilvusClient(available=False)
    retriever = VectorRetriever(
        build_chunks(),
        embedding_client=embedding,
        milvus_client=milvus,
    )

    results = retriever.search("SSRF metadata", top_k=2)

    assert results == []
    assert embedding.called is False
    assert milvus.called is False


def test_vector_retriever_returns_milvus_results() -> None:
    """
    Verify vector retriever returns Milvus-backed retrieval results.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    chunks = build_chunks()
    expected = [
        RetrievalResult(
            chunk=chunks[0],
            score=0.88,
            retrieval_type="vector",
            reason="Milvus vector similarity match",
        )
    ]
    embedding = FakeEmbeddingClient(vector=[0.1, 0.2])
    milvus = FakeMilvusClient(results=expected)
    retriever = VectorRetriever(
        chunks,
        embedding_client=embedding,
        milvus_client=milvus,
    )

    results = retriever.search("SSRF metadata", top_k=2)

    assert embedding.called is True
    assert milvus.called is True
    assert results == expected


def test_hybrid_retriever_merges_vector_results(monkeypatch) -> None:
    """
    Verify hybrid retriever can merge BM25 and vector results.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    chunks = build_chunks()

    class FakeVectorRetriever:
        """
        Return deterministic vector result for hybrid retriever.

        Parameters:
         chunks - searchable knowledge chunks

        Returns:
         Fake vector retriever

        Raises:
         None
        """

        def __init__(self, chunks: list[KnowledgeChunk]) -> None:
            """
            Initialize fake vector retriever.

            Parameters:
             chunks - searchable knowledge chunks

            Returns:
             None

            Raises:
             None
            """

            self.chunks = chunks

        def search(
            self,
            query: str,
            top_k: int = 5,
            filters: dict[str, str] | None = None,
        ) -> list[RetrievalResult]:
            """
            Return deterministic vector results.

            Parameters:
             query - retrieval query text
             top_k - maximum number of results
             filters - optional metadata filters

            Returns:
             Vector retrieval results

            Raises:
             None
            """

            return [
                RetrievalResult(
                    chunk=self.chunks[0],
                    score=0.9,
                    retrieval_type="vector",
                    reason="vector matched SSRF metadata",
                )
            ]

    monkeypatch.setattr("app.rag.hybrid_retriever.VectorRetriever", FakeVectorRetriever)

    results = HybridRetriever(chunks).search("SSRF metadata", top_k=2)

    assert results
    assert any("vector matched SSRF metadata" in result.reason for result in results)
    assert all(result.retrieval_type == "hybrid" for result in results)
