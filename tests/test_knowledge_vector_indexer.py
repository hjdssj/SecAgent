import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.knowledge_loader import KnowledgeLoader
from app.rag.schemas import KnowledgeChunk
from app.rag.vector_indexer import KnowledgeVectorIndexer


class FakeEmbeddingClient:
    """
    Provide deterministic embedding behavior for vector indexer tests.

    Parameters:
     available - whether embedding should be available
     vectors - vectors returned by embed_texts

    Returns:
     Fake embedding client

    Raises:
     None
    """

    def __init__(
        self,
        available: bool = True,
        vectors: list[list[float]] | None = None,
    ) -> None:
        """
        Initialize fake embedding state.

        Parameters:
         available - whether embedding should be available
         vectors - vectors returned by embed_texts

        Returns:
         None

        Raises:
         None
        """

        self._available = available
        self.vectors = vectors if vectors is not None else [[0.1, 0.2]]
        self.texts: list[str] = []

    def available(self) -> bool:
        """
        Return configured embedding availability.

        Parameters:
         None

        Returns:
         True when embedding is available

        Raises:
         None
        """

        return self._available

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """
        Return configured embeddings.

        Parameters:
         texts - source texts requested for embedding

        Returns:
         Configured embedding vectors

        Raises:
         None
        """

        self.texts = texts
        return self.vectors


class FakeMilvusClient:
    """
    Provide deterministic Milvus behavior for vector indexer tests.

    Parameters:
     available - whether Milvus should be available
     written - number of rows reported as written

    Returns:
     Fake Milvus client

    Raises:
     None
    """

    def __init__(self, available: bool = True, written: int = 1) -> None:
        """
        Initialize fake Milvus state.

        Parameters:
         available - whether Milvus should be available
         written - number of rows reported as written

        Returns:
         None

        Raises:
         None
        """

        self._available = available
        self.written = written
        self.deleted_sources: list[str] = []
        self.ensure_called = False
        self.rows: list[KnowledgeChunk] = []
        self.embeddings: list[list[float]] = []

    def available(self) -> bool:
        """
        Return configured Milvus availability.

        Parameters:
         None

        Returns:
         True when Milvus is available

        Raises:
         None
        """

        return self._available

    def ensure_knowledge_collection(self, recreate: bool = False) -> bool:
        """
        Record collection preparation.

        Parameters:
         recreate - whether collection recreation was requested

        Returns:
         True

        Raises:
         None
        """

        self.ensure_called = True
        return True

    def delete_knowledge_by_source(self, source: str) -> bool:
        """
        Record source cleanup.

        Parameters:
         source - source requested for deletion

        Returns:
         True

        Raises:
         None
        """

        self.deleted_sources.append(source)
        return True

    def upsert_knowledge_chunks(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
    ) -> int:
        """
        Record chunks and embeddings.

        Parameters:
         chunks - chunks submitted to Milvus
         embeddings - embeddings submitted to Milvus

        Returns:
         Configured write count

        Raises:
         None
        """

        self.rows = chunks
        self.embeddings = embeddings
        return self.written


def build_chunk(source: str = "demo.md") -> KnowledgeChunk:
    """
    Build one deterministic knowledge chunk.

    Parameters:
     source - source file name assigned to the chunk

    Returns:
     Knowledge chunk used by vector indexer tests

    Raises:
     None
    """

    return KnowledgeChunk(
        chunk_id="demo:1",
        doc_id="demo",
        source=source,
        title="SSRF",
        category="attack",
        content="SSRF against metadata endpoint.",
        tags=["ssrf"],
    )


def test_knowledge_vector_indexer_indexes_chunks() -> None:
    """
    Verify vector indexer writes chunks when embedding and Milvus are available.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    embedding = FakeEmbeddingClient(vectors=[[0.1, 0.2]])
    milvus = FakeMilvusClient(written=1)
    indexer = KnowledgeVectorIndexer(
        embedding_client=embedding,
        milvus_client=milvus,
    )

    result = indexer.index_chunks(
        chunks=[build_chunk()],
        source="demo.md",
        delete_existing=True,
    )

    assert result.indexed is True
    assert result.status == "indexed"
    assert result.chunks_written == 1
    assert milvus.deleted_sources == ["demo.md"]
    assert milvus.rows[0].chunk_id == "demo:1"
    assert embedding.texts[0].startswith("SSRF")


def test_knowledge_vector_indexer_skips_when_embedding_unavailable() -> None:
    """
    Verify vector indexer skips safely when embedding is unavailable.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    indexer = KnowledgeVectorIndexer(
        embedding_client=FakeEmbeddingClient(available=False),
        milvus_client=FakeMilvusClient(),
    )

    result = indexer.index_chunks([build_chunk()])

    assert result.indexed is False
    assert result.status == "embedding_unavailable"


def test_knowledge_vector_indexer_skips_when_milvus_unavailable() -> None:
    """
    Verify vector indexer skips safely when Milvus is unavailable.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    indexer = KnowledgeVectorIndexer(
        embedding_client=FakeEmbeddingClient(),
        milvus_client=FakeMilvusClient(available=False),
    )

    result = indexer.index_chunks([build_chunk()])

    assert result.indexed is False
    assert result.status == "milvus_unavailable"


def test_knowledge_vector_indexer_loads_source_chunks(tmp_path: Path) -> None:
    """
    Verify source indexing selects only chunks from the requested document.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory

    Returns:
     None

    Raises:
     None
    """

    (tmp_path / "one.md").write_text("# One\n\n## SSRF\n\nmetadata", encoding="utf-8")
    (tmp_path / "two.md").write_text("# Two\n\n## SQLi\n\nunion select", encoding="utf-8")
    milvus = FakeMilvusClient(written=2)
    indexer = KnowledgeVectorIndexer(
        loader=KnowledgeLoader(tmp_path),
        embedding_client=FakeEmbeddingClient(vectors=[[0.1, 0.2], [0.2, 0.3]]),
        milvus_client=milvus,
    )

    result = indexer.index_source("one.md")

    assert result.indexed is True
    assert result.chunks_written == 2
    assert {chunk.source for chunk in milvus.rows} == {"one.md"}
