from dataclasses import dataclass

from app.embedding.client import EmbeddingClient
from app.milvus.client import MilvusKnowledgeClient
from app.rag.knowledge_loader import DEFAULT_KNOWLEDGE_DIR, KnowledgeLoader
from app.rag.schemas import KnowledgeChunk


@dataclass
class KnowledgeVectorIndexResult:
    """
    Represent the result of one knowledge vector indexing attempt.

    Parameters:
     attempted - whether vector indexing was attempted
     indexed - whether chunks were written successfully
     chunks_written - number of chunks written to vector storage
     status - compact backend status for logs and API responses
     reason - human-readable indexing result reason

    Returns:
     Structured vector indexing result

    Raises:
     None
    """

    attempted: bool = False
    indexed: bool = False
    chunks_written: int = 0
    status: str = "not_attempted"
    reason: str = "Vector indexing was not attempted."


class KnowledgeVectorIndexer:
    """
    Index knowledge chunks into optional Milvus vector storage.

    Parameters:
     loader - knowledge loader used to select chunks
     embedding_client - optional embedding client replacement used by tests
     milvus_client - optional Milvus client replacement used by tests

    Returns:
     Backend vector indexing helper for knowledge uploads and rebuild scripts

    Raises:
     None
    """

    def __init__(
        self,
        loader: KnowledgeLoader | None = None,
        embedding_client: EmbeddingClient | None = None,
        milvus_client: MilvusKnowledgeClient | None = None,
    ) -> None:
        """
        Initialize vector indexing dependencies.

        Parameters:
         loader - knowledge loader used to select chunks
         embedding_client - optional embedding client replacement used by tests
         milvus_client - optional Milvus client replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.loader = loader or KnowledgeLoader(DEFAULT_KNOWLEDGE_DIR)
        self.embedding_client = embedding_client or EmbeddingClient()
        self.milvus_client = milvus_client or MilvusKnowledgeClient()

    def index_source(self, source: str) -> KnowledgeVectorIndexResult:
        """
        Index chunks belonging to one knowledge source.

        Parameters:
         source - markdown source file name to index

        Returns:
         Vector indexing result

        Raises:
         None
        """

        chunks = [chunk for chunk in self.loader.load_chunks() if chunk.source == source]
        return self.index_chunks(chunks=chunks, source=source, delete_existing=True)

    def index_all(self, recreate: bool = False) -> KnowledgeVectorIndexResult:
        """
        Index all local knowledge chunks.

        Parameters:
         recreate - whether to recreate the knowledge collection before writing

        Returns:
         Vector indexing result

        Raises:
         None
        """

        chunks = self.loader.load_chunks()
        return self.index_chunks(chunks=chunks, source="", recreate=recreate)

    def index_chunks(
        self,
        chunks: list[KnowledgeChunk],
        source: str = "",
        recreate: bool = False,
        delete_existing: bool = False,
    ) -> KnowledgeVectorIndexResult:
        """
        Index provided chunks into Milvus when embedding and Milvus are available.

        Parameters:
         chunks - knowledge chunks to index
         source - optional source used for cleanup and status messages
         recreate - whether to recreate the full knowledge collection
         delete_existing - whether to remove existing vectors for the same source first

        Returns:
         Vector indexing result

        Raises:
         None
        """

        if not chunks:
            return KnowledgeVectorIndexResult(
                attempted=True,
                status="no_chunks",
                reason="No knowledge chunks were available for vector indexing.",
            )

        if not self.embedding_client.available():
            return KnowledgeVectorIndexResult(
                attempted=True,
                status="embedding_unavailable",
                reason="Embedding is disabled or not configured; BM25 retrieval remains available.",
            )

        if not self.milvus_client.available():
            return KnowledgeVectorIndexResult(
                attempted=True,
                status="milvus_unavailable",
                reason="Milvus is disabled or unavailable; BM25 retrieval remains available.",
            )

        if not self.milvus_client.ensure_knowledge_collection(recreate=recreate):
            return KnowledgeVectorIndexResult(
                attempted=True,
                status="collection_unavailable",
                reason="Milvus knowledge collection could not be prepared.",
            )

        if delete_existing and source:
            self.milvus_client.delete_knowledge_by_source(source)

        embeddings = self.embedding_client.embed_texts(self._texts(chunks))

        if len(embeddings) != len(chunks):
            return KnowledgeVectorIndexResult(
                attempted=True,
                status="embedding_failed",
                reason="Embedding count did not match knowledge chunk count.",
            )

        written = self.milvus_client.upsert_knowledge_chunks(chunks, embeddings)

        if written != len(chunks):
            return KnowledgeVectorIndexResult(
                attempted=True,
                chunks_written=written,
                status="write_failed",
                reason="Milvus did not acknowledge all knowledge chunks.",
            )

        return KnowledgeVectorIndexResult(
            attempted=True,
            indexed=True,
            chunks_written=written,
            status="indexed",
            reason=f"Indexed {written} knowledge chunks into vector storage.",
        )

    def _texts(self, chunks: list[KnowledgeChunk]) -> list[str]:
        """
        Build embedding input texts from knowledge chunks.

        Parameters:
         chunks - knowledge chunks to embed

        Returns:
         Texts suitable for embedding generation

        Raises:
         None
        """

        return [
            "\n".join(
                [
                    chunk.title,
                    chunk.category,
                    " ".join(chunk.tags),
                    chunk.content,
                ]
            )
            for chunk in chunks
        ]
