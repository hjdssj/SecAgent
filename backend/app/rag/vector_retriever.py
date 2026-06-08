from app.rag.schemas import KnowledgeChunk, RetrievalResult
from app.embedding.client import EmbeddingClient
from app.milvus.client import MilvusKnowledgeClient


class VectorRetriever:
    """
    Retrieve knowledge chunks from Milvus vector search when configured.

    Parameters:
     chunks - searchable knowledge chunks available to the retriever
     embedding_client - optional embedding client replacement used by tests
     milvus_client - optional Milvus client replacement used by tests

    Returns:
     Vector retriever compatible with HybridRetriever

    Raises:
     None
    """

    def __init__(
        self,
        chunks: list[KnowledgeChunk],
        embedding_client: EmbeddingClient | None = None,
        milvus_client: MilvusKnowledgeClient | None = None,
    ) -> None:
        """
        Initialize the vector retriever.

        Parameters:
         chunks - searchable knowledge chunks available to the retriever
         embedding_client - optional embedding client replacement used by tests
         milvus_client - optional Milvus client replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.chunks = chunks
        self.embedding_client = embedding_client or EmbeddingClient()
        self.milvus_client = milvus_client or MilvusKnowledgeClient()
        self.chunk_by_id = {chunk.chunk_id: chunk for chunk in chunks}

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[RetrievalResult]:
        """
        Search vector index for relevant chunks.

        Parameters:
         query - retrieval query text
         top_k - maximum number of retrieval results
         filters - optional chunk metadata filters

        Returns:
         Vector retrieval results, or empty list when vector search is unavailable

        Raises:
         None
        """

        if not self.milvus_client.available():
            return []

        query_embedding = self.embedding_client.embed_text(query)

        if not query_embedding:
            return []

        return self.milvus_client.search_knowledge(
            query_embedding=query_embedding,
            chunk_by_id=self.chunk_by_id,
            top_k=top_k,
            filters=filters,
        )
