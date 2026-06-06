from app.rag.schemas import KnowledgeChunk, RetrievalResult


class VectorRetriever:
    """
    Provide a replaceable vector retrieval interface for future embedding search.

    Parameters:
     chunks - searchable knowledge chunks available to the retriever

    Returns:
     A vector retriever placeholder compatible with HybridRetriever

    Raises:
     None
    """

    def __init__(self, chunks: list[KnowledgeChunk]) -> None:
        """
        Initialize the vector retriever placeholder.

        Parameters:
         chunks - searchable knowledge chunks available to the retriever

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
        Search vector index for relevant chunks.

        Parameters:
         query - retrieval query text
         top_k - maximum number of retrieval results
         filters - optional chunk metadata filters

        Returns:
         Empty result list until a real embedding backend is configured

        Raises:
         None
        """

        return []
