from app.rag.bm25_retriever import BM25Retriever
from app.rag.schemas import KnowledgeChunk, RetrievalResult
from app.rag.vector_retriever import VectorRetriever


class HybridRetriever:
    """
    Combine BM25 and vector retrieval results into one ranked result list.

    Parameters:
     chunks - searchable knowledge chunks loaded from the local knowledge base
     bm25_weight - score weight assigned to BM25 retrieval
     vector_weight - score weight assigned to vector retrieval

    Returns:
     A hybrid retriever that can support keyword and vector recall

    Raises:
     None
    """

    def __init__(
        self,
        chunks: list[KnowledgeChunk],
        bm25_weight: float = 0.7,
        vector_weight: float = 0.3,
    ) -> None:
        """
        Initialize child retrievers and score weights.

        Parameters:
         chunks - searchable knowledge chunks loaded from the local knowledge base
         bm25_weight - score weight assigned to BM25 retrieval
         vector_weight - score weight assigned to vector retrieval

        Returns:
         None

        Raises:
         None
        """

        self.chunks = chunks
        self.bm25_weight = bm25_weight
        self.vector_weight = vector_weight
        self.bm25_retriever = BM25Retriever(chunks)
        self.vector_retriever = VectorRetriever(chunks)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[RetrievalResult]:
        """
        Search knowledge chunks with BM25 and vector retrieval.

        Parameters:
         query - retrieval query text
         top_k - maximum number of final retrieval results
         filters - optional chunk metadata filters

        Returns:
         Ranked hybrid retrieval results

        Raises:
         None
        """

        bm25_results = self.bm25_retriever.search(query, top_k=top_k * 2, filters=filters)
        vector_results = self.vector_retriever.search(query, top_k=top_k * 2, filters=filters)
        merged: dict[str, RetrievalResult] = {}

        for result in bm25_results:
            weighted_score = result.score * self.bm25_weight
            merged[result.chunk.chunk_id] = result.model_copy(
                update={
                    "score": round(weighted_score, 4),
                    "retrieval_type": "hybrid",
                    "reason": result.reason,
                }
            )

        for result in vector_results:
            weighted_score = result.score * self.vector_weight
            existing = merged.get(result.chunk.chunk_id)

            if existing:
                merged[result.chunk.chunk_id] = existing.model_copy(
                    update={
                        "score": round(existing.score + weighted_score, 4),
                        "reason": self._merge_reason(existing.reason, result.reason),
                    }
                )
                continue

            merged[result.chunk.chunk_id] = result.model_copy(
                update={
                    "score": round(weighted_score, 4),
                    "retrieval_type": "hybrid",
                }
            )

        return sorted(merged.values(), key=lambda item: item.score, reverse=True)[:top_k]

    def _merge_reason(self, first: str, second: str) -> str:
        """
        Merge two retrieval explanations without duplication.

        Parameters:
         first - first retrieval explanation
         second - second retrieval explanation

        Returns:
         Combined retrieval explanation

        Raises:
         None
        """

        parts = [part for part in [first, second] if part]
        return " | ".join(dict.fromkeys(parts))
