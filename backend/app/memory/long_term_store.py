from app.analysis.state import AnalysisState
from app.embedding.client import EmbeddingClient
from app.memory.long_term_builder import LongTermMemoryBuilder
from app.memory.long_term_policy import LongTermMemoryPolicy
from app.memory.long_term_schemas import (
    LongTermMemoryRecord,
    LongTermMemorySearchResult,
    LongTermMemoryWriteResult,
)
from app.milvus.client import MilvusKnowledgeClient
from app.models.alert import SecurityAlert


class LongTermMemoryStore:
    """
    Write and search long-term analysis memory through Milvus.

    Parameters:
     policy - optional write policy replacement used by tests
     builder - optional memory builder replacement used by tests
     embedding_client - optional embedding client replacement used by tests
     milvus_client - optional Milvus client replacement used by tests

    Returns:
     Store for optional long-term analysis memory

    Raises:
     None
    """

    def __init__(
        self,
        policy: LongTermMemoryPolicy | None = None,
        builder: LongTermMemoryBuilder | None = None,
        embedding_client: EmbeddingClient | None = None,
        milvus_client: MilvusKnowledgeClient | None = None,
    ) -> None:
        """
        Initialize long-term memory dependencies.

        Parameters:
         policy - optional write policy replacement used by tests
         builder - optional memory builder replacement used by tests
         embedding_client - optional embedding client replacement used by tests
         milvus_client - optional Milvus client replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.policy = policy or LongTermMemoryPolicy()
        self.builder = builder or LongTermMemoryBuilder()
        self.embedding_client = embedding_client or EmbeddingClient()
        self.milvus_client = milvus_client or MilvusKnowledgeClient()

    def save_analysis(
        self,
        alert: SecurityAlert,
        state: AnalysisState,
    ) -> LongTermMemoryWriteResult:
        """
        Save one alert analysis into long-term memory when policy allows it.

        Parameters:
         alert - final security alert
         state - analysis state produced with the alert

        Returns:
         Long-term memory write result

        Raises:
         None
        """

        should_write, skipped_reason = self.policy.should_write(alert)

        if not should_write:
            return LongTermMemoryWriteResult(skipped_reason=skipped_reason)

        if not self.embedding_client.available():
            return LongTermMemoryWriteResult(
                attempted=True,
                skipped_reason="EMBEDDING_UNAVAILABLE",
            )

        if not self.milvus_client.available():
            return LongTermMemoryWriteResult(
                attempted=True,
                skipped_reason="MILVUS_UNAVAILABLE",
            )

        record = self.builder.build(alert, state)
        embedding = self.embedding_client.embed_text(record.summary)

        if not embedding:
            return LongTermMemoryWriteResult(
                attempted=True,
                memory_id=record.memory_id,
                error="EMBEDDING_FAILED",
            )

        written = self.milvus_client.upsert_memory_records([record], [embedding])

        if written != 1:
            return LongTermMemoryWriteResult(
                attempted=True,
                memory_id=record.memory_id,
                error="MILVUS_WRITE_FAILED",
            )

        return LongTermMemoryWriteResult(
            attempted=True,
            written=True,
            memory_id=record.memory_id,
        )

    def search_similar(
        self,
        text: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[LongTermMemorySearchResult]:
        """
        Search similar long-term analysis memories.

        Parameters:
         text - query text to embed and search
         top_k - maximum number of similar memories
         filters - optional memory metadata filters

        Returns:
         Similar long-term memory results

        Raises:
         None
        """

        if not self.embedding_client.available() or not self.milvus_client.available():
            return []

        embedding = self.embedding_client.embed_text(text)

        if not embedding:
            return []

        return self.milvus_client.search_memory(
            query_embedding=embedding,
            top_k=top_k,
            filters=filters,
        )

    def search_for_alert(
        self,
        alert: SecurityAlert,
        state: AnalysisState | None = None,
        top_k: int = 3,
    ) -> tuple[list[LongTermMemorySearchResult], str | None]:
        """
        Search similar long-term memories for a current alert.

        Parameters:
         alert - current security alert
         state - optional current analysis state
         top_k - maximum number of similar memories

        Returns:
         Tuple containing similar memories and optional skipped reason

        Raises:
         None
        """

        should_search, skipped_reason = self.policy.should_search(alert)

        if not should_search:
            return [], skipped_reason

        if not self.embedding_client.available():
            return [], "EMBEDDING_UNAVAILABLE"

        if not self.milvus_client.available():
            return [], "MILVUS_UNAVAILABLE"

        query_text = self.builder.search_text(alert, state)
        filters = {"attack_type": alert.attack_type}
        results = self.search_similar(query_text, top_k=top_k, filters=filters)

        if not results:
            return [], "NO_SIMILAR_MEMORY"

        return results, None
