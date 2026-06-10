import json
from typing import Any

from app.memory.long_term_schemas import (
    LongTermMemoryRecord,
    LongTermMemorySearchResult,
)
from app.milvus.config import MilvusConfig, load_milvus_config
from app.rag.schemas import KnowledgeChunk, RetrievalResult


class MilvusKnowledgeClient:
    """
    Store and search knowledge chunks in Milvus when enabled.

    Parameters:
     config - optional Milvus runtime configuration

    Returns:
     Milvus knowledge client with safe disabled fallback behavior

    Raises:
     None
    """

    def __init__(self, config: MilvusConfig | None = None) -> None:
        """
        Initialize the Milvus knowledge client.

        Parameters:
         config - optional Milvus runtime configuration

        Returns:
         None

        Raises:
         None
        """

        self.config = config or load_milvus_config()
        self._client = None

    def available(self) -> bool:
        """
        Return whether Milvus is enabled and importable.

        Parameters:
         None

        Returns:
         True when Milvus is enabled and pymilvus is importable

        Raises:
         None
        """

        if not self.config.enabled:
            return False

        return self._client_or_none() is not None

    def ensure_knowledge_collection(self, recreate: bool = False) -> bool:
        """
        Ensure the knowledge collection exists.

        Parameters:
         recreate - whether to drop and recreate the collection

        Returns:
         True when the collection is ready, otherwise False

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None:
            return False

        name = self.config.knowledge_collection

        try:
            if recreate and client.has_collection(name):
                client.drop_collection(name)

            if client.has_collection(name):
                return True

            client.create_collection(
                collection_name=name,
                dimension=self.config.embedding_dimension,
                metric_type=self.config.metric_type,
                auto_id=False,
                primary_field_name="chunk_id",
                vector_field_name="embedding",
                enable_dynamic_field=True,
            )
        except Exception:
            return False

        return True

    def upsert_knowledge_chunks(
        self,
        chunks: list[KnowledgeChunk],
        embeddings: list[list[float]],
    ) -> int:
        """
        Upsert knowledge chunks with embeddings into Milvus.

        Parameters:
         chunks - knowledge chunks to write
         embeddings - embedding vectors aligned with chunks

        Returns:
         Number of chunks submitted to Milvus

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None or len(chunks) != len(embeddings):
            return 0

        if not self.ensure_knowledge_collection():
            return 0

        rows = [
            {
                "chunk_id": chunk.chunk_id,
                "doc_id": chunk.doc_id,
                "source": chunk.source,
                "title": chunk.title,
                "category": chunk.category,
                "tags_json": json.dumps(chunk.tags, ensure_ascii=False),
                "content": chunk.content,
                "embedding": embedding,
            }
            for chunk, embedding in zip(chunks, embeddings)
        ]

        try:
            if hasattr(client, "upsert"):
                client.upsert(collection_name=self.config.knowledge_collection, data=rows)
            else:
                client.insert(collection_name=self.config.knowledge_collection, data=rows)
        except Exception:
            return 0

        return len(rows)

    def delete_knowledge_by_source(self, source: str) -> bool:
        """
        Delete existing knowledge vectors for one source document.

        Parameters:
         source - source markdown file name

        Returns:
         True when deletion was attempted successfully or no client is available

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None or not source:
            return False

        escaped = source.replace('"', '\\"')
        expression = f'source == "{escaped}"'

        try:
            if hasattr(client, "delete"):
                client.delete(
                    collection_name=self.config.knowledge_collection,
                    filter=expression,
                )
        except Exception:
            return False

        return True

    def search_knowledge(
        self,
        query_embedding: list[float],
        chunk_by_id: dict[str, KnowledgeChunk],
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[RetrievalResult]:
        """
        Search knowledge chunks by query embedding.

        Parameters:
         query_embedding - embedding vector for the retrieval query
         chunk_by_id - local chunk lookup used to reconstruct RetrievalResult
         top_k - maximum number of results
         filters - optional chunk metadata filters

        Returns:
         Vector retrieval results, or empty list when unavailable

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None or not query_embedding:
            return []

        search_filter = self._filter_expression(filters)

        try:
            raw_results = client.search(
                collection_name=self.config.knowledge_collection,
                data=[query_embedding],
                limit=top_k,
                filter=search_filter,
                output_fields=[
                    "chunk_id",
                    "doc_id",
                    "source",
                    "title",
                    "category",
                    "tags_json",
                    "content",
                ],
            )
        except Exception:
            return []

        return self._to_results(raw_results, chunk_by_id)

    def ensure_memory_collection(self, recreate: bool = False) -> bool:
        """
        Ensure the long-term analysis memory collection exists.

        Parameters:
         recreate - whether to drop and recreate the collection

        Returns:
         True when the collection is ready, otherwise False

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None:
            return False

        name = self.config.memory_collection

        try:
            if recreate and client.has_collection(name):
                client.drop_collection(name)

            if client.has_collection(name):
                return True

            client.create_collection(
                collection_name=name,
                dimension=self.config.embedding_dimension,
                metric_type=self.config.metric_type,
                auto_id=False,
                primary_field_name="memory_id",
                vector_field_name="embedding",
                enable_dynamic_field=True,
            )
        except Exception:
            return False

        return True

    def upsert_memory_records(
        self,
        records: list[LongTermMemoryRecord],
        embeddings: list[list[float]],
    ) -> int:
        """
        Upsert long-term memory records with embeddings into Milvus.

        Parameters:
         records - long-term memory records to write
         embeddings - embedding vectors aligned with records

        Returns:
         Number of records submitted to Milvus

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None or len(records) != len(embeddings):
            return 0

        if not self.ensure_memory_collection():
            return 0

        rows = [
            {
                **{
                    key: value if value is not None else ""
                    for key, value in record.model_dump().items()
                },
                "embedding": embedding,
            }
            for record, embedding in zip(records, embeddings)
        ]

        try:
            if hasattr(client, "upsert"):
                client.upsert(collection_name=self.config.memory_collection, data=rows)
            else:
                client.insert(collection_name=self.config.memory_collection, data=rows)
        except Exception:
            return 0

        return len(rows)

    def search_memory(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[LongTermMemorySearchResult]:
        """
        Search long-term analysis memories by vector similarity.

        Parameters:
         query_embedding - embedding vector for the memory query
         top_k - maximum number of results
         filters - optional memory metadata filters

        Returns:
         Similar long-term memory results, or empty list when unavailable

        Raises:
         None
        """

        client = self._client_or_none()

        if client is None or not query_embedding:
            return []

        search_filter = self._memory_filter_expression(filters)

        try:
            raw_results = client.search(
                collection_name=self.config.memory_collection,
                data=[query_embedding],
                limit=top_k,
                filter=search_filter,
                output_fields=[
                    "memory_id",
                    "alert_id",
                    "session_id",
                    "source_ip",
                    "target",
                    "attack_type",
                    "risk_level",
                    "business_owner",
                    "asset_criticality",
                    "status",
                    "automation_decision",
                    "summary",
                    "evidence_text",
                    "recommendation_text",
                    "analyst_note",
                    "handled_by",
                    "handled_at",
                    "created_at",
                    "enabled",
                ],
            )
        except Exception:
            return []

        return self._to_memory_results(raw_results)

    def _client_or_none(self):
        """
        Return a cached Milvus client or None.

        Parameters:
         None

        Returns:
         MilvusClient instance or None

        Raises:
         None
        """

        if not self.config.enabled:
            return None

        if self._client is not None:
            return self._client

        try:
            from pymilvus import MilvusClient

            uri = f"http://{self.config.host}:{self.config.port}"
            kwargs: dict[str, Any] = {"uri": uri, "db_name": self.config.database}

            if self.config.user or self.config.password:
                kwargs["user"] = self.config.user
                kwargs["password"] = self.config.password

            self._client = MilvusClient(**kwargs)
        except Exception:
            self._client = None

        return self._client

    def _filter_expression(self, filters: dict[str, str] | None) -> str:
        """
        Build a simple Milvus filter expression.

        Parameters:
         filters - optional chunk metadata filters

        Returns:
         Milvus filter expression or empty string

        Raises:
         None
        """

        if not filters:
            return ""

        expressions = []

        for key in ["doc_id", "source", "category"]:
            value = filters.get(key)

            if value:
                escaped = value.replace('"', '\\"')
                expressions.append(f'{key} == "{escaped}"')

        return " and ".join(expressions)

    def _memory_filter_expression(self, filters: dict[str, str] | None) -> str:
        """
        Build a simple Milvus filter expression for memory metadata.

        Parameters:
         filters - optional memory metadata filters

        Returns:
         Milvus filter expression or empty string

        Raises:
         None
        """

        if not filters:
            return 'enabled == true'

        expressions = ['enabled == true']

        for key in [
            "source_ip",
            "attack_type",
            "risk_level",
            "business_owner",
            "asset_criticality",
            "status",
            "automation_decision",
        ]:
            value = filters.get(key)

            if value:
                escaped = value.replace('"', '\\"')
                expressions.append(f'{key} == "{escaped}"')

        return " and ".join(expressions)

    def _to_results(
        self,
        raw_results,
        chunk_by_id: dict[str, KnowledgeChunk],
    ) -> list[RetrievalResult]:
        """
        Convert Milvus search results into retrieval results.

        Parameters:
         raw_results - raw Milvus search response
         chunk_by_id - local chunk lookup used to reconstruct chunks

        Returns:
         Retrieval results

        Raises:
         None
        """

        if not raw_results:
            return []

        rows = raw_results[0] if isinstance(raw_results, list) else raw_results
        results: list[RetrievalResult] = []

        for row in rows:
            entity = row.get("entity", row) if isinstance(row, dict) else {}
            chunk_id = str(entity.get("chunk_id") or row.get("id") or "")
            chunk = chunk_by_id.get(chunk_id)

            if chunk is None:
                continue

            score = float(row.get("distance", row.get("score", 0.0)))
            results.append(
                RetrievalResult(
                    chunk=chunk,
                    score=round(score, 4),
                    retrieval_type="vector",
                    reason="Milvus vector similarity match",
                )
            )

        return results

    def _to_memory_results(self, raw_results) -> list[LongTermMemorySearchResult]:
        """
        Convert Milvus search results into long-term memory results.

        Parameters:
         raw_results - raw Milvus search response

        Returns:
         Long-term memory search results

        Raises:
         None
        """

        if not raw_results:
            return []

        rows = raw_results[0] if isinstance(raw_results, list) else raw_results
        results: list[LongTermMemorySearchResult] = []

        for row in rows:
            entity = row.get("entity", row) if isinstance(row, dict) else {}

            if not entity.get("memory_id"):
                continue

            try:
                record = LongTermMemoryRecord.model_validate(entity)
            except Exception:
                continue

            score = float(row.get("distance", row.get("score", 0.0)))
            results.append(
                LongTermMemorySearchResult(
                    record=record,
                    score=round(score, 4),
                )
            )

        return results
