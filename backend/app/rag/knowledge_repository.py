import re
from pathlib import Path

from app.rag.knowledge_loader import DEFAULT_KNOWLEDGE_DIR, KnowledgeLoader
from app.rag.schemas import KnowledgeDocument, KnowledgeUploadResponse
from app.rag.vector_indexer import KnowledgeVectorIndexer


class KnowledgeRepository:
    """
    Manage local markdown documents used by the RAG knowledge base.

    Parameters:
     knowledge_dir - directory containing markdown knowledge documents

    Returns:
     Repository for listing, reading, and writing knowledge documents

    Raises:
     None
    """

    def __init__(
        self,
        knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR,
        vector_indexer: KnowledgeVectorIndexer | None = None,
    ) -> None:
        """
        Initialize the knowledge repository.

        Parameters:
         knowledge_dir - directory containing markdown knowledge documents
         vector_indexer - optional vector indexer replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.knowledge_dir = knowledge_dir
        self.vector_indexer = vector_indexer

    def list_documents(self) -> list[KnowledgeDocument]:
        """
        List all local knowledge documents.

        Parameters:
         None

        Returns:
         Structured knowledge documents loaded from disk

        Raises:
         None
        """

        return KnowledgeLoader(self.knowledge_dir).load_documents()

    def get_document(self, source: str) -> KnowledgeDocument | None:
        """
        Read one local knowledge document by source file name.

        Parameters:
         source - markdown source file name

        Returns:
         Knowledge document when it exists, otherwise None

        Raises:
         None
        """

        safe_name = self.safe_filename(source)
        file_path = self.knowledge_dir / safe_name

        if not file_path.exists():
            return None

        documents = KnowledgeLoader(self.knowledge_dir).load_documents()

        for document in documents:
            if document.source == safe_name:
                return document

        return None

    def save_document(
        self,
        filename: str,
        content: str,
        overwrite: bool = False,
    ) -> KnowledgeUploadResponse:
        """
        Save one markdown document into the local knowledge base.

        Parameters:
         filename - requested markdown file name
         content - markdown document content
         overwrite - whether an existing file may be replaced

        Returns:
         Upload response containing saved document metadata

        Raises:
         FileExistsError - raised when target exists and overwrite is false
         ValueError - raised when filename or content is invalid
        """

        safe_name = self.safe_filename(filename)

        if not content.strip():
            raise ValueError("Knowledge document content cannot be empty")

        self.knowledge_dir.mkdir(parents=True, exist_ok=True)
        file_path = self.knowledge_dir / safe_name
        existed = file_path.exists()

        if existed and not overwrite:
            raise FileExistsError(f"Knowledge document already exists: {safe_name}")

        file_path.write_text(content, encoding="utf-8")
        document = self.get_document(safe_name)
        loader = KnowledgeLoader(self.knowledge_dir)
        chunks = [chunk for chunk in loader.load_chunks() if chunk.source == safe_name]
        vector_result = self._index_saved_document(loader, safe_name)

        return KnowledgeUploadResponse(
            source=safe_name,
            doc_id=document.doc_id if document else file_path.stem,
            title=document.title if document else file_path.stem,
            category=document.category if document else "general",
            tags=document.tags if document else [],
            chunk_count=len(chunks),
            overwritten=existed and overwrite,
            vector_indexed=vector_result.indexed,
            vector_chunks_written=vector_result.chunks_written,
            vector_status=vector_result.status,
            message=self._upload_message(vector_result.reason),
        )

    def safe_filename(self, filename: str) -> str:
        """
        Normalize and validate a markdown file name.

        Parameters:
         filename - requested file name

        Returns:
         Safe markdown file name

        Raises:
         ValueError - raised when the filename is invalid
        """

        raw_name = Path(filename).name.strip()

        if not raw_name:
            raise ValueError("Knowledge document filename is required")

        if not raw_name.lower().endswith(".md"):
            raw_name = f"{raw_name}.md"

        safe_name = re.sub(r"[^\w.-]+", "_", raw_name, flags=re.UNICODE)
        safe_name = safe_name.strip("._")

        if not safe_name or safe_name.lower() == "md":
            raise ValueError("Knowledge document filename is invalid")

        if not safe_name.lower().endswith(".md"):
            safe_name = f"{safe_name}.md"

        return safe_name

    def _index_saved_document(
        self,
        loader: KnowledgeLoader,
        source: str,
    ):
        """
        Index a saved document into vector storage when configured.

        Parameters:
         loader - loader scoped to the current knowledge directory
         source - saved markdown source file name

        Returns:
         Vector indexing result

        Raises:
         None
        """

        indexer = self.vector_indexer or KnowledgeVectorIndexer(loader=loader)
        return indexer.index_source(source)

    def _upload_message(self, vector_reason: str) -> str:
        """
        Build a user-facing upload message without exposing storage internals.

        Parameters:
         vector_reason - backend vector indexing result reason

        Returns:
         Upload response message

        Raises:
         None
        """

        return (
            "Knowledge document saved. BM25 retrieval is available immediately. "
            f"{vector_reason}"
        )
