import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.knowledge_repository import KnowledgeRepository
from app.rag.vector_indexer import KnowledgeVectorIndexResult


class FakeVectorIndexer:
    """
    Record knowledge vector indexing calls for repository tests.

    Parameters:
     result - indexing result returned to the repository

    Returns:
     Fake vector indexer

    Raises:
     None
    """

    def __init__(self, result: KnowledgeVectorIndexResult | None = None) -> None:
        """
        Initialize fake vector indexer state.

        Parameters:
         result - indexing result returned to the repository

        Returns:
         None

        Raises:
         None
        """

        self.result = result or KnowledgeVectorIndexResult(
            attempted=True,
            indexed=True,
            chunks_written=1,
            status="indexed",
            reason="Indexed 1 knowledge chunks into vector storage.",
        )
        self.sources: list[str] = []

    def index_source(self, source: str) -> KnowledgeVectorIndexResult:
        """
        Record the indexed source and return the configured result.

        Parameters:
         source - source requested for indexing

        Returns:
         Configured vector indexing result

        Raises:
         None
        """

        self.sources.append(source)
        return self.result


def test_knowledge_repository_saves_and_loads_markdown(tmp_path: Path) -> None:
    """
    Verify uploaded markdown is saved and exposed as a knowledge document.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory

    Returns:
     None

    Raises:
     None
    """

    repository = KnowledgeRepository(tmp_path)

    result = repository.save_document(
        filename="../Demo Knowledge.md",
        content="# Demo Knowledge\n\n## SQL Injection\n\nkeywords: sqli 942\n\nUse parameterized queries.",
    )

    document = repository.get_document(result.source)

    assert result.source == "Demo_Knowledge.md"
    assert result.title == "Demo Knowledge"
    assert result.chunk_count >= 1
    assert result.overwritten is False
    assert result.vector_indexed is False
    assert result.vector_status == "embedding_unavailable"
    assert document is not None
    assert "SQL Injection" in document.content

    chinese_result = repository.save_document(
        filename="应急响应手册.md",
        content="# 应急响应手册\n\n## SQL 注入\n\n记录封禁和回滚流程。",
    )

    assert chinese_result.source == "应急响应手册.md"


def test_knowledge_repository_rejects_duplicate_without_overwrite(tmp_path: Path) -> None:
    """
    Verify duplicate uploads require explicit overwrite.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory

    Returns:
     None

    Raises:
     None
    """

    repository = KnowledgeRepository(tmp_path)
    repository.save_document("playbook.md", "# Playbook\n\nfirst")

    with pytest.raises(FileExistsError):
        repository.save_document("playbook.md", "# Playbook\n\nsecond")

    result = repository.save_document("playbook.md", "# Playbook\n\nsecond", overwrite=True)

    assert result.overwritten is True
    assert repository.get_document("playbook.md") is not None


def test_knowledge_repository_validates_upload_input(tmp_path: Path) -> None:
    """
    Verify invalid upload input is rejected before writing to disk.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory

    Returns:
     None

    Raises:
     None
    """

    repository = KnowledgeRepository(tmp_path)

    with pytest.raises(ValueError):
        repository.save_document("", "# Missing Filename")

    with pytest.raises(ValueError):
        repository.save_document("empty.md", "   ")


def test_knowledge_repository_indexes_saved_document_with_configured_indexer(tmp_path: Path) -> None:
    """
    Verify saving a document attempts backend vector indexing.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory

    Returns:
     None

    Raises:
     None
    """

    indexer = FakeVectorIndexer()
    repository = KnowledgeRepository(tmp_path, vector_indexer=indexer)

    result = repository.save_document(
        filename="vector-demo.md",
        content="# Vector Demo\n\n## SSRF\n\nmetadata endpoint 169.254.169.254",
    )

    assert indexer.sources == ["vector-demo.md"]
    assert result.vector_indexed is True
    assert result.vector_chunks_written == 1
    assert result.vector_status == "indexed"
