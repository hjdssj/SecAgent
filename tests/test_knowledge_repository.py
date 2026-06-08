import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.knowledge_repository import KnowledgeRepository


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
