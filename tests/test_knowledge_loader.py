import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.knowledge_loader import KnowledgeLoader


def test_knowledge_loader_builds_documents_and_chunks() -> None:
    """
    Verify knowledge loader returns structured documents and searchable chunks.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    loader = KnowledgeLoader()

    documents = loader.load_documents()
    chunks = loader.load_chunks()

    assert documents
    assert chunks
    assert any(document.category == "attack" for document in documents)
    assert any(chunk.chunk_id and chunk.doc_id for chunk in chunks)
    assert any("sqli" in chunk.tags or "942" in chunk.tags for chunk in chunks)
