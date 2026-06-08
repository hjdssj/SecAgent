import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.api import knowledge as knowledge_api
from app.main import app
from app.rag.knowledge_repository import KnowledgeRepository


class DummyRAGAgent:
    """
    Track whether the knowledge API refreshes the active RAG cache.

    Parameters:
     None

    Returns:
     Dummy RAG cache object for API tests

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize refresh tracking.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.refreshed = False

    def refresh(self) -> None:
        """
        Mark the cache as refreshed.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.refreshed = True


class DummyOrchestrator:
    """
    Provide the minimal orchestrator surface used by the knowledge API.

    Parameters:
     rag_agent - RAG cache object exposed to API handlers

    Returns:
     Dummy orchestrator for API tests

    Raises:
     None
    """

    def __init__(self, rag_agent: DummyRAGAgent) -> None:
        """
        Initialize the dummy orchestrator.

        Parameters:
         rag_agent - RAG cache object exposed to API handlers

        Returns:
         None

        Raises:
         None
        """

        self.rag_agent = rag_agent


def test_knowledge_api_uploads_json_document(tmp_path: Path, monkeypatch) -> None:
    """
    Verify JSON uploads write a markdown document and refresh RAG cache.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory
     monkeypatch - pytest fixture used to replace module-level API dependencies

    Returns:
     None

    Raises:
     None
    """

    rag_agent = DummyRAGAgent()
    monkeypatch.setattr(knowledge_api, "repository", KnowledgeRepository(tmp_path))
    monkeypatch.setattr(knowledge_api, "orchestrator", DummyOrchestrator(rag_agent))

    client = TestClient(app)
    response = client.post(
        "/api/knowledge/documents",
        json={
            "filename": "demo.md",
            "content": "# Demo\n\n## XSS\n\nkeywords: xss 941\n\nEscape output.",
            "overwrite": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "demo.md"
    assert data["title"] == "Demo"
    assert data["chunk_count"] >= 1
    assert rag_agent.refreshed is True

    document_response = client.get("/api/knowledge/documents/demo.md")
    assert document_response.status_code == 200
    assert "Escape output" in document_response.json()["content"]


def test_knowledge_api_rejects_duplicate_without_overwrite(tmp_path: Path, monkeypatch) -> None:
    """
    Verify duplicate JSON uploads return a conflict response.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory
     monkeypatch - pytest fixture used to replace module-level API dependencies

    Returns:
     None

    Raises:
     None
    """

    repository = KnowledgeRepository(tmp_path)
    repository.save_document("demo.md", "# Demo\n\nfirst")
    monkeypatch.setattr(knowledge_api, "repository", repository)

    client = TestClient(app)
    response = client.post(
        "/api/knowledge/documents",
        json={
            "filename": "demo.md",
            "content": "# Demo\n\nsecond",
            "overwrite": False,
        },
    )

    assert response.status_code == 409


def test_knowledge_api_uploads_markdown_file(tmp_path: Path, monkeypatch) -> None:
    """
    Verify multipart uploads accept UTF-8 markdown files.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory
     monkeypatch - pytest fixture used to replace module-level API dependencies

    Returns:
     None

    Raises:
     None
    """

    rag_agent = DummyRAGAgent()
    monkeypatch.setattr(knowledge_api, "repository", KnowledgeRepository(tmp_path))
    monkeypatch.setattr(knowledge_api, "orchestrator", DummyOrchestrator(rag_agent))

    client = TestClient(app)
    response = client.post(
        "/api/knowledge/documents/upload",
        data={"overwrite": "false"},
        files={"file": ("upload.md", b"# Upload\n\n## Path Traversal\n\nkeywords: traversal 930")},
    )

    assert response.status_code == 200
    assert response.json()["source"] == "upload.md"
    assert rag_agent.refreshed is True


def test_knowledge_api_rejects_non_markdown_file(tmp_path: Path, monkeypatch) -> None:
    """
    Verify multipart uploads reject non-markdown files.

    Parameters:
     tmp_path - pytest fixture used to create an isolated knowledge directory
     monkeypatch - pytest fixture used to replace module-level API dependencies

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setattr(knowledge_api, "repository", KnowledgeRepository(tmp_path))

    client = TestClient(app)
    response = client.post(
        "/api/knowledge/documents/upload",
        data={"overwrite": "false"},
        files={"file": ("upload.txt", b"plain text")},
    )

    assert response.status_code == 422
