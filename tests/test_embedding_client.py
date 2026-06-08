import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.embedding.client import EmbeddingClient
from app.embedding.config import EmbeddingConfig


def test_embedding_client_disabled_returns_empty_vectors() -> None:
    """
    Verify disabled embedding config does not call external providers.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = EmbeddingConfig()
    config.enabled = False
    config.api_key = "key"
    config.base_url = "http://embedding"
    client = EmbeddingClient(config=config)

    assert client.available() is False
    assert client.embed_text("hello") is None
    assert client.embed_texts(["hello"]) == []


def test_embedding_url_appends_embeddings_path() -> None:
    """
    Verify embedding endpoint URL is derived from base URL.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    config = EmbeddingConfig()
    config.base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    client = EmbeddingClient(config=config)

    assert client._embeddings_url().endswith("/embeddings")
