import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.embedding.config import EmbeddingConfig, load_embedding_config


class EmbeddingClient:
    """
    Generate text embeddings through an OpenAI-compatible embeddings endpoint.

    Parameters:
     config - optional embedding runtime configuration

    Returns:
     Embedding client with safe disabled fallback behavior

    Raises:
     None
    """

    def __init__(self, config: EmbeddingConfig | None = None) -> None:
        """
        Initialize the embedding client.

        Parameters:
         config - optional embedding runtime configuration

        Returns:
         None

        Raises:
         None
        """

        self.config = config or load_embedding_config()

    def available(self) -> bool:
        """
        Return whether embedding calls are configured.

        Parameters:
         None

        Returns:
         True when embedding is enabled and credentials are present

        Raises:
         None
        """

        return bool(
            self.config.enabled
            and self.config.api_key
            and self.config.base_url
            and self.config.model
        )

    def embed_text(self, text: str) -> list[float] | None:
        """
        Generate an embedding for one text.

        Parameters:
         text - source text to embed

        Returns:
         Embedding vector when available, otherwise None

        Raises:
         None
        """

        vectors = self.embed_texts([text])

        if not vectors:
            return None

        return vectors[0]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """
        Generate embeddings for a list of texts.

        Parameters:
         texts - source texts to embed

        Returns:
         List of embedding vectors, or empty list when unavailable

        Raises:
         None
        """

        if not texts or not self.available():
            return []

        url = self._embeddings_url()
        payload = {
            "model": self.config.model,
            "input": texts,
        }
        request = Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            return []

        vectors: list[list[float]] = []

        for item in data.get("data", []):
            vector = item.get("embedding")

            if not isinstance(vector, list):
                continue

            vectors.append([float(value) for value in vector])

        return vectors

    def _embeddings_url(self) -> str:
        """
        Build the embeddings endpoint URL.

        Parameters:
         None

        Returns:
         Full embeddings URL

        Raises:
         None
        """

        base_url = self.config.base_url.rstrip("/")

        if base_url.endswith("/embeddings"):
            return base_url

        return f"{base_url}/embeddings"
