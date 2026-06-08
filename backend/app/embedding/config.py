from app.core.config import get_bool_env, get_env, get_float_env, get_int_env


class EmbeddingConfig:
    """
    Store runtime configuration for embedding generation.

    Parameters:
     None

    Returns:
     Embedding configuration loaded from environment variables

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize embedding configuration from environment variables.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.enabled = get_bool_env("EMBEDDING_ENABLED", False)
        self.provider = get_env("EMBEDDING_PROVIDER", "dashscope")
        self.model = get_env("EMBEDDING_MODEL", "text-embedding-v4")
        self.api_key = get_env("EMBEDDING_API_KEY") or get_env("DASHSCOPE_API_KEY")
        self.base_url = get_env("EMBEDDING_BASE_URL") or get_env(
            "DASHSCOPE_EMBEDDING_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        self.dimension = get_int_env("EMBEDDING_DIMENSION", 1024)
        self.timeout_seconds = get_float_env("EMBEDDING_TIMEOUT_SECONDS", 30.0)
        self.batch_size = get_int_env("EMBEDDING_BATCH_SIZE", 16)


def load_embedding_config() -> EmbeddingConfig:
    """
    Load embedding configuration from environment variables.

    Parameters:
     None

    Returns:
     Embedding configuration object

    Raises:
     None
    """

    return EmbeddingConfig()
