from app.core.config import get_bool_env, get_env, get_int_env


class MilvusConfig:
    """
    Store runtime configuration for optional Milvus vector storage.

    Parameters:
     None

    Returns:
     Milvus configuration loaded from environment variables

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize Milvus configuration from environment variables.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.enabled = get_bool_env("MILVUS_ENABLED", False)
        self.host = get_env("MILVUS_HOST", "localhost")
        self.port = get_int_env("MILVUS_PORT", 19530)
        self.user = get_env("MILVUS_USER")
        self.password = get_env("MILVUS_PASSWORD")
        self.database = get_env("MILVUS_DATABASE", "default")
        self.knowledge_collection = get_env(
            "MILVUS_KNOWLEDGE_COLLECTION",
            "secagent_knowledge_chunks",
        )
        self.memory_collection = get_env(
            "MILVUS_MEMORY_COLLECTION",
            "secagent_analysis_memory",
        )
        self.metric_type = get_env("MILVUS_METRIC_TYPE", "COSINE")
        self.index_type = get_env("MILVUS_INDEX_TYPE", "AUTOINDEX")
        self.top_k = get_int_env("MILVUS_TOP_K", 5)
        self.embedding_dimension = get_int_env("EMBEDDING_DIMENSION", 1024)


def load_milvus_config() -> MilvusConfig:
    """
    Load Milvus configuration from environment variables.

    Parameters:
     None

    Returns:
     Milvus configuration object

    Raises:
     None
    """

    return MilvusConfig()
