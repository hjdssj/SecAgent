import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.embedding.client import EmbeddingClient
from app.milvus.client import MilvusKnowledgeClient
from app.rag.knowledge_loader import KnowledgeLoader


def rebuild_knowledge_vectors(recreate: bool = False) -> int:
    """
    Rebuild Milvus vectors for local knowledge base chunks.

    Parameters:
     recreate - whether to recreate the knowledge collection before writing

    Returns:
     Number of chunks written to Milvus

    Raises:
     None
    """

    chunks = KnowledgeLoader().load_chunks()

    if not chunks:
        print("No knowledge chunks found.")
        return 0

    embedding_client = EmbeddingClient()

    if not embedding_client.available():
        print("Embedding is not configured. Set EMBEDDING_ENABLED=true and credentials.")
        return 0

    milvus_client = MilvusKnowledgeClient()

    if not milvus_client.available():
        print("Milvus is not available. Set MILVUS_ENABLED=true and start Milvus.")
        return 0

    if not milvus_client.ensure_knowledge_collection(recreate=recreate):
        print("Failed to prepare Milvus knowledge collection.")
        return 0

    texts = [
        "\n".join(
            [
                chunk.title,
                chunk.category,
                " ".join(chunk.tags),
                chunk.content,
            ]
        )
        for chunk in chunks
    ]
    embeddings = embedding_client.embed_texts(texts)

    if len(embeddings) != len(chunks):
        print("Embedding count does not match chunk count.")
        return 0

    written = milvus_client.upsert_knowledge_chunks(chunks, embeddings)
    print(f"written knowledge vectors: {written}")
    return written


def main() -> None:
    """
    Run knowledge vector rebuild from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = argparse.ArgumentParser(description="Rebuild SecAgent knowledge vectors.")
    parser.add_argument("--recreate", action="store_true")
    args = parser.parse_args()
    rebuild_knowledge_vectors(recreate=args.recreate)


if __name__ == "__main__":
    main()
