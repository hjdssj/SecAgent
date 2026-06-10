import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.rag.vector_indexer import KnowledgeVectorIndexer


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

    result = KnowledgeVectorIndexer().index_all(recreate=recreate)

    print(result.reason)
    return result.chunks_written


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
