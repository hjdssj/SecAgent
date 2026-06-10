import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.embedding.client import EmbeddingClient
from app.milvus.client import MilvusKnowledgeClient
from app.rag.bm25_retriever import BM25Retriever
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.knowledge_loader import KnowledgeLoader
from app.rag.schemas import KnowledgeChunk, RetrievalResult


@dataclass(frozen=True)
class RetrievalCase:
    """
    Represent one labeled retrieval benchmark query.

    Parameters:
     name - benchmark case name
     query - retrieval query text
     expected_terms - terms that should appear in a relevant chunk

    Returns:
     Labeled retrieval benchmark case

    Raises:
     None
    """

    name: str
    query: str
    expected_terms: tuple[str, ...]


@dataclass
class RetrievalMetrics:
    """
    Represent aggregate retrieval benchmark metrics.

    Parameters:
     mode - retrieval mode name
     available - whether the mode could run
     case_count - number of evaluated benchmark cases
     top1_accuracy - fraction of cases with a relevant top-1 result
     topk_accuracy - fraction of cases with a relevant result in top-k
     mrr - mean reciprocal rank
     avg_latency_ms - average retrieval latency in milliseconds
     details - per-case benchmark details
     skipped_reason - optional skipped reason

    Returns:
     Aggregate benchmark metrics

    Raises:
     None
    """

    mode: str
    available: bool
    case_count: int = 0
    top1_accuracy: float = 0.0
    topk_accuracy: float = 0.0
    mrr: float = 0.0
    avg_latency_ms: float = 0.0
    details: list[dict] | None = None
    skipped_reason: str | None = None


BENCHMARK_CASES = [
    RetrievalCase(
        name="sqli_login",
        query="login OR 1=1 union select sqlmap CRS 942 database parameterized query",
        expected_terms=("sql injection", "sqli", "942"),
    ),
    RetrievalCase(
        name="xss_search",
        query="search q script alert javascript onerror CRS 941 output encoding CSP",
        expected_terms=("xss", "cross site scripting", "941"),
    ),
    RetrievalCase(
        name="path_traversal_download",
        query="download file ../../etc/passwd directory traversal arbitrary file read CRS 930",
        expected_terms=("path traversal", "directory traversal", "930"),
    ),
    RetrievalCase(
        name="command_injection",
        query="cmd whoami id shell command injection remote code execution CRS 932",
        expected_terms=("command injection", "932", "t1059"),
    ),
    RetrievalCase(
        name="scanner_detection",
        query="sqlmap nikto acunetix nessus automated scanner CRS 913",
        expected_terms=("scanner", "913", "automated scanner"),
    ),
    RetrievalCase(
        name="mitre_public_app",
        query="public facing web application exploit attack chain MITRE T1190",
        expected_terms=("t1190", "exploit public-facing application"),
    ),
    RetrievalCase(
        name="remediation_sql",
        query="how to fix SQL injection use ORM parameterized queries least privilege",
        expected_terms=("parameterized", "sql injection", "database"),
    ),
]


def run_benchmark(top_k: int = 4) -> dict:
    """
    Run BM25-only and Milvus-enabled hybrid retrieval benchmark.

    Parameters:
     top_k - maximum number of retrieval results evaluated per query

    Returns:
     Benchmark result dictionary

    Raises:
     None
    """

    chunks = KnowledgeLoader().load_chunks()

    if not chunks:
        return {
            "case_count": 0,
            "error": "No knowledge chunks found.",
            "results": [],
        }

    bm25_metrics = evaluate_mode(
        mode="bm25_only",
        cases=BENCHMARK_CASES,
        chunks=chunks,
        searcher=BM25Retriever(chunks),
        top_k=top_k,
    )
    hybrid_metrics = evaluate_milvus_hybrid(chunks=chunks, top_k=top_k)

    return {
        "case_count": len(BENCHMARK_CASES),
        "chunk_count": len(chunks),
        "top_k": top_k,
        "results": [
            metrics_to_dict(bm25_metrics),
            metrics_to_dict(hybrid_metrics),
        ],
    }


def evaluate_milvus_hybrid(chunks: list[KnowledgeChunk], top_k: int) -> RetrievalMetrics:
    """
    Evaluate hybrid retrieval only when embedding and Milvus are available.

    Parameters:
     chunks - loaded knowledge chunks
     top_k - maximum number of retrieval results evaluated per query

    Returns:
     Hybrid retrieval metrics or skipped metrics

    Raises:
     None
    """

    embedding_client = EmbeddingClient()

    if not embedding_client.available():
        return RetrievalMetrics(
            mode="hybrid_milvus",
            available=False,
            skipped_reason="EMBEDDING_UNAVAILABLE",
        )

    milvus_client = MilvusKnowledgeClient()

    if not milvus_client.available():
        return RetrievalMetrics(
            mode="hybrid_milvus",
            available=False,
            skipped_reason="MILVUS_UNAVAILABLE",
        )

    return evaluate_mode(
        mode="hybrid_milvus",
        cases=BENCHMARK_CASES,
        chunks=chunks,
        searcher=HybridRetriever(chunks),
        top_k=top_k,
    )


def evaluate_mode(
    mode: str,
    cases: list[RetrievalCase],
    chunks: list[KnowledgeChunk],
    searcher,
    top_k: int,
) -> RetrievalMetrics:
    """
    Evaluate one retrieval mode on labeled benchmark cases.

    Parameters:
     mode - retrieval mode name
     cases - labeled benchmark cases
     chunks - loaded knowledge chunks
     searcher - object with a search(query, top_k) method
     top_k - maximum number of retrieval results evaluated per query

    Returns:
     Aggregate retrieval metrics

    Raises:
     None
    """

    details = []
    latencies = []
    top1_hits = 0
    topk_hits = 0
    reciprocal_ranks = []

    for case in cases:
        started = time.perf_counter()
        results = searcher.search(case.query, top_k=top_k)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        latencies.append(latency_ms)
        rank = first_relevant_rank(results, case.expected_terms)

        if rank == 1:
            top1_hits += 1

        if rank is not None:
            topk_hits += 1
            reciprocal_ranks.append(1 / rank)
        else:
            reciprocal_ranks.append(0)

        details.append(
            {
                "case": case.name,
                "query": case.query,
                "expected_terms": list(case.expected_terms),
                "latency_ms": latency_ms,
                "first_relevant_rank": rank,
                "top_results": [
                    {
                        "rank": index,
                        "title": result.chunk.title,
                        "source": result.chunk.source,
                        "category": result.chunk.category,
                        "score": result.score,
                        "retrieval_type": result.retrieval_type,
                        "reason": result.reason,
                    }
                    for index, result in enumerate(results, start=1)
                ],
            }
        )

    case_count = len(cases)
    return RetrievalMetrics(
        mode=mode,
        available=True,
        case_count=case_count,
        top1_accuracy=round(top1_hits / case_count, 4),
        topk_accuracy=round(topk_hits / case_count, 4),
        mrr=round(sum(reciprocal_ranks) / case_count, 4),
        avg_latency_ms=round(statistics.mean(latencies), 2) if latencies else 0.0,
        details=details,
    )


def first_relevant_rank(
    results: list[RetrievalResult],
    expected_terms: tuple[str, ...],
) -> int | None:
    """
    Return the rank of the first relevant retrieval result.

    Parameters:
     results - retrieval results ranked by the searcher
     expected_terms - terms that identify a relevant chunk

    Returns:
     One-based rank or None when no result is relevant

    Raises:
     None
    """

    for index, result in enumerate(results, start=1):
        if is_relevant(result.chunk, expected_terms):
            return index

    return None


def is_relevant(chunk: KnowledgeChunk, expected_terms: tuple[str, ...]) -> bool:
    """
    Decide whether a chunk matches benchmark relevance labels.

    Parameters:
     chunk - retrieved knowledge chunk
     expected_terms - expected relevance terms

    Returns:
     True when any expected term appears in title, source, category, tags, keywords, or content

    Raises:
     None
    """

    haystack = " ".join(
        [
            chunk.title,
            chunk.source,
            chunk.category,
            " ".join(chunk.tags),
            " ".join(chunk.keywords),
            chunk.content,
        ]
    ).lower()
    return any(term.lower() in haystack for term in expected_terms)


def metrics_to_dict(metrics: RetrievalMetrics) -> dict:
    """
    Convert metrics object into a JSON-serializable dictionary.

    Parameters:
     metrics - retrieval metrics

    Returns:
     JSON-serializable metrics dictionary

    Raises:
     None
    """

    return {
        "mode": metrics.mode,
        "available": metrics.available,
        "case_count": metrics.case_count,
        "top1_accuracy": metrics.top1_accuracy,
        "topk_accuracy": metrics.topk_accuracy,
        "mrr": metrics.mrr,
        "avg_latency_ms": metrics.avg_latency_ms,
        "skipped_reason": metrics.skipped_reason,
        "details": metrics.details or [],
    }


def print_summary(result: dict) -> None:
    """
    Print a readable benchmark summary.

    Parameters:
     result - benchmark result dictionary

    Returns:
     None

    Raises:
     None
    """

    print(
        f"RAG retrieval benchmark: cases={result.get('case_count', 0)}, "
        f"chunks={result.get('chunk_count', 0)}, top_k={result.get('top_k', 0)}"
    )

    for item in result.get("results", []):
        if not item["available"]:
            print(f"- {item['mode']}: skipped ({item['skipped_reason']})")
            continue

        print(
            f"- {item['mode']}: top1={item['top1_accuracy']:.2%}, "
            f"topK={item['topk_accuracy']:.2%}, mrr={item['mrr']:.4f}, "
            f"avg_latency={item['avg_latency_ms']}ms"
        )


def main() -> None:
    """
    Run retrieval benchmark from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = argparse.ArgumentParser(description="Benchmark SecAgent RAG retrieval.")
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run_benchmark(top_k=args.top_k)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print_summary(result)


if __name__ == "__main__":
    main()
