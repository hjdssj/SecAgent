import re

from app.context.schemas import ContextChunk, ContextReference


class ContextRetriever:
    """
    Retrieve enterprise context chunks with deterministic scoring.

    Parameters:
     chunks - searchable enterprise context chunks

    Returns:
     A context retriever for auto triage

    Raises:
     None
    """

    def __init__(self, chunks: list[ContextChunk]) -> None:
        """
        Initialize the context retriever.

        Parameters:
         chunks - searchable enterprise context chunks

        Returns:
         None

        Raises:
         None
        """

        self.chunks = chunks

    def search(self, query: str, top_k: int = 6) -> list[ContextReference]:
        """
        Search enterprise context chunks.

        Parameters:
         query - retrieval query containing source IP, target, rule, and attack context
         top_k - maximum number of context references

        Returns:
         Ranked context references

        Raises:
         None
        """

        query_terms = self._keywords(query)
        references: list[ContextReference] = []

        for chunk in self.chunks:
            score, matched = self._score(chunk, query_terms, query)

            if score <= 0:
                continue

            references.append(
                ContextReference(
                    source=chunk.source,
                    title=chunk.title,
                    category=chunk.category,
                    snippet=self._snippet(chunk.content),
                    score=round(score, 4),
                    metadata=chunk.metadata,
                    reason=f"Context matched: {', '.join(matched[:6])}",
                )
            )

        return sorted(references, key=lambda item: item.score, reverse=True)[:top_k]

    def _score(
        self,
        chunk: ContextChunk,
        query_terms: list[str],
        raw_query: str,
    ) -> tuple[float, list[str]]:
        """
        Score one context chunk against query terms and exact metadata.

        Parameters:
         chunk - context chunk being scored
         query_terms - normalized query terms
         raw_query - original query text

        Returns:
         Score and matched terms

        Raises:
         None
        """

        score = 0.0
        matched: list[str] = []
        chunk_terms = set(chunk.keywords)

        for term in query_terms:
            if term in chunk_terms:
                score += 1.0
                matched.append(term)

        for key in ["path", "ip", "rule_prefix", "attack_type"]:
            value = chunk.metadata.get(key)

            if value and value.lower() in raw_query.lower():
                score += 8.0
                matched.append(f"{key}={value}")

        owned_paths = chunk.metadata.get("owned_paths", "")
        for path in [item.strip() for item in owned_paths.split(",") if item.strip()]:
            if path.lower() in raw_query.lower():
                score += 5.0
                matched.append(f"owned_path={path}")

        return score, list(dict.fromkeys(matched))

    def _keywords(self, text: str) -> list[str]:
        """
        Extract normalized search terms.

        Parameters:
         text - source text used for keyword extraction

        Returns:
         List of lowercase search terms

        Raises:
         None
        """

        return re.findall(r"[a-z0-9_./'-]+", text.lower())

    def _snippet(self, content: str, max_length: int = 180) -> str:
        """
        Build a compact context snippet.

        Parameters:
         content - context content
         max_length - maximum snippet length

        Returns:
         Compact one-line snippet

        Raises:
         None
        """

        text = re.sub(r"\s+", " ", content).strip()
        return text[:max_length]
