import math
import re
from collections import Counter

from app.rag.schemas import KnowledgeChunk, RetrievalResult


class BM25Retriever:
    """
    Retrieve knowledge chunks with a lightweight BM25 ranking algorithm.

    Parameters:
     chunks - searchable knowledge chunks loaded from the local knowledge base
     k1 - term frequency saturation parameter
     b - document length normalization parameter

    Returns:
     A BM25 retriever instance for local security knowledge

    Raises:
     None
    """

    def __init__(
        self,
        chunks: list[KnowledgeChunk],
        k1: float = 1.5,
        b: float = 0.75,
    ) -> None:
        """
        Initialize the BM25 retriever and precompute corpus statistics.

        Parameters:
         chunks - searchable knowledge chunks loaded from the local knowledge base
         k1 - term frequency saturation parameter
         b - document length normalization parameter

        Returns:
         None

        Raises:
         None
        """

        self.chunks = chunks
        self.k1 = k1
        self.b = b
        self._doc_terms = [self._terms_for_chunk(chunk) for chunk in chunks]
        self._doc_lengths = [len(terms) for terms in self._doc_terms]
        self._avg_doc_length = (
            sum(self._doc_lengths) / len(self._doc_lengths)
            if self._doc_lengths
            else 0.0
        )
        self._document_frequency = self._build_document_frequency()

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[RetrievalResult]:
        """
        Search knowledge chunks with BM25 scoring.

        Parameters:
         query - retrieval query text
         top_k - maximum number of retrieval results
         filters - optional chunk metadata filters

        Returns:
         Ranked retrieval results

        Raises:
         None
        """

        query_terms = self._tokenize(query)

        if not query_terms:
            return []

        results: list[RetrievalResult] = []

        for index, chunk in enumerate(self.chunks):
            if not self._matches_filters(chunk, filters):
                continue

            score = self._score(query_terms, index)

            if score <= 0:
                continue

            matched_terms = self._matched_terms(query_terms, index)
            results.append(
                RetrievalResult(
                    chunk=chunk,
                    score=round(score, 4),
                    retrieval_type="bm25",
                    reason=f"BM25 matched terms: {', '.join(matched_terms[:6])}",
                )
            )

        return sorted(results, key=lambda item: item.score, reverse=True)[:top_k]

    def _score(self, query_terms: list[str], index: int) -> float:
        """
        Calculate BM25 score for one chunk.

        Parameters:
         query_terms - tokenized query terms
         index - chunk index in the local corpus

        Returns:
         BM25 score

        Raises:
         None
        """

        terms = self._doc_terms[index]
        term_counts = Counter(terms)
        doc_length = self._doc_lengths[index]
        score = 0.0

        for term in query_terms:
            if term not in term_counts:
                continue

            idf = self._idf(term)
            frequency = term_counts[term]
            numerator = frequency * (self.k1 + 1)
            denominator = frequency + self.k1 * (
                1 - self.b + self.b * doc_length / max(self._avg_doc_length, 1.0)
            )
            score += idf * numerator / denominator

        return score

    def _idf(self, term: str) -> float:
        """
        Calculate inverse document frequency for one term.

        Parameters:
         term - normalized term

        Returns:
         Smoothed inverse document frequency

        Raises:
         None
        """

        corpus_size = len(self.chunks)
        document_frequency = self._document_frequency.get(term, 0)
        return math.log(1 + (corpus_size - document_frequency + 0.5) / (document_frequency + 0.5))

    def _build_document_frequency(self) -> dict[str, int]:
        """
        Build document frequency statistics for the local corpus.

        Parameters:
         None

        Returns:
         Mapping from term to number of chunks containing that term

        Raises:
         None
        """

        document_frequency: dict[str, int] = {}

        for terms in self._doc_terms:
            for term in set(terms):
                document_frequency[term] = document_frequency.get(term, 0) + 1

        return document_frequency

    def _terms_for_chunk(self, chunk: KnowledgeChunk) -> list[str]:
        """
        Build searchable terms for one knowledge chunk.

        Parameters:
         chunk - knowledge chunk used for retrieval

        Returns:
         Token list including content, title, source, category, and tags

        Raises:
         None
        """

        text = " ".join(
            [
                chunk.title,
                chunk.content,
                chunk.source,
                chunk.category,
                " ".join(chunk.tags),
                " ".join(chunk.keywords),
            ]
        )
        return self._tokenize(text)

    def _matched_terms(self, query_terms: list[str], index: int) -> list[str]:
        """
        Return query terms that appeared in one chunk.

        Parameters:
         query_terms - tokenized query terms
         index - chunk index in the local corpus

        Returns:
         Ordered list of matched terms

        Raises:
         None
        """

        chunk_terms = set(self._doc_terms[index])
        return list(dict.fromkeys(term for term in query_terms if term in chunk_terms))

    def _matches_filters(
        self,
        chunk: KnowledgeChunk,
        filters: dict[str, str] | None,
    ) -> bool:
        """
        Check whether a chunk satisfies optional metadata filters.

        Parameters:
         chunk - knowledge chunk being considered
         filters - optional metadata filters

        Returns:
         True when the chunk matches all filters

        Raises:
         None
        """

        if not filters:
            return True

        for key, value in filters.items():
            if getattr(chunk, key, None) != value:
                return False

        return True

    def _tokenize(self, text: str) -> list[str]:
        """
        Tokenize mixed security text into normalized retrieval terms.

        Parameters:
         text - source text to tokenize

        Returns:
         Normalized token list

        Raises:
         None
        """

        return re.findall(r"[a-z0-9_./'-]+", text.lower())
