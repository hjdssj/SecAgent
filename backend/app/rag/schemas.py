from pydantic import BaseModel, Field


class KnowledgeDocument(BaseModel):
    """
    Represent one original security knowledge document.

    Parameters:
     doc_id - stable document identifier derived from the source file
     title - human-readable document title
     category - document category such as attack, mitre, waf_rule, cve, or remediation
     source - source file name or external source name
     tags - security labels used for filtering and query expansion
     content - full document content

    Returns:
     A structured security knowledge document

    Raises:
     None
    """

    doc_id: str
    title: str
    category: str
    source: str
    tags: list[str] = Field(default_factory=list)
    content: str


class KnowledgeUploadRequest(BaseModel):
    """
    Represent a markdown knowledge document upload request.

    Parameters:
     filename - requested markdown file name
     content - markdown document content
     overwrite - whether an existing document may be replaced

    Returns:
     Request body for writing a knowledge document

    Raises:
     None
    """

    filename: str
    content: str
    overwrite: bool = False


class KnowledgeUploadResponse(BaseModel):
    """
    Represent the result of saving one knowledge document.

    Parameters:
     source - saved markdown file name
     doc_id - saved document identifier
     title - saved document title
     category - inferred document category
     tags - inferred security tags
     chunk_count - number of searchable chunks generated from the document
     overwritten - whether an existing file was replaced
     vector_indexed - whether the saved chunks were written to vector storage
     vector_chunks_written - number of chunks written to vector storage
     vector_status - backend vector indexing status
     message - operational note for vector index refresh

    Returns:
     Structured knowledge upload response

    Raises:
     None
    """

    source: str
    doc_id: str
    title: str
    category: str
    tags: list[str] = Field(default_factory=list)
    chunk_count: int = 0
    overwritten: bool = False
    vector_indexed: bool = False
    vector_chunks_written: int = 0
    vector_status: str = "not_attempted"
    message: str = ""


class KnowledgeChunk(BaseModel):
    """
    Represent one searchable knowledge chunk loaded from local documents.

    Parameters:
     chunk_id - stable chunk identifier
     doc_id - source document identifier
     source - source file name of the knowledge chunk
     title - heading title of the knowledge chunk
     category - source document category
     content - markdown content belonging to the heading
     tags - inherited and extracted security labels
     keywords - normalized keyword list used for lightweight retrieval

    Returns:
     A searchable security knowledge chunk

    Raises:
     None
    """

    chunk_id: str = ""
    doc_id: str = ""
    source: str
    title: str
    category: str = "general"
    content: str
    tags: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)


class RetrievalResult(BaseModel):
    """
    Represent one low-level retrieval result returned by a retriever.

    Parameters:
     chunk - matched knowledge chunk
     score - normalized or raw retrieval score
     retrieval_type - retrieval source such as bm25, vector, or hybrid
     reason - concise explanation of why the chunk matched

    Returns:
     A scored retrieval result with an explainable match reason

    Raises:
     None
    """

    chunk: KnowledgeChunk
    score: float = 0.0
    retrieval_type: str = "bm25"
    reason: str = ""


class KnowledgeReference(BaseModel):
    """
    Represent one knowledge reference returned by RAG retrieval.

    Parameters:
     source - source file name of the matched knowledge
     title - matched knowledge title
     category - source document category
     snippet - short evidence snippet extracted from the knowledge content
     score - retrieval score used for ranking references
     retrieval_type - retrieval source such as bm25, vector, or hybrid
     reason - concise explanation of why the reference matched

    Returns:
     A structured reference that can be added to reports

    Raises:
     None
    """

    source: str
    title: str
    category: str = "general"
    snippet: str
    score: float = 0.0
    retrieval_type: str = "bm25"
    reason: str = ""


class RAGAnalysisResult(BaseModel):
    """
    Represent RAG-enhanced analysis generated from local security knowledge.

    Parameters:
     query - rewritten security query used for retrieval
     summary - concise security knowledge summary for the current event
     references - matched knowledge references
     recommended_actions - remediation actions retrieved from knowledge base
     matched_knowledge - titles of matched knowledge chunks
     citations - compact citation strings used by reports and evidence

    Returns:
     A structured RAG analysis result used to enrich alerts and reports

    Raises:
     None
    """

    query: str
    summary: str
    references: list[KnowledgeReference] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    matched_knowledge: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
