from pydantic import BaseModel, Field


class KnowledgeChunk(BaseModel):
    """
    Represent one searchable knowledge chunk loaded from local documents.

    Parameters:
     source - source file name of the knowledge chunk
     title - heading title of the knowledge chunk
     content - markdown content belonging to the heading
     keywords - normalized keyword list used for lightweight retrieval

    Returns:
     A searchable security knowledge chunk

    Raises:
     None
    """

    source: str
    title: str
    content: str
    keywords: list[str] = Field(default_factory=list)


class KnowledgeReference(BaseModel):
    """
    Represent one knowledge reference returned by RAG retrieval.

    Parameters:
     source - source file name of the matched knowledge
     title - matched knowledge title
     snippet - short evidence snippet extracted from the knowledge content
     score - retrieval score used for ranking references

    Returns:
     A structured reference that can be added to reports

    Raises:
     None
    """

    source: str
    title: str
    snippet: str
    score: float = 0.0


class RAGAnalysisResult(BaseModel):
    """
    Represent RAG-enhanced analysis generated from local security knowledge.

    Parameters:
     query - rewritten security query used for retrieval
     summary - concise security knowledge summary for the current event
     references - matched knowledge references
     recommended_actions - remediation actions retrieved from knowledge base
     matched_knowledge - titles of matched knowledge chunks

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
