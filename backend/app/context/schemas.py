from pydantic import BaseModel, Field


class ContextChunk(BaseModel):
    """
    Represent one searchable enterprise context chunk.

    Parameters:
     chunk_id - stable context chunk identifier
     source - source context file name
     title - context section title
     category - context category inferred from source file
     content - section content
     metadata - key-value context metadata extracted from markdown
     keywords - normalized searchable terms

    Returns:
     A searchable enterprise context chunk

    Raises:
     None
    """

    chunk_id: str
    source: str
    title: str
    category: str
    content: str
    metadata: dict[str, str] = Field(default_factory=dict)
    keywords: list[str] = Field(default_factory=list)


class ContextReference(BaseModel):
    """
    Represent one enterprise context reference used by triage.

    Parameters:
     source - source context file name
     title - matched context section title
     category - context category
     snippet - compact context snippet
     score - retrieval score
     metadata - extracted key-value context metadata
     reason - concise match reason

    Returns:
     A context reference that can be attached to alerts

    Raises:
     None
    """

    source: str
    title: str
    category: str
    snippet: str
    score: float = 0.0
    metadata: dict[str, str] = Field(default_factory=dict)
    reason: str = ""


class ContextAnalysisResult(BaseModel):
    """
    Represent enterprise context extracted for one alert.

    Parameters:
     query - context retrieval query
     references - matched context references
     business_owner - owner inferred from context
     asset_name - target asset name inferred from context
     asset_criticality - target asset criticality
     is_internal_scanner - whether source IP matched scanner whitelist
     waf_action - WAF action inferred from policy context
     change_window - active change window inferred from context
     recommended_decision - decision hint inferred from playbooks
     summary - concise context summary

    Returns:
     Structured enterprise context for auto triage

    Raises:
     None
    """

    query: str
    references: list[ContextReference] = Field(default_factory=list)
    business_owner: str | None = None
    asset_name: str | None = None
    asset_criticality: str | None = None
    is_internal_scanner: bool = False
    waf_action: str | None = None
    change_window: str | None = None
    recommended_decision: str | None = None
    summary: str = ""
