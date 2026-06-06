from typing import Literal

from pydantic import BaseModel, Field

AnalysisMode = Literal["fast", "enriched", "deep"]


class RiskScoreItem(BaseModel):
    """
    Represent one explainable risk score contribution.

    Parameters:
     name - human-readable score item name
     score - risk score delta contributed by this item
     reason - concise explanation of the score contribution
     source - score source such as rule, waf, rag, intel, or memory

    Returns:
     A risk score contribution item

    Raises:
     None
    """

    name: str
    score: int
    reason: str
    source: str


class RiskScoreBreakdown(BaseModel):
    """
    Represent the full explainable risk score breakdown for an alert.

    Parameters:
     base_score - initial score before item contributions are applied
     items - score contribution items
     total_score - final bounded risk score
     risk_level - final risk level
     confidence - analysis confidence

    Returns:
     A structured risk scoring explanation

    Raises:
     None
    """

    base_score: int = Field(default=0, ge=0, le=100)
    items: list[RiskScoreItem] = Field(default_factory=list)
    total_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = "low"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AnalysisMetadata(BaseModel):
    """
    Represent runtime metadata for one alert analysis.

    Parameters:
     analysis_mode - selected cost-control analysis mode
     enabled_modules - modules executed for this alert
     skipped_modules - modules intentionally skipped for this alert
     latency_ms - total analysis latency in milliseconds
     rag_used - whether RAG retrieval was executed
     threat_intel_used - whether threat intelligence was executed
     memory_used - whether event memory was executed

    Returns:
     Analysis runtime metadata for API and frontend display

    Raises:
     None
    """

    analysis_mode: AnalysisMode = "fast"
    enabled_modules: list[str] = Field(default_factory=list)
    skipped_modules: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    rag_used: bool = False
    threat_intel_used: bool = False
    memory_used: bool = False
