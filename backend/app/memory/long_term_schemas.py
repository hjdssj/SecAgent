from pydantic import BaseModel, Field


class LongTermMemoryRecord(BaseModel):
    """
    Represent one long-term analysis memory record.

    Parameters:
     memory_id - stable memory identifier
     alert_id - source alert identifier
     session_id - source analysis session identifier
     source_ip - source IP observed in the alert
     target - target path or URL observed in the alert
     attack_type - final attack type
     risk_level - final risk level
     business_owner - inferred business owner
     asset_criticality - inferred asset criticality
     status - alert workflow status
     automation_decision - automation decision assigned by triage
     summary - concise analysis summary used for semantic search
     evidence_text - compact evidence text
     recommendation_text - compact recommendation text
     analyst_note - optional analyst note from alert lifecycle
     handled_by - optional analyst or handler name
     handled_at - optional handled timestamp
     created_at - memory creation timestamp
     enabled - whether the memory can participate in retrieval

    Returns:
     Long-term memory record ready for vector storage

    Raises:
     None
    """

    memory_id: str
    alert_id: str
    session_id: str | None = None
    source_ip: str
    target: str
    attack_type: str
    risk_level: str
    business_owner: str | None = None
    asset_criticality: str | None = None
    status: str
    automation_decision: str
    summary: str
    evidence_text: str = ""
    recommendation_text: str = ""
    analyst_note: str | None = None
    handled_by: str | None = None
    handled_at: str | None = None
    created_at: str
    enabled: bool = True


class LongTermMemorySearchResult(BaseModel):
    """
    Represent one similar long-term memory search result.

    Parameters:
     record - matched long-term memory record
     score - vector similarity score returned by Milvus
     reason - concise match explanation

    Returns:
     Similar memory search result

    Raises:
     None
    """

    record: LongTermMemoryRecord
    score: float = 0.0
    reason: str = "Milvus long-term memory similarity match"


class LongTermMemoryWriteResult(BaseModel):
    """
    Represent the result of one long-term memory write attempt.

    Parameters:
     attempted - whether a write was attempted
     written - whether the memory was written
     memory_id - written memory identifier when available
     skipped_reason - reason why writing was skipped
     error - failure reason when writing failed

    Returns:
     Structured long-term memory write result

    Raises:
     None
    """

    attempted: bool = False
    written: bool = False
    memory_id: str | None = None
    skipped_reason: str | None = None
    error: str | None = None

