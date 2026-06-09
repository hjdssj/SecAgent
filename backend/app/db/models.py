from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AlertRecord(Base):
    """
    Represent one persisted security alert record.

    Parameters:
     None

    Returns:
     SQLAlchemy ORM model mapped to the alerts table

    Raises:
     None
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    event_timestamp: Mapped[datetime | None] = mapped_column(DateTime, index=True, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, index=True, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, index=True, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    aggregation_key: Mapped[str | None] = mapped_column(String(768), index=True, nullable=True)
    attack_type: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    mitre_attack_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)

    analysis_mode: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="fast")
    score_breakdown_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="auto_triaged")
    automation_decision: Mapped[str] = mapped_column(String(64), nullable=False, default="observe_only")
    triage_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requires_human_review: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)

    business_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    asset_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    asset_criticality: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    context_references_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    handled_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    handled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    llm_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    llm_skipped_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    llm_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    llm_latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    llm_prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
