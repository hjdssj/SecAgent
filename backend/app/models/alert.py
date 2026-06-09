from typing import Literal, Optional

from pydantic import BaseModel, Field

from app.analysis.schemas import AnalysisMetadata, AnalysisMode, RiskScoreBreakdown
from app.triage.schemas import AlertStatus, AutomationDecision

RiskLevel = Literal["low", "medium", "high", "critical"]


class MitreTechnique(BaseModel):
    """
    表示与安全告警相关的 MITRE ATT&CK 技术映射。

    Parameters:
     technique_id - ATT&CK 技术编号，例如 T1190
     name - ATT&CK 技术名称，例如 Exploit Public-Facing Application

    Returns:
     一个结构化的 MITRE ATT&CK 技术映射对象

    Raises:
     None
    """

    technique_id: str
    name: str


class SecurityAlert(BaseModel):
    """
    表示安全分析流程最终生成的结构化告警结果。

    Parameters:
     alert_id - 告警唯一标识
     session_id - analysis session identifier used for follow-up context
     event_id - 该告警对应的原始安全事件唯一标识
     event_timestamp - 原始安全事件发生时间
     attack_type - 识别出的攻击类型，例如 SQL Injection、XSS 或 Path Traversal
     risk_score - 0 到 100 之间的风险分数
     risk_level - 标准化风险等级，只能是 low、medium、high 或 critical
     source_ip - 请求来源 IP
     target - 被攻击目标，通常是请求路径或 URL
     confidence - 分析结果置信度，范围为 0.0 到 1.0
     evidence - 支撑攻击判断的证据列表
     mitre_attack - 与该告警相关的 MITRE ATT&CK 技术映射列表
     recommendations - 面向安全运营人员的处置建议列表
     report_markdown - 可选的 Markdown 格式安全事件分析报告
     analysis_mode - 成本控制分析模式，取值为 fast、enriched 或 deep
     score_breakdown - 可解释风险评分拆解
     analysis_metadata - 本次分析启用模块、跳过模块和耗时等元数据
     status - alert workflow status assigned by auto triage or analyst action
     automation_decision - automation action recommended by auto triage
     triage_reason - reason for the auto triage decision
     requires_human_review - whether an analyst must review the alert
     business_owner - business owner inferred from enterprise context
     asset_name - target asset name inferred from enterprise context
     asset_criticality - target asset criticality inferred from enterprise context
     context_references - enterprise context references used by triage
     llm_used - whether an LLM generated an analyst report
     llm_skipped_reason - reason why LLM report generation was skipped
     llm_summary - concise LLM-generated analyst summary
     llm_model - LLM model used for report generation
     llm_provider - LLM provider used for report generation
     llm_latency_ms - LLM call latency in milliseconds
     llm_prompt_tokens - prompt tokens returned by provider when available
     llm_completion_tokens - completion tokens returned by provider when available
     llm_total_tokens - total tokens returned by provider when available
     llm_error - LLM failure reason when report generation failed

    Returns:
     一个可用于 API 响应和前端展示的结构化安全告警对象

    Raises:
     None
    """

    alert_id: str
    session_id: Optional[str] = None
    event_id: str
    event_ids: list[str] = Field(default_factory=list)
    event_timestamp: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = Field(default=1, ge=1)
    attack_type: str
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel
    source_ip: str
    target: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    mitre_attack: list[MitreTechnique] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    report_markdown: Optional[str] = None
    analysis_mode: AnalysisMode = "fast"
    score_breakdown: Optional[RiskScoreBreakdown] = None
    analysis_metadata: Optional[AnalysisMetadata] = None
    status: AlertStatus = "auto_triaged"
    automation_decision: AutomationDecision = "observe_only"
    triage_reason: str = ""
    requires_human_review: bool = False
    business_owner: Optional[str] = None
    asset_name: Optional[str] = None
    asset_criticality: Optional[str] = None
    context_references: list[str] = Field(default_factory=list)
    analyst_note: Optional[str] = None
    handled_by: Optional[str] = None
    handled_at: Optional[str] = None
    llm_used: bool = False
    llm_skipped_reason: Optional[str] = None
    llm_summary: Optional[str] = None
    llm_model: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_latency_ms: float = 0.0
    llm_prompt_tokens: Optional[int] = None
    llm_completion_tokens: Optional[int] = None
    llm_total_tokens: Optional[int] = None
    llm_error: Optional[str] = None
