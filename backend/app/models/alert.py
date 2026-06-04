from typing import Literal, Optional

from pydantic import BaseModel, Field

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
     event_id - 该告警对应的原始安全事件唯一标识
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

    Returns:
     一个可用于 API 响应和前端展示的结构化安全告警对象

    Raises:
     None
    """

    alert_id: str
    event_id: str
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
