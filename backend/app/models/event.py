from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """
    定义标准化安全事件模型。

    Parameters:
     event_id - 事件唯一标识，可由日志源提供，也可由系统后续生成
     timestamp - 事件发生时间
     source_ip - 请求来源 IP
     method - HTTP 请求方法，例如 GET、POST、PUT 或 DELETE
     url - 原始请求 URL，通常包含 path 和 query
     path - 请求路径，例如 /login
     query - 请求参数，例如 id=1' OR '1'='1
     status - HTTP 响应状态码，例如 200、403 或 500
     user_agent - 请求 User-Agent，用于识别 sqlmap、扫描器等自动化工具
     waf_rule_id - WAF 命中的规则 ID，例如 OWASP CRS 中的 942100
     waf_message - WAF 命中规则的描述信息
     raw_log - 原始日志内容，用于保留证据和后续审计

    Returns:
     一个标准化安全事件对象，供后续 Agent 分析流程使用

    Raises:
     None
    """

    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ip: str = Field(default="unknown")
    method: str = Field(default="GET")
    url: str = Field(default="")
    path: str = Field(default="")
    query: str = Field(default="")
    status: Optional[int] = None
    user_agent: str = Field(default="")
    waf_rule_id: Optional[str] = None
    waf_message: Optional[str] = None
    raw_log: str = Field(default="")
    query_params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body_fields: dict[str, str] = Field(default_factory=dict)


class ParsedSecurityEvent(BaseModel):
    """
    定义经过日志解析后的安全事件模型。

    Parameters:
     event - 原始标准化安全事件
     attack_type - 初步识别出的攻击类型，例如 SQL Injection、XSS 或 Path Traversal
     attack_features - 从日志中提取出的攻击特征列表
     evidence - 支撑攻击判断的证据列表
     confidence - 攻击判断置信度，范围为 0.0 到 1.0

    Returns:
     一个日志解析后的安全事件对象，供 DecisionAgent 生成最终告警

    Raises:
     None
    """

    event: SecurityEvent
    attack_type: str
    attack_features: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
