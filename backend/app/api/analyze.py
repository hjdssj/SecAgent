from fastapi import APIRouter

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent

router = APIRouter(prefix="/api", tags=["analyze"])
orchestrator = SecurityAnalysisOrchestrator()


@router.post("/analyze", response_model=SecurityAlert)
def analyze_event(event: SecurityEvent) -> SecurityAlert:
    """
    分析单条标准化安全事件并返回安全告警。

    Parameters:
     event - 标准化安全事件请求体，由前端、日志回放脚本或 WAF 日志采集器提交

    Returns:
     结构化安全告警，包含攻击类型、风险等级、证据和处置建议

    Raises:
     None
    """

    return orchestrator.analyze(event)
