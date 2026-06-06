from app.agents.decision_agent import DecisionAgent
from app.agents.log_parser_agent import LogParserAgent
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent
from app.rag.rag_agent import RAGAgent


class SecurityAnalysisOrchestrator:
    """
    编排安全事件分析流程。

    Parameters:
     None

    Returns:
     一个用于串联日志解析和风险决策流程的分析编排器实例

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        初始化安全分析编排器依赖的 Agent。

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.log_parser = LogParserAgent()
        self.decision_agent = DecisionAgent()
        self.rag_agent = RAGAgent()

    def analyze(self, event: SecurityEvent) -> SecurityAlert:
        """
        分析标准化安全事件并生成最终安全告警。

        Parameters:
         event - 标准化安全事件对象

        Returns:
         最终安全告警，包含攻击类型、风险等级、证据和处置建议

        Raises:
         None
        """

        parsed = self.log_parser.parse(event)
        alert = self.decision_agent.decide(parsed)
        return self.rag_agent.enrich_alert(alert, parsed)
