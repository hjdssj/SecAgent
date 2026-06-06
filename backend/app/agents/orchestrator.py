from app.agents.decision_agent import DecisionAgent
from app.agents.log_parser_agent import LogParserAgent
from app.intel.schemas import ThreatIntelResult
from app.intel.threat_intel_agent import ThreatIntelAgent
from app.memory.event_memory import EventMemory
from app.memory.schemas import IpMemorySummary
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
        self.threat_intel_agent = ThreatIntelAgent()
        self.event_memory = EventMemory()

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
        alert = self.rag_agent.enrich_alert(alert, parsed)

        intel = self.threat_intel_agent.lookup(alert.source_ip)
        alert = self.threat_intel_agent.enrich_alert(alert, intel)

        memory_summary = self.event_memory.get_ip_summary(alert.source_ip)
        alert = self.event_memory.enrich_alert(alert, memory_summary)
        alert = self._append_context_judgment(alert, intel, memory_summary)
        self.event_memory.record_alert(alert)

        return alert

    def _append_context_judgment(
        self,
        alert: SecurityAlert,
        intel: ThreatIntelResult,
        memory_summary: IpMemorySummary,
    ) -> SecurityAlert:
        """
        Append a final multi-source context judgment to the alert report.

        Parameters:
         alert - security alert enriched by RAG, threat intelligence, and memory
         intel - threat intelligence result for the source IP
         memory_summary - historical behavior summary for the source IP

        Returns:
         Security alert enriched with a final context judgment section

        Raises:
         None
        """

        judgment = self._build_context_judgment(alert, intel, memory_summary)
        evidence = [
            *alert.evidence,
            f"综合研判：{judgment}",
        ]
        report_markdown = (
            f"{(alert.report_markdown or '').rstrip()}\n\n"
            "## 综合研判\n\n"
            f"{judgment}\n"
        )

        return alert.model_copy(
            update={
                "evidence": evidence,
                "report_markdown": report_markdown,
            }
        )

    def _build_context_judgment(
        self,
        alert: SecurityAlert,
        intel: ThreatIntelResult,
        memory_summary: IpMemorySummary,
    ) -> str:
        """
        Build a concise SOC-style judgment from multi-source context.

        Parameters:
         alert - security alert enriched by previous analysis stages
         intel - threat intelligence result for the source IP
         memory_summary - historical behavior summary for the source IP

        Returns:
         One concise multi-source judgment sentence

        Raises:
         None
        """

        if intel.risk_score >= 80 and memory_summary.alert_count >= 1:
            return (
                f"源 IP {alert.source_ip} 同时具备高风险威胁情报和历史告警记录，"
                f"当前 {alert.attack_type} 更可能是持续攻击或自动化探测的一部分。"
            )

        if intel.risk_score >= 80:
            return (
                f"源 IP {alert.source_ip} 在本地威胁情报中风险较高，"
                f"当前 {alert.attack_type} 建议按高优先级事件处置。"
            )

        if memory_summary.alert_count >= 3 or len(memory_summary.attack_types) >= 2:
            return (
                f"源 IP {alert.source_ip} 已存在多次或多类型历史告警，"
                f"当前 {alert.attack_type} 疑似连续扫描或漏洞探测。"
            )

        return (
            f"当前 {alert.attack_type} 已结合日志证据、RAG 知识库、威胁情报和历史行为完成研判，"
            "建议继续保留证据并观察同源后续行为。"
        )
