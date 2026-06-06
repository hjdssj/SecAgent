from app.agents.decision_agent import DecisionAgent
from app.agents.log_parser_agent import LogParserAgent
from app.analysis.policy import AnalysisPolicy
from app.analysis.schemas import AnalysisMetadata, AnalysisMode, RiskScoreBreakdown, RiskScoreItem
from app.analysis.timer import AnalysisTimer
from app.context.context_agent import ContextAgent
from app.intel.schemas import ThreatIntelResult
from app.intel.threat_intel_agent import ThreatIntelAgent
from app.memory.event_memory import EventMemory
from app.memory.schemas import IpMemorySummary
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent
from app.rag.rag_agent import RAGAgent
from app.triage.auto_triage_policy import AutoTriagePolicy
from app.triage.schemas import AutoTriageResult


class SecurityAnalysisOrchestrator:
    """
    Coordinate the cost-controlled security analysis pipeline.

    Parameters:
     None

    Returns:
     An orchestrator that runs parsing, scoring, optional enrichment, and reporting

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize security analysis pipeline dependencies.

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
        self.analysis_policy = AnalysisPolicy()
        self.context_agent = ContextAgent()
        self.auto_triage_policy = AutoTriagePolicy()

    def analyze(self, event: SecurityEvent) -> SecurityAlert:
        """
        Analyze a normalized security event and generate the final alert.

        Parameters:
         event - normalized security event object

        Returns:
         Final security alert with analysis mode, score breakdown, and metadata

        Raises:
         None
        """

        timer = AnalysisTimer()
        parsed = self.log_parser.parse(event)
        alert = self.decision_agent.decide(parsed)
        mode = self.analysis_policy.select_mode(alert)
        enabled_modules, skipped_modules = self.analysis_policy.modules_for_mode(mode)
        alert = alert.model_copy(update={"analysis_mode": mode})

        intel = ThreatIntelResult(source_ip=alert.source_ip)
        memory_summary = IpMemorySummary(source_ip=alert.source_ip)

        if mode in ("enriched", "deep"):
            before_score = alert.risk_score
            before_evidence_count = len(alert.evidence)
            alert = self.rag_agent.enrich_alert(alert, parsed)
            if len(alert.evidence) > before_evidence_count:
                alert = self._append_score_item(
                    alert,
                    name="RAG knowledge match",
                    score=3,
                    reason="RAG retrieval returned security knowledge references for this event",
                    source="rag",
                    previous_score=before_score,
                )

            memory_summary = self.event_memory.get_ip_summary(alert.source_ip)
            before_score = alert.risk_score
            alert = self.event_memory.enrich_alert(alert, memory_summary)
            alert = self._append_score_item(
                alert,
                name="Historical behavior",
                score=alert.risk_score - before_score,
                reason=self._memory_score_reason(memory_summary),
                source="memory",
                previous_score=before_score,
            )

        if mode == "deep":
            intel = self.threat_intel_agent.lookup(alert.source_ip)
            before_score = alert.risk_score
            alert = self.threat_intel_agent.enrich_alert(alert, intel)
            alert = self._append_score_item(
                alert,
                name="Threat intelligence",
                score=alert.risk_score - before_score,
                reason=self._intel_score_reason(intel),
                source="intel",
                previous_score=before_score,
            )

        if mode in ("enriched", "deep"):
            alert = self._append_context_judgment(alert, intel, memory_summary)

        context = self.context_agent.analyze(alert, parsed)
        alert = self.context_agent.enrich_alert(alert, context)
        triage = self.auto_triage_policy.decide(alert, context)
        alert = self._apply_auto_triage(alert, triage)

        enabled_modules = [*enabled_modules, "ContextRAG", "AutoTriage"]
        metadata = AnalysisMetadata(
            analysis_mode=mode,
            enabled_modules=enabled_modules,
            skipped_modules=skipped_modules,
            latency_ms=timer.elapsed_ms(),
            rag_used="RAG" in enabled_modules,
            threat_intel_used="ThreatIntel" in enabled_modules,
            memory_used="Memory" in enabled_modules,
        )
        alert = alert.model_copy(update={"analysis_metadata": metadata})
        alert = self._append_analysis_summary(alert, metadata)
        self.event_memory.record_alert(alert)

        return alert

    def _apply_auto_triage(
        self,
        alert: SecurityAlert,
        triage: AutoTriageResult,
    ) -> SecurityAlert:
        """
        Apply automatic triage result to the alert.

        Parameters:
         alert - alert enriched with enterprise context
         triage - automatic triage decision

        Returns:
         Alert with workflow status and automation decision fields

        Raises:
         None
        """

        evidence = [
            *alert.evidence,
            f"AutoTriage: {triage.triage_reason}",
        ]
        report_markdown = (
            f"{(alert.report_markdown or '').rstrip()}\n\n"
            "## AutoTriage\n\n"
            f"- Status: {triage.status}\n"
            f"- Automation decision: {triage.automation_decision}\n"
            f"- Requires human review: {triage.requires_human_review}\n"
            f"- Reason: {triage.triage_reason}\n"
        )

        return alert.model_copy(
            update={
                "status": triage.status,
                "automation_decision": triage.automation_decision,
                "triage_reason": triage.triage_reason,
                "requires_human_review": triage.requires_human_review,
                "context_references": triage.context_references or alert.context_references,
                "evidence": evidence,
                "report_markdown": report_markdown,
            }
        )

    def _append_score_item(
        self,
        alert: SecurityAlert,
        name: str,
        score: int,
        reason: str,
        source: str,
        previous_score: int,
    ) -> SecurityAlert:
        """
        Append one score item and optionally apply a score delta.

        Parameters:
         alert - alert being enriched
         name - human-readable score item name
         score - score delta contributed by this item
         reason - reason for the score delta
         source - score source
         previous_score - risk score before the related module ran

        Returns:
         Alert with updated score breakdown

        Raises:
         None
        """

        current_score = alert.risk_score

        if source == "rag" and score > 0:
            current_score = min(alert.risk_score + score, 100)
            alert = alert.model_copy(
                update={
                    "risk_score": current_score,
                    "risk_level": self._level(current_score),
                }
            )

        applied_score = current_score - previous_score if source != "rag" else score
        breakdown = self._breakdown_or_default(alert)
        breakdown = breakdown.model_copy(
            update={
                "items": [
                    *breakdown.items,
                    RiskScoreItem(
                        name=name,
                        score=applied_score,
                        reason=reason,
                        source=source,
                    ),
                ],
                "total_score": alert.risk_score,
                "risk_level": alert.risk_level,
                "confidence": alert.confidence,
            }
        )

        return alert.model_copy(update={"score_breakdown": breakdown})

    def _breakdown_or_default(self, alert: SecurityAlert) -> RiskScoreBreakdown:
        """
        Return existing score breakdown or create a fallback one.

        Parameters:
         alert - alert that should contain score breakdown information

        Returns:
         Existing or fallback score breakdown

        Raises:
         None
        """

        if alert.score_breakdown:
            return alert.score_breakdown

        return RiskScoreBreakdown(
            base_score=0,
            items=[
                RiskScoreItem(
                    name="Base decision score",
                    score=alert.risk_score,
                    reason="Initial rule-based risk score",
                    source="rule",
                )
            ],
            total_score=alert.risk_score,
            risk_level=alert.risk_level,
            confidence=alert.confidence,
        )

    def _append_context_judgment(
        self,
        alert: SecurityAlert,
        intel: ThreatIntelResult,
        memory_summary: IpMemorySummary,
    ) -> SecurityAlert:
        """
        Append a final multi-source context judgment to the alert report.

        Parameters:
         alert - security alert enriched by optional analysis modules
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

    def _append_analysis_summary(
        self,
        alert: SecurityAlert,
        metadata: AnalysisMetadata,
    ) -> SecurityAlert:
        """
        Append analysis mode, metadata, and score breakdown to the markdown report.

        Parameters:
         alert - final alert before report summary is appended
         metadata - runtime analysis metadata

        Returns:
         Alert with analysis summary in report markdown

        Raises:
         None
        """

        breakdown = alert.score_breakdown
        score_lines = ""

        if breakdown:
            score_lines = "\n".join(
                f"- {item.name}（{item.source}）：{item.score:+d}，{item.reason}"
                for item in breakdown.items
            )

        enabled = ", ".join(metadata.enabled_modules) if metadata.enabled_modules else "None"
        skipped = ", ".join(metadata.skipped_modules) if metadata.skipped_modules else "None"
        report_markdown = (
            f"{(alert.report_markdown or '').rstrip()}\n\n"
            "## 分析模式与评分解释\n\n"
            f"- 分析模式：{metadata.analysis_mode}\n"
            f"- 启用模块：{enabled}\n"
            f"- 跳过模块：{skipped}\n"
            f"- 分析耗时：{metadata.latency_ms}ms\n"
            f"- 最终分数：{alert.risk_score}（{alert.risk_level}）\n\n"
            "**评分拆解**\n\n"
            f"{score_lines or '- 暂无评分拆解'}\n"
        )

        return alert.model_copy(update={"report_markdown": report_markdown})

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
            f"当前 {alert.attack_type} 已结合日志证据、RAG 知识库和历史行为完成研判，"
            "建议继续保留证据并观察同源后续行为。"
        )

    def _intel_score_reason(self, intel: ThreatIntelResult) -> str:
        """
        Build a score reason for threat intelligence enrichment.

        Parameters:
         intel - threat intelligence lookup result

        Returns:
         Human-readable score reason

        Raises:
         None
        """

        return (
            f"Threat intelligence reputation is {intel.reputation}, "
            f"risk score is {intel.risk_score}, source is {intel.source}"
        )

    def _memory_score_reason(self, memory_summary: IpMemorySummary) -> str:
        """
        Build a score reason for memory enrichment.

        Parameters:
         memory_summary - historical behavior summary for source IP

        Returns:
         Human-readable score reason

        Raises:
         None
        """

        if not memory_summary.storage_available:
            return "Memory storage was unavailable, no historical risk increase applied"

        return (
            f"Source IP has {memory_summary.alert_count} historical alerts, "
            f"{len(memory_summary.attack_types)} attack types, and "
            f"{len(memory_summary.targets)} observed targets"
        )

    def _level(self, score: int) -> str:
        """
        Convert a risk score into a risk level.

        Parameters:
         score - risk score from 0 to 100

        Returns:
         Risk level string

        Raises:
         None
        """

        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
