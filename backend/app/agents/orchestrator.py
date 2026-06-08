from app.agents.decision_agent import DecisionAgent
from app.agents.log_parser_agent import LogParserAgent
from app.analysis.policy import AnalysisPolicy
from app.analysis.schemas import AnalysisMetadata, AnalysisMode, RiskScoreBreakdown, RiskScoreItem
from app.analysis.state import AnalysisState
from app.analysis.timer import AnalysisTimer
from app.context.context_agent import ContextAgent
from app.intel.schemas import ThreatIntelResult
from app.intel.threat_intel_agent import ThreatIntelAgent
from app.llm.report_enhancer import LLMReportEnhancer
from app.llm.unknown_attack_classifier import LLMUnknownAttackClassifier
from app.memory.event_memory import EventMemory
from app.memory.long_term_schemas import LongTermMemorySearchResult
from app.memory.long_term_store import LongTermMemoryStore
from app.memory.schemas import IpMemorySummary
from app.memory.session_memory import SessionMemoryStore
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
        self.llm_unknown_classifier = LLMUnknownAttackClassifier()
        self.llm_report_enhancer = LLMReportEnhancer()
        self.session_memory = SessionMemoryStore()
        self.long_term_memory = LongTermMemoryStore()

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

        alert, _ = self.analyze_with_state(event)
        return alert

    def analyze_with_state(self, event: SecurityEvent) -> tuple[SecurityAlert, AnalysisState]:
        """
        Analyze a normalized security event and return the final alert with state.

        Parameters:
         event - normalized security event object

        Returns:
         Tuple containing final alert and analysis state

        Raises:
         None
        """

        timer = AnalysisTimer()
        state = AnalysisState(event=event)
        state.add_workflow_step(
            "analysis_started",
            summary=f"Started analysis session {state.session_id}",
        )
        parsed = self.log_parser.parse(event)
        state.add_workflow_step(
            "log_parser",
            summary=f"Rule parser returned {parsed.attack_type}",
        )
        parsed, llm_classification = self.llm_unknown_classifier.enhance(parsed)
        state.parsed_event = parsed
        state.llm_unknown_classification = llm_classification
        state.add_workflow_step(
            "llm_unknown_classifier",
            status="completed" if llm_classification.used else "skipped",
            summary=(
                f"LLM fallback returned {parsed.attack_type}"
                if llm_classification.used
                else llm_classification.skipped_reason or "not used"
            ),
        )
        alert = self.decision_agent.decide(parsed)
        alert = alert.model_copy(update={"session_id": state.session_id})
        state.add_finding(
            finding_type="attack_detection",
            title=f"Detected {alert.attack_type}",
            description=f"Risk score {alert.risk_score}, confidence {alert.confidence}",
            evidence=alert.evidence[:5],
            confidence=alert.confidence,
            source="decision_agent",
        )
        state.add_workflow_step(
            "decision_agent",
            summary=f"Generated base alert {alert.alert_id}",
        )
        mode = self.analysis_policy.select_mode(alert)
        enabled_modules, skipped_modules = self.analysis_policy.modules_for_mode(mode)
        alert = alert.model_copy(update={"analysis_mode": mode})
        state.add_workflow_step(
            "analysis_policy",
            summary=f"Selected {mode} mode",
        )

        intel = ThreatIntelResult(source_ip=alert.source_ip)
        memory_summary = IpMemorySummary(source_ip=alert.source_ip)

        if mode in ("enriched", "deep"):
            before_score = alert.risk_score
            before_evidence_count = len(alert.evidence)
            alert = self.rag_agent.enrich_alert(alert, parsed)
            state.add_workflow_step(
                "rag_agent",
                summary="RAG enrichment executed",
            )
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
            state.memory_summary = memory_summary
            before_score = alert.risk_score
            alert = self.event_memory.enrich_alert(alert, memory_summary)
            state.add_workflow_step(
                "event_memory",
                summary=f"Historical alert count: {memory_summary.alert_count}",
            )
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
            state.threat_intel_result = intel
            before_score = alert.risk_score
            alert = self.threat_intel_agent.enrich_alert(alert, intel)
            state.add_workflow_step(
                "threat_intel",
                summary=f"Threat intel reputation: {intel.reputation}",
            )
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
        state.context_result = context
        alert = self.context_agent.enrich_alert(alert, context)
        state.add_workflow_step(
            "context_agent",
            summary=context.summary or "Enterprise context analyzed",
        )
        triage = self.auto_triage_policy.decide(alert, context)
        state.triage_result = triage
        alert = self._apply_auto_triage(alert, triage)
        state.add_finding(
            finding_type="triage",
            title=f"Triage status {triage.status}",
            description=triage.triage_reason,
            evidence=triage.context_references,
            confidence=alert.confidence,
            source="auto_triage",
        )
        state.add_workflow_step(
            "auto_triage",
            summary=triage.triage_reason,
        )

        similar_memories: list[LongTermMemorySearchResult] = []
        long_term_search_reason = "FAST_MODE"

        if mode in ("enriched", "deep"):
            similar_memories, long_term_search_reason = self.long_term_memory.search_for_alert(
                alert,
                state,
            )
            alert = self._append_long_term_memory_matches(alert, similar_memories)
            state.add_workflow_step(
                "long_term_memory_search",
                status="completed" if similar_memories else "skipped",
                summary=(
                    f"Matched {len(similar_memories)} similar memories"
                    if similar_memories
                    else long_term_search_reason or "no similar memory"
                ),
            )
        else:
            state.add_workflow_step(
                "long_term_memory_search",
                status="skipped",
                summary=long_term_search_reason,
            )

        alert = self.llm_report_enhancer.enhance(alert)
        state.add_workflow_step(
            "llm_report_enhancer",
            status="completed" if alert.llm_used else "skipped",
            summary=alert.llm_summary or alert.llm_skipped_reason or "not used",
        )

        enabled_modules = [*enabled_modules, "ContextRAG", "AutoTriage"]

        if llm_classification.used:
            enabled_modules = [*enabled_modules, "LLMUnknownClassifier"]
        elif (
            llm_classification.skipped_reason
            and llm_classification.skipped_reason != "RULE_CLASSIFIED"
        ):
            skipped_modules = [
                *skipped_modules,
                f"LLMUnknownClassifier:{llm_classification.skipped_reason}",
            ]
        elif llm_classification.error:
            skipped_modules = [
                *skipped_modules,
                f"LLMUnknownClassifier:{llm_classification.error}",
            ]

        if alert.llm_used:
            enabled_modules = [*enabled_modules, "LLMReport"]
        elif alert.llm_skipped_reason:
            skipped_modules = [*skipped_modules, f"LLMReport:{alert.llm_skipped_reason}"]

        if similar_memories:
            enabled_modules = [*enabled_modules, "LongTermMemorySearch"]
        else:
            skipped_modules = [
                *skipped_modules,
                f"LongTermMemorySearch:{long_term_search_reason}",
            ]

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
        state.add_reflection(
            summary=self._build_reflection_summary(alert, llm_classification),
            suggested_knowledge_update=alert.attack_type == "Unknown",
            suggested_rule_update=llm_classification.used and alert.attack_type != "Unknown",
        )
        state.final_alert = alert
        state.add_workflow_step(
            "analysis_completed",
            summary=f"Final alert {alert.alert_id}, risk {alert.risk_level}",
            latency_ms=metadata.latency_ms,
        )
        long_term_result = self.long_term_memory.save_analysis(alert, state)
        state.add_workflow_step(
            "long_term_memory",
            status=(
                "completed"
                if long_term_result.written
                else "failed"
                if long_term_result.error
                else "skipped"
            ),
            summary=(
                f"Written {long_term_result.memory_id}"
                if long_term_result.written
                else long_term_result.error
                or long_term_result.skipped_reason
                or "not written"
            ),
        )
        self.session_memory.save_state(state)
        self.event_memory.record_alert(alert)

        return alert, state

    def _append_long_term_memory_matches(
        self,
        alert: SecurityAlert,
        memories: list[LongTermMemorySearchResult],
    ) -> SecurityAlert:
        """
        Append similar long-term memory matches to the alert.

        Parameters:
         alert - current security alert
         memories - similar long-term memory search results

        Returns:
         Alert enriched with similar historical memory references

        Raises:
         None
        """

        if not memories:
            return alert

        evidence = [*alert.evidence]
        report_lines = ["## 长期记忆相似事件", ""]

        for item in memories[:3]:
            record = item.record
            summary = (
                f"历史告警 {record.alert_id}：{record.attack_type}，"
                f"风险 {record.risk_level}，目标 {record.target}，"
                f"相似度 {item.score:.2f}"
            )
            evidence.append(f"长期记忆相似事件：{summary}")
            report_lines.append(f"- {summary}")

            if record.analyst_note:
                report_lines.append(f"  处置备注：{record.analyst_note}")

            if record.recommendation_text:
                recommendation = record.recommendation_text.splitlines()[0]
                report_lines.append(f"  历史建议：{recommendation}")

        report_markdown = (
            f"{(alert.report_markdown or '').rstrip()}\n\n"
            f"{chr(10).join(report_lines)}\n"
        )

        return alert.model_copy(
            update={
                "evidence": evidence,
                "report_markdown": report_markdown,
            }
        )

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

    def _build_reflection_summary(
        self,
        alert: SecurityAlert,
        llm_classification,
    ) -> str:
        """
        Build a concise reflection summary for session memory.

        Parameters:
         alert - final security alert generated by the pipeline
         llm_classification - LLM fallback classification metadata

        Returns:
         Reflection summary suitable for short-term session memory

        Raises:
         None
        """

        if alert.attack_type == "Unknown":
            return (
                "规则、上下文和可选 LLM fallback 未能给出明确攻击类型，"
                "建议复盘原始日志并考虑补充检测规则或知识库条目。"
            )

        if getattr(llm_classification, "used", False):
            return (
                f"本次 {alert.attack_type} 来自 Unknown 专用 LLM fallback 补识别，"
                "建议将稳定特征沉淀为规则，减少后续 LLM 调用。"
            )

        return (
            f"本次事件已形成 {alert.attack_type} 告警，"
            f"风险等级为 {alert.risk_level}，可作为后续追问和复盘上下文。"
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
