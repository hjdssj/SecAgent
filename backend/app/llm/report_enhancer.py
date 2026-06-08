from app.llm.client import OpenAICompatibleLLMClient
from app.llm.config import load_llm_config
from app.llm.policy import LLMCallPolicy
from app.llm.prompt_builder import LLMReportPromptBuilder
from app.llm.schemas import LLMConfig, LLMReportResult
from app.models.alert import SecurityAlert


class LLMReportEnhancer:
    """
    Optionally enhance high-value alerts with an LLM-generated report.

    Parameters:
     config - optional LLM runtime configuration
     client - optional LLM client replacement used by tests

    Returns:
     Report enhancer that preserves deterministic alert decisions

    Raises:
     None
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        client: OpenAICompatibleLLMClient | None = None,
    ) -> None:
        """
        Initialize the enhancer.

        Parameters:
         config - optional LLM runtime configuration
         client - optional LLM client replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.config = config or load_llm_config()
        self.policy = LLMCallPolicy(self.config)
        self.prompt_builder = LLMReportPromptBuilder()
        self.client = client or OpenAICompatibleLLMClient(self.config)

    def enhance(self, alert: SecurityAlert) -> SecurityAlert:
        """
        Enhance one alert with an optional LLM report.

        Parameters:
         alert - final deterministic alert before LLM enhancement

        Returns:
         Alert with LLM metadata and optional LLM report content

        Raises:
         None
        """

        should_call, skipped_reason = self.policy.should_call(alert)

        if not should_call:
            return alert.model_copy(
                update={
                    "llm_used": False,
                    "llm_skipped_reason": skipped_reason,
                    "llm_model": self.config.model,
                    "llm_provider": self.config.provider,
                }
            )

        result = self.client.generate_report(self.prompt_builder.build_messages(alert))
        return self._apply_result(alert, result)

    def _apply_result(
        self,
        alert: SecurityAlert,
        result: LLMReportResult,
    ) -> SecurityAlert:
        """
        Apply an LLM result to an alert.

        Parameters:
         alert - alert before LLM metadata is applied
         result - LLM enhancement result

        Returns:
         Alert updated with LLM fields and report section when available

        Raises:
         None
        """

        report_markdown = alert.report_markdown
        evidence = list(alert.evidence)

        if result.used and result.report_markdown:
            report_markdown = (
                f"{(alert.report_markdown or '').rstrip()}\n\n"
                "## LLM 分析师报告\n\n"
                f"{result.report_markdown.strip()}\n"
            )
            evidence.append("LLM 已基于现有证据生成分析师报告，不参与攻击判定和风险评分。")

        if result.error:
            evidence.append(f"LLM 报告生成失败：{result.error}")

        return alert.model_copy(
            update={
                "evidence": evidence,
                "report_markdown": report_markdown,
                "llm_used": result.used,
                "llm_skipped_reason": result.skipped_reason,
                "llm_summary": result.summary,
                "llm_model": result.model or self.config.model,
                "llm_provider": result.provider or self.config.provider,
                "llm_latency_ms": result.latency_ms,
                "llm_prompt_tokens": result.prompt_tokens,
                "llm_completion_tokens": result.completion_tokens,
                "llm_total_tokens": result.total_tokens,
                "llm_error": result.error,
            }
        )
