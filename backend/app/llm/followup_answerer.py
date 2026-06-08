from app.analysis.followup import AnalysisFollowupMessage, AnalysisFollowupResponse
from app.analysis.state import AnalysisState
from app.llm.client import OpenAICompatibleLLMClient
from app.llm.config import load_llm_config
from app.llm.schemas import LLMConfig, LLMFollowupResult


class AnalysisFollowupPromptBuilder:
    """
    Build bounded prompts for analysis follow-up answers.

    Parameters:
     None

    Returns:
     Prompt builder for session-based follow-up answers

    Raises:
     None
    """

    def build_messages(
        self,
        state: AnalysisState,
        question: str,
        history: list[AnalysisFollowupMessage] | None = None,
    ) -> list[dict[str, str]]:
        """
        Build OpenAI-compatible chat messages for one follow-up question.

        Parameters:
         state - saved analysis state used as answer context
         question - analyst follow-up question
         history - previous follow-up messages in the current conversation

        Returns:
         Chat messages for the LLM provider

        Raises:
         None
        """

        return [
            {
                "role": "system",
                "content": self._system_prompt(),
            },
            {
                "role": "user",
                "content": self._user_prompt(state, question, history or []),
            },
        ]

    def _system_prompt(self) -> str:
        """
        Build fixed follow-up system prompt.

        Parameters:
         None

        Returns:
         System prompt text

        Raises:
         None
        """

        return (
            "你是企业 SOC 安全分析追问助手。你只能基于用户提供的已保存分析上下文回答，"
            "不要重新判定攻击类型，不要修改风险分数，不要编造外部情报、CVE、IP 归属或处置结果。"
            "如果上下文不足，请明确说明缺少哪些信息。请用中文 Markdown 简洁回答。"
        )

    def _user_prompt(
        self,
        state: AnalysisState,
        question: str,
        history: list[AnalysisFollowupMessage],
    ) -> str:
        """
        Build user prompt from analysis state and question.

        Parameters:
         state - saved analysis state used as answer context
         question - analyst follow-up question
         history - previous follow-up messages in the current conversation

        Returns:
         User prompt text

        Raises:
         None
        """

        alert = state.final_alert
        parsed = state.parsed_event
        metadata = alert.analysis_metadata if alert else None
        score_breakdown = alert.score_breakdown if alert else None

        return "\n".join(
            [
                "请基于下面的已保存分析上下文回答追问。",
                "",
                "追问：",
                self._truncate(question, 2000),
                "",
                "本次对话历史：",
                self._history_lines(history),
                "",
                "会话信息：",
                f"- session_id: {state.session_id}",
                f"- created_at: {state.created_at}",
                "",
                "原始事件：",
                self._truncate(state.event.model_dump_json(), 3000),
                "",
                "解析结果：",
                self._truncate(parsed.model_dump_json() if parsed else "None", 3000),
                "",
                "最终告警：",
                self._truncate(alert.model_dump_json() if alert else "None", 5000),
                "",
                "评分拆解：",
                self._truncate(score_breakdown.model_dump_json() if score_breakdown else "None", 2500),
                "",
                "分析元数据：",
                self._truncate(metadata.model_dump_json() if metadata else "None", 2000),
                "",
                "Findings：",
                self._json_lines([item.model_dump_json() for item in state.findings], 3000),
                "",
                "Workflow：",
                self._json_lines([item.model_dump_json() for item in state.workflow_steps], 3000),
                "",
                "Reflections：",
                self._json_lines([item.model_dump_json() for item in state.reflections], 2000),
                "",
                "企业上下文：",
                self._truncate(
                    state.context_result.model_dump_json() if state.context_result else "None",
                    3000,
                ),
                "",
                "威胁情报：",
                self._truncate(
                    state.threat_intel_result.model_dump_json()
                    if state.threat_intel_result
                    else "None",
                    2000,
                ),
                "",
                "历史记忆：",
                self._truncate(
                    state.memory_summary.model_dump_json() if state.memory_summary else "None",
                    2000,
                ),
            ]
        )

    def _json_lines(self, lines: list[str], limit: int) -> str:
        """
        Join JSON lines and truncate the result.

        Parameters:
         lines - JSON strings to join
         limit - maximum returned character count

        Returns:
         Truncated joined JSON lines

        Raises:
         None
        """

        if not lines:
            return "None"

        return self._truncate("\n".join(lines), limit)

    def _history_lines(self, history: list[AnalysisFollowupMessage]) -> str:
        """
        Format prior follow-up messages for the prompt.

        Parameters:
         history - previous follow-up messages in the current conversation

        Returns:
         Bounded conversation history text

        Raises:
         None
        """

        if not history:
            return "None"

        lines = [
            f"{index + 1}. {message.role}: {self._truncate(message.content, 1000)}"
            for index, message in enumerate(history[-12:])
        ]
        return self._truncate("\n".join(lines), 6000)

    def _truncate(self, value: str, limit: int) -> str:
        """
        Truncate text to a maximum character count.

        Parameters:
         value - source text
         limit - maximum allowed characters

        Returns:
         Truncated text

        Raises:
         None
        """

        if len(value) <= limit:
            return value

        return f"{value[:limit]}...[truncated]"


class AnalysisFollowupAnswerer:
    """
    Answer follow-up questions using saved analysis context and an LLM.

    Parameters:
     config - optional LLM runtime configuration
     client - optional LLM client replacement used by tests
     prompt_builder - optional prompt builder replacement used by tests

    Returns:
     Follow-up answerer that does not mutate alerts or session state

    Raises:
     None
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        client: OpenAICompatibleLLMClient | None = None,
        prompt_builder: AnalysisFollowupPromptBuilder | None = None,
    ) -> None:
        """
        Initialize the answerer.

        Parameters:
         config - optional LLM runtime configuration
         client - optional LLM client replacement used by tests
         prompt_builder - optional prompt builder replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.config = config or load_llm_config()
        self.client = client or OpenAICompatibleLLMClient(self.config)
        self.prompt_builder = prompt_builder or AnalysisFollowupPromptBuilder()

    def answer(
        self,
        state: AnalysisState,
        question: str,
        history: list[AnalysisFollowupMessage] | None = None,
    ) -> AnalysisFollowupResponse:
        """
        Answer one follow-up question from saved analysis context.

        Parameters:
         state - saved analysis state
         question - analyst follow-up question
         history - previous follow-up messages in the current conversation

        Returns:
         Follow-up answer response

        Raises:
         None
        """

        if not self.config.enabled:
            return self._response_from_result(
                state,
                question,
                LLMFollowupResult(
                    used=False,
                    error="LLM_DISABLED",
                    model=self.config.model,
                    provider=self.config.provider,
                ),
            )

        if not self.config.api_key:
            return self._response_from_result(
                state,
                question,
                LLMFollowupResult(
                    used=False,
                    error="LLM_API_KEY_MISSING",
                    model=self.config.model,
                    provider=self.config.provider,
                ),
            )

        if not self.config.base_url:
            return self._response_from_result(
                state,
                question,
                LLMFollowupResult(
                    used=False,
                    error="LLM_BASE_URL_MISSING",
                    model=self.config.model,
                    provider=self.config.provider,
                ),
            )

        result = self.client.answer_followup(
            self.prompt_builder.build_messages(state, question, history or [])
        )
        return self._response_from_result(state, question, result)

    def _response_from_result(
        self,
        state: AnalysisState,
        question: str,
        result: LLMFollowupResult,
    ) -> AnalysisFollowupResponse:
        """
        Convert an LLM result into an API response.

        Parameters:
         state - saved analysis state
         question - analyst follow-up question
         result - LLM follow-up result

        Returns:
         Follow-up answer response

        Raises:
         None
        """

        answer = result.answer_markdown

        if result.error:
            answer = f"无法生成追问回答：{result.error}"

        return AnalysisFollowupResponse(
            session_id=state.session_id,
            question=question,
            answer_markdown=answer,
            llm_used=result.used,
            llm_model=result.model or self.config.model,
            llm_provider=result.provider or self.config.provider,
            llm_latency_ms=result.latency_ms,
            llm_prompt_tokens=result.prompt_tokens,
            llm_completion_tokens=result.completion_tokens,
            llm_total_tokens=result.total_tokens,
            llm_error=result.error,
        )
