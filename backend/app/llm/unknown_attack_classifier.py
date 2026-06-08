from app.llm.client import OpenAICompatibleLLMClient
from app.llm.config import load_llm_config
from app.llm.schemas import LLMAttackClassificationResult, LLMConfig
from app.models.event import ParsedSecurityEvent, SecurityEvent

NORMALIZED_ATTACK_TYPES = {
    "sql injection": "SQL Injection",
    "sqli": "SQL Injection",
    "xss": "XSS",
    "cross-site scripting": "XSS",
    "path traversal": "Path Traversal",
    "directory traversal": "Path Traversal",
    "command injection": "Command Injection",
    "rce": "Command Injection",
    "remote command execution": "Command Injection",
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "brute force": "Brute Force",
    "credential stuffing": "Brute Force",
    "file upload": "File Upload",
    "malicious file upload": "File Upload",
    "authentication bypass": "Authentication Bypass",
    "auth bypass": "Authentication Bypass",
    "automated scanner": "Automated Scanner",
    "scanner": "Automated Scanner",
}


class LLMUnknownAttackClassifier:
    """
    Use LLM fallback classification only for rule-unknown events.

    Parameters:
     config - optional LLM runtime configuration
     client - optional LLM client replacement used by tests

    Returns:
     Classifier that can enrich ParsedSecurityEvent when rules return Unknown

    Raises:
     None
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        client: OpenAICompatibleLLMClient | None = None,
    ) -> None:
        """
        Initialize the classifier.

        Parameters:
         config - optional LLM runtime configuration
         client - optional LLM client replacement used by tests

        Returns:
         None

        Raises:
         None
        """

        self.config = config or load_llm_config()
        self.client = client or OpenAICompatibleLLMClient(self.config)

    def enhance(
        self,
        parsed: ParsedSecurityEvent,
    ) -> tuple[ParsedSecurityEvent, LLMAttackClassificationResult]:
        """
        Try to classify an Unknown parsed event with LLM assistance.

        Parameters:
         parsed - parsed event from deterministic log parsing

        Returns:
         Tuple of possibly updated parsed event and LLM classification metadata

        Raises:
         None
        """

        should_call, skipped_reason = self._should_call(parsed)

        if not should_call:
            return parsed, LLMAttackClassificationResult(
                skipped_reason=skipped_reason,
                model=self.config.model,
                provider=self.config.provider,
            )

        result = self.client.classify_attack(self._build_messages(parsed))

        if result.error:
            return self._append_evidence(
                parsed,
                f"LLM Unknown 补充识别失败：{result.error}",
            ), result

        if not result.used:
            return parsed, result

        if not result.attack_suspected:
            return self._append_evidence(
                parsed,
                "LLM Unknown 补充识别：未发现明确攻击特征。",
            ), result

        normalized_attack_type = self._normalize_attack_type(result.attack_type)

        if not normalized_attack_type:
            return self._append_evidence(
                parsed,
                f"LLM Unknown 补充识别未采纳：未知攻击类型 {result.attack_type or 'None'}。",
            ), result

        if result.confidence < self.config.unknown_classifier_min_confidence:
            return self._append_evidence(
                parsed,
                (
                    "LLM Unknown 补充识别未采纳："
                    f"置信度 {result.confidence:.2f} 低于阈值 "
                    f"{self.config.unknown_classifier_min_confidence:.2f}。"
                ),
            ), result

        evidence = [
            *parsed.evidence,
            (
                "LLM Unknown 补充识别："
                f"{normalized_attack_type}，置信度 {result.confidence:.2f}。"
            ),
        ]

        if result.reason:
            evidence.append(f"LLM 识别理由：{result.reason}")

        if result.matched_indicators:
            indicators = "；".join(result.matched_indicators[:5])
            evidence.append(f"LLM 命中特征：{indicators}")

        return parsed.model_copy(
            update={
                "attack_type": normalized_attack_type,
                "attack_features": [
                    *parsed.attack_features,
                    "LLM Unknown Classification",
                    normalized_attack_type,
                ],
                "evidence": evidence,
                "confidence": max(parsed.confidence, result.confidence),
            }
        ), result

    def _should_call(self, parsed: ParsedSecurityEvent) -> tuple[bool, str | None]:
        """
        Decide whether the unknown attack classifier should call LLM.

        Parameters:
         parsed - parsed event from deterministic log parsing

        Returns:
         Tuple containing should-call flag and optional skipped reason

        Raises:
         None
        """

        if parsed.attack_type != "Unknown":
            return False, "RULE_CLASSIFIED"

        if not self.config.enabled:
            return False, "LLM_DISABLED"

        if not self.config.unknown_classifier_enabled:
            return False, "LLM_UNKNOWN_CLASSIFIER_DISABLED"

        if not self.config.api_key:
            return False, "LLM_API_KEY_MISSING"

        if not self.config.base_url:
            return False, "LLM_BASE_URL_MISSING"

        return True, None

    def _build_messages(self, parsed: ParsedSecurityEvent) -> list[dict[str, str]]:
        """
        Build OpenAI-compatible messages for unknown attack classification.

        Parameters:
         parsed - parsed event from deterministic log parsing

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
                "content": self._user_prompt(parsed),
            },
        ]

    def _system_prompt(self) -> str:
        """
        Build the fixed classifier system prompt.

        Parameters:
         None

        Returns:
         System prompt text

        Raises:
         None
        """

        return (
            "你是安全日志攻击类型识别专家。只根据输入日志判断是否疑似攻击，"
            "不要编造外部情报。attack_type 必须从以下集合中选择或返回 null："
            "SQL Injection, XSS, Path Traversal, Command Injection, SSRF, "
            "Brute Force, File Upload, Authentication Bypass, Automated Scanner。"
            "输出必须是 JSON，格式为："
            "{\"attack_suspected\":true/false,\"attack_type\":\"...或null\","
            "\"confidence\":0.0,\"reason\":\"...\","
            "\"matched_indicators\":[\"...\"]}。"
        )

    def _user_prompt(self, parsed: ParsedSecurityEvent) -> str:
        """
        Build the classifier user prompt from a parsed security event.

        Parameters:
         parsed - parsed event from deterministic log parsing

        Returns:
         User prompt text

        Raises:
         None
        """

        event = parsed.event

        return "\n".join(
            [
                "规则引擎未能识别该日志的攻击类型，请做补充判断。",
                "",
                "标准化字段：",
                f"- source_ip: {event.source_ip}",
                f"- method: {event.method}",
                f"- url: {event.url}",
                f"- path: {event.path}",
                f"- query: {event.query}",
                f"- status: {event.status}",
                f"- user_agent: {event.user_agent}",
                f"- waf_rule_id: {event.waf_rule_id or 'None'}",
                f"- waf_message: {event.waf_message or 'None'}",
                "",
                "规则阶段已有证据：",
                self._bullet_list(parsed.evidence),
                "",
                "原始日志：",
                self._truncate(event.raw_log or self._fallback_raw_log(event), 3000),
            ]
        )

    def _append_evidence(
        self,
        parsed: ParsedSecurityEvent,
        evidence: str,
    ) -> ParsedSecurityEvent:
        """
        Append one evidence line to a parsed event.

        Parameters:
         parsed - parsed event to update
         evidence - evidence line to append

        Returns:
         Updated parsed event

        Raises:
         None
        """

        return parsed.model_copy(update={"evidence": [*parsed.evidence, evidence]})

    def _normalize_attack_type(self, attack_type: str | None) -> str | None:
        """
        Normalize LLM attack type text into internal attack type values.

        Parameters:
         attack_type - raw attack type returned by the model

        Returns:
         Normalized attack type or None when unsupported

        Raises:
         None
        """

        if not attack_type:
            return None

        return NORMALIZED_ATTACK_TYPES.get(attack_type.strip().lower())

    def _bullet_list(self, items: list[str]) -> str:
        """
        Format list items as Markdown bullets.

        Parameters:
         items - text items to format

        Returns:
         Markdown bullet list or None marker

        Raises:
         None
        """

        if not items:
            return "- None"

        return "\n".join(f"- {self._truncate(item, 500)}" for item in items[:20])

    def _fallback_raw_log(self, event: SecurityEvent) -> str:
        """
        Build a compact raw log fallback from normalized fields.

        Parameters:
         event - normalized security event

        Returns:
         Text fallback used when raw_log is empty

        Raises:
         None
        """

        return (
            f"{event.source_ip} {event.method} {event.url} "
            f"{event.status or ''} {event.user_agent}"
        )

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
