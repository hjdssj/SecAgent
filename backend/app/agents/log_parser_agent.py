import re

from app.models.event import ParsedSecurityEvent, SecurityEvent


class LogParserAgent:
    """
    解析标准化安全事件并提取攻击特征。

    Parameters:
     None

    Returns:
     一个用于从安全事件中提取攻击特征的 Agent 实例

    Raises:
     None
    """

    SQLI_PATTERNS = [
        r"(?i)union\s+select",
        r"(?i)or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        r"(?i)sleep\s*\(",
        r"(?i)benchmark\s*\(",
        r"(?i)information_schema",
    ]

    XSS_PATTERNS = [
        r"(?i)<script",
        r"(?i)javascript:",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
        r"(?i)alert\s*\(",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"(?i)/etc/passwd",
        r"(?i)boot\.ini",
        r"(?i)win\.ini",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"(?i);\s*(cat|whoami|id|curl|wget)\b",
        r"(?i)\|\s*(cat|whoami|id|curl|wget)\b",
        r"`[^`]+`",
        r"\$\([^)]+\)",
    ]

    SCANNER_PATTERNS = [
        r"(?i)sqlmap",
        r"(?i)nikto",
        r"(?i)acunetix",
        r"(?i)nessus",
    ]

    def parse(self, event: SecurityEvent) -> ParsedSecurityEvent:
        """
        将标准化安全事件解析为攻击分析特征。

        Parameters:
         event - 标准化安全事件，包含 URL、请求参数、User-Agent、WAF 规则和原始日志

        Returns:
         解析后的安全事件，包含攻击类型、攻击特征、证据和置信度

        Raises:
         None
        """

        text = self._build_detection_text(event)
        detections: list[tuple[str, str]] = []

        detections.extend(self._match_patterns("SQL Injection", self.SQLI_PATTERNS, text))
        detections.extend(self._match_patterns("XSS", self.XSS_PATTERNS, text))
        detections.extend(
            self._match_patterns("Path Traversal", self.PATH_TRAVERSAL_PATTERNS, text)
        )
        detections.extend(
            self._match_patterns("Command Injection", self.COMMAND_INJECTION_PATTERNS, text)
        )
        detections.extend(
            self._match_patterns("Automated Scanner", self.SCANNER_PATTERNS, text)
        )

        if event.waf_rule_id:
            detections.append(("WAF Rule Match", f"命中 WAF 规则：{event.waf_rule_id}"))

        if event.waf_message:
            detections.append(("WAF Message", f"WAF 告警信息：{event.waf_message}"))

        attack_type = self._choose_attack_type(detections, event)
        attack_features = [attack for attack, _ in detections]
        evidence = [item for _, item in detections]
        confidence = self._calculate_confidence(evidence)

        return ParsedSecurityEvent(
            event=event,
            attack_type=attack_type,
            attack_features=attack_features,
            evidence=evidence,
            confidence=confidence,
        )

    def _build_detection_text(self, event: SecurityEvent) -> str:
        """
        构建用于攻击特征检测的文本。

        Parameters:
         event - 标准化安全事件

        Returns:
         由 URL、路径、请求参数、User-Agent、WAF 信息和原始日志合并得到的检测文本

        Raises:
         None
        """

        return " ".join(
            [
                event.url,
                event.path,
                event.query,
                event.user_agent,
                event.waf_message or "",
                event.raw_log,
            ]
        )

    def _match_patterns(
        self,
        attack_type: str,
        patterns: list[str],
        text: str,
    ) -> list[tuple[str, str]]:
        """
        使用正则表达式匹配攻击特征。

        Parameters:
         attack_type - 当前规则组对应的攻击类型
         patterns - 用于检测该攻击类型的正则表达式列表
         text - 待检测的日志文本

        Returns:
         命中的攻击类型和证据说明列表

        Raises:
         None
        """

        matches: list[tuple[str, str]] = []

        for pattern in patterns:
            if re.search(pattern, text):
                matches.append((attack_type, f"命中 {attack_type} 特征：{pattern}"))

        return matches

    def _choose_attack_type(
        self,
        detections: list[tuple[str, str]],
        event: SecurityEvent,
    ) -> str:
        """
        根据 WAF 规则和攻击特征选择最终攻击类型。

        Parameters:
         detections - 已命中的攻击类型和证据说明列表
         event - 标准化安全事件

        Returns:
         最终攻击类型；如果无法判断则返回 Unknown

        Raises:
         None
        """

        rule_id = event.waf_rule_id or ""

        if rule_id.startswith("932"):
            return "Command Injection"
        if rule_id.startswith("942"):
            return "SQL Injection"
        if rule_id.startswith("930"):
            return "Path Traversal"
        if rule_id.startswith("941"):
            return "XSS"
        if rule_id.startswith("913"):
            return "Automated Scanner"

        message = (event.waf_message or "").lower()

        if "sql injection" in message:
            return "SQL Injection"
        if "xss" in message:
            return "XSS"
        if "path traversal" in message or "directory traversal" in message:
            return "Path Traversal"
        if "command injection" in message or "remote command execution" in message:
            return "Command Injection"

        found = {attack for attack, _ in detections}
        priority = [
            "Command Injection",
            "SQL Injection",
            "Path Traversal",
            "XSS",
            "Automated Scanner",
        ]

        for attack_type in priority:
            if attack_type in found:
                return attack_type

        return "Unknown"

    def _calculate_confidence(self, evidence: list[str]) -> float:
        """
        根据证据数量计算攻击判断置信度。

        Parameters:
         evidence - 支撑攻击判断的证据列表

        Returns:
         0.0 到 1.0 之间的置信度分数

        Raises:
         None
        """

        count = len(evidence)

        if count == 0:
            return 0.2
        if count == 1:
            return 0.5
        if count == 2:
            return 0.65
        if count == 3:
            return 0.8

        return 0.9
