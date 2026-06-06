from collections.abc import Iterable

from app.models.event import ParsedSecurityEvent


class SecurityQueryRewriter:
    """
    Rewrite parsed security events into retrieval-friendly security queries.

    Parameters:
     None

    Returns:
     A query rewriter instance for RAG retrieval

    Raises:
     None
    """

    ATTACK_TERMS = {
        "SQL Injection": [
            "sql injection",
            "authentication bypass",
            "parameterized query",
            "OWASP CRS 942",
            "MITRE T1190",
        ],
        "XSS": [
            "cross site scripting",
            "output encoding",
            "content security policy",
            "OWASP CRS 941",
            "MITRE T1189",
        ],
        "Path Traversal": [
            "path traversal",
            "directory traversal",
            "arbitrary file read",
            "OWASP CRS 930",
            "MITRE T1190",
        ],
        "Command Injection": [
            "command injection",
            "shell command",
            "allowlist validation",
            "OWASP CRS 932",
            "MITRE T1059",
        ],
        "Automated Scanner": [
            "scanner detection",
            "sqlmap",
            "automated reconnaissance",
            "OWASP CRS 913",
        ],
    }

    RULE_TERMS = {
        "913": ["scanner detection", "automated scanner", "reconnaissance"],
        "930": ["path traversal", "directory traversal", "arbitrary file read"],
        "941": ["xss", "cross site scripting", "output encoding"],
        "942": ["sql injection", "database security", "parameterized query"],
        "932": ["command injection", "shell command", "command execution"],
    }

    def rewrite(self, parsed: ParsedSecurityEvent) -> str:
        """
        Rewrite a parsed event into a security knowledge retrieval query.

        Parameters:
         parsed - parsed security event containing attack type and log context

        Returns:
         Retrieval query string containing attack, WAF, MITRE, and remediation terms

        Raises:
         None
        """

        event = parsed.event
        rule_terms = self._rule_terms(event.waf_rule_id)
        terms = [
            parsed.attack_type,
            event.path,
            event.query,
            event.waf_rule_id or "",
            event.waf_message or "",
            event.user_agent,
            *parsed.attack_features,
            *parsed.evidence,
            *self.ATTACK_TERMS.get(parsed.attack_type, []),
            *rule_terms,
            "remediation",
            "evidence",
            "citation",
        ]

        return " ".join(self._deduplicate(term for term in terms if term)).strip()

    def _rule_terms(self, waf_rule_id: str | None) -> list[str]:
        """
        Expand a WAF rule ID into retrieval-friendly security terms.

        Parameters:
         waf_rule_id - WAF rule ID detected from the event

        Returns:
         Expanded terms related to the WAF rule family

        Raises:
         None
        """

        if not waf_rule_id:
            return []

        for prefix, terms in self.RULE_TERMS.items():
            if waf_rule_id.startswith(prefix):
                return [f"OWASP CRS {prefix}", *terms]

        return []

    def _deduplicate(self, terms: Iterable[str]) -> list[str]:
        """
        Remove duplicated query terms while preserving order.

        Parameters:
         terms - iterable containing query terms

        Returns:
         Deduplicated query term list

        Raises:
         None
        """

        deduplicated: list[str] = []
        seen: set[str] = set()

        for term in terms:
            normalized = str(term).strip()

            if not normalized or normalized.lower() in seen:
                continue

            seen.add(normalized.lower())
            deduplicated.append(normalized)

        return deduplicated
