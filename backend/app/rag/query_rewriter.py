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
        terms = [
            parsed.attack_type,
            event.path,
            event.query,
            event.waf_rule_id or "",
            event.waf_message or "",
            event.user_agent,
            *self.ATTACK_TERMS.get(parsed.attack_type, []),
            "remediation",
            "evidence",
        ]

        return " ".join(term for term in terms if term).strip()
