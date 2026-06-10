import re
from urllib.parse import parse_qsl

from app.models.event import SecurityEvent
from app.rules.loader import RuleLoader
from app.rules.schemas import AttackRule, LogFeatures, RuleEvidence, RuleMatch, RuleMatchResult


class RuleMatcher:
    """
    Match normalized security events against structured attack rules.

    Parameters:
     rules - optional attack rules used by tests or custom runtime config

    Returns:
     Rule matcher for runtime security events

    Raises:
     None
    """

    def __init__(self, rules: list[AttackRule] | None = None) -> None:
        """
        Initialize matcher with attack rules.

        Parameters:
         rules - optional attack rules used by tests or custom runtime config

        Returns:
         None

        Raises:
         None
        """

        self.rules = rules if rules is not None else RuleLoader().load_rules()

    def match(self, event: SecurityEvent) -> RuleMatchResult:
        """
        Match one normalized event against all enabled attack rules.

        Parameters:
         event - normalized security event

        Returns:
         Structured rule matching result

        Raises:
         None
        """

        features = self.extract_features(event)
        matches = [
            item
            for rule in self.rules
            if rule.enabled
            for item in [self._match_rule(rule, event, features)]
            if item is not None
        ]

        if not matches:
            return RuleMatchResult(matched=False, confidence=0.2)

        primary = sorted(
            matches,
            key=lambda item: (item.rule.priority, len(item.evidence), item.rule.confidence),
            reverse=True,
        )[0]
        evidence = self._evidence(matches)
        attack_features = self._attack_features(matches)

        return RuleMatchResult(
            matched=True,
            attack_type=primary.rule.attack_type,
            confidence=self._confidence(primary, matches),
            attack_features=attack_features,
            evidence=evidence,
            matched_rule_ids=[item.rule.rule_id for item in matches],
        )

    def extract_features(self, event: SecurityEvent) -> LogFeatures:
        """
        Extract normalized fields and indicators from one security event.

        Parameters:
         event - normalized security event

        Returns:
         Runtime log features consumed by rule matching

        Raises:
         None
        """

        fields = {
            "url": event.url or "",
            "path": event.path or "",
            "query": event.query or "",
            "user_agent": event.user_agent or "",
            "waf_rule_id": event.waf_rule_id or "",
            "waf_message": event.waf_message or "",
            "raw_log": event.raw_log or "",
            "method": event.method or "",
            "status": str(event.status or ""),
        }
        fields.update(self._access_path_fields("query", self._query_params(event)))
        fields.update(self._access_path_fields("headers", event.headers))
        fields.update(self._access_path_fields("cookies", event.cookies))
        fields.update(self._access_path_fields("body", event.body_fields))
        indicators = set()
        haystack = " ".join(
            [
                fields["url"],
                fields["query"],
                fields["user_agent"],
                fields["waf_message"],
            ]
        ).lower()

        if event.status and event.status >= 400:
            indicators.add("http_error")

        if event.status == 403:
            indicators.add("waf_blocked")

        if event.waf_rule_id:
            indicators.add("waf_rule_hit")

        if any(token in fields["user_agent"].lower() for token in ["sqlmap", "nikto", "acunetix", "nessus"]):
            indicators.add("scanner_user_agent")

        if any(token in haystack for token in ["union select", " or ", "sleep(", "benchmark(", "information_schema"]):
            indicators.add("sql_keyword")

        if any(token in haystack for token in ["<script", "javascript:", "onerror", "onload", "alert("]):
            indicators.add("xss_keyword")

        if any(token in haystack for token in ["../", "..\\", "/etc/passwd", "boot.ini", "win.ini"]):
            indicators.add("path_traversal_keyword")

        if any(token in haystack for token in ["whoami", "; id", "| id", "$(whoami)", "curl ", "wget "]):
            indicators.add("command_keyword")

        return LogFeatures(fields=fields, indicators=indicators)

    def _query_params(self, event: SecurityEvent) -> dict[str, str]:
        """
        Return structured query parameters from explicit fields or query text.

        Parameters:
         event - normalized security event

        Returns:
         Mapping of query parameter names to values

        Raises:
         None
        """

        if event.query_params:
            return event.query_params

        return {
            key: value
            for key, value in parse_qsl(event.query, keep_blank_values=True)
        }

    def _access_path_fields(
        self,
        prefix: str,
        values: dict[str, str],
    ) -> dict[str, str]:
        """
        Build access-path field names from structured event dictionaries.

        Parameters:
         prefix - access-path prefix such as query or headers
         values - key-value fields extracted from the event

        Returns:
         Flattened field mapping such as query.id or headers.User-Agent

        Raises:
         None
        """

        return {
            f"{prefix}.{key}": str(value)
            for key, value in values.items()
            if value is not None
        }

    def _match_rule(
        self,
        rule: AttackRule,
        event: SecurityEvent,
        features: LogFeatures,
    ) -> RuleMatch | None:
        """
        Match one rule against extracted event features.

        Parameters:
         rule - attack rule to evaluate
         event - normalized security event
         features - extracted log features

        Returns:
         RuleMatch when matched, otherwise None

        Raises:
         None
        """

        required = set(rule.match.required_indicators)

        if required and not required.issubset(features.indicators):
            return None

        evidence = []
        waf_rule_id = event.waf_rule_id or ""

        if waf_rule_id and waf_rule_id in rule.match.waf_rule_ids:
            evidence.append(
                RuleEvidence(
                    rule_id=rule.rule_id,
                    attack_type=rule.attack_type,
                    field="waf_rule_id",
                    reason=self._reason(
                        rule,
                        f"WAF 规则 ID {waf_rule_id}",
                    ),
                )
            )

        if waf_rule_id and any(waf_rule_id.startswith(prefix) for prefix in rule.match.waf_rule_prefixes):
            evidence.append(
                RuleEvidence(
                    rule_id=rule.rule_id,
                    attack_type=rule.attack_type,
                    field="waf_rule_id",
                    reason=self._reason(
                        rule,
                        f"WAF 规则前缀 {waf_rule_id}",
                    ),
                )
            )

        evidence.extend(self._pattern_evidence(rule, features))

        if not evidence:
            return None

        return RuleMatch(rule=rule, evidence=evidence)

    def _pattern_evidence(
        self,
        rule: AttackRule,
        features: LogFeatures,
    ) -> list[RuleEvidence]:
        """
        Return evidence produced by regex pattern matches.

        Parameters:
         rule - attack rule containing field and pattern conditions
         features - extracted log features

        Returns:
         Evidence items for regex matches

        Raises:
         None
        """

        evidence = []

        for field in rule.match.fields:
            value = features.fields.get(field, "")

            if not value:
                continue

            for pattern in rule.match.any_patterns:
                if not re.search(pattern, value, flags=re.IGNORECASE):
                    continue

                evidence.append(
                    RuleEvidence(
                        rule_id=rule.rule_id,
                        attack_type=rule.attack_type,
                        field=field,
                        reason=self._reason(
                            rule,
                            (
                                f"字段 {field} 匹配 {rule.attack_type} "
                                f"特征 {pattern}"
                            ),
                        ),
                    )
                )

        return evidence

    def _attack_features(self, matches: list[RuleMatch]) -> list[str]:
        """
        Build parser attack features from matched rules.

        Parameters:
         matches - matched rules

        Returns:
         Deduplicated attack feature list

        Raises:
         None
        """

        features = []

        for item in matches:
            for value in [item.rule.attack_type, f"Rule:{item.rule.rule_id}"]:
                if value not in features:
                    features.append(value)

        return features

    def _evidence(self, matches: list[RuleMatch]) -> list[str]:
        """
        Build parser evidence lines from matched rules.

        Parameters:
         matches - matched rules

        Returns:
         Deduplicated evidence lines

        Raises:
         None
        """

        evidence = []

        for item in matches:
            for detail in item.evidence:
                if detail.reason not in evidence:
                    evidence.append(detail.reason)

        return evidence

    def _confidence(self, primary: RuleMatch, matches: list[RuleMatch]) -> float:
        """
        Calculate final confidence for the primary match.

        Parameters:
         primary - highest-priority rule match
         matches - all matched rules

        Returns:
         Confidence value from 0.0 to 1.0

        Raises:
         None
        """

        bonus = min(0.1, max(0, len(matches) - 1) * 0.03 + len(primary.evidence) * 0.01)
        return min(round(primary.rule.confidence + bonus, 2), 0.95)

    def _reason(self, rule: AttackRule, detail: str) -> str:
        """
        Build an evidence reason with rule metadata.

        Parameters:
         rule - matched attack rule
         detail - concrete match detail

        Returns:
         Human-readable evidence line

        Raises:
         None
        """

        standards = self._standards(rule)
        metadata = f"source={rule.source}, provenance={rule.provenance}"

        if rule.reference:
            metadata = f"{metadata}, reference={rule.reference}"

        if standards:
            metadata = f"{metadata}, standards={standards}"

        return f"命中规则 {rule.rule_id}：{detail}（{metadata}）"

    def _standards(self, rule: AttackRule) -> str:
        """
        Format rule standards into compact evidence text.

        Parameters:
         rule - matched attack rule

        Returns:
         Compact standards text

        Raises:
         None
        """

        parts = []

        if rule.standards.mitre:
            parts.append(f"MITRE={','.join(rule.standards.mitre)}")

        if rule.standards.cwe:
            parts.append(f"CWE={','.join(rule.standards.cwe)}")

        if rule.standards.owasp_top10:
            parts.append(f"OWASP={','.join(rule.standards.owasp_top10)}")

        if rule.standards.crs:
            parts.append(f"CRS={','.join(rule.standards.crs)}")

        return ";".join(parts)
