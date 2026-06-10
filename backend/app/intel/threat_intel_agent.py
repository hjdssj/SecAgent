from app.intel.config import ThreatIntelConfig
from app.intel.local_intel_store import LocalIntelStore
from app.intel.providers import AbuseIPDBClient, VirusTotalClient
from app.intel.schemas import ThreatIntelResult
from app.models.alert import SecurityAlert


class ThreatIntelAgent:
    """
    Enrich security alerts with local threat intelligence context.

    Parameters:
     intel_store - local intelligence store used for fallback source IP lookup
     abuseipdb_client - optional AbuseIPDB client used by tests
     virustotal_client - optional VirusTotal client used by tests

    Returns:
     A threat intelligence agent for alert enrichment

    Raises:
     None
    """

    def __init__(
        self,
        intel_store: LocalIntelStore | None = None,
        abuseipdb_client: AbuseIPDBClient | None = None,
        virustotal_client: VirusTotalClient | None = None,
    ) -> None:
        """
        Initialize the threat intelligence agent.

        Parameters:
         intel_store - local intelligence store used for fallback source IP lookup
         abuseipdb_client - optional AbuseIPDB client used by tests
         virustotal_client - optional VirusTotal client used by tests

        Returns:
         None

        Raises:
         None
        """

        self.intel_store = intel_store or LocalIntelStore()
        config = ThreatIntelConfig()
        self.abuseipdb_client = abuseipdb_client or AbuseIPDBClient(config)
        self.virustotal_client = virustotal_client or VirusTotalClient(config)

    def lookup(self, source_ip: str) -> ThreatIntelResult:
        """
        Look up threat intelligence for a source IP from real providers and local fallback.

        Parameters:
         source_ip - source IP address to look up

        Returns:
         Threat intelligence result for the source IP

        Raises:
         None
        """

        results = [
            result
            for result in [
                self.abuseipdb_client.lookup_ip(source_ip),
                self.virustotal_client.lookup_ip(source_ip),
                self.intel_store.lookup_ip(source_ip),
            ]
            if result is not None
        ]
        return self._merge_results(source_ip, results)

    def enrich_alert(
        self,
        alert: SecurityAlert,
        intel: ThreatIntelResult,
    ) -> SecurityAlert:
        """
        Enrich a security alert with threat intelligence evidence and scoring.

        Parameters:
         alert - base security alert to enrich
         intel - threat intelligence result for alert source IP

        Returns:
         Security alert enriched with threat intelligence context

        Raises:
         None
        """

        score_delta = self._score_delta(intel)
        risk_score = min(alert.risk_score + score_delta, 100)
        evidence = [
            *alert.evidence,
            self._evidence(intel),
        ]
        recommendations = [
            *alert.recommendations,
            *self._recommendations(intel),
        ]
        report_markdown = self._append_report_section(
            alert.report_markdown or "",
            intel,
            score_delta,
        )

        return alert.model_copy(
            update={
                "risk_score": risk_score,
                "risk_level": self._level(risk_score),
                "evidence": evidence,
                "recommendations": self._merge_unique(recommendations),
                "report_markdown": report_markdown,
            }
        )

    def _evidence(self, intel: ThreatIntelResult) -> str:
        """
        Build threat intelligence evidence text.

        Parameters:
         intel - threat intelligence result

        Returns:
         Evidence text for the alert

        Raises:
         None
        """

        tags = ", ".join(intel.tags) if intel.tags else "none"
        return (
            f"威胁情报：源 IP {intel.source_ip} 信誉为 {intel.reputation}，"
            f"情报风险分 {intel.risk_score}，来源：{intel.source}，标签：{tags}"
        )

    def _recommendations(self, intel: ThreatIntelResult) -> list[str]:
        """
        Build threat intelligence remediation recommendations.

        Parameters:
         intel - threat intelligence result

        Returns:
         Threat intelligence remediation recommendation list

        Raises:
         None
        """

        if intel.risk_score >= 80:
            return [
                f"将源 IP {intel.source_ip} 加入高优先级观察名单，并评估是否临时封禁。",
                "结合 WAF 和访问日志回溯该来源的横向探测行为。",
            ]

        if intel.risk_score >= 50:
            return [
                f"持续观察源 IP {intel.source_ip}，关注是否出现多路径扫描或重复攻击。",
            ]

        return []

    def _append_report_section(
        self,
        report_markdown: str,
        intel: ThreatIntelResult,
        score_delta: int,
    ) -> str:
        """
        Append threat intelligence context to a markdown report.

        Parameters:
         report_markdown - original markdown report
         intel - threat intelligence result
         score_delta - risk score delta applied from intelligence

        Returns:
         Markdown report enriched with threat intelligence context

        Raises:
         None
        """

        tags = ", ".join(intel.tags) if intel.tags else "none"
        return (
            f"{report_markdown.rstrip()}\n\n"
            "## 威胁情报\n\n"
            f"- 源 IP：{intel.source_ip}\n"
            f"- 信誉：{intel.reputation}\n"
            f"- 情报风险分：{intel.risk_score}\n"
            f"- 标签：{tags}\n"
            f"- 来源：{intel.source}\n"
            f"- 说明：{intel.description}\n"
            f"- 风险分调整：+{score_delta}\n"
        )

    def _merge_results(
        self,
        source_ip: str,
        results: list[ThreatIntelResult],
    ) -> ThreatIntelResult:
        """
        Merge multiple provider results into one threat intelligence verdict.

        Parameters:
         source_ip - source IP address looked up
         results - provider and fallback intelligence results

        Returns:
         Combined threat intelligence result

        Raises:
         None
        """

        if not results:
            return ThreatIntelResult(source_ip=source_ip)

        meaningful_results = [
            result
            for result in results
            if result.source != "local_mock" or result.risk_score > 0 or result.reputation != "unknown"
        ]
        merged_results = meaningful_results or results
        risk_score = max(result.risk_score for result in merged_results)
        sources = [result.source for result in merged_results if result.source]
        descriptions = [
            f"{result.source}: {result.description}"
            for result in merged_results
            if result.description
        ]
        tags: list[str] = []

        for result in merged_results:
            for tag in result.tags:
                if tag not in tags:
                    tags.append(tag)

        return ThreatIntelResult(
            source_ip=source_ip,
            reputation=self._reputation_from_results(merged_results, risk_score),
            risk_score=risk_score,
            tags=tags,
            source="+".join(dict.fromkeys(sources)) or "unknown",
            description=" | ".join(descriptions) or "No threat intelligence record found.",
        )

    def _reputation_from_results(
        self,
        results: list[ThreatIntelResult],
        risk_score: int,
    ) -> str:
        """
        Build the final reputation label from provider results and score.

        Parameters:
         results - provider and fallback intelligence results
         risk_score - final merged risk score

        Returns:
         Reputation label

        Raises:
         None
        """

        reputations = {result.reputation for result in results}

        if "malicious" in reputations or risk_score >= 75:
            return "malicious"

        if "suspicious" in reputations or risk_score >= 25:
            return "suspicious"

        if "clean" in reputations:
            return "clean"

        return "unknown"

    def _score_delta(self, intel: ThreatIntelResult) -> int:
        """
        Calculate risk score delta from threat intelligence.

        Parameters:
         intel - threat intelligence result

        Returns:
         Additional risk score caused by threat intelligence

        Raises:
         None
        """

        if intel.risk_score >= 85:
            return 10
        if intel.risk_score >= 65:
            return 6
        if intel.risk_score >= 40:
            return 3
        return 0

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

    def _merge_unique(self, items: list[str]) -> list[str]:
        """
        Deduplicate strings while preserving order.

        Parameters:
         items - source string list

        Returns:
         Deduplicated string list

        Raises:
         None
        """

        merged: list[str] = []
        seen: set[str] = set()

        for item in items:
            if item in seen:
                continue

            seen.add(item)
            merged.append(item)

        return merged
