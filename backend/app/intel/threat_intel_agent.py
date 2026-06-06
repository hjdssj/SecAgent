from app.intel.local_intel_store import LocalIntelStore
from app.intel.schemas import ThreatIntelResult
from app.models.alert import SecurityAlert


class ThreatIntelAgent:
    """
    Enrich security alerts with local threat intelligence context.

    Parameters:
     intel_store - local intelligence store used for source IP lookup

    Returns:
     A threat intelligence agent for alert enrichment

    Raises:
     None
    """

    def __init__(self, intel_store: LocalIntelStore | None = None) -> None:
        """
        Initialize the threat intelligence agent.

        Parameters:
         intel_store - local intelligence store used for source IP lookup

        Returns:
         None

        Raises:
         None
        """

        self.intel_store = intel_store or LocalIntelStore()

    def lookup(self, source_ip: str) -> ThreatIntelResult:
        """
        Look up threat intelligence for a source IP.

        Parameters:
         source_ip - source IP address to look up

        Returns:
         Threat intelligence result for the source IP

        Raises:
         None
        """

        return self.intel_store.lookup_ip(source_ip)

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
            f"情报风险分 {intel.risk_score}，标签：{tags}"
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
