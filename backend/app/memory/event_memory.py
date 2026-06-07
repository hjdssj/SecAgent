from redis.exceptions import RedisError

from app.core.config import get_env
from app.memory.schemas import IpMemorySummary
from app.models.alert import SecurityAlert
from app.storage.redis_client import get_redis_client

MEMORY_PREFIX = get_env("REDIS_MEMORY_PREFIX", "memory:ip")


class EventMemory:
    """
    Store and summarize historical alert behavior for source IP addresses.

    Parameters:
     None

    Returns:
     An event memory instance backed by Redis when available

    Raises:
     None
    """

    def get_ip_summary(self, source_ip: str) -> IpMemorySummary:
        """
        Read historical alert summary for one source IP.

        Parameters:
         source_ip - source IP address to summarize

        Returns:
         Historical behavior summary for the source IP

        Raises:
         None
        """

        try:
            client = get_redis_client()
            key = self._key(source_ip)
            alert_count = int(client.hget(key, "alert_count") or 0)
            attack_types = sorted(client.smembers(f"{key}:attack_types"))
            targets = sorted(client.smembers(f"{key}:targets"))
            last_seen = client.hget(key, "last_seen")
        except RedisError:
            return IpMemorySummary(source_ip=source_ip, storage_available=False)

        return IpMemorySummary(
            source_ip=source_ip,
            alert_count=alert_count,
            attack_types=attack_types,
            targets=targets,
            last_seen=last_seen,
            storage_available=True,
        )

    def record_alert(self, alert: SecurityAlert) -> None:
        """
        Record one generated alert into source IP memory.

        Parameters:
         alert - generated security alert to record

        Returns:
         None

        Raises:
         None
        """

        try:
            client = get_redis_client()
            key = self._key(alert.source_ip)
            pipe = client.pipeline()
            pipe.hincrby(key, "alert_count", 1)
            pipe.hset(key, "last_seen", alert.alert_id)
            pipe.sadd(f"{key}:attack_types", alert.attack_type)
            pipe.sadd(f"{key}:targets", alert.target)
            pipe.lpush(f"{key}:alerts", alert.model_dump_json())
            pipe.ltrim(f"{key}:alerts", 0, 49)
            pipe.execute()
        except RedisError:
            return

    def enrich_alert(
        self,
        alert: SecurityAlert,
        summary: IpMemorySummary,
    ) -> SecurityAlert:
        """
        Enrich an alert with historical behavior memory.

        Parameters:
         alert - security alert to enrich
         summary - historical behavior summary for the alert source IP

        Returns:
         Security alert enriched with memory context

        Raises:
         None
        """

        score_delta = self._score_delta(summary)
        risk_score = min(alert.risk_score + score_delta, 100)
        evidence = [
            *alert.evidence,
            self._evidence(summary),
        ]
        recommendations = [
            *alert.recommendations,
            *self._recommendations(summary),
        ]
        report_markdown = self._append_report_section(
            alert.report_markdown or "",
            summary,
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

    def _evidence(self, summary: IpMemorySummary) -> str:
        """
        Build historical behavior evidence text.

        Parameters:
         summary - historical behavior summary

        Returns:
         Evidence text for alert enrichment

        Raises:
         None
        """

        if not summary.storage_available:
            return "历史行为：Memory 存储不可用，当前告警未纳入历史统计。"

        if summary.alert_count == 0:
            return f"历史行为：源 IP {summary.source_ip} 暂无历史告警记录。"

        attacks = ", ".join(summary.attack_types) if summary.attack_types else "unknown"
        targets = ", ".join(summary.targets[:5]) if summary.targets else "unknown"
        return (
            f"历史行为：源 IP {summary.source_ip} 已有 {summary.alert_count} 条历史告警，"
            f"攻击类型：{attacks}，目标：{targets}"
        )

    def _recommendations(self, summary: IpMemorySummary) -> list[str]:
        """
        Build recommendations from historical behavior summary.

        Parameters:
         summary - historical behavior summary

        Returns:
         Memory-based recommendation list

        Raises:
         None
        """

        if not summary.storage_available or summary.alert_count == 0:
            return []

        recommendations = [
            f"结合源 IP {summary.source_ip} 的历史告警进行时间线复盘。",
        ]

        if summary.alert_count >= 3:
            recommendations.append("该来源已多次触发告警，建议评估限速、封禁或加入重点观察名单。")

        if len(summary.attack_types) >= 2:
            recommendations.append("该来源涉及多种攻击类型，疑似自动化扫描或漏洞探测。")

        return recommendations

    def _append_report_section(
        self,
        report_markdown: str,
        summary: IpMemorySummary,
        score_delta: int,
    ) -> str:
        """
        Append historical behavior context to a markdown report.

        Parameters:
         report_markdown - original markdown report
         summary - historical behavior summary
         score_delta - risk score delta applied from memory

        Returns:
         Markdown report enriched with memory context

        Raises:
         None
        """

        attacks = ", ".join(summary.attack_types) if summary.attack_types else "none"
        targets = ", ".join(summary.targets[:8]) if summary.targets else "none"
        availability = "available" if summary.storage_available else "unavailable"

        return (
            f"{report_markdown.rstrip()}\n\n"
            "## 历史行为\n\n"
            f"- Memory 状态：{availability}\n"
            f"- 源 IP：{summary.source_ip}\n"
            f"- 历史告警数：{summary.alert_count}\n"
            f"- 历史攻击类型：{attacks}\n"
            f"- 历史目标：{targets}\n"
            f"- 最近记录：{summary.last_seen or 'none'}\n"
            f"- 风险分调整：+{score_delta}\n"
        )

    def _score_delta(self, summary: IpMemorySummary) -> int:
        """
        Calculate risk score delta from historical behavior.

        Parameters:
         summary - historical behavior summary

        Returns:
         Additional risk score caused by historical behavior

        Raises:
         None
        """

        if not summary.storage_available:
            return 0

        delta = 0

        if summary.alert_count >= 5:
            delta += 8
        elif summary.alert_count >= 3:
            delta += 5
        elif summary.alert_count >= 1:
            delta += 2

        if len(summary.attack_types) >= 3:
            delta += 4
        elif len(summary.attack_types) >= 2:
            delta += 2

        return delta

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

    def _key(self, source_ip: str) -> str:
        """
        Build Redis key prefix for one source IP.

        Parameters:
         source_ip - source IP address

        Returns:
         Redis key prefix for the source IP memory

        Raises:
         None
        """

        return f"{MEMORY_PREFIX}:{source_ip}"
