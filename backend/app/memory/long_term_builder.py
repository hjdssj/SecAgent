from datetime import UTC, datetime

from app.analysis.state import AnalysisState
from app.memory.long_term_schemas import LongTermMemoryRecord
from app.models.alert import SecurityAlert


class LongTermMemoryBuilder:
    """
    Build long-term memory records from final alerts and analysis state.

    Parameters:
     None

    Returns:
     Builder for long-term analysis memory records

    Raises:
     None
    """

    def build(
        self,
        alert: SecurityAlert,
        state: AnalysisState,
    ) -> LongTermMemoryRecord:
        """
        Build one long-term memory record.

        Parameters:
         alert - final security alert
         state - analysis state produced with the alert

        Returns:
         Long-term memory record

        Raises:
         None
        """

        summary = self.summary_text(alert, state)

        return LongTermMemoryRecord(
            memory_id=f"memory-{alert.alert_id}",
            alert_id=alert.alert_id,
            session_id=alert.session_id or state.session_id,
            source_ip=alert.source_ip,
            target=alert.target,
            attack_type=alert.attack_type,
            risk_level=alert.risk_level,
            business_owner=alert.business_owner,
            asset_criticality=alert.asset_criticality,
            status=alert.status,
            automation_decision=alert.automation_decision,
            summary=summary,
            evidence_text=self._join(alert.evidence, 3000),
            recommendation_text=self._join(alert.recommendations, 2000),
            analyst_note=alert.analyst_note,
            handled_by=alert.handled_by,
            handled_at=alert.handled_at,
            created_at=datetime.now(UTC).isoformat(),
            enabled=True,
        )

    def summary_text(
        self,
        alert: SecurityAlert,
        state: AnalysisState,
    ) -> str:
        """
        Build semantic summary text used for embedding.

        Parameters:
         alert - final security alert
         state - analysis state produced with the alert

        Returns:
         Text summary suitable for embedding and search

        Raises:
         None
        """

        finding_titles = "; ".join(item.title for item in state.findings[:5])
        reflection_text = "; ".join(item.summary for item in state.reflections[:3])
        metadata = alert.analysis_metadata
        mode = metadata.analysis_mode if metadata else alert.analysis_mode

        return "\n".join(
            [
                f"attack_type: {alert.attack_type}",
                f"risk_level: {alert.risk_level}",
                f"risk_score: {alert.risk_score}",
                f"confidence: {alert.confidence}",
                f"source_ip: {alert.source_ip}",
                f"target: {alert.target}",
                f"business_owner: {alert.business_owner or 'unknown'}",
                f"asset_criticality: {alert.asset_criticality or 'unknown'}",
                f"status: {alert.status}",
                f"automation_decision: {alert.automation_decision}",
                f"analysis_mode: {mode}",
                f"triage_reason: {alert.triage_reason}",
                f"findings: {finding_titles or 'none'}",
                f"reflections: {reflection_text or 'none'}",
                f"evidence: {self._join(alert.evidence, 1200)}",
                f"recommendations: {self._join(alert.recommendations, 1000)}",
                f"analyst_note: {alert.analyst_note or 'none'}",
            ]
        )

    def search_text(
        self,
        alert: SecurityAlert,
        state: AnalysisState | None = None,
    ) -> str:
        """
        Build semantic query text for similar long-term memory search.

        Parameters:
         alert - current security alert
         state - optional current analysis state

        Returns:
         Query text suitable for embedding and similar memory retrieval

        Raises:
         None
        """

        parsed = state.parsed_event if state else None
        attack_features = "; ".join(parsed.attack_features[:8]) if parsed else ""

        return "\n".join(
            [
                f"attack_type: {alert.attack_type}",
                f"risk_level: {alert.risk_level}",
                f"source_ip: {alert.source_ip}",
                f"target: {alert.target}",
                f"business_owner: {alert.business_owner or 'unknown'}",
                f"asset_criticality: {alert.asset_criticality or 'unknown'}",
                f"triage_reason: {alert.triage_reason}",
                f"attack_features: {attack_features or 'none'}",
                f"evidence: {self._join(alert.evidence, 1000)}",
            ]
        )

    def _join(self, items: list[str], limit: int) -> str:
        """
        Join strings and truncate the result.

        Parameters:
         items - text items to join
         limit - maximum returned character count

        Returns:
         Joined and truncated text

        Raises:
         None
        """

        text = "\n".join(items)

        if len(text) <= limit:
            return text

        return f"{text[:limit]}...[truncated]"
