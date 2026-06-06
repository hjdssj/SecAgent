from app.context.schemas import ContextAnalysisResult
from app.models.alert import SecurityAlert
from app.triage.schemas import AutoTriageResult


class AutoTriagePolicy:
    """
    Decide alert workflow status from risk, enterprise context, and automation constraints.

    Parameters:
     None

    Returns:
     A deterministic auto triage policy

    Raises:
     None
    """

    def decide(
        self,
        alert: SecurityAlert,
        context: ContextAnalysisResult,
    ) -> AutoTriageResult:
        """
        Decide the automatic triage result for one alert.

        Parameters:
         alert - security alert enriched with analysis context
         context - enterprise context analysis result

        Returns:
         Auto triage result

        Raises:
         None
        """

        references = [
            f"{ref.title} ({ref.source}, score={ref.score:.2f})"
            for ref in context.references[:5]
        ]

        if context.is_internal_scanner and alert.risk_score < 70:
            return AutoTriageResult(
                status="auto_triaged",
                automation_decision="auto_close",
                triage_reason=(
                    "Source IP is whitelisted as an internal scanner and current risk is below high."
                ),
                requires_human_review=False,
                context_references=references,
            )

        if context.asset_criticality == "critical" and alert.risk_score >= 70:
            return AutoTriageResult(
                status="needs_review",
                automation_decision="human_review_required",
                triage_reason=(
                    "Critical asset received a high-risk alert, so analyst review is required."
                ),
                requires_human_review=True,
                context_references=references,
            )

        if alert.risk_score >= 90:
            return AutoTriageResult(
                status="needs_review",
                automation_decision="human_review_required",
                triage_reason="Critical risk score requires analyst validation before closure.",
                requires_human_review=True,
                context_references=references,
            )

        if alert.risk_score >= 80:
            return AutoTriageResult(
                status="needs_review",
                automation_decision="notify_owner",
                triage_reason="High-risk alert should notify the business owner for review.",
                requires_human_review=True,
                context_references=references,
            )

        if context.waf_action == "block" and alert.risk_score < 80:
            return AutoTriageResult(
                status="auto_triaged",
                automation_decision="observe_only",
                triage_reason="WAF policy is blocking and current risk does not require immediate review.",
                requires_human_review=False,
                context_references=references,
            )

        return AutoTriageResult(
            status="needs_review",
            automation_decision="human_review_required",
            triage_reason="Enterprise context is insufficient for safe automatic closure.",
            requires_human_review=True,
            context_references=references,
        )
