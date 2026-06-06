from typing import Literal

from pydantic import BaseModel, Field

AlertStatus = Literal[
    "auto_triaged",
    "needs_review",
    "investigating",
    "resolved",
    "false_positive",
]
AutomationDecision = Literal[
    "observe_only",
    "auto_close",
    "notify_owner",
    "block_ip_recommended",
    "human_review_required",
]


class AutoTriageResult(BaseModel):
    """
    Represent the automatic triage decision for one alert.

    Parameters:
     status - workflow status assigned by auto triage
     automation_decision - recommended automation action
     triage_reason - explanation for the decision
     requires_human_review - whether an analyst must review the alert
     context_references - compact context references used by the decision

    Returns:
     Structured auto triage result

    Raises:
     None
    """

    status: AlertStatus = "auto_triaged"
    automation_decision: AutomationDecision = "observe_only"
    triage_reason: str = ""
    requires_human_review: bool = False
    context_references: list[str] = Field(default_factory=list)
