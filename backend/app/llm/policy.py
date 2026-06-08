from app.llm.schemas import LLMConfig
from app.models.alert import SecurityAlert

RISK_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class LLMCallPolicy:
    """
    Decide whether an alert should trigger optional LLM enhancement.

    Parameters:
     config - LLM runtime configuration

    Returns:
     Policy object for LLM cost control

    Raises:
     None
    """

    def __init__(self, config: LLMConfig) -> None:
        """
        Initialize the policy with LLM configuration.

        Parameters:
         config - LLM runtime configuration

        Returns:
         None

        Raises:
         None
        """

        self.config = config

    def should_call(self, alert: SecurityAlert) -> tuple[bool, str | None]:
        """
        Decide whether to call the LLM for one alert.

        Parameters:
         alert - final alert before LLM enhancement

        Returns:
         Tuple containing should-call flag and optional skipped reason

        Raises:
         None
        """

        if not self.config.enabled:
            return False, "LLM_DISABLED"

        if not self.config.api_key:
            return False, "LLM_API_KEY_MISSING"

        if not self.config.base_url:
            return False, "LLM_BASE_URL_MISSING"

        if self.config.only_for_review and not alert.requires_human_review:
            return False, "ALERT_DOES_NOT_REQUIRE_REVIEW"

        min_rank = RISK_ORDER.get(self.config.min_risk_level, RISK_ORDER["high"])
        alert_rank = RISK_ORDER.get(alert.risk_level, 0)

        if alert_rank < min_rank:
            return False, "RISK_BELOW_LLM_THRESHOLD"

        return True, None
