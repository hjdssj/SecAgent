from app.core.config import get_bool_env, get_env
from app.models.alert import SecurityAlert

RISK_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class LongTermMemoryPolicy:
    """
    Decide whether an alert should be written to long-term memory.

    Parameters:
     None

    Returns:
     Long-term memory write policy loaded from environment variables

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize long-term memory policy.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.enabled = get_bool_env("LONG_TERM_MEMORY_ENABLED", False)
        self.min_risk_level = get_env("LONG_TERM_MEMORY_MIN_RISK_LEVEL", "high")
        self.write_auto_closed = get_bool_env("LONG_TERM_MEMORY_WRITE_AUTO_CLOSED", False)
        self.search_enabled = get_bool_env("LONG_TERM_MEMORY_SEARCH_ENABLED", self.enabled)
        self.require_analyst_note = get_bool_env(
            "LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE",
            False,
        )

    def should_write(self, alert: SecurityAlert) -> tuple[bool, str | None]:
        """
        Decide whether one alert should be written to long-term memory.

        Parameters:
         alert - final security alert

        Returns:
         Tuple containing should-write flag and optional skipped reason

        Raises:
         None
        """

        if not self.enabled:
            return False, "LONG_TERM_MEMORY_DISABLED"

        if not self.write_auto_closed and alert.automation_decision == "auto_close":
            return False, "AUTO_CLOSED_ALERT_SKIPPED"

        if self.require_analyst_note and not alert.analyst_note:
            return False, "ANALYST_NOTE_REQUIRED"

        alert_rank = RISK_ORDER.get(alert.risk_level, 0)
        min_rank = RISK_ORDER.get(self.min_risk_level, RISK_ORDER["high"])

        if alert_rank < min_rank:
            return False, "RISK_LEVEL_BELOW_THRESHOLD"

        return True, None

    def should_search(self, alert: SecurityAlert) -> tuple[bool, str | None]:
        """
        Decide whether similar long-term memories should be searched for one alert.

        Parameters:
         alert - current security alert

        Returns:
         Tuple containing should-search flag and optional skipped reason

        Raises:
         None
        """

        if not self.search_enabled:
            return False, "LONG_TERM_MEMORY_SEARCH_DISABLED"

        alert_rank = RISK_ORDER.get(alert.risk_level, 0)
        min_rank = RISK_ORDER.get(self.min_risk_level, RISK_ORDER["high"])

        if alert_rank < min_rank:
            return False, "RISK_LEVEL_BELOW_THRESHOLD"

        return True, None
