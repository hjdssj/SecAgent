from app.core.config import get_bool_env, get_env, get_int_env


class ThreatIntelConfig:
    """
    Hold runtime configuration for real threat intelligence providers.

    Parameters:
     None

    Returns:
     Threat intelligence provider configuration loaded from environment variables

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize provider configuration from environment variables.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.abuseipdb_enabled = get_bool_env("THREAT_INTEL_ABUSEIPDB_ENABLED", False)
        self.abuseipdb_api_key = get_env("ABUSEIPDB_API_KEY")
        self.abuseipdb_base_url = get_env(
            "THREAT_INTEL_ABUSEIPDB_BASE_URL",
            "https://api.abuseipdb.com/api/v2/check",
        )
        self.abuseipdb_max_age_days = get_int_env("THREAT_INTEL_ABUSEIPDB_MAX_AGE_DAYS", 90)

        self.virustotal_enabled = get_bool_env("THREAT_INTEL_VIRUSTOTAL_ENABLED", False)
        self.virustotal_api_key = get_env("VIRUSTOTAL_API_KEY")
        self.virustotal_base_url = get_env(
            "THREAT_INTEL_VIRUSTOTAL_BASE_URL",
            "https://www.virustotal.com/api/v3/ip_addresses",
        )

        self.timeout_seconds = get_int_env("THREAT_INTEL_TIMEOUT_SECONDS", 10)
