import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.intel.config import ThreatIntelConfig
from app.intel.schemas import ThreatIntelResult


class AbuseIPDBClient:
    """
    Query AbuseIPDB for source IP reputation.

    Parameters:
     config - threat intelligence runtime configuration
     opener - optional HTTP opener used by tests

    Returns:
     Client that converts AbuseIPDB responses into ThreatIntelResult

    Raises:
     None
    """

    def __init__(self, config: ThreatIntelConfig, opener=None) -> None:
        """
        Initialize the AbuseIPDB client.

        Parameters:
         config - threat intelligence runtime configuration
         opener - optional HTTP opener used by tests

        Returns:
         None

        Raises:
         None
        """

        self.config = config
        self.opener = opener or urlopen

    def available(self) -> bool:
        """
        Return whether AbuseIPDB lookup is configured.

        Parameters:
         None

        Returns:
         True when the provider is enabled and has an API key

        Raises:
         None
        """

        return self.config.abuseipdb_enabled and bool(self.config.abuseipdb_api_key)

    def lookup_ip(self, source_ip: str) -> ThreatIntelResult | None:
        """
        Look up one IP address through AbuseIPDB.

        Parameters:
         source_ip - source IP address to query

        Returns:
         ThreatIntelResult when available, otherwise None

        Raises:
         None
        """

        if not self.available():
            return None

        query = urlencode(
            {
                "ipAddress": source_ip,
                "maxAgeInDays": self.config.abuseipdb_max_age_days,
                "verbose": "",
            }
        )
        request = Request(
            f"{self.config.abuseipdb_base_url}?{query}",
            headers={
                "Key": self.config.abuseipdb_api_key,
                "Accept": "application/json",
            },
            method="GET",
        )

        data = self._load_json(request)

        if data is None:
            return None

        payload = data.get("data", {})

        if not isinstance(payload, dict):
            return None

        confidence = self._int(payload.get("abuseConfidenceScore"))
        reports = self._int(payload.get("totalReports"))
        country = str(payload.get("countryCode") or "")
        usage_type = str(payload.get("usageType") or "")
        isp = str(payload.get("isp") or "")
        domain = str(payload.get("domain") or "")
        tags = ["abuseipdb"]

        if reports > 0:
            tags.append("reported")

        if usage_type:
            tags.append(usage_type.lower().replace(" ", "_"))

        description = (
            f"AbuseIPDB confidence {confidence}, total reports {reports}, "
            f"country {country or 'unknown'}, usage {usage_type or 'unknown'}, "
            f"ISP {isp or 'unknown'}, domain {domain or 'unknown'}."
        )

        return ThreatIntelResult(
            source_ip=source_ip,
            reputation=self._reputation(confidence),
            risk_score=confidence,
            tags=tags,
            source="abuseipdb",
            description=description,
        )

    def _load_json(self, request: Request) -> dict[str, Any] | None:
        """
        Execute one HTTP request and parse its JSON response.

        Parameters:
         request - prepared urllib request

        Returns:
         Parsed JSON dictionary or None on failure

        Raises:
         None
        """

        try:
            with self.opener(request, timeout=self.config.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None

    def _int(self, value: object) -> int:
        """
        Convert a provider value to an integer.

        Parameters:
         value - source value

        Returns:
         Parsed integer or zero

        Raises:
         None
        """

        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _reputation(self, score: int) -> str:
        """
        Convert AbuseIPDB confidence into a reputation label.

        Parameters:
         score - AbuseIPDB abuse confidence score

        Returns:
         Reputation label

        Raises:
         None
        """

        if score >= 75:
            return "malicious"
        if score >= 25:
            return "suspicious"
        return "clean"


class VirusTotalClient:
    """
    Query VirusTotal for source IP reputation.

    Parameters:
     config - threat intelligence runtime configuration
     opener - optional HTTP opener used by tests

    Returns:
     Client that converts VirusTotal responses into ThreatIntelResult

    Raises:
     None
    """

    def __init__(self, config: ThreatIntelConfig, opener=None) -> None:
        """
        Initialize the VirusTotal client.

        Parameters:
         config - threat intelligence runtime configuration
         opener - optional HTTP opener used by tests

        Returns:
         None

        Raises:
         None
        """

        self.config = config
        self.opener = opener or urlopen

    def available(self) -> bool:
        """
        Return whether VirusTotal lookup is configured.

        Parameters:
         None

        Returns:
         True when the provider is enabled and has an API key

        Raises:
         None
        """

        return self.config.virustotal_enabled and bool(self.config.virustotal_api_key)

    def lookup_ip(self, source_ip: str) -> ThreatIntelResult | None:
        """
        Look up one IP address through VirusTotal.

        Parameters:
         source_ip - source IP address to query

        Returns:
         ThreatIntelResult when available, otherwise None

        Raises:
         None
        """

        if not self.available():
            return None

        request = Request(
            f"{self.config.virustotal_base_url.rstrip('/')}/{source_ip}",
            headers={
                "x-apikey": self.config.virustotal_api_key,
                "Accept": "application/json",
            },
            method="GET",
        )
        data = self._load_json(request)

        if data is None:
            return None

        attributes = data.get("data", {}).get("attributes", {})

        if not isinstance(attributes, dict):
            return None

        stats = attributes.get("last_analysis_stats", {})

        if not isinstance(stats, dict):
            stats = {}

        malicious = self._int(stats.get("malicious"))
        suspicious = self._int(stats.get("suspicious"))
        harmless = self._int(stats.get("harmless"))
        undetected = self._int(stats.get("undetected"))
        total = max(malicious + suspicious + harmless + undetected, 1)
        weighted = round(((malicious * 100) + (suspicious * 50)) / total)
        risk_score = min(max(weighted, 0), 100)
        tags = ["virustotal"]

        if malicious:
            tags.append("malicious_votes")

        if suspicious:
            tags.append("suspicious_votes")

        reputation = attributes.get("reputation")
        if reputation is not None:
            tags.append(f"vt_reputation_{reputation}")

        description = (
            f"VirusTotal analysis stats malicious={malicious}, suspicious={suspicious}, "
            f"harmless={harmless}, undetected={undetected}, reputation={reputation}."
        )

        return ThreatIntelResult(
            source_ip=source_ip,
            reputation=self._reputation(risk_score),
            risk_score=risk_score,
            tags=tags,
            source="virustotal",
            description=description,
        )

    def _load_json(self, request: Request) -> dict[str, Any] | None:
        """
        Execute one HTTP request and parse its JSON response.

        Parameters:
         request - prepared urllib request

        Returns:
         Parsed JSON dictionary or None on failure

        Raises:
         None
        """

        try:
            with self.opener(request, timeout=self.config.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None

    def _int(self, value: object) -> int:
        """
        Convert a provider value to an integer.

        Parameters:
         value - source value

        Returns:
         Parsed integer or zero

        Raises:
         None
        """

        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _reputation(self, score: int) -> str:
        """
        Convert VirusTotal weighted score into a reputation label.

        Parameters:
         score - normalized provider risk score

        Returns:
         Reputation label

        Raises:
         None
        """

        if score >= 60:
            return "malicious"
        if score >= 20:
            return "suspicious"
        return "clean"
