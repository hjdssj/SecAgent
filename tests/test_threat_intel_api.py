import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.intel.config import ThreatIntelConfig
from app.intel.providers import AbuseIPDBClient, VirusTotalClient
from app.intel.schemas import ThreatIntelResult
from app.intel.threat_intel_agent import ThreatIntelAgent


class FakeResponse:
    """
    Provide a minimal context-manager HTTP response for provider tests.

    Parameters:
     payload - JSON-serializable response body

    Returns:
     Fake urllib response object

    Raises:
     None
    """

    def __init__(self, payload: dict) -> None:
        """
        Initialize response payload.

        Parameters:
         payload - JSON-serializable response body

        Returns:
         None

        Raises:
         None
        """

        self.payload = payload

    def __enter__(self):
        """
        Enter response context manager.

        Parameters:
         None

        Returns:
         FakeResponse instance

        Raises:
         None
        """

        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        """
        Exit response context manager.

        Parameters:
         exc_type - exception type
         exc - exception value
         traceback - exception traceback

        Returns:
         None

        Raises:
         None
        """

        return None

    def read(self) -> bytes:
        """
        Return encoded JSON response bytes.

        Parameters:
         None

        Returns:
         UTF-8 encoded JSON payload

        Raises:
         None
        """

        return json.dumps(self.payload).encode("utf-8")


def build_config() -> ThreatIntelConfig:
    """
    Build deterministic enabled provider config for tests.

    Parameters:
     None

    Returns:
     Threat intel config with fake API keys

    Raises:
     None
    """

    config = ThreatIntelConfig()
    config.abuseipdb_enabled = True
    config.abuseipdb_api_key = "abuse-test-key"
    config.abuseipdb_base_url = "https://abuse.example/check"
    config.virustotal_enabled = True
    config.virustotal_api_key = "vt-test-key"
    config.virustotal_base_url = "https://vt.example/ip_addresses"
    config.timeout_seconds = 1
    return config


def test_abuseipdb_client_parses_check_response() -> None:
    """
    Verify AbuseIPDB check response is converted into a threat intel result.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    captured = {}

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["key"] = request.headers.get("Key")
        captured["accept"] = request.headers.get("Accept")
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "data": {
                    "ipAddress": "45.67.89.10",
                    "abuseConfidenceScore": 91,
                    "totalReports": 13,
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.net",
                }
            }
        )

    result = AbuseIPDBClient(build_config(), opener=opener).lookup_ip("45.67.89.10")

    assert result is not None
    assert result.source_ip == "45.67.89.10"
    assert result.source == "abuseipdb"
    assert result.reputation == "malicious"
    assert result.risk_score == 91
    assert "reported" in result.tags
    assert "Data+Center" not in captured["url"]
    assert "ipAddress=45.67.89.10" in captured["url"]
    assert captured["key"] == "abuse-test-key"
    assert captured["accept"] == "application/json"
    assert captured["timeout"] == 1


def test_virustotal_client_parses_ip_report_response() -> None:
    """
    Verify VirusTotal IP response is converted into a threat intel result.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    captured = {}

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["apikey"] = request.headers.get("X-apikey")
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 7,
                            "suspicious": 2,
                            "harmless": 30,
                            "undetected": 11,
                        },
                        "reputation": -25,
                    }
                }
            }
        )

    result = VirusTotalClient(build_config(), opener=opener).lookup_ip("45.67.89.10")

    assert result is not None
    assert result.source_ip == "45.67.89.10"
    assert result.source == "virustotal"
    assert result.risk_score == 16
    assert result.reputation == "clean"
    assert "malicious_votes" in result.tags
    assert captured["url"] == "https://vt.example/ip_addresses/45.67.89.10"
    assert captured["apikey"] == "vt-test-key"
    assert captured["timeout"] == 1


def test_threat_intel_agent_merges_real_providers_and_local_fallback() -> None:
    """
    Verify ThreatIntelAgent returns the highest-risk provider verdict.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    class FakeProvider:
        """
        Return deterministic threat intel results for merge tests.

        Parameters:
         result - threat intel result to return

        Returns:
         Fake provider object

        Raises:
         None
        """

        def __init__(self, result: ThreatIntelResult | None) -> None:
            """
            Initialize deterministic provider result.

            Parameters:
             result - threat intel result to return

            Returns:
             None

            Raises:
             None
            """

            self.result = result

        def lookup_ip(self, source_ip: str) -> ThreatIntelResult | None:
            """
            Return deterministic result.

            Parameters:
             source_ip - source IP address

            Returns:
             Configured threat intel result

            Raises:
             None
            """

            return self.result

    class FakeLocalStore:
        """
        Return deterministic local fallback intelligence.

        Parameters:
         None

        Returns:
         Fake local intel store

        Raises:
         None
        """

        def lookup_ip(self, source_ip: str) -> ThreatIntelResult:
            """
            Return local fallback result.

            Parameters:
             source_ip - source IP address

            Returns:
             Local threat intel result

            Raises:
             None
            """

            return ThreatIntelResult(
                source_ip=source_ip,
                reputation="unknown",
                risk_score=0,
                tags=[],
                source="local_mock",
                description="local fallback",
            )

    agent = ThreatIntelAgent(
        intel_store=FakeLocalStore(),
        abuseipdb_client=FakeProvider(
            ThreatIntelResult(
                source_ip="45.67.89.10",
                reputation="malicious",
                risk_score=88,
                tags=["abuseipdb", "reported"],
                source="abuseipdb",
                description="AbuseIPDB high confidence",
            )
        ),
        virustotal_client=FakeProvider(
            ThreatIntelResult(
                source_ip="45.67.89.10",
                reputation="suspicious",
                risk_score=35,
                tags=["virustotal", "suspicious_votes"],
                source="virustotal",
                description="VirusTotal suspicious votes",
            )
        ),
    )

    result = agent.lookup("45.67.89.10")

    assert result.reputation == "malicious"
    assert result.risk_score == 88
    assert result.source == "abuseipdb+virustotal"
    assert "reported" in result.tags
    assert "suspicious_votes" in result.tags
    assert "local_mock" not in result.source
