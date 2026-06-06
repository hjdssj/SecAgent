from pydantic import BaseModel, Field


class ThreatIntelResult(BaseModel):
    """
    Represent local threat intelligence lookup result for a source IP.

    Parameters:
     source_ip - IP address used for threat intelligence lookup
     reputation - reputation label such as unknown, suspicious, or malicious
     risk_score - threat intelligence risk score from 0 to 100
     tags - threat tags such as scanner, botnet, proxy, or sqlmap
     source - intelligence source name
     description - human-readable intelligence description

    Returns:
     A structured threat intelligence result for alert enrichment

    Raises:
     None
    """

    source_ip: str
    reputation: str = "unknown"
    risk_score: int = Field(default=0, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    source: str = "local_mock"
    description: str = "No local threat intelligence record found."
