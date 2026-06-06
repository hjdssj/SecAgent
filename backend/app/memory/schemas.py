from pydantic import BaseModel, Field


class IpMemorySummary(BaseModel):
    """
    Represent historical alert memory summary for one source IP.

    Parameters:
     source_ip - source IP address summarized by memory
     alert_count - number of historical alerts recorded for the IP
     attack_types - attack types observed in historical alerts
     targets - target paths observed in historical alerts
     last_seen - last recorded event time or alert identifier
     storage_available - whether memory storage was available during lookup

    Returns:
     A structured summary of source IP historical behavior

    Raises:
     None
    """

    source_ip: str
    alert_count: int = 0
    attack_types: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    last_seen: str | None = None
    storage_available: bool = True
