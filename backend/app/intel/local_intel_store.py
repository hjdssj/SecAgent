import json
from pathlib import Path
from typing import Any

from app.intel.schemas import ThreatIntelResult

DEFAULT_INTEL_PATH = Path(__file__).resolve().parents[1] / "data" / "intel" / "threat_ip_mock.json"


class LocalIntelStore:
    """
    Load local mock threat intelligence records from a JSON file.

    Parameters:
     intel_path - local JSON file containing mock IP intelligence records

    Returns:
     A local threat intelligence store instance

    Raises:
     None
    """

    def __init__(self, intel_path: Path = DEFAULT_INTEL_PATH) -> None:
        """
        Initialize the local threat intelligence store.

        Parameters:
         intel_path - local JSON file containing mock IP intelligence records

        Returns:
         None

        Raises:
         None
        """

        self.intel_path = intel_path
        self._records: dict[str, Any] | None = None

    def lookup_ip(self, source_ip: str) -> ThreatIntelResult:
        """
        Look up one source IP in the local threat intelligence store.

        Parameters:
         source_ip - source IP address to look up

        Returns:
         Threat intelligence result for the source IP

        Raises:
         None
        """

        record = self._load_records().get(source_ip)

        if not isinstance(record, dict):
            return ThreatIntelResult(source_ip=source_ip)

        return ThreatIntelResult(
            source_ip=source_ip,
            reputation=str(record.get("reputation", "unknown")),
            risk_score=int(record.get("risk_score", 0)),
            tags=[str(item) for item in record.get("tags", [])],
            source=str(record.get("source", "local_mock")),
            description=str(record.get("description", "")),
        )

    def _load_records(self) -> dict[str, Any]:
        """
        Load and cache local intelligence records.

        Parameters:
         None

        Returns:
         Mapping from IP address to intelligence record

        Raises:
         None
        """

        if self._records is not None:
            return self._records

        if not self.intel_path.exists():
            self._records = {}
            return self._records

        try:
            data = json.loads(self.intel_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._records = {}
            return self._records

        self._records = data if isinstance(data, dict) else {}
        return self._records
