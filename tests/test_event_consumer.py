import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.models.event import SecurityEvent
from app.services import event_consumer
from app.services.event_consumer import (
    acknowledge_message,
    load_consumer_offset,
    save_consumer_offset,
    should_ignore_event,
)


def test_event_consumer_ignores_waf_health_path() -> None:
    """
    Verify consumer skips WAF health check events before analysis.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(path="/__waf_health", url="/__waf_health")

    assert should_ignore_event(event) is True


def test_event_consumer_keeps_business_path() -> None:
    """
    Verify consumer keeps normal business events for analysis.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(path="/login", url="/login?id=1")

    assert should_ignore_event(event) is False


def test_event_consumer_saves_and_loads_offset(tmp_path: Path, monkeypatch) -> None:
    """
    Verify consumer persists the latest handled Redis Stream ID.

    Parameters:
     tmp_path - pytest temporary directory used to store the offset file
     monkeypatch - pytest helper used to isolate environment configuration

    Returns:
     None

    Raises:
     None
    """

    offset_path = tmp_path / ".event_consumer.offset"
    monkeypatch.setenv("EVENT_CONSUMER_OFFSET_PATH", str(offset_path))
    monkeypatch.setenv("EVENT_CONSUMER_START_ID", "0-0")

    save_consumer_offset("1780638486509-0")

    assert load_consumer_offset() == "1780638486509-0"


def test_event_consumer_acknowledges_message_offset(tmp_path: Path, monkeypatch) -> None:
    """
    Verify acknowledging a message updates memory and file offsets.

    Parameters:
     tmp_path - pytest temporary directory used to store the offset file
     monkeypatch - pytest helper used to isolate environment configuration

    Returns:
     None

    Raises:
     None
    """

    offset_path = tmp_path / ".event_consumer.offset"
    monkeypatch.setenv("EVENT_CONSUMER_OFFSET_PATH", str(offset_path))
    monkeypatch.setenv("EVENT_CONSUMER_START_ID", "0-0")

    acknowledge_message("1780638486510-0")

    assert event_consumer.LAST_ID == "1780638486510-0"
    assert load_consumer_offset() == "1780638486510-0"


def test_event_consumer_loads_start_id_when_offset_missing(tmp_path: Path, monkeypatch) -> None:
    """
    Verify consumer falls back to configured start ID when no offset file exists.

    Parameters:
     tmp_path - pytest temporary directory used to isolate offset configuration
     monkeypatch - pytest helper used to isolate environment configuration

    Returns:
     None

    Raises:
     None
    """

    monkeypatch.setenv("EVENT_CONSUMER_OFFSET_PATH", str(tmp_path / "missing.offset"))
    monkeypatch.setenv("EVENT_CONSUMER_START_ID", "42-0")

    assert load_consumer_offset() == "42-0"
