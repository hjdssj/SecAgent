import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

import app.memory.session_memory as session_memory_module
from app.analysis.state import AnalysisState
from app.memory.session_memory import SessionMemoryStore
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent


class FakeRedisPipeline:
    """
    Store Redis pipeline operations in a fake Redis object.

    Parameters:
     redis - fake Redis instance receiving writes

    Returns:
     Fake Redis pipeline

    Raises:
     None
    """

    def __init__(self, redis) -> None:
        """
        Initialize fake pipeline.

        Parameters:
         redis - fake Redis instance receiving writes

        Returns:
         None

        Raises:
         None
        """

        self.redis = redis

    def set(self, key: str, value: str, ex: int | None = None):
        """
        Record one set operation.

        Parameters:
         key - Redis key
         value - string value
         ex - optional TTL seconds

        Returns:
         Fake pipeline for chaining

        Raises:
         None
        """

        self.redis.values[key] = value
        self.redis.ttls[key] = ex
        return self

    def execute(self) -> None:
        """
        Finish fake pipeline execution.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        return None


class FakeRedis:
    """
    Provide minimal Redis behavior for session memory tests.

    Parameters:
     None

    Returns:
     Fake Redis client

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Initialize fake Redis storage.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.values: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}

    def pipeline(self) -> FakeRedisPipeline:
        """
        Return a fake Redis pipeline.

        Parameters:
         None

        Returns:
         Fake Redis pipeline

        Raises:
         None
        """

        return FakeRedisPipeline(self)

    def get(self, key: str) -> str | None:
        """
        Return a stored value by key.

        Parameters:
         key - Redis key to read

        Returns:
         Stored string or None

        Raises:
         None
        """

        return self.values.get(key)


def build_state() -> AnalysisState:
    """
    Build deterministic analysis state for session memory tests.

    Parameters:
     None

    Returns:
     Analysis state containing a final alert

    Raises:
     None
    """

    state = AnalysisState(
        session_id="session-test",
        event=SecurityEvent(source_ip="1.1.1.1", path="/login", url="/login"),
    )
    state.final_alert = SecurityAlert(
        alert_id="alert-test",
        session_id=state.session_id,
        event_id="event-test",
        attack_type="Unknown",
        risk_score=25,
        risk_level="low",
        source_ip="1.1.1.1",
        target="/login",
        confidence=0.5,
    )
    state.add_workflow_step("decision_agent", summary="Generated alert")
    state.add_finding(
        finding_type="attack_detection",
        title="Detected Unknown",
        confidence=0.5,
        source="decision_agent",
    )
    return state


def test_session_memory_store_saves_and_loads_state(monkeypatch) -> None:
    """
    Verify session memory writes and reads analysis state from Redis keys.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    fake_redis = FakeRedis()
    monkeypatch.setattr(session_memory_module, "get_redis_client", lambda: fake_redis)
    store = SessionMemoryStore(ttl_seconds=60)
    state = build_state()

    saved = store.save_state(state)
    loaded = store.load_state(state.session_id)

    assert saved is True
    assert loaded is not None
    assert loaded.session_id == "session-test"
    assert loaded.final_alert is not None
    assert loaded.final_alert.alert_id == "alert-test"
    assert fake_redis.ttls[store.result_key("session-test")] == 60
    assert store.session_key("session-test", "workflow") in fake_redis.values
