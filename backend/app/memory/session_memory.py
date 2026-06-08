from redis.exceptions import RedisError

from app.analysis.state import AnalysisState
from app.core.config import get_env, get_int_env
from app.storage.redis_client import get_redis_client

RESULT_PREFIX = get_env("SESSION_RESULT_PREFIX", "security:result")
SESSION_PREFIX = get_env("SESSION_MEMORY_PREFIX", "security:session")
SESSION_TTL_SECONDS = get_int_env("SESSION_MEMORY_TTL_SECONDS", 86400)


class SessionMemoryStore:
    """
    Persist short-lived analysis session context in Redis.

    Parameters:
     result_prefix - Redis key prefix for final analysis result context
     session_prefix - Redis key prefix for detailed session sections
     ttl_seconds - Redis TTL for session context

    Returns:
     Store for analysis session memory and follow-up context

    Raises:
     None
    """

    def __init__(
        self,
        result_prefix: str = RESULT_PREFIX,
        session_prefix: str = SESSION_PREFIX,
        ttl_seconds: int = SESSION_TTL_SECONDS,
    ) -> None:
        """
        Initialize Redis-backed session memory settings.

        Parameters:
         result_prefix - Redis key prefix for final analysis result context
         session_prefix - Redis key prefix for detailed session sections
         ttl_seconds - Redis TTL for session context

        Returns:
         None

        Raises:
         None
        """

        self.result_prefix = result_prefix
        self.session_prefix = session_prefix
        self.ttl_seconds = ttl_seconds

    def save_state(self, state: AnalysisState) -> bool:
        """
        Save one analysis state into Redis session memory.

        Parameters:
         state - analysis state produced by the orchestrator

        Returns:
         True when Redis write succeeds, otherwise False

        Raises:
         None
        """

        try:
            client = get_redis_client()
            result_key = self.result_key(state.session_id)
            session_key = self.session_key(state.session_id, "state")
            findings_key = self.session_key(state.session_id, "findings")
            workflow_key = self.session_key(state.session_id, "workflow")
            reflections_key = self.session_key(state.session_id, "reflections")

            pipe = client.pipeline()
            pipe.set(result_key, state.model_dump_json(), ex=self.ttl_seconds)
            pipe.set(session_key, state.model_dump_json(), ex=self.ttl_seconds)
            pipe.set(
                findings_key,
                self._dump_list(state.findings),
                ex=self.ttl_seconds,
            )
            pipe.set(
                workflow_key,
                self._dump_list(state.workflow_steps),
                ex=self.ttl_seconds,
            )
            pipe.set(
                reflections_key,
                self._dump_list(state.reflections),
                ex=self.ttl_seconds,
            )
            pipe.execute()
        except RedisError:
            return False

        return True

    def load_state(self, session_id: str) -> AnalysisState | None:
        """
        Load one analysis state from Redis by session ID.

        Parameters:
         session_id - analysis session identifier

        Returns:
         Analysis state when found, otherwise None

        Raises:
         None
        """

        try:
            client = get_redis_client()
            raw = client.get(self.result_key(session_id))
        except RedisError:
            return None

        if not raw:
            return None

        return AnalysisState.model_validate_json(raw)

    def result_key(self, session_id: str) -> str:
        """
        Build Redis key for final analysis result context.

        Parameters:
         session_id - analysis session identifier

        Returns:
         Redis key for follow-up context

        Raises:
         None
        """

        return f"{self.result_prefix}:{session_id}"

    def session_key(self, session_id: str, section: str) -> str:
        """
        Build Redis key for one detailed session memory section.

        Parameters:
         session_id - analysis session identifier
         section - session memory section name

        Returns:
         Redis key for the requested section

        Raises:
         None
        """

        return f"{self.session_prefix}:{session_id}:{section}"

    def _dump_list(self, items: list[object]) -> str:
        """
        Serialize a list of Pydantic objects to JSON.

        Parameters:
         items - Pydantic objects to serialize

        Returns:
         JSON string containing serialized list items

        Raises:
         None
        """

        return "[" + ",".join(item.model_dump_json() for item in items) + "]"
