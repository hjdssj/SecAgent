import argparse
import time
from pathlib import Path

from redis.exceptions import RedisError

from app.core.config import PROJECT_ROOT, get_csv_env, get_env, get_float_env, get_int_env, get_path_env
from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models.event import SecurityEvent
from app.repositories.alert_repository import AlertRepository
from app.storage.redis_client import EVENT_STREAM, get_redis_client, publish_alert, publish_deadletter

DEFAULT_OFFSET_PATH = PROJECT_ROOT / "data" / "redis" / ".event_consumer.offset"
LAST_ID = get_env("EVENT_CONSUMER_START_ID", "0-0")
DEFAULT_IGNORED_PATHS = ["/__waf_health"]


def consume_once(count: int = 10, block_ms: int = 1000) -> int:
    """
    Consume one batch of security events from Redis Stream and generate alerts.

    Parameters:
     count - maximum number of security events to consume in one batch
     block_ms - maximum Redis blocking read time in milliseconds

    Returns:
     Number of successfully processed security events

    Raises:
     None
    """

    global LAST_ID

    LAST_ID = load_consumer_offset()
    client = get_redis_client()
    messages = client.xread(
        streams={EVENT_STREAM: LAST_ID},
        count=count,
        block=block_ms,
    )

    if not messages:
        return 0

    init_db()
    orchestrator = SecurityAnalysisOrchestrator()
    processed = 0

    for _, stream_messages in messages:
        for message_id, fields in stream_messages:
            raw_event = fields.get("event")
            if not raw_event:
                acknowledge_message(message_id)
                continue

            try:
                event = SecurityEvent.model_validate_json(raw_event)

                if should_ignore_event(event):
                    acknowledge_message(message_id)
                    continue

                alert = orchestrator.analyze(event)
                publish_alert(alert)

                with SessionLocal() as session:
                    AlertRepository(session).save(alert)

                processed += 1
                acknowledge_message(message_id)
            except Exception as error:
                _publish_deadletter(message_id, raw_event, error)
                acknowledge_message(message_id)

    return processed


def consumer_offset_path() -> Path:
    """
    Return the path used to persist the last consumed Redis Stream ID.

    Parameters:
     None

    Returns:
     Filesystem path for the consumer offset file

    Raises:
     None
    """

    return get_path_env("EVENT_CONSUMER_OFFSET_PATH", DEFAULT_OFFSET_PATH)


def load_consumer_offset() -> str:
    """
    Load the Redis Stream ID from which the consumer should continue.

    Parameters:
     None

    Returns:
     Last consumed Redis Stream ID, or EVENT_CONSUMER_START_ID when no offset exists

    Raises:
     None
    """

    offset_path = consumer_offset_path()

    if not offset_path.exists():
        return get_env("EVENT_CONSUMER_START_ID", "0-0")

    offset = offset_path.read_text(encoding="utf-8", errors="ignore").strip()
    return offset or get_env("EVENT_CONSUMER_START_ID", "0-0")


def save_consumer_offset(message_id: str) -> None:
    """
    Persist the latest consumed Redis Stream ID.

    Parameters:
     message_id - Redis Stream message ID that has been handled

    Returns:
     None

    Raises:
     None
    """

    offset_path = consumer_offset_path()
    offset_path.parent.mkdir(parents=True, exist_ok=True)
    offset_path.write_text(message_id, encoding="utf-8")


def acknowledge_message(message_id: str) -> None:
    """
    Mark a Redis Stream message as handled by updating memory and file offset.

    Parameters:
     message_id - Redis Stream message ID that should not be replayed

    Returns:
     None

    Raises:
     None
    """

    global LAST_ID

    LAST_ID = message_id
    save_consumer_offset(message_id)


def should_ignore_event(event: SecurityEvent) -> bool:
    """
    Decide whether a consumed event should be skipped before analysis.

    Parameters:
     event - normalized security event read from Redis Stream

    Returns:
     True when the event path is configured as consumer noise, otherwise False

    Raises:
     None
    """

    return event.path in ignored_event_paths()


def ignored_event_paths() -> set[str]:
    """
    Return event paths ignored by the consumer.

    Parameters:
     None

    Returns:
     Set of ignored event paths

    Raises:
     None
    """

    paths = get_csv_env(
        "EVENT_CONSUMER_IGNORED_PATHS",
        get_csv_env("WAF_COLLECTOR_IGNORED_PATHS", DEFAULT_IGNORED_PATHS),
    )
    return set(paths)


def consume_forever(
    count: int = 10,
    block_ms: int = 1000,
    interval_seconds: float = 1.0,
) -> None:
    """
    Continuously consume security events from Redis Stream.

    Parameters:
     count - maximum number of security events to consume in one batch
     block_ms - maximum Redis blocking read time in milliseconds
     interval_seconds - sleep interval between empty or failed reads

    Returns:
     None

    Raises:
     None
    """

    while True:
        try:
            processed = consume_once(count=count, block_ms=block_ms)
        except RedisError as error:
            print(f"consumer redis error: {error}")
            time.sleep(interval_seconds)
            continue

        if processed:
            print(f"processed events: {processed}")

        time.sleep(interval_seconds)


def _publish_deadletter(message_id: str, raw_event: str, error: Exception) -> None:
    """
    Publish a failed event to deadletter stream without interrupting the consumer.

    Parameters:
     message_id - Redis Stream message ID that failed
     raw_event - original event payload
     error - exception raised while processing the event

    Returns:
     None

    Raises:
     None
    """

    try:
        publish_deadletter(
            {
                "source_stream": EVENT_STREAM,
                "source_message_id": message_id,
                "event": raw_event,
                "error_type": type(error).__name__,
                "error": str(error),
            }
        )
    except RedisError:
        return


def main() -> None:
    """
    Run the event consumer from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = argparse.ArgumentParser(description="Consume SecAgent events from Redis.")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--count", type=int, default=get_int_env("EVENT_CONSUMER_COUNT", 10))
    parser.add_argument(
        "--block-ms",
        type=int,
        default=get_int_env("EVENT_CONSUMER_BLOCK_MS", 1000),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=get_float_env("EVENT_CONSUMER_INTERVAL", 1.0),
    )
    args = parser.parse_args()

    if args.follow:
        consume_forever(
            count=args.count,
            block_ms=args.block_ms,
            interval_seconds=args.interval,
        )
        return

    processed = consume_once(count=args.count, block_ms=args.block_ms)
    print(f"processed events: {processed}")


if __name__ == "__main__":
    main()
