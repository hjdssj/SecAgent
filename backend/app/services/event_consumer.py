import argparse
import time

from redis.exceptions import RedisError

from app.core.config import get_env, get_float_env, get_int_env
from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models.event import SecurityEvent
from app.repositories.alert_repository import AlertRepository
from app.storage.redis_client import EVENT_STREAM, get_redis_client, publish_alert, publish_deadletter

LAST_ID = get_env("EVENT_CONSUMER_START_ID", "0-0")


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
            LAST_ID = message_id

            raw_event = fields.get("event")
            if not raw_event:
                continue

            try:
                event = SecurityEvent.model_validate_json(raw_event)
                alert = orchestrator.analyze(event)
                publish_alert(alert)

                with SessionLocal() as session:
                    AlertRepository(session).save(alert)

                processed += 1
            except Exception as error:
                _publish_deadletter(message_id, raw_event, error)

    return processed


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
