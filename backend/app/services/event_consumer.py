from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.models.event import SecurityEvent
from app.storage.redis_client import EVENT_STREAM, get_redis_client, publish_alert

LAST_ID = "0-0"


def consume_once(count: int = 10) -> int:
    """
    从 Redis Stream 中消费一批安全事件并生成安全告警。

    Parameters:
     count - 单次最多消费的安全事件数量

    Returns:
     成功处理的安全事件数量

    Raises:
     None
    """

    global LAST_ID

    client = get_redis_client()
    messages = client.xread(
        streams={EVENT_STREAM: LAST_ID},
        count=count,
        block=1000,
    )

    if not messages:
        return 0

    orchestrator = SecurityAnalysisOrchestrator()
    processed = 0

    for _, stream_messages in messages:
        for message_id, fields in stream_messages:
            LAST_ID = message_id

            raw_event = fields.get("event")
            if not raw_event:
                continue

            event = SecurityEvent.model_validate_json(raw_event)
            alert = orchestrator.analyze(event)
            publish_alert(alert)

            processed += 1

    return processed


def main() -> None:
    """
    执行一次安全事件消费并打印处理数量。

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    processed = consume_once()
    print(f"processed events: {processed}")


if __name__ == "__main__":
    main()
