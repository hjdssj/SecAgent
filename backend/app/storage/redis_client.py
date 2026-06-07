from redis import Redis

from app.core.config import get_env, get_int_env
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent

EVENT_STREAM = get_env("REDIS_EVENT_STREAM", "security:events")
ALERT_STREAM = get_env("REDIS_ALERT_STREAM", "security:alerts")
DEADLETTER_STREAM = get_env("REDIS_DEADLETTER_STREAM", "security:deadletter")


def get_redis_client() -> Redis:
    """
    创建 Redis 客户端连接。

    Parameters:
     None

    Returns:
     Redis 客户端实例

    Raises:
     None
    """

    return Redis(
        host=get_env("REDIS_HOST", "localhost"),
        port=get_int_env("REDIS_PORT", 6379),
        db=get_int_env("REDIS_DB", 0),
        password=get_env("REDIS_PASSWORD") or None,
        decode_responses=True,
    )


def publish_event(event: SecurityEvent) -> str:
    """
    将标准化安全事件写入 Redis Stream。

    Parameters:
     event - 标准化安全事件对象

    Returns:
     Redis Stream 消息 ID

    Raises:
     None
    """

    client = get_redis_client()
    message_id = client.xadd(
        EVENT_STREAM,
        {
            "event": event.model_dump_json(),
        },
    )
    return message_id


def publish_alert(alert: SecurityAlert) -> str:
    """
    将生成后的安全告警写入 Redis Stream。

    Parameters:
     alert - 已生成的安全告警对象

    Returns:
     Redis Stream 消息 ID

    Raises:
     None
    """

    client = get_redis_client()
    message_id = client.xadd(
        ALERT_STREAM,
        {
            "alert": alert.model_dump_json(),
        },
    )
    return message_id


def publish_deadletter(payload: dict[str, str]) -> str:
    """
    Publish a failed event payload to the deadletter stream.

    Parameters:
     payload - string fields describing the failed event and error

    Returns:
     Redis Stream message ID

    Raises:
     None
    """

    client = get_redis_client()
    return client.xadd(DEADLETTER_STREAM, payload)


def read_recent_alerts(count: int = 20) -> list[SecurityAlert]:
    """
    从 Redis Stream 中读取最近生成的安全告警。

    Parameters:
     count - 返回的最大告警数量

    Returns:
     按时间从新到旧排列的安全告警列表

    Raises:
     None
    """

    client = get_redis_client()
    items = client.xrevrange(ALERT_STREAM, count=count)

    alerts: list[SecurityAlert] = []

    for _, fields in items:
        raw_alert = fields.get("alert")
        if not raw_alert:
            continue

        alerts.append(SecurityAlert.model_validate_json(raw_alert))

    return alerts
