import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"

sys.path.append(str(BACKEND_DIR))

from app.storage.redis_client import ALERT_STREAM, DEADLETTER_STREAM, EVENT_STREAM, get_redis_client

from app.core.config import get_env

MEMORY_PATTERN = f"{get_env('REDIS_MEMORY_PREFIX', 'memory:ip')}:*"


def clear_redis() -> int:
    """
    Clear demo Redis streams and memory keys.

    Parameters:
     None

    Returns:
     Number of Redis keys deleted

    Raises:
     None
    """

    client = get_redis_client()
    keys = [
        EVENT_STREAM,
        ALERT_STREAM,
        DEADLETTER_STREAM,
        *client.keys(MEMORY_PATTERN),
    ]

    if not keys:
        return 0

    return int(client.delete(*keys))


def main() -> None:
    """
    Run Redis cleanup from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    deleted = clear_redis()
    print(f"deleted redis keys: {deleted}")


if __name__ == "__main__":
    main()
